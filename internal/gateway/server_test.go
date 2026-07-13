package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func testGateway(t *testing.T, upstream string) (*Server, Config) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: filepath.Join(directory, "token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: directory, ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		Routes: []Route{{ID: "local", BaseURL: upstream, MaxConcurrent: 2}},
	}
	routes := map[string]loadedRoute{"local": {Route: config.Routes[0], base: parsed, credential: "upstream-secret"}}
	server, err := Open(config, routes, nil, "service-secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.closeGrantListeners)
	return server, config
}

func TestRelayHTTPResponseUsesAnExactByteCeiling(t *testing.T) {
	t.Run("known oversized response fails before forwarding", func(t *testing.T) {
		response := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Length": []string{"5"}},
			Body:          io.NopCloser(strings.NewReader("12345")),
			ContentLength: 5,
		}
		recorder := httptest.NewRecorder()
		relayHTTPResponseBounded(recorder, response, true, 4)
		if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "response_too_large") {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("unknown length overflow aborts without leaking a probe byte", func(t *testing.T) {
		response := &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Length": []string{"5"}, "Set-Cookie": []string{"secret=1"}},
			Body:          io.NopCloser(strings.NewReader("12345")),
			ContentLength: -1,
		}
		recorder := httptest.NewRecorder()
		expectHTTPAbort(t, func() { relayHTTPResponseBounded(recorder, response, true, 4) })
		if recorder.Code != http.StatusOK || recorder.Body.String() != "1234" {
			t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("Content-Length") != "" || recorder.Header().Get("Set-Cookie") != "" ||
			recorder.Header().Get("X-Steward-Service-Grant") != "active" ||
			recorder.Header().Get(streamStatusTrailer) != "response_too_large" {
			t.Fatalf("headers=%v", recorder.Header())
		}
	})
}

func TestUnknownLengthResponseSignalsCompletionOrAbortsConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body io.Reader = strings.NewReader("1234")
		if request.URL.Path == "/oversized" {
			body = strings.NewReader("12345")
		} else if request.URL.Path == "/failed" {
			body = io.MultiReader(strings.NewReader("12"), iotest.ErrReader(errors.New("upstream truncated")))
		}
		relayHTTPResponseBounded(w, &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(body), ContentLength: -1,
		}, false, 4)
	}))
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/complete")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || string(body) != "1234" || response.Trailer.Get(streamStatusTrailer) != "completed" {
		t.Fatalf("complete body=%q readErr=%v trailers=%v", body, readErr, response.Trailer)
	}

	response, err = server.Client().Get(server.URL + "/oversized")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr == nil || string(body) != "1234" {
		t.Fatalf("oversized body=%q readErr=%v; want a client-visible framing error", body, readErr)
	}

	response, err = server.Client().Get(server.URL + "/failed")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr == nil || string(body) != "12" {
		t.Fatalf("failed body=%q readErr=%v; want a client-visible framing error", body, readErr)
	}
}

func expectHTTPAbort(t *testing.T, action func()) {
	t.Helper()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		action()
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("recovered=%v; want http.ErrAbortHandler", recovered)
	}
}

func TestGrantInferenceAndServiceFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer upstream-secret" || r.Header.Get("Cookie") != "" {
			t.Fatalf("unexpected upstream request path=%s auth=%q cookie=%q", r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected service request path=%s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte("agent-ok"))
	}))
	defer service.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{
		GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1,
		RouteID: "local", ModelAlias: "model", Service: true, ServiceURL: service.URL,
	}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	socket := inferenceSocketPath(config.GrantRoot, grant.GrantID)
	client := unixHTTPClient(socket)
	request, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"model"}`))
	request.Header.Set("Authorization", "Bearer sentinel")
	request.Header.Set("Cookie", "secret=agent")
	result, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", result.StatusCode)
	}
	_ = result.Body.Close()
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	request, _ = http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"model"}`))
	result, err = client.Do(request)
	if err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("inference status=%v err=%v", result.StatusCode, err)
	}
	_ = result.Body.Close()
	serviceRequest := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/health", nil)
	serviceRequest.Header.Set("Authorization", "Bearer service-secret")
	response = httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(response, serviceRequest)
	if response.Code != http.StatusOK || response.Body.String() != "agent-ok" {
		t.Fatalf("service status=%d body=%s", response.Code, response.Body.String())
	}
	for _, denied := range []*http.Request{
		httptest.NewRequest(http.MethodConnect, "/v1/services/"+grant.GrantID+"/health", nil),
		httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/../secret", nil),
		httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/%252e%252e/secret", nil),
		httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/..%255csecret", nil),
	} {
		denied.Header.Set("Authorization", "Bearer service-secret")
		response = httptest.NewRecorder()
		server.ServiceHandler().ServeHTTP(response, denied)
		if response.Code != http.StatusForbidden {
			t.Fatalf("denied service status=%d body=%s", response.Code, response.Body.String())
		}
	}
	server.semaphores[grant.RouteID] <- struct{}{}
	server.semaphores[grant.RouteID] <- struct{}{}
	request, _ = http.NewRequest(http.MethodGet, "http://gateway/v1/models", nil)
	result, err = client.Do(request)
	if err != nil || result.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("busy route status=%v err=%v", result, err)
	}
	_ = result.Body.Close()
	<-server.semaphores[grant.RouteID]
	<-server.semaphores[grant.RouteID]
}

func TestServiceProxyUsesOnlyTheGrantUnixSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{
		GrantID: GrantID("tenant", "unix-service", 1), TenantID: "tenant", InstanceID: "unix-service", Generation: 1,
		Service: true,
	}
	grant.ServiceURL = ServiceSocketURL(config.GrantRoot, grant.GrantID)
	register := func(value Grant) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(value)
		response := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
		return response
	}
	response := register(grant)
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	listener, err := net.Listen("unix", serviceSocketPath(config.GrantRoot, grant.GrantID))
	if err != nil {
		t.Fatal(err)
	}
	var followedRedirect atomic.Bool
	service := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte("unix-ok"))
		case "/redirect":
			http.Redirect(w, r, "/redirect-target", http.StatusFound)
		case "/redirect-target":
			followedRedirect.Store(true)
			_, _ = w.Write([]byte("redirect-followed"))
		default:
			http.NotFound(w, r)
		}
	})}
	defer func() {
		_ = service.Close()
		_ = listener.Close()
	}()
	go func() { _ = service.Serve(listener) }()
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/health", nil)
	request.Header.Set("Authorization", "Bearer service-secret")
	response = httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "unix-ok" {
		t.Fatalf("service status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/redirect", nil)
	request.Header.Set("Authorization", "Bearer service-secret")
	response = httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "redirect_denied") || followedRedirect.Load() {
		t.Fatalf("redirect status=%d body=%s followed=%t", response.Code, response.Body.String(), followedRedirect.Load())
	}

	wrong := Grant{
		GrantID: GrantID("tenant", "wrong-service", 1), TenantID: "tenant", InstanceID: "wrong-service", Generation: 1,
		Service: true, ServiceURL: grant.ServiceURL,
	}
	response = register(wrong)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("cross-grant socket status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGrantFencingAuthenticationAndRestartState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "agent", 2), TenantID: "tenant", InstanceID: "agent", Generation: 2, RouteID: "local", ModelAlias: "model"}
	register := func(value Grant) int {
		raw, _ := json.Marshal(value)
		response := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
		return response.Code
	}
	if got := register(grant); got != http.StatusCreated {
		t.Fatalf("register=%d", got)
	}
	rollback := grant
	rollback.Generation = 1
	if got := register(rollback); got != http.StatusBadRequest {
		t.Fatalf("rollback=%d", got)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/", nil)
	response := httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", response.Code)
	}
	server.closeGrantListeners()
	reopened, err := Open(config, server.routes, nil, "service-secret")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.grants[grant.GrantID].Active {
		t.Fatal("gateway restart silently reactivated grant")
	}
}

func TestInactiveInferenceGrantAllowsOnlyServiceEnrichment(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer service.Close()
	server, _ := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "agent", 4), TenantID: "tenant", InstanceID: "agent", Generation: 4, RouteID: "local", ModelAlias: "model", Service: true}
	register := func(value Grant) int {
		raw, _ := json.Marshal(value)
		response := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
		return response.Code
	}
	if got := register(grant); got != http.StatusCreated {
		t.Fatalf("reserve=%d", got)
	}
	grant.Service, grant.ServiceURL = true, service.URL
	if got := register(grant); got != http.StatusCreated {
		t.Fatalf("enrich=%d", got)
	}
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/grants/"+grant.GrantID, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), service.URL) {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	changed := grant
	changed.ModelAlias = "other"
	if got := register(changed); got != http.StatusConflict {
		t.Fatalf("changed=%d", got)
	}
}

func TestGrantDeactivateUnregisterAndServiceDenials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "service", 1), TenantID: "tenant", InstanceID: "service", Generation: 1, Service: true, ServiceURL: upstream.URL}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	for _, action := range []string{"activate", "deactivate"} {
		response = httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/"+action, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", action, response.Code, response.Body.String())
		}
	}
	authorized := func(method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer service-secret")
		response := httptest.NewRecorder()
		server.ServiceHandler().ServeHTTP(response, request)
		return response
	}
	if got := authorized(http.MethodGet, "/v1/services/"+grant.GrantID+"/"); got.Code != http.StatusNotFound {
		t.Fatalf("inactive service status=%d", got.Code)
	}
	if got := authorized(http.MethodGet, "/unknown"); got.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d", got.Code)
	}
	windowStarted := time.Now()
	server.connectorAttempts[grant.GrantID] = connectorAttemptWindow{started: windowStarted, count: maxConnectorAttemptsPerMinute}
	server.egressDeniedAttempts[grant.GrantID] = egressDeniedAttemptWindow{started: windowStarted, count: maxEgressDeniedAttemptsPerGrantMinute}
	server.egressTenantDenials[grant.TenantID] = egressDeniedAttemptWindow{started: windowStarted, count: maxEgressDeniedAttemptsPerTenantMinute}
	server.egressHostDenials = egressDeniedAttemptWindow{started: windowStarted, count: 1}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/grants/"+grant.GrantID, nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(GrantDirectory(config.GrantRoot, grant.GrantID)); !os.IsNotExist(err) {
		t.Fatalf("grant directory still exists: %v", err)
	}
	if _, ok := server.egressDeniedAttempts[grant.GrantID]; ok {
		t.Fatal("unregistered grant retained its egress denial window")
	}
	if got := server.egressTenantDenials[grant.TenantID].count; got != maxEgressDeniedAttemptsPerTenantMinute {
		t.Fatal("unregister reset the tenant denial window and allowed grant churn to borrow shared capacity")
	}
	if _, ok := server.connectorAttempts[grant.GrantID]; ok {
		t.Fatal("unregistered grant retained its connector attempt window")
	}
	if server.egressHostDenials.count != 1 {
		t.Fatal("unregister reset the host denial window and reopened shared audit capacity")
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/grants/"+grant.GrantID, nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("idempotent delete status=%d", response.Code)
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/missing/activate", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing activate status=%d", response.Code)
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/grants/missing", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing get status=%d", response.Code)
	}
}

func TestUnregisterRestoresGrantWhenStateCannotPersist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "agent", 9), TenantID: "tenant", InstanceID: "agent", Generation: 9, RouteID: "local", ModelAlias: "model"}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	blocker := filepath.Join(filepath.Dir(config.StateFile), "state-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.config.StateFile = filepath.Join(blocker, "state.json")
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	if response.Code != http.StatusServiceUnavailable || server.grants[grant.GrantID].Active {
		t.Fatalf("failed activation was not rolled back: status=%d grant=%#v", response.Code, server.grants[grant.GrantID])
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/grants/"+grant.GrantID, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unregister status=%d body=%s", response.Code, response.Body.String())
	}
	if restored, ok := server.grants[grant.GrantID]; !ok || !grantsEqual(restored, grant) || server.listeners[grant.GrantID] == nil {
		t.Fatalf("grant was not restored after persistence failure: %#v", restored)
	}
}

func TestGrantAndProxyValidationErrors(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	server, _ := testGateway(t, redirect.URL)
	for _, body := range []string{
		`{}`,
		`{"grant_id":"grant-` + strings.Repeat("a", 64) + `","tenant_id":"t","instance_id":"i","generation":1,"service":true,"service_url":"http://example.com:80"}`,
		`{"grant_id":"grant-` + strings.Repeat("a", 64) + `","tenant_id":"t","instance_id":"i","generation":1,"service":true,"service_url":"http://127.0.0.1:80?"}`,
		`{"grant_id":"grant-` + strings.Repeat("a", 64) + `","tenant_id":"t","instance_id":"i","generation":1,"route_id":"missing","model_alias":"model","service":false}`,
		`{"grant_id":"grant-` + strings.Repeat("a", 64) + `","tenant_id":"t","instance_id":"i","generation":1,"service":false,"service_url":"http://127.0.0.1:80"}`,
		`{"grant_id":"grant-` + strings.Repeat("a", 64) + `","tenant_id":"t","instance_id":"i","generation":1,"service":true,"active":true}`,
		strings.Repeat("x", maxConfigBytes+1),
	} {
		response := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid register status=%d body=%s", response.Code, response.Body.String())
		}
	}
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, RouteID: "local", ModelAlias: "model"}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	client := unixHTTPClient(inferenceSocketPath(server.config.GrantRoot, grant.GrantID))
	for _, spec := range []struct{ method, path string }{{http.MethodGet, "/v1/chat/completions"}, {http.MethodGet, "/v1/models?q=x"}} {
		result, err := client.Do(mustRequest(t, spec.method, "http://gateway"+spec.path))
		if err != nil || result.StatusCode != http.StatusForbidden {
			t.Fatalf("denied request status=%v err=%v", result, err)
		}
		_ = result.Body.Close()
	}
	request := mustRequest(t, http.MethodPost, "http://gateway/v1/chat/completions")
	request.Body = io.NopCloser(strings.NewReader(`{"model":"model"}`))
	request.ContentLength = int64(len(`{"model":"model"}`))
	result, err := client.Do(request)
	if err != nil || result.StatusCode != http.StatusBadGateway {
		t.Fatalf("redirect status=%v err=%v", result, err)
	}
	_ = result.Body.Close()
	redirect.Close()
	request = mustRequest(t, http.MethodPost, "http://gateway/v1/chat/completions")
	request.Body = io.NopCloser(strings.NewReader(`{"model":"model"}`))
	request.ContentLength = int64(len(`{"model":"model"}`))
	result, err = client.Do(request)
	if err != nil || result.StatusCode != http.StatusBadGateway {
		t.Fatalf("unavailable status=%v err=%v", result, err)
	}
	_ = result.Body.Close()
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestGatewayStartServesUnixControlAndShutsDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(config.ControlSocket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := unixHTTPClient(config.ControlSocket).Get("http://gateway/v1/healthz")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("health response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not shut down")
	}
}

func TestGatewayStartRestoresEphemeralServiceGrantDirectory(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{
		GrantID: GrantID("tenant", "service-restart", 1), TenantID: "tenant", InstanceID: "service-restart", Generation: 1,
		Service: true,
	}
	grant.ServiceURL = ServiceSocketURL(config.GrantRoot, grant.GrantID)
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	server.closeGrantListeners()
	reopened, err := Open(config, server.routes, nil, "service-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(config.GrantRoot); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reopened.Start(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	directory := GrantDirectory(config.GrantRoot, grant.GrantID)
	for time.Now().Before(deadline) {
		if info, statErr := os.Stat(directory); statErr == nil && info.IsDir() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o730 {
		t.Fatalf("restored directory info=%v err=%v", info, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not shut down")
	}
}

func TestOpenRejectsUntrustedPersistedState(t *testing.T) {
	parsed, _ := url.Parse("http://127.0.0.1:1")
	routes := map[string]loadedRoute{"local": {Route: Route{ID: "local", BaseURL: parsed.String(), MaxConcurrent: 1}, base: parsed}}
	if _, err := Open(Config{}, routes, nil, ""); err == nil {
		t.Fatal("empty service token accepted")
	}
	valid := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, RouteID: "local", ModelAlias: "model"}
	duplicate, _ := json.Marshal(snapshot{Version: 1, Grants: []retainedGrant{retainGrant(valid, "", ""), retainGrant(valid, "", "")}})
	invalid, _ := json.Marshal(snapshot{Version: 1, Grants: []retainedGrant{retainGrant(Grant{GrantID: "bad"}, "", "")}})
	for _, test := range []struct {
		name string
		raw  []byte
		mode os.FileMode
		dir  bool
	}{
		{name: "malformed", raw: []byte(`{}`), mode: 0o600},
		{name: "duplicate", raw: duplicate, mode: 0o600},
		{name: "invalid grant", raw: invalid, mode: 0o600},
		{name: "permissive", raw: []byte(`{"version":1,"grants":[]}`), mode: 0o644},
		{name: "oversized", raw: []byte(strings.Repeat("x", maxConfigBytes+1)), mode: 0o600},
		{name: "directory", mode: 0o700, dir: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := os.MkdirTemp("/tmp", "gs-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			state := filepath.Join(directory, "state.json")
			if test.dir {
				if err := os.Mkdir(state, test.mode); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(state, test.raw, test.mode); err != nil {
				t.Fatal(err)
			}
			config := Config{StateFile: state, GrantRoot: filepath.Join(directory, "grants"), ControlSocket: filepath.Join(directory, "control.sock"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid()}
			if _, err := Open(config, routes, nil, "token"); err == nil {
				t.Fatal("untrusted state accepted")
			}
		})
	}
}

func TestInspectStateReportsFormatAndRetainedGrantCount(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	config := Config{StateFile: statePath, GrantRoot: filepath.Join(directory, "grants")}
	serviceGrant := Grant{
		GrantID: GrantID("tenant", "service", 1), TenantID: "tenant", InstanceID: "service", Generation: 1, Service: true,
	}
	for _, test := range []struct {
		name    string
		version int
		grants  []retainedGrant
	}{
		{name: "empty-v1", version: 1, grants: []retainedGrant{}},
		{name: "empty-v2", version: 2, grants: []retainedGrant{}},
		{name: "retained-v1", version: 1, grants: []retainedGrant{retainGrant(serviceGrant, "", "")}},
		{name: "retained-v2", version: 2, grants: []retainedGrant{retainGrant(serviceGrant, "", "")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(snapshot{Version: test.version, Grants: test.grants})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			summary, err := InspectState(config, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !summary.Present || summary.FormatVersion != test.version || summary.RetainedGrants != len(test.grants) {
				t.Fatalf("summary = %#v", summary)
			}
		})
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	summary, err := InspectState(config, nil, nil)
	if err != nil || summary != (StateSummary{}) {
		t.Fatalf("missing state summary=%#v err=%v", summary, err)
	}
}

func TestGatewayStartReportsInvalidSocketDirectories(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	blocker := filepath.Join(filepath.Dir(config.ControlSocket), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.config.ControlSocket = filepath.Join(blocker, "control.sock")
	if err := server.Start(context.Background()); err == nil {
		t.Fatal("invalid control socket directory accepted")
	}
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}
