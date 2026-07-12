package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferenceGrantEnforcesModelAndSynthesizesModels(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		if r.Header.Get("Authorization") != "Bearer upstream-secret" {
			t.Errorf("upstream credential=%q", r.Header.Get("Authorization"))
		}
		raw, _ := io.ReadAll(r.Body)
		if !bytes.Contains(raw, []byte(`"model":"tenant/model"`)) {
			t.Errorf("forwarded body=%s", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"hidden-upstream-model"}`))
	}))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1,
		RouteID: "local", ModelAlias: "tenant/model"}
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	client := unixHTTPClient(inferenceSocketPath(config.GrantRoot, grant.GrantID))

	for _, path := range []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/responses"} {
		body := `{"input":{"nested":[1,true,null]},"model":"tenant/model"}`
		request, _ := http.NewRequest(http.MethodPost, "http://gateway"+path, strings.NewReader(body))
		response, err := client.Do(request)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("path=%s response=%v err=%v", path, response, err)
		}
		_ = response.Body.Close()
	}
	beforeModels := upstreamRequests.Load()
	response, err := client.Get("http://gateway/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	var models struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&models); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || models.Object != "list" || len(models.Data) != 1 || models.Data[0].ID != grant.ModelAlias {
		t.Fatalf("models status=%d payload=%#v", response.StatusCode, models)
	}
	if upstreamRequests.Load() != beforeModels {
		t.Fatal("model discovery reached the upstream and could leak its catalog")
	}

	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "missing", body: `{"input":"hello"}`, want: http.StatusBadRequest},
		{name: "nested only", body: `{"input":{"model":"tenant/model"}}`, want: http.StatusBadRequest},
		{name: "mismatch", body: `{"model":"other"}`, want: http.StatusForbidden},
		{name: "duplicate", body: `{"model":"tenant/model","model":"other"}`, want: http.StatusBadRequest},
		{name: "escaped duplicate", body: `{"model":"tenant/model","mo\u0064el":"tenant/model"}`, want: http.StatusBadRequest},
		{name: "other duplicate", body: `{"model":"tenant/model","input":1,"input":2}`, want: http.StatusBadRequest},
		{name: "non string", body: `{"model":["tenant/model"]}`, want: http.StatusBadRequest},
		{name: "top level array", body: `["tenant/model"]`, want: http.StatusBadRequest},
		{name: "trailing", body: `{"model":"tenant/model"}{}`, want: http.StatusBadRequest},
	}
	beforeDenied := upstreamRequests.Load()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(test.body))
			response, err := client.Do(request)
			if err != nil || response.StatusCode != test.want {
				t.Fatalf("response=%v err=%v", response, err)
			}
			_ = response.Body.Close()
		})
	}
	oversized := strings.Repeat(" ", maxProxyBody) + `{"model":"tenant/model"}`
	request, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(oversized))
	response, err = client.Do(request)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if upstreamRequests.Load() != beforeDenied {
		t.Fatal("denied model request reached upstream")
	}
}

func TestInferenceStreamIsRevokedOnDeactivate(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "stream", 1), TenantID: "tenant", InstanceID: "stream", Generation: 1,
		RouteID: "local", ModelAlias: "model"}
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	done := make(chan struct{})
	go func() {
		defer close(done)
		request, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"model"}`))
		response, err := unixHTTPClient(inferenceSocketPath(config.GrantRoot, grant.GrantID)).Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inference request did not reach upstream")
	}
	server.mu.Lock()
	lease := server.grantLeases[grant.GrantID].context
	server.mu.Unlock()
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/deactivate", nil, http.StatusOK)
	select {
	case <-lease.Done():
	case <-time.After(time.Second):
		t.Fatal("deactivation did not cancel the grant lease")
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("deactivation did not cancel inference upstream")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("inference request survived deactivation")
	}
}

func TestReloadFencesInferenceRouteAndExposesPolicyDigest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, config := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1,
		RouteID: "local", ModelAlias: "model"}
	raw := controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	var registered grantResponse
	if err := json.Unmarshal(raw, &registered); err != nil || !strings.HasPrefix(registered.RoutePolicyDigest, "sha256:") {
		t.Fatalf("registration=%s err=%v", raw, err)
	}
	inspection := controlRequest(t, server, http.MethodGet, "/v1/grants/"+grant.GrantID, nil, http.StatusOK)
	if !bytes.Contains(inspection, []byte(registered.RoutePolicyDigest)) || bytes.Contains(inspection, []byte("upstream-secret")) {
		t.Fatalf("inspection did not expose a safe stable digest: %s", inspection)
	}

	changedConfig := config
	changedConfig.Routes = append([]Route(nil), config.Routes...)
	changedConfig.Routes[0].MaxConcurrent++
	changedRoute := server.routes["local"]
	changedRoute.MaxConcurrent++
	if err := server.Reload(changedConfig, map[string]loadedRoute{"local": changedRoute}, nil, "service-secret"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("retained inference concurrency change accepted: %v", err)
	}
	credentialChange := server.routes["local"]
	credentialChange.credential = "rotated"
	if err := server.Reload(config, map[string]loadedRoute{"local": credentialChange}, nil, "service-secret"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("retained inference credential change accepted: %v", err)
	}
	baseChange := server.routes["local"]
	baseChange.base, _ = url.Parse("http://127.0.0.1:1")
	baseChange.BaseURL = baseChange.base.String()
	changedConfig = config
	changedConfig.Routes = []Route{baseChange.Route}
	if err := server.Reload(changedConfig, map[string]loadedRoute{"local": baseChange}, nil, "service-secret"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("retained inference target change accepted: %v", err)
	}

	delete(server.grants, grant.GrantID)
	if err := server.Reload(changedConfig, map[string]loadedRoute{"local": baseChange}, nil, "rotated-service-token"); err != nil {
		t.Fatalf("unreferenced inference route change rejected: %v", err)
	}
}
