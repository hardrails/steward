package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEgressProxyHTTPConnectDenialAuditAndLifecycle(t *testing.T) {
	httpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-owned" || r.Header.Get("Cookie") != "session=agent" {
			t.Errorf("end-to-end credentials not preserved: auth=%q cookie=%q", r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		if r.Header.Get("X-Remove-Me") != "" {
			t.Errorf("Connection-nominated header reached upstream")
		}
		w.Header().Set("Set-Cookie", "upstream=works")
		_, _ = w.Write([]byte("http-ok"))
	}))
	defer httpUpstream.Close()
	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("https-ok"))
	}))
	defer tlsUpstream.Close()
	httpURL, _ := url.Parse(httpUpstream.URL)
	tlsURL, _ := url.Parse(tlsUpstream.URL)
	httpPort := mustPort(t, httpURL.Port())
	tlsPort := mustPort(t, tlsURL.Port())
	directory, err := os.MkdirTemp("/tmp", "ge-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	config := Config{StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		RelayGID: os.Getgid(), EgressAuditFile: filepath.Join(directory, "egress.jsonl"), EgressRoutes: []EgressRoute{{
			ID: "public-web", MaxConcurrent: 4, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxTunnelSeconds: 10,
			Destinations: []EgressDestination{{Host: "127.0.0.1", Ports: []int{httpPort, tlsPort}, AllowedCIDRs: []string{"127.0.0.0/8"}}},
		}}}
	routes, err := config.validateEgressRoutes()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Open(config, nil, routes, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.closeGrantListeners(); _ = server.audit.Close() })
	grant := Grant{GrantID: GrantID("tenant-a", "agent-a", 1), TenantID: "tenant-a", InstanceID: "agent-a", Generation: 1,
		EgressRouteIDs: []string{"public-web"}}
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)

	proxyURL, _ := url.Parse("http://steward-relay:8082")
	roots := x509.NewCertPool()
	roots.AddCert(tlsUpstream.Certificate())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", egressSocketPath(config.GrantRoot, grant.GrantID))
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, httpUpstream.URL+"/secret-path?token=sensitive", nil)
	request.Header.Set("Authorization", "Bearer agent-owned")
	request.Header.Set("Cookie", "session=agent")
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "smuggled")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "http-ok" || response.Header.Get("Set-Cookie") != "upstream=works" {
		t.Fatalf("HTTP proxy status=%d body=%q headers=%v", response.StatusCode, body, response.Header)
	}
	response, err = client.Get(tlsUpstream.URL + "/tls-path")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "https-ok" {
		t.Fatalf("HTTPS proxy status=%d body=%q", response.StatusCode, body)
	}
	transport.CloseIdleConnections()

	deniedPort := httpPort + 1
	if deniedPort == tlsPort {
		deniedPort++
	}
	response, err = client.Get("http://127.0.0.1:" + strconv.Itoa(deniedPort) + "/denied")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	statsResponse := controlRequest(t, server, http.MethodGet, "/v1/grants/"+grant.GrantID+"/egress", nil, http.StatusOK)
	var stats EgressStats
	if err := json.Unmarshal(statsResponse, &stats); err != nil || stats.Allowed < 2 || stats.Denied < 1 || stats.BytesToAgent == 0 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	audit, err := os.ReadFile(config.EgressAuditFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(audit)
	if !strings.Contains(text, `"decision":"allow"`) || !strings.Contains(text, `"decision":"deny"`) ||
		strings.Contains(text, "secret-path") || strings.Contains(text, "sensitive") || strings.Contains(text, "agent-owned") {
		t.Fatalf("unsafe or incomplete audit: %s", text)
	}
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/deactivate", nil, http.StatusOK)
	response, err = client.Get(httpUpstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestEgressDestinationMatchingAndAddressSafety(t *testing.T) {
	if !hostMatches("*.example.com", "api.v2.example.com") || hostMatches("*.example.com", "example.com") || hostMatches("example.com", "api.example.com") {
		t.Fatal("hostname wildcard boundary is incorrect")
	}
	private := netip.MustParseAddr("10.1.2.3")
	loopback := netip.MustParseAddr("127.0.0.1")
	public := netip.MustParseAddr("8.8.8.8")
	if addressAllowed(private, nil) || addressAllowed(loopback, nil) || !addressAllowed(public, nil) {
		t.Fatal("default address safety policy is incorrect")
	}
	if !addressAllowed(private, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}) ||
		!addressAllowed(loopback, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}) ||
		addressAllowed(private, []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}) {
		t.Fatal("explicit CIDR pinning is incorrect")
	}
}

func TestGatewayReloadFencesGrantedRoutesAndRuntimePaths(t *testing.T) {
	directory := t.TempDir()
	config := Config{Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: filepath.Join(directory, "token"), StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: 1, RelayGID: 1, EgressAuditFile: filepath.Join(directory, "audit.jsonl"), EgressRoutes: []EgressRoute{{
			ID: "web", MaxConcurrent: 1, MaxRequestBytes: 1024, MaxResponseBytes: 2048, MaxTunnelSeconds: 30,
			Destinations: []EgressDestination{{Host: "example.com", Ports: []int{443}}},
		}}}
	routes, err := config.validateEgressRoutes()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Open(config, nil, routes, "token-a")
	if err != nil {
		t.Fatal(err)
	}
	defer server.audit.Close()
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, EgressRouteIDs: []string{"web"}}
	server.grants[grant.GrantID] = grant
	changed := config
	changed.EgressRoutes = append([]EgressRoute(nil), config.EgressRoutes...)
	changed.EgressRoutes[0].MaxConcurrent = 2
	changedRoutes, _ := changed.validateEgressRoutes()
	server.egressSemaphores["web"] <- struct{}{}
	if err := server.Reload(changed, nil, changedRoutes, "token-b"); err == nil || !strings.Contains(err.Error(), "busy egress route") {
		t.Fatalf("busy limit change accepted: %v", err)
	}
	if cap(server.egressSemaphores["web"]) != 1 {
		t.Fatal("failed reload changed the live egress semaphore")
	}
	<-server.egressSemaphores["web"]
	if err := server.Reload(changed, nil, changedRoutes, "token-b"); err != nil || cap(server.egressSemaphores["web"]) != 2 {
		t.Fatalf("reload err=%v capacity=%d", err, cap(server.egressSemaphores["web"]))
	}
	if err := server.Reload(changed, nil, nil, "token-b"); err == nil || !strings.Contains(err.Error(), "removes egress route") {
		t.Fatalf("granted route removal accepted: %v", err)
	}
	changed.ControlSocket += ".moved"
	if err := server.Reload(changed, nil, changedRoutes, "token-b"); err == nil {
		t.Fatal("runtime socket path change accepted")
	}
}

func TestEgressHTTPFailureModesAreBoundedAndFailClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			w.Header().Set("Content-Length", "20")
			_, _ = w.Write([]byte("01234567890123456789"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	port := mustPort(t, parsed.Port())
	audit, err := openAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	route := loadedEgressRoute{EgressRoute: EgressRoute{ID: "web", MaxConcurrent: 1, MaxRequestBytes: 4, MaxResponseBytes: 5, MaxTunnelSeconds: 5},
		destinations: []loadedEgressDestination{{EgressDestination: EgressDestination{Host: "127.0.0.1", Ports: []int{port}}, prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}}
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, EgressRouteIDs: []string{"web"}, Active: true}
	server := &Server{routes: map[string]loadedRoute{}, egressRoutes: map[string]loadedEgressRoute{"web": route},
		egressSemaphores: map[string]chan struct{}{"web": make(chan struct{}, 1)}, grants: map[string]Grant{grant.GrantID: grant},
		egressStats: map[string]EgressStats{}, audit: audit}
	handler := server.egressHandler(grant.GrantID)
	request := httptest.NewRequest(http.MethodGet, "/relative", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("relative status=%d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://example.com:443/denied", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("route status=%d", recorder.Code)
	}
	server.egressSemaphores["web"] <- struct{}{}
	request = httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("busy status=%d", recorder.Code)
	}
	<-server.egressSemaphores["web"]
	request = httptest.NewRequest(http.MethodPost, upstream.URL, strings.NewReader("oversized"))
	request.ContentLength = 9
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("request limit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, upstream.URL+"/large", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "response_too_large") {
		t.Fatalf("response limit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "audit_unavailable") {
		t.Fatalf("audit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestResolveAllowedIPAndProxyDestinationValidation(t *testing.T) {
	destination := loadedEgressDestination{prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	address, err := resolveAllowedIP(context.Background(), "127.0.0.1", destination)
	if err != nil || address.String() != "127.0.0.1" {
		t.Fatalf("address=%v err=%v", address, err)
	}
	if _, err := resolveAllowedIP(context.Background(), "127.0.0.1", loadedEgressDestination{}); err == nil {
		t.Fatal("private literal accepted without CIDR")
	}
	localhost := loadedEgressDestination{prefixes: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}}
	address, err = resolveAllowedIP(context.Background(), "localhost", localhost)
	if err != nil || !address.IsLoopback() {
		t.Fatalf("localhost address=%v err=%v", address, err)
	}
	if _, err := resolveAllowedIP(context.Background(), "not a dns name", localhost); err == nil {
		t.Fatal("invalid DNS name resolved")
	}
	for _, target := range []string{"ftp://example.com/file", "http://user@example.com/file"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if _, _, err := proxyDestination(request); err == nil {
			t.Fatalf("invalid target accepted: %s", target)
		}
	}
	badPort := httptest.NewRequest(http.MethodGet, "http://example.com/file", nil)
	badPort.URL.Host = "example.com:bad"
	if _, _, err := proxyDestination(badPort); err == nil {
		t.Fatal("invalid port accepted")
	}
	request := httptest.NewRequest(http.MethodConnect, "http://proxy", nil)
	request.Host = "missing-port"
	if _, _, err := proxyDestination(request); err == nil {
		t.Fatal("CONNECT without port accepted")
	}
}

func TestAuditLogRotatesAndRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.jsonl")
	audit, err := openAuditLog(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.file.Truncate(maxAuditBytes); err != nil {
		t.Fatal(err)
	}
	if err := audit.Append(egressAuditEvent{Decision: "deny", Reason: "test", GrantID: GrantID("t", "i", 1), TenantID: "t", InstanceID: "i", Method: "GET"}); err != nil {
		t.Fatal(err)
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Size() != maxAuditBytes {
		t.Fatalf("rotated info=%v err=%v", info, err)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), `"decision":"deny"`) {
		t.Fatalf("new audit=%q err=%v", raw, err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unsafe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openAuditLog(filepath.Join(directory, "unsafe"), true); err == nil {
		t.Fatal("world-readable audit accepted")
	}
	disabled, err := openAuditLog("", false)
	if err != nil || disabled.Append(egressAuditEvent{}) != nil || disabled.Close() != nil {
		t.Fatalf("disabled audit err=%v", err)
	}
}

func TestEgressConnectFailuresAndHelperEdges(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	audit, err := openAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	route := loadedEgressRoute{EgressRoute: EgressRoute{ID: "web", MaxConcurrent: 1, MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxTunnelSeconds: 1},
		destinations: []loadedEgressDestination{{EgressDestination: EgressDestination{Host: "127.0.0.1", Ports: []int{port}}, prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}}
	grant := Grant{GrantID: GrantID("t", "i", 1), TenantID: "t", InstanceID: "i", Generation: 1, Active: true, EgressRouteIDs: []string{"web"}}
	server := &Server{egressRoutes: map[string]loadedEgressRoute{"web": route}, egressSemaphores: map[string]chan struct{}{"web": make(chan struct{}, 1)},
		grants: map[string]Grant{grant.GrantID: grant}, egressStats: map[string]EgressStats{}, audit: audit}
	request := httptest.NewRequest(http.MethodConnect, "http://proxy", nil)
	request.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	recorder := httptest.NewRecorder()
	server.egressHandler(grant.GrantID).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("non-hijacker status=%d", recorder.Code)
	}
	_ = listener.Close()
	request = httptest.NewRequest(http.MethodConnect, "http://proxy", nil)
	request.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	recorder = httptest.NewRecorder()
	server.egressHandler(grant.GrantID).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("closed upstream status=%d", recorder.Code)
	}
	if !GrantsEqual(grant, grant) || min64(2, 1) != 1 || min64(1, 2) != 1 || max64(2, 1) != 2 || max64(1, 2) != 2 {
		t.Fatal("gateway helper result is incorrect")
	}
	for _, test := range []struct {
		raw, host string
		invalid   bool
	}{{"example.com", "example.com", false}, {"example.com:bad", "example.com", true}, {"[::1]", "::1", false}, {"[::1]:bad", "::1", true}, {"::1", "::1", true}} {
		if invalidExplicitPort(test.raw, test.host) != test.invalid {
			t.Fatalf("invalidExplicitPort(%q,%q)", test.raw, test.host)
		}
	}
	recorder = httptest.NewRecorder()
	server.getEgressStats(recorder, httptest.NewRequest(http.MethodGet, "/v1/grants/missing/egress", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing stats status=%d", recorder.Code)
	}
}

func controlRequest(t *testing.T, server *Server, method, path string, value any, want int) []byte {
	t.Helper()
	var body io.Reader
	if value != nil {
		raw, _ := json.Marshal(value)
		body = strings.NewReader(string(raw))
	}
	recorder := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(recorder, httptest.NewRequest(method, path, body))
	if recorder.Code != want {
		t.Fatalf("%s %s status=%d body=%s", method, path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	port, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
