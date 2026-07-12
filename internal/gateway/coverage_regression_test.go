package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type coverageRoundTripper func(*http.Request) (*http.Response, error)

func (f coverageRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newCoverageGateway(t *testing.T) (*Server, Config) {
	t.Helper()
	directory := t.TempDir()
	base, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: filepath.Join(directory, "token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		EgressAuditFile: filepath.Join(directory, "audit.jsonl"),
	}
	route := loadedRoute{Route: Route{ID: "local", BaseURL: base.String(), MaxConcurrent: 1}, base: base, credential: "secret"}
	destination := loadedEgressDestination{
		EgressDestination: EgressDestination{Host: "example.test", Ports: []int{443}, AllowedCIDRs: []string{"203.0.113.0/24"}},
		prefixes:          []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}
	egress := loadedEgressRoute{
		EgressRoute:  EgressRoute{ID: "web", MaxConcurrent: 1, MaxRequestBytes: 1024, MaxResponseBytes: 2048, MaxTunnelSeconds: 10},
		destinations: []loadedEgressDestination{destination},
	}
	server, err := Open(config, map[string]loadedRoute{"local": route}, map[string]loadedEgressRoute{"web": egress}, "service-secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.closeGrantListeners()
		_ = server.audit.Close()
	})
	return server, config
}

func coverageRegister(t *testing.T, server *Server, grant Grant) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	return response
}

func TestRegisterRollbackRemovesPartialAuthority(t *testing.T) {
	t.Run("state persistence", func(t *testing.T) {
		server, config := newCoverageGateway(t)
		blocker := filepath.Join(filepath.Dir(config.StateFile), "state-blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		server.config.StateFile = filepath.Join(blocker, "state.json")
		grant := Grant{GrantID: GrantID("tenant", "persist", 1), TenantID: "tenant", InstanceID: "persist", Generation: 1, RouteID: "local", ModelAlias: "model"}
		response := coverageRegister(t, server, grant)
		if response.Code != http.StatusServiceUnavailable || server.grants[grant.GrantID].GrantID != "" || server.listeners[grant.GrantID] != nil {
			t.Fatalf("status=%d grant=%#v listener=%v body=%s", response.Code, server.grants[grant.GrantID], server.listeners[grant.GrantID], response.Body.String())
		}
	})

	t.Run("service directory", func(t *testing.T) {
		server, config := newCoverageGateway(t)
		blocker := filepath.Join(filepath.Dir(config.GrantRoot), "grant-blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		server.config.GrantRoot = blocker
		grant := Grant{GrantID: GrantID("tenant", "service", 1), TenantID: "tenant", InstanceID: "service", Generation: 1, Service: true}
		response := coverageRegister(t, server, grant)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if _, ok := server.grants[grant.GrantID]; ok {
			t.Fatal("failed service registration retained a grant")
		}
	})

	t.Run("inference socket", func(t *testing.T) {
		server, config := newCoverageGateway(t)
		grant := Grant{GrantID: GrantID("tenant", "inference", 1), TenantID: "tenant", InstanceID: "inference", Generation: 1, RouteID: "local", ModelAlias: "model"}
		directory := GrantDirectory(config.GrantRoot, grant.GrantID)
		if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(directory, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		response := coverageRegister(t, server, grant)
		if response.Code != http.StatusServiceUnavailable || server.listeners[grant.GrantID] != nil {
			t.Fatalf("status=%d listener=%v body=%s", response.Code, server.listeners[grant.GrantID], response.Body.String())
		}
		if _, ok := server.grants[grant.GrantID]; ok {
			t.Fatal("failed inference registration retained a grant")
		}
	})

	t.Run("egress failure closes newly opened inference socket", func(t *testing.T) {
		server, config := newCoverageGateway(t)
		grant := Grant{
			GrantID: GrantID("tenant", "combined", 1), TenantID: "tenant", InstanceID: "combined", Generation: 1,
			RouteID: "local", ModelAlias: "model", EgressRouteIDs: []string{"web"},
		}
		directory := GrantDirectory(config.GrantRoot, grant.GrantID)
		blockedSocket := egressSocketPath(config.GrantRoot, grant.GrantID)
		if err := os.MkdirAll(blockedSocket, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blockedSocket, "keep"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		response := coverageRegister(t, server, grant)
		if response.Code != http.StatusServiceUnavailable || server.listeners[grant.GrantID] != nil || server.egressListeners[grant.GrantID] != nil {
			t.Fatalf("status=%d inference=%v egress=%v body=%s", response.Code, server.listeners[grant.GrantID], server.egressListeners[grant.GrantID], response.Body.String())
		}
		if _, err := os.Stat(inferenceSocketPath(config.GrantRoot, grant.GrantID)); !os.IsNotExist(err) {
			t.Fatalf("rolled-back inference socket remains: %v (directory %s)", err, directory)
		}
	})
}

func TestRegisterRollbackRestoresRetainedGrantBindings(t *testing.T) {
	server, config := newCoverageGateway(t)
	grant := Grant{GrantID: GrantID("tenant", "enrichment", 1), TenantID: "tenant", InstanceID: "enrichment", Generation: 1, Service: true}
	if response := coverageRegister(t, server, grant); response.Code != http.StatusCreated {
		t.Fatalf("reserve status=%d body=%s", response.Code, response.Body.String())
	}
	originalPolicy, originalCredential := server.policyDigests[grant.GrantID], server.credentialDigests[grant.GrantID]
	blocker := filepath.Join(filepath.Dir(config.GrantRoot), "enrichment-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.config.GrantRoot = blocker
	enriched := grant
	enriched.ServiceURL = ServiceSocketURL(blocker, grant.GrantID)
	response := coverageRegister(t, server, enriched)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("enrich status=%d body=%s", response.Code, response.Body.String())
	}
	if restored := server.grants[grant.GrantID]; !grantsEqual(restored, grant) || server.policyDigests[grant.GrantID] != originalPolicy || server.credentialDigests[grant.GrantID] != originalCredential {
		t.Fatalf("retained binding changed: grant=%#v policy=%q credential=%q", restored, server.policyDigests[grant.GrantID], server.credentialDigests[grant.GrantID])
	}
}

func TestProxyWebSocketRejectsUntrustedUpstreamOutcomes(t *testing.T) {
	server, _ := newCoverageGateway(t)
	base, _ := url.Parse("http://service.test")
	incoming := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "http://gateway/socket", nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		request.Header.Set("Sec-WebSocket-Version", "13")
		return request
	}
	tests := []struct {
		name      string
		transport http.RoundTripper
		want      int
		code      string
	}{
		{name: "missing transport", want: http.StatusBadGateway, code: "upstream_unavailable"},
		{name: "transport failure", want: http.StatusBadGateway, code: "upstream_unavailable", transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})},
		{name: "redirect", want: http.StatusBadGateway, code: "redirect_denied", transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("redirect")), ContentLength: 8}, nil
		})},
		{name: "ordinary response", want: http.StatusTeapot, transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTeapot, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("not-upgraded")), ContentLength: 12}, nil
		})},
		{name: "invalid upgrade body", want: http.StatusBadGateway, code: "upgrade_invalid", transport: coverageRoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{
				"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"},
				"Sec-WebSocket-Accept": []string{webSocketAccept(request.Header.Get("Sec-WebSocket-Key"))},
			}, Body: io.NopCloser(strings.NewReader("not duplex"))}, nil
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.proxyWebSocket(response, incoming(), base, "/socket", test.transport)
			if response.Code != test.want || test.code != "" && !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}

	t.Run("valid upstream cannot upgrade a non-hijackable response", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		transport := coverageRoundTripper(func(request *http.Request) (*http.Response, error) {
			headers := make(http.Header)
			headers.Set("Connection", "Upgrade")
			headers.Set("Upgrade", "websocket")
			headers.Set("Sec-WebSocket-Accept", webSocketAccept(request.Header.Get("Sec-WebSocket-Key")))
			return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: headers, Body: client}, nil
		})
		response := httptest.NewRecorder()
		server.proxyWebSocket(response, incoming(), base, "/socket", transport)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "upgrade_unavailable") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
}

func TestLoadedEgressRouteEqualityIncludesEveryAuthorityField(t *testing.T) {
	if routeBaseURL(nil) != "" || !sameLoadedRoute(loadedRoute{}, loadedRoute{}) {
		t.Fatal("empty loaded routes are not stable")
	}
	base := loadedEgressRoute{
		EgressRoute: EgressRoute{ID: "web", MaxConcurrent: 1, MaxRequestBytes: 2, MaxResponseBytes: 3, MaxTunnelSeconds: 4},
		destinations: []loadedEgressDestination{{
			EgressDestination: EgressDestination{Host: "example.test", Ports: []int{443}},
			prefixes:          []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}},
	}
	if !sameLoadedEgressRoute(base, base) {
		t.Fatal("identical egress routes differ")
	}
	mutations := []func(*loadedEgressRoute){
		func(value *loadedEgressRoute) { value.ID = "other" },
		func(value *loadedEgressRoute) { value.MaxConcurrent++ },
		func(value *loadedEgressRoute) { value.MaxRequestBytes++ },
		func(value *loadedEgressRoute) { value.MaxResponseBytes++ },
		func(value *loadedEgressRoute) { value.MaxTunnelSeconds++ },
		func(value *loadedEgressRoute) { value.destinations = nil },
		func(value *loadedEgressRoute) { value.destinations[0].Host = "other.test" },
		func(value *loadedEgressRoute) { value.destinations[0].Ports = []int{80} },
		func(value *loadedEgressRoute) {
			value.destinations[0].prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		},
	}
	for index, mutate := range mutations {
		candidate := base
		candidate.destinations = append([]loadedEgressDestination(nil), base.destinations...)
		mutate(&candidate)
		if sameLoadedEgressRoute(base, candidate) {
			t.Fatalf("authority mutation %d compared equal", index)
		}
	}
}

func TestReloadRejectsBusyConcurrencyChanges(t *testing.T) {
	server, config := newCoverageGateway(t)
	server.semaphores["local"] <- struct{}{}
	changedRoute := server.routes["local"]
	changedRoute.MaxConcurrent = 2
	changedConfig := config
	changedConfig.Routes = []Route{changedRoute.Route}
	if err := server.Reload(changedConfig, map[string]loadedRoute{"local": changedRoute}, server.egressRoutes, "next-token"); err == nil || !strings.Contains(err.Error(), "busy inference") {
		t.Fatalf("busy inference reload err=%v", err)
	}
	<-server.semaphores["local"]

	server.egressSemaphores["web"] <- struct{}{}
	changedEgress := server.egressRoutes["web"]
	changedEgress.MaxConcurrent = 2
	changedConfig = config
	changedConfig.EgressRoutes = []EgressRoute{changedEgress.EgressRoute}
	if err := server.Reload(changedConfig, server.routes, map[string]loadedEgressRoute{"web": changedEgress}, "next-token"); err == nil || !strings.Contains(err.Error(), "busy egress") {
		t.Fatalf("busy egress reload err=%v", err)
	}
	<-server.egressSemaphores["web"]
}
