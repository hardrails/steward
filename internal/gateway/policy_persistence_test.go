package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedGrantPolicyBindingSurvivesRestart(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "gp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	base, _ := url.Parse("https://inference.example.test/v1")
	route := loadedRoute{Route: Route{
		ID: "inference", BaseURL: base.String(), CredentialFile: "/secure/inference.token", MaxConcurrent: 2,
	}, base: base, credential: "credential-a"}
	egress := loadedEgressRoute{EgressRoute: EgressRoute{
		ID: "web", MaxConcurrent: 2, MaxRequestBytes: 4096, MaxResponseBytes: 8192, MaxTunnelSeconds: 30,
		Destinations: []EgressDestination{{Host: "example.com", Ports: []int{443}, AllowedCIDRs: []string{"203.0.113.0/24"}}},
	}, destinations: []loadedEgressDestination{{
		EgressDestination: EgressDestination{Host: "example.com", Ports: []int{443}, AllowedCIDRs: []string{"203.0.113.0/24"}},
		prefixes:          []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}}}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		EgressAuditFile: filepath.Join(directory, "audit.jsonl"), Routes: []Route{route.Route}, EgressRoutes: []EgressRoute{egress.EgressRoute},
	}
	routes := map[string]loadedRoute{route.ID: route}
	egressRoutes := map[string]loadedEgressRoute{egress.ID: egress}
	server, err := Open(config, routes, egressRoutes, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{
		GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1,
		RouteID: route.ID, ModelAlias: "private-model", EgressRouteIDs: []string{egress.ID},
	}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	var registered grantResponse
	if err := json.Unmarshal(response.Body.Bytes(), &registered); err != nil || registered.RoutePolicyDigest == "" {
		t.Fatalf("registered=%#v err=%v", registered, err)
	}
	persistedState, err := os.ReadFile(config.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persistedState, []byte(registered.RoutePolicyDigest)) || bytes.Contains(persistedState, []byte("credential-a")) {
		t.Fatal("gateway state did not retain the public policy commitment without credential contents")
	}
	server.closeGrantListeners()
	_ = server.audit.Close()

	reopened, err := Open(config, routes, egressRoutes, "service-token")
	if err != nil {
		t.Fatalf("unchanged policy rejected: %v", err)
	}
	if reopened.policyDigests[grant.GrantID] != registered.RoutePolicyDigest {
		t.Fatalf("retained digest=%q want=%q", reopened.policyDigests[grant.GrantID], registered.RoutePolicyDigest)
	}
	reopened.closeGrantListeners()
	_ = reopened.audit.Close()

	changedBase, _ := url.Parse("https://other-inference.example.test/v1")
	changedRoutes := map[string]loadedRoute{route.ID: route}
	changed := changedRoutes[route.ID]
	changed.BaseURL, changed.base = changedBase.String(), changedBase
	changedRoutes[route.ID] = changed
	if opened, err := Open(config, changedRoutes, egressRoutes, "service-token"); err == nil {
		opened.closeGrantListeners()
		_ = opened.audit.Close()
		t.Fatal("retained grant accepted a changed inference base URL")
	}

	changedRoutes = map[string]loadedRoute{route.ID: route}
	changed = changedRoutes[route.ID]
	changed.credential = "credential-b"
	changedRoutes[route.ID] = changed
	if opened, err := Open(config, changedRoutes, egressRoutes, "service-token"); err == nil {
		opened.closeGrantListeners()
		_ = opened.audit.Close()
		t.Fatal("retained grant accepted changed credential contents")
	}

	changedEgress := map[string]loadedEgressRoute{egress.ID: egress}
	changedEgressRoute := changedEgress[egress.ID]
	changedEgressRoute.destinations = append([]loadedEgressDestination(nil), egress.destinations...)
	changedDestination := changedEgressRoute.destinations[0]
	changedDestination.AllowedCIDRs = []string{"198.51.100.0/24"}
	changedDestination.prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	changedEgressRoute.destinations[0] = changedDestination
	changedEgress[egress.ID] = changedEgressRoute
	if opened, err := Open(config, routes, changedEgress, "service-token"); err == nil {
		opened.closeGrantListeners()
		_ = opened.audit.Close()
		t.Fatal("retained grant accepted a changed egress CIDR")
	}
}

func TestLegacyPolicyBearingGatewayStateFailsClosed(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "gpl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	base, _ := url.Parse("https://inference.example.test/v1")
	route := loadedRoute{Route: Route{ID: "inference", BaseURL: base.String(), MaxConcurrent: 1}, base: base}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), Routes: []Route{route.Route},
	}
	routes := map[string]loadedRoute{route.ID: route}
	server, err := Open(config, routes, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, RouteID: route.ID, ModelAlias: "model"}
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	server.closeGrantListeners()
	_ = server.audit.Close()

	stateRaw, err := os.ReadFile(config.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatal(err)
	}
	state["version"] = float64(1)
	grants := state["grants"].([]any)
	persisted := grants[0].(map[string]any)
	delete(persisted, "route_policy_digest")
	delete(persisted, "credential_binding_digest")
	legacy, _ := json.Marshal(state)
	if err := os.WriteFile(config.StateFile, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(config, routes, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "without a durable route policy binding") {
		if opened != nil {
			opened.closeGrantListeners()
			_ = opened.audit.Close()
		}
		t.Fatalf("legacy policy-bearing state was not rejected: %v", err)
	}
}
