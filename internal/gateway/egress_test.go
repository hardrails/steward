package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	"sync"
	"sync/atomic"
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
	replacement := grant
	replacement.Generation = 2
	replacement.EgressRouteIDs = nil
	replacement.Service = true
	controlRequest(t, server, http.MethodPost, "/v1/grants", replacement, http.StatusBadRequest)
	current := server.grants[grant.GrantID]
	if !current.Active || !GrantsEqual(current, Grant{GrantID: grant.GrantID, TenantID: grant.TenantID, InstanceID: grant.InstanceID,
		Generation: grant.Generation, EgressRouteIDs: grant.EgressRouteIDs, Active: true}) {
		t.Fatalf("active replacement changed grant: %#v", current)
	}
	select {
	case <-server.egressLeases[grant.GrantID].context.Done():
		t.Fatal("rejected replacement revoked unchanged active authority")
	default:
	}

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
	windowStarted := time.Now()
	server.mu.Lock()
	server.egressDeniedAttempts[grant.GrantID] = egressDeniedAttemptWindow{
		started: windowStarted, count: maxEgressDeniedAttemptsPerGrantMinute,
	}
	server.egressTenantDenials[grant.TenantID] = egressDeniedAttemptWindow{
		started: windowStarted, count: maxEgressDeniedAttemptsPerTenantMinute,
	}
	server.egressHostDenials = egressDeniedAttemptWindow{started: windowStarted, count: maxEgressDeniedAttemptsHostMinute}
	server.mu.Unlock()
	allowedAfterSaturation, _ := http.NewRequest(http.MethodGet, httpUpstream.URL+"/allowed-after-denial-saturation", nil)
	allowedAfterSaturation.Header.Set("Authorization", "Bearer agent-owned")
	allowedAfterSaturation.Header.Set("Cookie", "session=agent")
	response, err = client.Do(allowedAfterSaturation)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "http-ok" {
		t.Fatalf("denial saturation blocked allowed traffic: status=%d body=%q", response.StatusCode, body)
	}
	server.mu.Lock()
	server.egressDeniedAttempts = make(map[string]egressDeniedAttemptWindow)
	server.egressTenantDenials = make(map[string]egressDeniedAttemptWindow)
	server.egressHostDenials = egressDeniedAttemptWindow{}
	server.mu.Unlock()
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
	if connection, err := openProxyTLS(egressSocketPath(config.GrantRoot, grant.GrantID), net.JoinHostPort("127.0.0.1", strconv.Itoa(tlsPort)), "other.example"); err == nil {
		_ = connection.Close()
		t.Fatal("CONNECT accepted TLS SNI outside the approved IP destination")
	}
	activeTunnel, err := openProxyTLS(egressSocketPath(config.GrantRoot, grant.GrantID), net.JoinHostPort("127.0.0.1", strconv.Itoa(tlsPort)), "")
	if err != nil {
		t.Fatalf("open revocation test tunnel: %v", err)
	}

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
	_ = activeTunnel.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := activeTunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("deactivated grant left an established CONNECT tunnel open")
	}
	_ = activeTunnel.Close()
	response, err = client.Get(httpUpstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	destroyTunnel, err := openProxyTLS(egressSocketPath(config.GrantRoot, grant.GrantID), net.JoinHostPort("127.0.0.1", strconv.Itoa(tlsPort)), "")
	if err != nil {
		t.Fatalf("open unregister test tunnel: %v", err)
	}
	controlRequest(t, server, http.MethodDelete, "/v1/grants/"+grant.GrantID, nil, http.StatusNoContent)
	_ = destroyTunnel.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := destroyTunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("unregistered grant left an established CONNECT tunnel open")
	}
	_ = destroyTunnel.Close()
}

func TestEgressDeactivationCancelsInflightHTTPRequest(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	port := mustPort(t, parsed.Port())
	directory, err := os.MkdirTemp("/tmp", "ger-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	config := Config{StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		RelayGID: os.Getgid(), EgressAuditFile: filepath.Join(directory, "egress.jsonl"), EgressRoutes: []EgressRoute{{
			ID: "web", MaxConcurrent: 1, MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, MaxTunnelSeconds: 30,
			Destinations: []EgressDestination{{Host: "127.0.0.1", Ports: []int{port}, AllowedCIDRs: []string{"127.0.0.0/8"}}},
		}}}
	routes, err := config.validateEgressRoutes()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Open(config, nil, routes, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.closeGrantListeners(); _ = server.audit.Close() }()
	grant := Grant{GrantID: GrantID("tenant", "http-agent", 1), TenantID: "tenant", InstanceID: "http-agent", Generation: 1, EgressRouteIDs: []string{"web"}}
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	proxyURL, _ := url.Parse("http://steward-relay:8082")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", egressSocketPath(config.GrantRoot, grant.GrantID))
	}}, Timeout: 5 * time.Second}
	result := make(chan struct{}, 1)
	go func() {
		response, _ := client.Get(upstream.URL)
		if response != nil {
			_ = response.Body.Close()
		}
		result <- struct{}{}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request did not start")
	}
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/deactivate", nil, http.StatusOK)
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("deactivation did not cancel the upstream HTTP context")
	}
	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight HTTP request survived deactivation")
	}
}

func TestEgressDeniedAttemptLimitIsGrantIsolatedAndSkipsAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := openAuditLog(auditPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()

	grantA := Grant{GrantID: GrantID("tenant-a", "agent-a", 1), TenantID: "tenant-a", InstanceID: "agent-a", Generation: 1,
		EgressRouteIDs: []string{"web"}, Active: true}
	grantSameTenant := Grant{GrantID: GrantID("tenant-a", "agent-b", 1), TenantID: "tenant-a", InstanceID: "agent-b", Generation: 1,
		EgressRouteIDs: []string{"web"}, Active: true}
	grantOtherTenant := Grant{GrantID: GrantID("tenant-b", "agent-a", 1), TenantID: "tenant-b", InstanceID: "agent-a", Generation: 1,
		EgressRouteIDs: []string{"web"}, Active: true}
	server := &Server{
		grants: map[string]Grant{
			grantA.GrantID: grantA, grantSameTenant.GrantID: grantSameTenant, grantOtherTenant.GrantID: grantOtherTenant,
		},
		egressDeniedAttempts: map[string]egressDeniedAttemptWindow{
			grantA.GrantID: {started: time.Now(), count: maxEgressDeniedAttemptsPerGrantMinute},
		},
		egressStats: map[string]EgressStats{}, audit: audit,
	}

	before, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/relative", nil)
	response := httptest.NewRecorder()
	server.egressHandler(grantA.GrantID).ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), `"error":"egress_rate_limited"`) {
		t.Fatalf("exhausted grant status=%d body=%s", response.Code, response.Body.String())
	}
	after, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || server.egressStats[grantA.GrantID].Denied != 0 {
		t.Fatalf("rate-limited denial wrote audit/stats: before=%d after=%d stats=%#v", before.Size(), after.Size(), server.egressStats[grantA.GrantID])
	}

	for _, grant := range []Grant{grantSameTenant, grantOtherTenant} {
		request = httptest.NewRequest(http.MethodGet, "/relative", nil)
		response = httptest.NewRecorder()
		server.egressHandler(grant.GrantID).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || server.egressStats[grant.GrantID].Denied != 1 {
			t.Fatalf("independent grant %s status=%d stats=%#v body=%s", grant.GrantID, response.Code, server.egressStats[grant.GrantID], response.Body.String())
		}
	}
}

func TestEgressLateDenialPreservesGrantRevocationResponse(t *testing.T) {
	server := &Server{grants: make(map[string]Grant)}
	grant := Grant{GrantID: "grant-deleted", TenantID: "tenant-a", InstanceID: "agent-a"}
	response := httptest.NewRecorder()
	server.rejectEgress(response, grant, "grant_revoked", http.MethodConnect, "api.example.test", 443,
		http.StatusServiceUnavailable, "egress grant was revoked during address resolution")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"grant_revoked"`) ||
		strings.Contains(response.Body.String(), "egress_rate_limited") {
		t.Fatalf("late revocation status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEgressRevocationResponsesSurviveDenialSaturation(t *testing.T) {
	grant := Grant{
		GrantID: GrantID("tenant-a", "agent-a", 1), TenantID: "tenant-a", InstanceID: "agent-a",
		Generation: 1, EgressRouteIDs: []string{"web"}, Active: false,
	}
	started := time.Now()
	server := &Server{
		grants: map[string]Grant{grant.GrantID: grant},
		egressDeniedAttempts: map[string]egressDeniedAttemptWindow{
			grant.GrantID: {started: started, count: maxEgressDeniedAttemptsPerGrantMinute},
		},
		egressTenantDenials: map[string]egressDeniedAttemptWindow{
			grant.TenantID: {started: started, count: maxEgressDeniedAttemptsPerTenantMinute},
		},
		egressHostDenials: egressDeniedAttemptWindow{started: started, count: maxEgressDeniedAttemptsHostMinute},
	}

	inactive := httptest.NewRecorder()
	server.egressHandler(grant.GrantID).ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil))
	if inactive.Code != http.StatusServiceUnavailable || !strings.Contains(inactive.Body.String(), `"error":"grant_inactive"`) ||
		strings.Contains(inactive.Body.String(), "egress_rate_limited") {
		t.Fatalf("saturated inactive response status=%d body=%s", inactive.Code, inactive.Body.String())
	}

	revoked := httptest.NewRecorder()
	server.rejectEgress(revoked, grant, "grant_revoked", http.MethodConnect, "api.example.test", 443,
		http.StatusServiceUnavailable, "egress grant was revoked during address resolution")
	if revoked.Code != http.StatusServiceUnavailable || !strings.Contains(revoked.Body.String(), `"error":"grant_revoked"`) ||
		strings.Contains(revoked.Body.String(), "egress_rate_limited") {
		t.Fatalf("saturated revoked response status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestEgressDeniedAttemptFixedWindowsPreserveTenantCapacity(t *testing.T) {
	if maxEgressDeniedAttemptsPerTenantMinute >= maxEgressDeniedAttemptsHostMinute {
		t.Fatal("one tenant must not be able to exhaust the host denial budget")
	}
	started := time.Unix(1_700_000_000, 0)
	grants := make(map[string]Grant)
	tenantAGrants := make([]string, 5)
	for index := range tenantAGrants {
		tenantAGrants[index] = fmt.Sprintf("tenant-a-grant-%d", index)
		grants[tenantAGrants[index]] = Grant{GrantID: tenantAGrants[index], TenantID: "tenant-a"}
	}
	grants["tenant-b-grant"] = Grant{GrantID: "tenant-b-grant", TenantID: "tenant-b"}
	server := &Server{
		grants:               grants,
		egressDeniedAttempts: make(map[string]egressDeniedAttemptWindow),
		egressTenantDenials:  make(map[string]egressDeniedAttemptWindow),
	}
	for _, grantID := range tenantAGrants[:4] {
		for attempt := 0; attempt < maxEgressDeniedAttemptsPerGrantMinute; attempt++ {
			if !server.allowEgressDeniedAttempt(grantID, started.Add(time.Duration(attempt)*time.Millisecond)) {
				t.Fatalf("grant %s attempt %d denied before layered fixed-window limit", grantID, attempt)
			}
		}
	}
	if got := server.egressTenantDenials["tenant-a"].count; got != maxEgressDeniedAttemptsPerTenantMinute {
		t.Fatalf("tenant-a denial count=%d want=%d", got, maxEgressDeniedAttemptsPerTenantMinute)
	}
	if server.allowEgressDeniedAttempt(tenantAGrants[4], started.Add(30*time.Second)) {
		t.Fatal("tenant-a borrowed capacity after exhausting its fixed tenant window")
	}
	if _, ok := server.egressDeniedAttempts[tenantAGrants[4]]; ok {
		t.Fatal("tenant denial consumed or created an unused grant window")
	}
	if !server.allowEgressDeniedAttempt("tenant-b-grant", started.Add(30*time.Second)) {
		t.Fatal("one tenant exhausted another tenant's reserved denial capacity")
	}
	if got := server.egressHostDenials.count; got != maxEgressDeniedAttemptsPerTenantMinute+1 {
		t.Fatalf("host denial count=%d want=%d", got, maxEgressDeniedAttemptsPerTenantMinute+1)
	}
}

func TestEgressDeniedAttemptClockRollbackAndFixedWindowReset(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	server := &Server{
		grants: map[string]Grant{"grant-a": {GrantID: "grant-a", TenantID: "tenant-a"}},
		egressDeniedAttempts: map[string]egressDeniedAttemptWindow{
			"grant-a": {started: started, count: maxEgressDeniedAttemptsPerGrantMinute},
		},
		egressTenantDenials: map[string]egressDeniedAttemptWindow{
			"tenant-a": {started: started, count: maxEgressDeniedAttemptsPerTenantMinute},
		},
		egressHostDenials: egressDeniedAttemptWindow{started: started, count: maxEgressDeniedAttemptsHostMinute},
	}
	if server.allowEgressDeniedAttempt("grant-a", started.Add(-time.Second)) {
		t.Fatal("clock rollback reopened denial authority")
	}
	if server.allowEgressDeniedAttempt("grant-a", started.Add(30*time.Second)) {
		t.Fatal("exhausted fixed windows accepted an attempt before reset")
	}
	resetAt := started.Add(time.Minute)
	if !server.allowEgressDeniedAttempt("grant-a", resetAt) {
		t.Fatal("elapsed fixed windows did not reset together")
	}
	for name, window := range map[string]egressDeniedAttemptWindow{
		"grant":  server.egressDeniedAttempts["grant-a"],
		"tenant": server.egressTenantDenials["tenant-a"],
		"host":   server.egressHostDenials,
	} {
		if !window.started.Equal(resetAt) || window.count != 1 {
			t.Fatalf("%s window after reset=%#v want started=%s count=1", name, window, resetAt)
		}
	}
}

func TestEgressDeniedAttemptConcurrentHostBound(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	server := &Server{grants: make(map[string]Grant)}
	grantIDs := make([]string, 32)
	for index := range grantIDs {
		grantIDs[index] = fmt.Sprintf("grant-%d", index)
		server.grants[grantIDs[index]] = Grant{GrantID: grantIDs[index], TenantID: fmt.Sprintf("tenant-%d", index)}
	}
	server.grants["spare"] = Grant{GrantID: "spare", TenantID: "spare-tenant"}
	var accepted atomic.Int64
	var wait sync.WaitGroup
	const attempts = 2048
	wait.Add(attempts)
	for attempt := 0; attempt < attempts; attempt++ {
		grantID := grantIDs[attempt%len(grantIDs)]
		go func() {
			defer wait.Done()
			if server.allowEgressDeniedAttempt(grantID, started) {
				accepted.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := accepted.Load(); got != int64(maxEgressDeniedAttemptsHostMinute) {
		t.Fatalf("concurrent accepted denials=%d want host bound=%d", got, maxEgressDeniedAttemptsHostMinute)
	}
	if server.allowEgressDeniedAttempt("spare", started) {
		t.Fatal("concurrent attempts exceeded the host denial bound")
	}
}

func TestEgressDeniedAttemptProductionClockReadIsSerialized(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	server := &Server{
		grants: map[string]Grant{"grant-a": {GrantID: "grant-a", TenantID: "tenant-a"}},
	}
	var sampledOutsideLock atomic.Bool
	clock := func() time.Time {
		if server.mu.TryLock() {
			sampledOutsideLock.Store(true)
			server.mu.Unlock()
		}
		return now
	}

	if decision := server.reserveEgressDeniedAttemptWithClock("grant-a", clock); decision != egressDenialAllowed {
		t.Fatalf("first egress denial decision=%v", decision)
	}
	if sampledOutsideLock.Load() {
		t.Fatal("production egress denial limiter sampled its clock before taking the state lock")
	}
}

func TestEgressDeniedAttemptConcurrentUnregisterDoesNotResurrectState(t *testing.T) {
	started := time.Unix(1_700_000_000, 0)
	server := &Server{grants: map[string]Grant{"grant-a": {GrantID: "grant-a", TenantID: "tenant-a"}}}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for attempt := 0; attempt < 256; attempt++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			server.allowEgressDeniedAttempt("grant-a", started)
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		server.mu.Lock()
		delete(server.grants, "grant-a")
		delete(server.egressDeniedAttempts, "grant-a")
		delete(server.egressTenantDenials, "tenant-a")
		server.mu.Unlock()
	}()
	close(start)
	wait.Wait()
	server.mu.Lock()
	_, grantWindowExists := server.egressDeniedAttempts["grant-a"]
	_, tenantWindowExists := server.egressTenantDenials["tenant-a"]
	server.mu.Unlock()
	if grantWindowExists || tenantWindowExists {
		t.Fatalf("late denials recreated state: grant=%t tenant=%t", grantWindowExists, tenantWindowExists)
	}
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
	server.policyDigests[grant.GrantID] = server.routePolicyDigestLocked(grant)
	server.credentialDigests[grant.GrantID] = routeCredentialBindingDigest(grant, server.routes)
	changed := config
	changed.EgressRoutes = append([]EgressRoute(nil), config.EgressRoutes...)
	changed.EgressRoutes[0].MaxConcurrent = 2
	changedRoutes, _ := changed.validateEgressRoutes()
	if err := server.Reload(changed, nil, changedRoutes, "token-b"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("retained route limit change accepted: %v", err)
	}
	if cap(server.egressSemaphores["web"]) != 1 {
		t.Fatal("failed reload changed the live egress semaphore")
	}
	delete(server.grants, grant.GrantID)
	delete(server.policyDigests, grant.GrantID)
	delete(server.credentialDigests, grant.GrantID)
	if err := server.Reload(changed, nil, changedRoutes, "token-b"); err != nil || cap(server.egressSemaphores["web"]) != 2 {
		t.Fatalf("unreferenced route reload err=%v capacity=%d", err, cap(server.egressSemaphores["web"]))
	}
	server.grants[grant.GrantID] = grant
	server.policyDigests[grant.GrantID] = server.routePolicyDigestLocked(grant)
	server.credentialDigests[grant.GrantID] = routeCredentialBindingDigest(grant, server.routes)
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
		if r.URL.Path == "/stream-large" {
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("012345"))
			return
		}
		if r.URL.Path == "/stream-fail" {
			connection, buffer, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack truncated response: %v", err)
				return
			}
			defer connection.Close()
			_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12")
			_ = buffer.Flush()
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
	request = httptest.NewRequest(http.MethodGet, upstream.URL+"/stream-large", nil)
	recorder = httptest.NewRecorder()
	expectHTTPAbort(t, func() { handler.ServeHTTP(recorder, request) })
	stats := server.egressStats[grant.GrantID]
	if recorder.Code != http.StatusOK || recorder.Body.String() != "01234" ||
		recorder.Header().Get(streamStatusTrailer) != "response_too_large" ||
		stats.LastDecision != "terminal:response_too_large" || stats.BytesToAgent != 5 {
		t.Fatalf("stream limit status=%d body=%q stats=%#v", recorder.Code, recorder.Body.String(), stats)
	}
	request = httptest.NewRequest(http.MethodGet, upstream.URL+"/stream-fail", nil)
	recorder = httptest.NewRecorder()
	expectHTTPAbort(t, func() { handler.ServeHTTP(recorder, request) })
	stats = server.egressStats[grant.GrantID]
	if recorder.Code != http.StatusOK || recorder.Body.String() != "12" ||
		recorder.Header().Get(streamStatusTrailer) != "stream_failed" ||
		stats.LastDecision != "terminal:stream_failed" {
		t.Fatalf("stream failure status=%d body=%q stats=%#v", recorder.Code, recorder.Body.String(), stats)
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

func TestConnectCopyBoundedNeverForwardsTheProbeByte(t *testing.T) {
	for _, test := range []struct {
		name    string
		source  string
		wantN   int64
		wantOut string
	}{
		{name: "below limit", source: "1234", wantN: 4, wantOut: "1234"},
		{name: "exact limit", source: "12345", wantN: 5, wantOut: "12345"},
		{name: "over limit", source: "123456", wantN: 6, wantOut: "12345"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var destination strings.Builder
			written, err := copyBounded(&destination, strings.NewReader(test.source), 5)
			if err != nil || written != test.wantN || destination.String() != test.wantOut {
				t.Fatalf("written=%d output=%q err=%v", written, destination.String(), err)
			}
		})
	}
}

func TestConnectHandshakeDeadlineAndBridgePeerCancellation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	longTunnel := now.Add(time.Hour)
	if got := boundedTLSClientHelloDeadline(now, longTunnel); got != now.Add(tlsClientHelloTimeout) {
		t.Fatalf("long tunnel hello deadline=%v", got)
	}
	shortTunnel := now.Add(time.Second)
	if got := boundedTLSClientHelloDeadline(now, shortTunnel); got != shortTunnel {
		t.Fatalf("short tunnel hello deadline=%v", got)
	}

	agent, agentPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	done := make(chan struct{})
	go func() {
		bridgeConnect(agent, agent, upstream, 1024, 1024)
		close(done)
	}()
	_ = upstreamPeer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("one closed CONNECT direction left its peer copy blocked")
	}
	_ = agentPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := agentPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("CONNECT bridge did not close the opposite peer")
	}
	_ = agentPeer.Close()
}

func TestResolveAllowedIPAndProxyDestinationValidation(t *testing.T) {
	destination := loadedEgressDestination{prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	address, err := resolveAllowedIP(context.Background(), "127.0.0.1", destination)
	if err != nil || address.String() != "127.0.0.1" {
		t.Fatalf("address=%v err=%v", address, err)
	}
	if _, err := resolveAllowedIP(context.Background(), "127.0.0.1", loadedEgressDestination{}); err == nil ||
		!errors.Is(err, errAddressDenied) {
		t.Fatalf("private literal policy error=%v", err)
	}
	localhost := loadedEgressDestination{prefixes: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}}
	address, err = resolveAllowedIP(context.Background(), "localhost", localhost)
	if err != nil || !address.IsLoopback() {
		t.Fatalf("localhost address=%v err=%v", address, err)
	}
	if _, err := resolveAllowedIP(context.Background(), "not a dns name", localhost); err == nil ||
		!errors.Is(err, errAddressResolutionFailed) {
		t.Fatalf("invalid DNS resolution error=%v", err)
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

func TestClassifyAddressFailureSeparatesPolicyResolutionAndRevocation(t *testing.T) {
	if status, code := classifyAddressFailure(errAddressDenied, context.Background()); status != http.StatusForbidden || code != "address_denied" {
		t.Fatalf("policy status=%d code=%q", status, code)
	}
	if status, code := classifyAddressFailure(errAddressResolutionFailed, context.Background()); status != http.StatusBadGateway || code != "resolution_failed" {
		t.Fatalf("resolution status=%d code=%q", status, code)
	}
	lease, revoke := context.WithCancel(context.Background())
	revoke()
	if status, code := classifyAddressFailure(errAddressResolutionFailed, lease); status != http.StatusServiceUnavailable || code != "grant_revoked" {
		t.Fatalf("revocation status=%d code=%q", status, code)
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
	if !tlsServerNameAllowed("api.example.com", "api.example.com") || tlsServerNameAllowed("api.example.com", "other.example.com") ||
		!tlsServerNameAllowed("127.0.0.1", "") || tlsServerNameAllowed("127.0.0.1", "api.example.com") {
		t.Fatal("CONNECT TLS server-name policy is incorrect")
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

type bufferedTestConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedTestConn) Read(value []byte) (int, error) { return c.reader.Read(value) }

func openProxyTLS(socket, authority, serverName string) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: time.Second}).Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		_ = raw.Close()
		return nil, err
	}
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_ = raw.Close()
		return nil, fmt.Errorf("CONNECT status %d", response.StatusCode)
	}
	connection := tls.Client(&bufferedTestConn{Conn: raw, reader: reader}, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- the test isolates proxy policy, not certificate trust.
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
	})
	if err := connection.Handshake(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
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
