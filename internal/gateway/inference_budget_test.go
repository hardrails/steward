package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInferenceAllowanceStopsConcurrentProviderCalls(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.route.MaxCallsPerGrant = 3
	var allowed, denied atomic.Int64
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := rig.call("/v1/chat/completions", `{"model":"default"}`)
			if response.Code == http.StatusOK {
				allowed.Add(1)
			} else if response.Code == http.StatusTooManyRequests &&
				strings.Contains(response.Body.String(), "inference_allowance_exhausted") &&
				response.Header().Get("X-Should-Retry") == "false" && response.Header().Get("Retry-After") == "" {
				denied.Add(1)
			} else {
				t.Errorf("unexpected response: %d %s", response.Code, response.Body.String())
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 3 || allowed.Load() != 3 || denied.Load() != 13 || len(rig.records(t)) != 6 {
		t.Fatalf("calls=%d allowed=%d denied=%d", calls.Load(), allowed.Load(), denied.Load())
	}
}

func TestInferenceAllowanceSurvivesRestartAndUnknownOutcome(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.route.MaxCallsPerGrant = 1
	if response := rig.call("/v1/responses", `{"model":"default"}`); response.Code != 422 {
		t.Fatalf("unknown attempt: %d %s", response.Code, response.Body.String())
	}
	if err := rig.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, _, err := openConnectorReceiptLedger(rig.config, rig.private)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rig.server.connectorLedger = reopened
	for range 2 {
		response := rig.call("/v1/chat/completions", `{"model":"default"}`)
		if response.Code != 429 || !strings.Contains(response.Body.String(), "inference_allowance_exhausted") {
			t.Fatalf("restart restored allowance: %d %s", response.Code, response.Body.String())
		}
	}
	if calls.Load() != 1 || len(rig.records(t)) != 2 {
		t.Fatal("denied request reached provider or appended another attempt")
	}
}

func TestInferenceAllowanceCannotFallBackToUnboundedLedger(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.route.MaxCallsPerGrant = 1
	// Hide the optional bounded interface while retaining ordinary accounting.
	rig.server.connectorLedger = struct{ connectorReceiptLog }{rig.ledger}
	response := rig.call("/v1/chat/completions", `{"model":"default"}`)
	if response.Code != 503 || calls.Load() != 0 || len(rig.records(t)) != 0 {
		t.Fatal("bounded route fell back to ordinary attempt accounting")
	}
}

func TestInferenceAllowanceIsBoundToRetainedRoutePolicy(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.server.grants = map[string]Grant{rig.grant.GrantID: rig.grant}
	previous := rig.server.routePolicyDigestLocked(rig.grant)
	for _, limit := range []int{1, 2, 0} {
		route := rig.route
		route.MaxCallsPerGrant = limit
		nextConfig := rig.config
		nextConfig.Routes = []Route{route.Route}
		if err := rig.server.Reload(nextConfig, map[string]loadedRoute{route.ID: route}, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "retained grant") {
			t.Fatalf("retained allowance change accepted on reload: %v", err)
		}
		rig.server.routes[route.ID] = route
		current := rig.server.routePolicyDigestLocked(rig.grant)
		if current == previous {
			t.Fatalf("changing allowance to %d did not change retained grant authority", limit)
		}
		previous = current
	}
}

func TestInferenceAllowanceConfigurationRejectsUnaccountedOrInvalidLimits(t *testing.T) {
	for _, test := range []struct {
		limit    int
		receipts bool
		reject   bool
	}{
		{0, false, false}, {0, true, false}, {1, true, false}, {1_000_000, true, false},
		{-1, true, true}, {1_000_001, true, true}, {1, false, true},
	} {
		config := Config{Version: 1, ControlSocket: "/tmp/control.sock", StateFile: "/tmp/state", GrantRoot: "/tmp/grants",
			ServiceTokenFile: "/tmp/token", ServiceAddress: "127.0.0.1:8092", ExecutorGID: 1, RelayGID: 1,
			Routes: []Route{{ID: "provider", BaseURL: "http://127.0.0.1:8080/v1", MaxConcurrent: 1,
				MaxCallsPerGrant: test.limit, RequireAttemptReceipts: test.receipts}}}
		_, err := config.validateAndLoadRoutes()
		if (err != nil) != test.reject {
			t.Fatalf("limit=%d receipts=%v err=%v", test.limit, test.receipts, err)
		}
	}
}
