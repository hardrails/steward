package gateway

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

func taskScopedInferenceRig(t *testing.T, serviceURL string, provider *httptest.Server) (*serviceTaskRig, loadedRoute) {
	t.Helper()
	rig := newServiceTaskRig(t, serviceURL)
	base, _ := url.Parse(provider.URL)
	route := loadedRoute{Route: Route{ID: "scoped", MaxConcurrent: 4, RequireAttemptReceipts: true, RequireTaskScope: true}, base: base, credential: "provider-only-key"}
	rig.server.routes = map[string]loadedRoute{route.ID: route}
	rig.server.config.Routes = []Route{route.Route}
	rig.grant.RouteID, rig.grant.ModelAlias, rig.grant.Active = route.ID, "default", true
	rig.server.grants[rig.grant.GrantID] = rig.grant
	rig.server.policyDigests[rig.grant.GrantID] = rig.server.routePolicyDigestLocked(rig.grant)
	if !rig.server.validGrant(rig.grant) {
		t.Fatal("test's complete scoped grant was rejected")
	}
	return rig, route
}

func scopedInferenceCall(rig *serviceTaskRig, route loadedRoute, permit string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", strings.NewReader(`{"model":"default"}`))
	request.Header.Set("Authorization", "Bearer "+permit)
	// Neither a name nor an extra unverified header supplies authority. Neither
	// may leak the permit to the external provider.
	request.Header.Set("X-Task-Id", "not-authority")
	request.Header.Set(inferencePermitHeader, permit)
	result := httptest.NewRecorder()
	rig.server.proxyInference(result, request, rig.grant, route)
	return result
}

func TestScopedInferenceUsesOnlyAdmittedPermitsAndKeepsConcurrentTaskIdentity(t *testing.T) {
	var calls atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get("Authorization") != "Bearer provider-only-key" || request.Header.Get(inferencePermitHeader) != "" {
			t.Error("task permit leaked to the provider")
		}
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer provider.Close()
	carried := make(chan string, 2)
	var accepted atomic.Int64
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		carried <- request.Header.Get(inferencePermitHeader)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_, _ = fmt.Fprintf(w, `{"run_id":"run-%d"}`, accepted.Add(1))
	}))
	defer service.Close()
	rig, route := taskScopedInferenceRig(t, service.URL, provider)
	bodies := [][]byte{[]byte(`{"input":"first task"}`), []byte(`{"input":"second task"}`)}
	permits := []string{taskPermitFor(t, rig, "first", bodies[0], nil), taskPermitFor(t, rig, "second", bodies[1], nil)}
	for _, permit := range []string{"steward-local", "forged-task-name", permits[0]} {
		if result := scopedInferenceCall(rig, route, permit); result.Code != 403 || result.Header().Get("X-Should-Retry") != "false" {
			t.Fatalf("unadmitted scope reached inference: %d", result.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("denied scope reached the provider")
	}
	for i, permit := range permits {
		if result := invokeServiceTask(rig, bodies[i], permit); result.Code != 202 {
			t.Fatalf("task admission=%d %s", result.Code, result.Body.String())
		}
		if got := <-carried; got != permit {
			t.Fatal("service did not receive its original admitted scope")
		}
	}
	var workers sync.WaitGroup
	for _, permit := range permits {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if result := scopedInferenceCall(rig, route, permit); result.Code != 200 {
				t.Errorf("admitted scope refused: %d %s", result.Code, result.Body.String())
			}
		}()
	}
	workers.Wait()
	seen := map[string]int{}
	public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
	if _, err := connectorledger.VerifyRecords(rig.config.ConnectorReceiptFile, public, rig.config.ConnectorReceiptNodeID, 1,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			if event.Kind == connectorledger.InferenceAttempt {
				if record.Receipt.SchemaVersion != connectorledger.SchemaV10 {
					t.Error("scoped attempt lost its schema")
				}
				seen[event.InferenceRequestDigest]++
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(seen) != 2 || seen[taskpermit.RequestDigest(bodies[0])] != 2 || seen[taskpermit.RequestDigest(bodies[1])] != 2 {
		t.Fatalf("cross-task accounting: calls=%d receipts=%v", calls.Load(), seen)
	}
	// Rebuild authority through the production verified ledger reader, not a
	// copied map or reissued task. Ongoing admission survives permit expiry.
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, index, err := openConnectorReceiptLedger(rig.config, rig.config.connectorReceiptKey)
	if err != nil {
		t.Fatal(err)
	}
	rig.server.connectorLedger, rig.server.serviceTasks, rig.server.serviceTaskPermits = reopened, index.tasks, index.permits
	rig.server.now = func() time.Time { return rig.now.Add(24 * time.Hour) }
	if result := scopedInferenceCall(rig, route, permits[1]); result.Code != 200 || calls.Load() != 3 {
		t.Fatalf("retained task scope lost across ledger reopen: %d %s", result.Code, result.Body.String())
	}
	// Terminal authority refuses a new inference call, even if the worker still
	// holds the original permit. The native ledger closes the race separately.
	raw, _ := decodeServiceTaskPermitHeader(permits[0])
	task := rig.server.serviceTaskPermits[dsse.Digest(raw)]
	state := rig.server.serviceTasks[task]
	terminal := state.Dispatch
	terminal.Phase, terminal.Outcome, terminal.TaskStatus = connectorledger.Terminal, connectorledger.Responded, connectorledger.TaskStatusAgentReportedCompleted
	terminal.HTTPStatus = 200
	terminal.ResultDigest = "sha256:" + strings.Repeat("1", 64)
	if err := rig.server.finishServiceTask(task, terminal); err != nil {
		t.Fatal(err)
	}
	if result := scopedInferenceCall(rig, route, permits[0]); result.Code != 403 || calls.Load() != 3 {
		t.Fatal("closed task retained inference authority")
	}
	rig.server.mu.Lock()
	revoked := rig.server.grants[rig.grant.GrantID]
	revoked.Active = false
	rig.server.grants[rig.grant.GrantID] = revoked
	rig.server.mu.Unlock()
	if result := scopedInferenceCall(rig, route, permits[1]); result.Code != 403 || calls.Load() != 3 {
		t.Fatal("revoked grant retained inference authority")
	}
}

func TestTaskScopeChangesPolicyAndRequiresTaskAuthority(t *testing.T) {
	provider := httptest.NewServer(http.NotFoundHandler())
	defer provider.Close()
	rig := newInferenceReceiptRig(t, provider)
	before := rig.server.routePolicyDigestLocked(rig.grant)
	route := rig.route
	route.RequireTaskScope = true
	rig.server.routes[route.ID] = route
	if before == rig.server.routePolicyDigestLocked(rig.grant) || rig.server.validGrant(rig.grant) {
		t.Fatal("task scope was not an authority-bearing policy restriction")
	}
}

type closeParentBeforeInferenceBegin struct {
	connectorReceiptLog
	closeParent func()
}

func (log closeParentBeforeInferenceBegin) Begin(event connectorledger.Event) (connectorledger.Head, error) {
	log.closeParent()
	return log.connectorReceiptLog.Begin(event)
}

func TestParentClosingBeforeInferenceBeginReturnsScopeDenial(t *testing.T) {
	var calls atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer provider.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"run_id":"closing-run"}`))
	}))
	defer service.Close()
	rig, route := taskScopedInferenceRig(t, service.URL, provider)
	body := []byte(`{"input":"closing task"}`)
	permit := taskPermitFor(t, rig, "closing", body, nil)
	if result := invokeServiceTask(rig, body, permit); result.Code != 202 {
		t.Fatalf("admission=%d %s", result.Code, result.Body.String())
	}
	raw, _ := decodeServiceTaskPermitHeader(permit)
	task := rig.server.serviceTaskPermits[dsse.Digest(raw)]
	ledger := rig.server.connectorLedger
	rig.server.connectorLedger = closeParentBeforeInferenceBegin{ledger, func() {
		terminal := rig.server.serviceTasks[task].Dispatch
		terminal.Phase, terminal.Outcome = connectorledger.Terminal, connectorledger.Responded
		terminal.TaskStatus, terminal.HTTPStatus = connectorledger.TaskStatusAgentReportedCompleted, 200
		terminal.ResultDigest = "sha256:" + strings.Repeat("1", 64)
		if err := rig.server.finishServiceTask(task, terminal); err != nil {
			t.Fatal(err)
		}
	}}
	for range 2 { // First failure and replay both identify task authority, not storage.
		result := scopedInferenceCall(rig, route, permit)
		if result.Code != 403 || result.Header().Get("X-Should-Retry") != "false" ||
			!strings.Contains(result.Body.String(), "inference_task_scope_required") ||
			strings.Contains(result.Body.String(), "restore the ledger") {
			t.Fatalf("wrong closing-task boundary: %d %s", result.Code, result.Body.String())
		}
	}
	if calls.Load() != 0 || ledger.Failed() {
		t.Fatal("scope rejection contacted the provider or poisoned the ledger")
	}
	public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
	if _, err := connectorledger.VerifyRecords(rig.config.ConnectorReceiptFile, public, rig.config.ConnectorReceiptNodeID, 1,
		func(record connectorledger.VerifiedReceipt) error {
			if record.Receipt.Event.Kind == connectorledger.InferenceAttempt {
				t.Error("denied scope retained an inference attempt")
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}
