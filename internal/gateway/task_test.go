package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

type serviceTaskRig struct {
	server     *Server
	config     Config
	grant      Grant
	operation  ServiceOperation
	privateKey ed25519.PrivateKey
	now        time.Time
}

type ambiguousServiceTaskReceiptLog struct {
	connectorReceiptLog
	failed atomic.Bool
}

func (log *ambiguousServiceTaskReceiptLog) Begin(event connectorledger.Event) (connectorledger.Head, error) {
	if _, err := log.connectorReceiptLog.Begin(event); err != nil {
		return connectorledger.Head{}, err
	}
	log.failed.Store(true)
	return connectorledger.Head{}, errors.New("fixture authorization sync outcome is ambiguous")
}

func (log *ambiguousServiceTaskReceiptLog) Failed() bool { return log.failed.Load() }

type blockingServiceTaskFailureCheckLog struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*blockingServiceTaskFailureCheckLog) Begin(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("fixture append refused before write")
}

func (*blockingServiceTaskFailureCheckLog) Finish(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("unexpected fixture finish")
}

func (log *blockingServiceTaskFailureCheckLog) Failed() bool {
	log.once.Do(func() { close(log.entered) })
	<-log.release
	return false
}

func (*blockingServiceTaskFailureCheckLog) Close() error { return nil }

func newServiceTaskRig(t *testing.T, upstream string) *serviceTaskRig {
	t.Helper()
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := ServiceOperation{
		ServiceID: "hermes-api", ID: "hermes.run", Method: http.MethodPost, Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
		MaxSeconds: 5, MaxPermitSeconds: 300,
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		ServiceOperations:      []ServiceOperation{operation},
		ConnectorReceiptFile:   filepath.Join(directory, "effect-receipts.ndjson"),
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []ConnectorReceiptTenantBudget{{TenantID: "tenant-a", Bytes: 4 << 20}},
		connectorReceiptKey:           receiptPrivate,
	}
	server, err := Open(config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.closeGrantListeners()
		_ = server.audit.Close()
		if server.connectorLedger != nil {
			_ = server.connectorLedger.Close()
		}
	})
	grant := Grant{
		GrantID: GrantID("tenant-a", "agent-a", 1), TenantID: "tenant-a", NodeID: "node-a",
		InstanceID: "agent-a", Generation: 1, RuntimeRef: "executor-" + strings.Repeat("a", 64),
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
		Service: true, ServiceID: operation.ServiceID, ServiceURL: upstream,
		TaskAuthorities: []TaskAuthority{{KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(public)}},
	}
	registerTaskGrant(t, server, grant)
	activateConnectorGrant(t, server, grant.GrantID)
	now := time.Now().UTC().Truncate(time.Second)
	server.now = func() time.Time { return now }
	return &serviceTaskRig{server: server, config: config, grant: grant, operation: operation, privateKey: private, now: now}
}

func registerTaskGrant(t *testing.T, server *Server, grant Grant) grantResponse {
	t.Helper()
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register task grant status=%d body=%s", response.Code, response.Body.String())
	}
	var result grantResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.RoutePolicyDigest == "" {
		t.Fatalf("register task grant result=%#v err=%v", result, err)
	}
	return result
}

func taskPermitFor(t *testing.T, rig *serviceTaskRig, taskID string, body []byte, mutate func(*taskpermit.Statement)) string {
	t.Helper()
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1, NodeID: rig.grant.NodeID, TenantID: rig.grant.TenantID,
		InstanceID: rig.grant.InstanceID, RuntimeRef: rig.grant.RuntimeRef, GrantID: rig.grant.GrantID,
		Generation: rig.grant.Generation, CapsuleDigest: rig.grant.CapsuleDigest, PolicyDigest: rig.grant.PolicyDigest,
		RoutePolicyDigest: rig.server.policyDigestFor(rig.grant.GrantID), ServiceID: rig.grant.ServiceID,
		OperationID: rig.operation.ID, OperationPolicyDigest: ServiceOperationDigest(rig.operation), TaskID: taskID,
		RequestDigest: taskpermit.RequestDigest(body), RequestBytes: int64(len(body)), ContentType: rig.operation.ContentType,
		NotBefore: rig.now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: rig.now.Add(4 * time.Minute).Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(&statement)
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, "task-approver", rig.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, err := taskpermit.EncodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func invokeServiceTask(rig *serviceTaskRig, body []byte, permit string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/services/"+rig.grant.GrantID+rig.operation.Path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer service-token")
	request.Header.Set("Content-Type", rig.operation.ContentType)
	request.Header.Set("Forwarded", "for=192.0.2.10;host=admin.internal")
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	request.Header.Set("Idempotency-Key", "caller-controlled")
	request.Header.Set("Prefer", "respond-async")
	request.Header.Set("X-Hermes-Admin", "true")
	if permit != "" {
		request.Header.Set(taskPermitHeader, permit)
	}
	response := httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(response, request)
	return response
}

func TestSignedServiceTaskDispatchesOnceAndReplaysDurableRunID(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/v1/runs" || request.Header.Get(taskPermitHeader) != "" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
			request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" ||
			request.Header.Get("Idempotency-Key") != "" || request.Header.Get("Prefer") != "" ||
			request.Header.Get("X-Hermes-Admin") != "" || request.UserAgent() != "" {
			t.Errorf("upstream request path=%q headers=%v", request.URL.Path, request.Header)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Set-Cookie", "secret=never")
		w.Header().Set("Authorization", "Bearer reflected")
		w.Header().Set("X-Steward-Forged", "accepted")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"queued"}`))
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"STEWARD_WORKSPACE_AUDIT","session_id":"task-session"}`)
	permit := taskPermitFor(t, rig, "task-0123456789abcdef", body, nil)

	first := invokeServiceTask(rig, body, permit)
	if first.Code != http.StatusAccepted || first.Header().Get(taskReceiptHeader) != "recorded" ||
		first.Header().Get("Set-Cookie") != "" || first.Header().Get("Authorization") != "" || first.Header().Get("X-Steward-Forged") != "" ||
		first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("X-Content-Type-Options") != "nosniff" ||
		first.Body.String() != `{"run_id":"run_0123456789abcdef0123456789abcdef"}` || calls.Load() != 1 {
		t.Fatalf("first status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), calls.Load())
	}
	replay := invokeServiceTask(rig, body, permit)
	if replay.Code != http.StatusAccepted || replay.Header().Get(taskReceiptHeader) != "replayed" ||
		replay.Body.String() != "{\"run_id\":\"run_0123456789abcdef0123456789abcdef\"}" || calls.Load() != 1 {
		t.Fatalf("replay status=%d headers=%v body=%s calls=%d", replay.Code, replay.Header(), replay.Body.String(), calls.Load())
	}
	rig.server.now = func() time.Time { return rig.now.Add(24 * time.Hour) }
	expiredReplay := invokeServiceTask(rig, body, permit)
	if expiredReplay.Code != http.StatusAccepted || expiredReplay.Header().Get(taskReceiptHeader) != "replayed" || calls.Load() != 1 {
		t.Fatalf("expired replay status=%d headers=%v body=%s calls=%d", expiredReplay.Code, expiredReplay.Header(), expiredReplay.Body.String(), calls.Load())
	}
	newExpiredPermit := taskPermitFor(t, rig, "task-never-dispatched", body, nil)
	if denied := invokeServiceTask(rig, body, newExpiredPermit); denied.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("new expired task status=%d body=%s calls=%d", denied.Code, denied.Body.String(), calls.Load())
	}

	public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
	var records []connectorledger.Event
	if _, err := connectorledger.VerifyRecords(rig.config.ConnectorReceiptFile, public, rig.config.ConnectorReceiptNodeID, 1,
		func(record connectorledger.VerifiedReceipt) error {
			records = append(records, record.Receipt.Event)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Kind != connectorledger.ServiceTask || records[0].RequestDigest != taskpermit.RequestDigest(body) ||
		records[1].RunID != "run_0123456789abcdef0123456789abcdef" || strings.Contains(string(mustReadFile(t, rig.config.ConnectorReceiptFile)), "STEWARD_WORKSPACE_AUDIT") {
		t.Fatalf("task receipts=%#v", records)
	}
}

func TestSignedServiceTaskAcceptsOnlyDocumentedSuccessStatuses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"run_id":"run_0123456789abcdef0123456789abcdef"}`))
			}))
			defer upstream.Close()
			rig := newServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"allowed-status"}`)
			permit := taskPermitFor(t, rig, fmt.Sprintf("task-status-%d", status), body, nil)

			first := invokeServiceTask(rig, body, permit)
			replay := invokeServiceTask(rig, body, permit)
			if first.Code != status || replay.Code != status || replay.Header().Get(taskReceiptHeader) != "replayed" || calls.Load() != 1 {
				t.Fatalf("first=%d replay=%d headers=%v calls=%d", first.Code, replay.Code, replay.Header(), calls.Load())
			}
		})
	}

	state := serviceTaskReceipt{
		Authorization: connectorledger.Event{PermitDigest: "sha256:" + strings.Repeat("a", 64)},
		Terminal: connectorledger.Event{
			Phase: connectorledger.Terminal, Outcome: connectorledger.Responded,
			HTTPStatus: http.StatusPartialContent, RunID: "run_should_not_cross_boundary",
		},
	}
	response := httptest.NewRecorder()
	(&Server{}).writeExistingServiceTask(response, state, state.Authorization.PermitDigest)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"task_already_spent"`) {
		t.Fatalf("undocumented replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSignedServiceTaskQuotaFailureDoesNotSpendOrDispatch(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"run_id":"run_0123456789abcdef0123456789abcdef"}`))
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"quota"}`)
	permit := taskPermitFor(t, rig, "task-quota-recovery", body, nil)
	realLedger := rig.server.connectorLedger
	defer func() { rig.server.connectorLedger = realLedger }()
	rig.server.connectorLedger = refusingConnectorReceiptLog{err: connectorledger.ErrTenantQuotaExceeded}

	denied := invokeServiceTask(rig, body, permit)
	if denied.Code != http.StatusServiceUnavailable ||
		!strings.Contains(denied.Body.String(), `"error":"task_evidence_quota_exhausted"`) || calls.Load() != 0 {
		t.Fatalf("quota status=%d body=%s calls=%d", denied.Code, denied.Body.String(), calls.Load())
	}
	taskDigest := taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, "task-quota-recovery")
	rig.server.mu.Lock()
	_, reserved := rig.server.serviceTasks[taskDigest]
	rig.server.mu.Unlock()
	if reserved {
		t.Fatal("pre-write quota failure retained an in-memory spent reservation")
	}

	rig.server.connectorLedger = realLedger
	retried := invokeServiceTask(rig, body, permit)
	if retried.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("retry status=%d body=%s calls=%d", retried.Code, retried.Body.String(), calls.Load())
	}
}

func TestSignedServiceTaskAmbiguousAuthorizationFailureDoesNotRemainInProgress(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"run_id":"run_0123456789abcdef0123456789abcdef"}`))
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"ambiguous-authorization"}`)
	permit := taskPermitFor(t, rig, "task-ambiguous-authorization", body, nil)
	rig.server.connectorLedger = &ambiguousServiceTaskReceiptLog{connectorReceiptLog: rig.server.connectorLedger}

	for attempt := 1; attempt <= 2; attempt++ {
		response := invokeServiceTask(rig, body, permit)
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 0 {
			t.Fatalf("attempt %d status=%d body=%s calls=%d", attempt, response.Code, response.Body.String(), calls.Load())
		}
	}
	taskDigest := taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, "task-ambiguous-authorization")
	rawPermit, err := taskpermit.DecodeHeader(permit)
	if err != nil {
		t.Fatal(err)
	}
	rig.server.mu.Lock()
	state, taskReserved := rig.server.serviceTasks[taskDigest]
	_, permitReserved := rig.server.serviceTaskPermits[dsse.Digest(rawPermit)]
	reservedTasks := len(rig.server.serviceTasks)
	rig.server.mu.Unlock()
	if !taskReserved || !permitReserved || !state.authorizationAmbiguous || reservedTasks != 1 {
		t.Fatalf("ambiguous authorization task=%t permit=%t marked=%t count=%d", taskReserved, permitReserved, state.authorizationAmbiguous, reservedTasks)
	}

	otherBody := []byte(`{"input":"other","session_id":"ambiguous-authorization"}`)
	otherPermit := taskPermitFor(t, rig, "task-after-ambiguous-authorization", otherBody, nil)
	other := invokeServiceTask(rig, otherBody, otherPermit)
	if other.Code != http.StatusServiceUnavailable ||
		!strings.Contains(other.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 0 {
		t.Fatalf("other task status=%d body=%s calls=%d", other.Code, other.Body.String(), calls.Load())
	}
	rig.server.mu.Lock()
	reservedTasks = len(rig.server.serviceTasks)
	rig.server.mu.Unlock()
	if reservedTasks != 1 {
		t.Fatalf("failed ledger retained %d task reservations", reservedTasks)
	}

	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()
	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
	})
	reopened.now = func() time.Time { return rig.now }
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	rig.server = reopened
	replay := invokeServiceTask(rig, body, permit)
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), `"error":"outcome_unknown"`) || calls.Load() != 0 {
		t.Fatalf("reconciled replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), calls.Load())
	}
}

func TestSignedServiceTaskLedgerFailureCheckDoesNotBlockGrantControl(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	blocked := &blockingServiceTaskFailureCheckLog{entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-blocked.release:
		default:
			close(blocked.release)
		}
	}()
	rig.server.connectorLedger = blocked
	body := []byte(`{"input":"work","session_id":"slow-authorization"}`)
	permit := taskPermitFor(t, rig, "task-slow-authorization", body, nil)
	dispatchDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { dispatchDone <- invokeServiceTask(rig, body, permit) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("task ledger failure check did not block")
	}

	controlDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		rig.server.ControlHandler().ServeHTTP(
			response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil),
		)
		controlDone <- response
	}()
	select {
	case response := <-controlDone:
		if response.Code != http.StatusOK {
			t.Fatalf("grant deactivation status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		close(blocked.release)
		t.Fatal("blocked task ledger failure check stalled grant control")
	}

	close(blocked.release)
	response := <-dispatchDone
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 0 {
		t.Fatalf("task status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestSignedServiceTaskRejectsBindingChangesBeforeDispatch(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"run_id":"run_0123456789abcdef0123456789abcdef"}`))
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"one"}`)
	valid := taskPermitFor(t, rig, "task-binding", body, nil)

	tests := []struct {
		name   string
		body   []byte
		permit string
	}{
		{"missing permit", body, ""},
		{"changed bytes", []byte(`{"input":"other","session_id":"one"}`), valid},
		{"wrong generation", body, taskPermitFor(t, rig, "task-generation", body, func(statement *taskpermit.Statement) { statement.Generation++ })},
		{"wrong node", body, taskPermitFor(t, rig, "task-node", body, func(statement *taskpermit.Statement) { statement.NodeID = "node-b" })},
		{"wrong operation policy", body, taskPermitFor(t, rig, "task-policy", body, func(statement *taskpermit.Statement) {
			statement.OperationPolicyDigest = "sha256:" + strings.Repeat("f", 64)
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := invokeServiceTask(rig, test.body, test.permit)
			if response.Code < 400 || calls.Load() != 0 {
				t.Fatalf("status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
			}
		})
	}

	read := httptest.NewRequest(http.MethodGet, "/v1/services/"+rig.grant.GrantID+"/health", nil)
	read.Header.Set("Authorization", "Bearer service-token")
	read.Header.Set(taskPermitHeader, valid)
	response := httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(response, read)
	if response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("permit smuggling status=%d calls=%d", response.Code, calls.Load())
	}

	encoded := httptest.NewRequest(http.MethodPost, "/v1/services/"+rig.grant.GrantID+"/v1/%72uns", bytes.NewReader(body))
	encoded.Header.Set("Authorization", "Bearer service-token")
	encoded.Header.Set("Content-Type", rig.operation.ContentType)
	encoded.Header.Set(taskPermitHeader, valid)
	response = httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(response, encoded)
	if response.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("encoded task path status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestSignedServiceTaskConcurrentReplayAndUnknownOutcomeDoNotRedispatch(t *testing.T) {
	t.Run("concurrent", func(t *testing.T) {
		var calls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"run_id":"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		}))
		defer upstream.Close()
		rig := newServiceTaskRig(t, upstream.URL)
		body := []byte(`{"input":"work","session_id":"concurrent"}`)
		permit := taskPermitFor(t, rig, "task-concurrent", body, nil)
		responses := make([]*httptest.ResponseRecorder, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		for index := range responses {
			go func(index int) {
				defer wait.Done()
				responses[index] = invokeServiceTask(rig, body, permit)
			}(index)
		}
		wait.Wait()
		successes := 0
		for _, response := range responses {
			if response.Code >= 200 && response.Code < 300 {
				successes++
				continue
			}
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"task_in_progress"`) {
				t.Fatalf("unexpected concurrent response status=%d body=%s", response.Code, response.Body.String())
			}
		}
		if calls.Load() != 1 || successes != 1 {
			t.Fatalf("calls=%d statuses=%d,%d", calls.Load(), responses[0].Code, responses[1].Code)
		}
	})

	t.Run("unknown outcome", func(t *testing.T) {
		var calls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			calls.Add(1)
			panic(http.ErrAbortHandler)
		}))
		defer upstream.Close()
		rig := newServiceTaskRig(t, upstream.URL)
		body := []byte(`{"input":"work","session_id":"ambiguous"}`)
		permit := taskPermitFor(t, rig, "task-ambiguous", body, nil)
		first := invokeServiceTask(rig, body, permit)
		replay := invokeServiceTask(rig, body, permit)
		if first.Code != http.StatusBadGateway || replay.Code != http.StatusConflict ||
			!strings.Contains(replay.Body.String(), `"error":"outcome_unknown"`) || calls.Load() != 1 {
			t.Fatalf("first=%d replay=%d body=%s calls=%d", first.Code, replay.Code, replay.Body.String(), calls.Load())
		}
	})
}

func TestSignedServiceTaskRecordsUntrustedResponsesWithoutRelayingThem(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		encoding    string
		body        string
		firstError  string
		replayError string
	}{
		{name: "redirect", status: http.StatusFound, contentType: "application/json", body: `{"run_id":"run_redirect"}`, firstError: "redirect_denied", replayError: "task_already_spent"},
		{name: "partial success", status: http.StatusPartialContent, contentType: "application/json", body: `{"run_id":"run_partial"}`, firstError: "service_task_rejected", replayError: "task_already_spent"},
		{name: "missing run id", status: http.StatusAccepted, contentType: "application/json", body: `{"status":"queued"}`, firstError: "outcome_unknown", replayError: "outcome_unknown"},
		{name: "duplicate run id", status: http.StatusAccepted, contentType: "application/json", body: `{"run_id":"run_one","run_id":"run_two"}`, firstError: "outcome_unknown", replayError: "outcome_unknown"},
		{name: "wrong media type", status: http.StatusAccepted, contentType: "text/plain", body: `{"run_id":"run_plain"}`, firstError: "outcome_unknown", replayError: "outcome_unknown"},
		{name: "encoded response", status: http.StatusAccepted, contentType: "application/json", encoding: "gzip", body: `{"run_id":"run_encoded"}`, firstError: "outcome_unknown", replayError: "outcome_unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", test.contentType)
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				w.Header().Set("X-Steward-Forged", "recorded")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			rig := newServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"response"}`)
			permit := taskPermitFor(t, rig, "task-response-"+strings.ReplaceAll(test.name, " ", "-"), body, nil)

			first := invokeServiceTask(rig, body, permit)
			if first.Code != http.StatusBadGateway || first.Header().Get(taskReceiptHeader) != "recorded" ||
				first.Header().Get("X-Steward-Forged") != "" || !strings.Contains(first.Body.String(), `"error":"`+test.firstError+`"`) || calls.Load() != 1 {
				t.Fatalf("first status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), calls.Load())
			}
			replay := invokeServiceTask(rig, body, permit)
			if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), `"error":"`+test.replayError+`"`) || calls.Load() != 1 {
				t.Fatalf("replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), calls.Load())
			}
		})
	}
}

func TestSignedServiceTaskClosesAuthorityLostAfterDurableAdmission(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		errorCode  string
		secondTime time.Time
		revoke     bool
	}{
		{name: "permit expires during fsync", status: http.StatusForbidden, errorCode: "permit_expired", secondTime: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "grant revoked during fsync", status: http.StatusServiceUnavailable, errorCode: "grant_revoked", revoke: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var upstreamCalls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamCalls.Add(1)
			}))
			defer upstream.Close()
			rig := newServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"authority-loss"}`)
			permit := taskPermitFor(t, rig, "task-authority-loss", body, nil)
			var clockCalls atomic.Int64
			rig.server.now = func() time.Time {
				if clockCalls.Add(1) == 2 {
					if test.revoke {
						rig.server.mu.Lock()
						grant := rig.server.grants[rig.grant.GrantID]
						grant.Active = false
						rig.server.grants[rig.grant.GrantID] = grant
						rig.server.mu.Unlock()
					}
					if !test.secondTime.IsZero() {
						return test.secondTime
					}
				}
				return rig.now
			}

			first := invokeServiceTask(rig, body, permit)
			if first.Code != test.status || first.Header().Get(taskReceiptHeader) != "recorded" ||
				!strings.Contains(first.Body.String(), `"error":"`+test.errorCode+`"`) || upstreamCalls.Load() != 0 {
				t.Fatalf("status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), upstreamCalls.Load())
			}
			taskDigest := taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, "task-authority-loss")
			rig.server.mu.Lock()
			terminal := rig.server.serviceTasks[taskDigest].Terminal
			if test.revoke {
				grant := rig.server.grants[rig.grant.GrantID]
				grant.Active = true
				rig.server.grants[rig.grant.GrantID] = grant
			}
			rig.server.mu.Unlock()
			if terminal.ErrorCode != test.errorCode || terminal.Outcome != connectorledger.Failed {
				t.Fatalf("terminal=%#v", terminal)
			}
			if replay := invokeServiceTask(rig, body, permit); replay.Code != http.StatusConflict || upstreamCalls.Load() != 0 {
				t.Fatalf("replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), upstreamCalls.Load())
			}
		})
	}
}

func TestSignedServiceTaskDispatchRacesSafelyWithEquivalentReload(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"run_id":"run_%032d"}`, call)
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)

	reloadErrors := make(chan error, 1)
	go func() {
		for range 50 {
			if err := rig.server.Reload(rig.config, nil, nil, "service-token"); err != nil {
				reloadErrors <- err
				return
			}
		}
		reloadErrors <- nil
	}()
	for index := range 25 {
		body := []byte(fmt.Sprintf(`{"input":"work-%d","session_id":"reload"}`, index))
		permit := taskPermitFor(t, rig, fmt.Sprintf("task-reload-%02d", index), body, nil)
		response := invokeServiceTask(rig, body, permit)
		if response.Code != http.StatusAccepted {
			t.Fatalf("dispatch %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	if err := <-reloadErrors; err != nil {
		t.Fatalf("equivalent reload: %v", err)
	}
	if calls.Load() != 25 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}

	changed := rig.config
	changed.ServiceOperations = append([]ServiceOperation(nil), rig.config.ServiceOperations...)
	changed.ServiceOperations[0].MaxSeconds++
	if err := rig.server.Reload(changed, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "changes task operations") {
		t.Fatalf("retained operation drift accepted: %v", err)
	}
}

func TestSignedServiceTaskReplaySurvivesGatewayRestart(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"run_id":"run_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
	}))
	defer upstream.Close()
	rig := newServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"restart"}`)
	permit := taskPermitFor(t, rig, "task-restart", body, nil)
	if response := invokeServiceTask(rig, body, permit); response.Code != http.StatusOK {
		t.Fatalf("initial status=%d body=%s", response.Code, response.Body.String())
	}
	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()

	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
	})
	reopened.now = func() time.Time { return rig.now.Add(24 * time.Hour) }
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	rig.server = reopened
	response := invokeServiceTask(rig, body, permit)
	if response.Code != http.StatusOK || response.Header().Get(taskReceiptHeader) != "replayed" || calls.Load() != 1 {
		t.Fatalf("restart replay status=%d headers=%v calls=%d", response.Code, response.Header(), calls.Load())
	}
}

func TestTaskAuthorizedGatewayStateRequiresFormatFour(t *testing.T) {
	rig := newServiceTaskRig(t, "http://127.0.0.1:1")
	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()

	raw, err := os.ReadFile(rig.config.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	grants, ok := state["grants"].([]any)
	if !ok || state["version"] != float64(4) || len(grants) != 1 {
		t.Fatalf("task state=%s", raw)
	}
	retained, ok := grants[0].(map[string]any)
	if !ok || retained["service_id"] != rig.grant.ServiceID || retained["task_authorities"] == nil {
		t.Fatalf("retained task grant=%#v", retained)
	}
	state["version"] = float64(3)
	downgraded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rig.config.StateFile, downgraded, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(rig.config, nil, nil, "service-token")
	if opened != nil {
		opened.closeGrantListeners()
		_ = opened.audit.Close()
		if opened.connectorLedger != nil {
			_ = opened.connectorLedger.Close()
		}
	}
	if err == nil || !strings.Contains(err.Error(), "task authority") {
		t.Fatalf("format-3 task authority state err=%v", err)
	}
}

func TestTaskRoutePolicyDigestBindsTaskAuthorityOperationAndBudget(t *testing.T) {
	rig := newServiceTaskRig(t, "http://127.0.0.1:1")
	operations := map[string]map[string]ServiceOperation{
		rig.grant.ServiceID: {rig.operation.ID: rig.operation},
	}
	base := routePolicyDigest(rig.grant, nil, nil, nil, operations, 4<<20)
	if base == "" {
		t.Fatal("task route policy digest is empty")
	}

	changedGrant := rig.grant
	changedGrant.TaskAuthorities = append([]TaskAuthority(nil), rig.grant.TaskAuthorities...)
	changedGrant.TaskAuthorities[0].KeyID = "other-task-approver"
	if got := routePolicyDigest(changedGrant, nil, nil, nil, operations, 4<<20); got == base {
		t.Fatal("task authority key ID did not change route policy digest")
	}
	changedOperation := rig.operation
	changedOperation.MaxSeconds++
	changedOperations := map[string]map[string]ServiceOperation{
		rig.grant.ServiceID: {changedOperation.ID: changedOperation},
	}
	if got := routePolicyDigest(rig.grant, nil, nil, nil, changedOperations, 4<<20); got == base {
		t.Fatal("service operation policy did not change route policy digest")
	}
	if got := routePolicyDigest(rig.grant, nil, nil, nil, operations, 8<<20); got == base {
		t.Fatal("tenant receipt budget did not change route policy digest")
	}
	unrelated := make(map[string]map[string]ServiceOperation, len(operations)+1)
	for serviceID, configured := range operations {
		unrelated[serviceID] = configured
	}
	unrelated["other-api"] = map[string]ServiceOperation{"other.run": {
		ServiceID: "other-api", ID: "other.run", Method: http.MethodPost, Path: "/v1/run",
		ContentType: "application/json", MaxRequestBytes: 1024, MaxResponseBytes: 4096,
		MaxSeconds: 10, MaxPermitSeconds: 60,
	}}
	if got := routePolicyDigest(rig.grant, nil, nil, nil, unrelated, 4<<20); got != base {
		t.Fatalf("unrelated service changed task route policy digest: before=%s after=%s", base, got)
	}
}

func TestServiceTaskResponseRequiresOneExactRunID(t *testing.T) {
	for name, test := range map[string]struct {
		body string
		ok   bool
	}{
		"minimal":       {`{"run_id":"run-1"}`, true},
		"extra fields":  {`{"run_id":"run-1","status":"queued"}`, true},
		"missing":       {`{"status":"queued"}`, false},
		"duplicate":     {`{"run_id":"run-1","run_id":"run-2"}`, false},
		"wrong case":    {`{"Run_ID":"run-1"}`, false},
		"wrong type":    {`{"run_id":1}`, false},
		"invalid token": {`{"run_id":"../run"}`, false},
		"scalar":        {`"run-1"`, false},
		"trailing":      {`{"run_id":"run-1"} {}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			runID, ok := serviceRunID([]byte(test.body))
			if ok != test.ok || ok && runID != "run-1" {
				t.Fatalf("run_id=%q ok=%t", runID, ok)
			}
		})
	}
}

func TestServiceTaskGrantRequiresCanonicalSignedAuthority(t *testing.T) {
	rig := newServiceTaskRig(t, "http://127.0.0.1:1")
	grant := rig.grant
	grant.Active = false
	if !rig.server.validGrant(grant) {
		t.Fatal("valid task-enabled service grant rejected")
	}
	rig.server.config.ConnectorReceiptNodeID = "node-b/gateway"
	if rig.server.validGrant(grant) {
		t.Fatal("task-enabled service grant accepted under another node's receipt identity")
	}
	rig.server.config.ConnectorReceiptNodeID = ServiceTaskReceiptNodeID(grant.NodeID)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second := TaskAuthority{KeyID: "z-approver", PublicKey: base64.StdEncoding.EncodeToString(public)}
	for name, mutate := range map[string]func(*Grant){
		"missing node":       func(value *Grant) { value.NodeID = "" },
		"missing service":    func(value *Grant) { value.ServiceID = "" },
		"unknown service":    func(value *Grant) { value.ServiceID = "other-api" },
		"invalid public key": func(value *Grant) { value.TaskAuthorities[0].PublicKey = "not-base64" },
		"duplicate material": func(value *Grant) {
			duplicate := value.TaskAuthorities[0]
			duplicate.KeyID = "z-approver"
			value.TaskAuthorities = append(value.TaskAuthorities, duplicate)
		},
		"unsorted keys": func(value *Grant) {
			value.TaskAuthorities = append([]TaskAuthority{second}, value.TaskAuthorities...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := grant
			candidate.TaskAuthorities = append([]TaskAuthority(nil), grant.TaskAuthorities...)
			mutate(&candidate)
			if rig.server.validGrant(candidate) {
				t.Fatalf("invalid task grant accepted: %#v", candidate)
			}
		})
	}
}

func TestServiceOperationDigestBindsEveryPolicyField(t *testing.T) {
	base := ServiceOperation{
		ServiceID: "hermes-api", ID: "hermes.run", Method: http.MethodPost, Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 1024, MaxResponseBytes: 4096,
		MaxSeconds: 30, MaxPermitSeconds: 300,
	}
	want := ServiceOperationDigest(base)
	if !strings.HasPrefix(want, "sha256:") {
		t.Fatalf("digest=%q", want)
	}
	mutations := []func(*ServiceOperation){
		func(value *ServiceOperation) { value.ServiceID = "other-api" },
		func(value *ServiceOperation) { value.ID = "hermes.other" },
		func(value *ServiceOperation) { value.Method = http.MethodPut },
		func(value *ServiceOperation) { value.Path = "/v1/other" },
		func(value *ServiceOperation) { value.ContentType = "application/cbor" },
		func(value *ServiceOperation) { value.MaxRequestBytes++ },
		func(value *ServiceOperation) { value.MaxResponseBytes++ },
		func(value *ServiceOperation) { value.MaxSeconds++ },
		func(value *ServiceOperation) { value.MaxPermitSeconds++ },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		if got := ServiceOperationDigest(changed); got == want {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
