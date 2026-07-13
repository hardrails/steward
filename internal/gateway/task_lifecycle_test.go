package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/taskpermit"
)

const lifecycleTestRunID = "run_0123456789abcdef0123456789abcdef"

type ambiguousLifecycleDispatchLog struct {
	connectorReceiptLog
	durable bool
	failed  atomic.Bool
}

type ambiguousLifecycleTerminalLog struct {
	connectorReceiptLog
	durable bool
	failed  atomic.Bool
}

func (log *ambiguousLifecycleTerminalLog) Finish(event connectorledger.Event) (connectorledger.Head, error) {
	if log.durable {
		if _, err := log.connectorReceiptLog.Finish(event); err != nil {
			return connectorledger.Head{}, err
		}
	}
	log.failed.Store(true)
	return connectorledger.Head{}, errors.New("fixture terminal sync outcome is ambiguous")
}

func (log *ambiguousLifecycleTerminalLog) Failed() bool {
	return log.failed.Load() || log.connectorReceiptLog.Failed()
}

func (log *ambiguousLifecycleDispatchLog) Dispatch(event connectorledger.Event) (connectorledger.Head, error) {
	if log.durable {
		if _, err := log.connectorReceiptLog.Dispatch(event); err != nil {
			return connectorledger.Head{}, err
		}
	}
	log.failed.Store(true)
	return connectorledger.Head{}, errors.New("fixture dispatch sync outcome is ambiguous")
}

func (log *ambiguousLifecycleDispatchLog) Failed() bool {
	return log.failed.Load() || log.connectorReceiptLog.Failed()
}

func newLifecycleServiceTaskRig(t *testing.T, upstream string) *serviceTaskRig {
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
		MaxSeconds: 5, MaxPermitSeconds: 300, TaskProtocol: TaskProtocolLifecycleV1,
		StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 5, PollIntervalSeconds: 1,
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		ServiceOperations:      []ServiceOperation{operation},
		ConnectorReceiptFile:   filepath.Join(directory, "effect-receipts.ndjson"),
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []ConnectorReceiptTenantBudget{{
			TenantID: "tenant-a", Bytes: 4 << 20,
		}},
		connectorReceiptKey: receiptPrivate,
	}
	server, err := Open(config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeLifecycleTestServer(server) })
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

func closeLifecycleTestServer(server *Server) {
	if server == nil {
		return
	}
	server.closeGrantListeners()
	_ = server.audit.Close()
	if server.connectorLedger != nil {
		_ = server.connectorLedger.Close()
	}
}

func reopenLifecycleServiceTaskRig(t *testing.T, rig *serviceTaskRig, now time.Time) {
	t.Helper()
	closeLifecycleTestServer(rig.server)
	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeLifecycleTestServer(reopened) })
	reopened.now = func() time.Time { return now }
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	rig.server = reopened
}

func lifecycleReceiptRecords(t *testing.T, rig *serviceTaskRig) []connectorledger.VerifiedReceipt {
	t.Helper()
	public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
	var records []connectorledger.VerifiedReceipt
	if _, err := connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, public, rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			records = append(records, record)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	return records
}

func requireLifecycleTaskChain(t *testing.T, records []connectorledger.VerifiedReceipt, phases ...connectorledger.Phase) {
	t.Helper()
	if len(records) != len(phases) {
		t.Fatalf("lifecycle receipt count=%d want=%d records=%#v", len(records), len(phases), records)
	}
	for index, phase := range phases {
		record := records[index]
		wantPrevious := "sha256:" + strings.Repeat("0", 64)
		if index > 0 {
			wantPrevious = records[index-1].Hash
		}
		if record.Receipt.SchemaVersion != connectorledger.SchemaV4 ||
			record.Receipt.Event.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
			record.Receipt.Event.Phase != phase || record.Receipt.TaskSequence != uint64(index+1) ||
			record.Receipt.PreviousTaskHash != wantPrevious {
			t.Fatalf("lifecycle receipt %d=%#v want phase=%q previous=%q", index, record, phase, wantPrevious)
		}
	}
}

func lifecycleAuthorizationEvent(t *testing.T, rig *serviceTaskRig, body []byte, permitHeader string) connectorledger.Event {
	t.Helper()
	rawPermit, err := taskpermit.DecodeHeader(permitHeader)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := taskAuthorityKeys(rig.grant.TaskAuthorities)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := taskpermit.Verify(rawPermit, trusted, rig.now, time.Duration(rig.operation.MaxPermitSeconds)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	event := serviceTaskReceiptEvent(
		rig.grant, rig.server.policyDigestFor(rig.grant.GrantID), rig.operation,
		taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, verified.Statement.TaskID), verified, body,
	)
	if event.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		t.Fatalf("lifecycle authorization omitted protocol: %#v", event)
	}
	return event
}

func TestLifecycleServiceTaskRecordsDispatchAndReplaysWithoutRedispatch(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/v1/runs" || request.URL.RawQuery != "" {
			t.Errorf("dispatch target=%q", request.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"queued"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"lifecycle-dispatch"}`)
	permit := taskPermitFor(t, rig, "task-lifecycle-dispatch", body, nil)

	first := invokeServiceTask(rig, body, permit)
	if first.Code != http.StatusAccepted || first.Header().Get(taskReceiptHeader) != "recorded" ||
		first.Body.String() != `{"run_id":"`+lifecycleTestRunID+`"}` || calls.Load() != 1 {
		t.Fatalf("first status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), calls.Load())
	}
	records := lifecycleReceiptRecords(t, rig)
	requireLifecycleTaskChain(t, records, connectorledger.Authorize, connectorledger.Dispatch)
	if records[0].Receipt.Event.RunID != "" || records[1].Receipt.Event.RunID != lifecycleTestRunID ||
		records[1].Receipt.Event.Outcome != connectorledger.Responded || records[1].Receipt.Event.HTTPStatus != http.StatusAccepted {
		t.Fatalf("lifecycle dispatch receipts=%#v", records)
	}

	replay := invokeServiceTask(rig, body, permit)
	if replay.Code != http.StatusAccepted || replay.Header().Get(taskReceiptHeader) != "replayed" ||
		replay.Body.String() != `{"run_id":"`+lifecycleTestRunID+`"}` || calls.Load() != 1 {
		t.Fatalf("replay status=%d headers=%v body=%s calls=%d", replay.Code, replay.Header(), replay.Body.String(), calls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
}

func TestLifecycleServiceTaskRestartRetainsAcceptedDispatch(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"lifecycle-restart"}`)
	permit := taskPermitFor(t, rig, "task-lifecycle-restart", body, nil)
	if response := invokeServiceTask(rig, body, permit); response.Code != http.StatusAccepted {
		t.Fatalf("dispatch status=%d body=%s", response.Code, response.Body.String())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)

	reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
	replay := invokeServiceTask(rig, body, permit)
	if replay.Code != http.StatusAccepted || replay.Header().Get(taskReceiptHeader) != "replayed" ||
		replay.Body.String() != `{"run_id":"`+lifecycleTestRunID+`"}` || calls.Load() != 1 {
		t.Fatalf("restart replay status=%d headers=%v body=%s calls=%d", replay.Code, replay.Header(), replay.Body.String(), calls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
}

func TestLifecycleServiceTaskAuthOnlyRestartClosesOutcomeUnknown(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"lifecycle-auth-only"}`)
	permit := taskPermitFor(t, rig, "task-lifecycle-auth-only", body, nil)
	authorization := lifecycleAuthorizationEvent(t, rig, body, permit)
	if _, err := rig.server.connectorLedger.Begin(authorization); err != nil {
		t.Fatal(err)
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize)

	reopenLifecycleServiceTaskRig(t, rig, rig.now)
	records := lifecycleReceiptRecords(t, rig)
	requireLifecycleTaskChain(t, records, connectorledger.Authorize, connectorledger.Terminal)
	terminal := records[1].Receipt.Event
	if terminal.Outcome != connectorledger.Failed || terminal.ErrorCode != "outcome_unknown" ||
		terminal.RunID != "" || terminal.TaskStatus != "" {
		t.Fatalf("auth-only recovery terminal=%#v", terminal)
	}
	replay := invokeServiceTask(rig, body, permit)
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), `"error":"outcome_unknown"`) || calls.Load() != 0 {
		t.Fatalf("auth-only replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), calls.Load())
	}
}

func TestLifecycleServiceTaskDuplicateRunIDRecordsSignedConflict(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	firstBody := []byte(`{"input":"first","session_id":"lifecycle-run-owner"}`)
	firstPermit := taskPermitFor(t, rig, "task-lifecycle-run-owner-a", firstBody, nil)
	if response := invokeServiceTask(rig, firstBody, firstPermit); response.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", response.Code, response.Body.String())
	}
	secondBody := []byte(`{"input":"second","session_id":"lifecycle-run-owner"}`)
	secondPermit := taskPermitFor(t, rig, "task-lifecycle-run-owner-b", secondBody, nil)
	second := invokeServiceTask(rig, secondBody, secondPermit)
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), `"error":"run_id_conflict"`) || calls.Load() != 2 {
		t.Fatalf("second status=%d body=%s calls=%d", second.Code, second.Body.String(), calls.Load())
	}

	secondDigest := taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, "task-lifecycle-run-owner-b")
	var secondRecords []connectorledger.VerifiedReceipt
	for _, record := range lifecycleReceiptRecords(t, rig) {
		if record.Receipt.Event.TaskDigest == secondDigest {
			secondRecords = append(secondRecords, record)
		}
	}
	requireLifecycleTaskChain(t, secondRecords, connectorledger.Authorize, connectorledger.Terminal)
	terminal := secondRecords[1].Receipt.Event
	if terminal.Outcome != connectorledger.Failed || terminal.ErrorCode != "run_id_conflict" ||
		terminal.RunID != "" || terminal.TaskStatus != "" {
		t.Fatalf("duplicate run terminal=%#v", terminal)
	}
}

func TestLifecycleServiceTaskAmbiguousDispatchReconcilesFromDurableLedger(t *testing.T) {
	for _, test := range []struct {
		name       string
		durable    bool
		wantStatus int
		wantError  string
		wantPhases []connectorledger.Phase
	}{
		{name: "durable dispatch", durable: true, wantStatus: http.StatusAccepted, wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Dispatch}},
		{name: "absent dispatch", wantStatus: http.StatusConflict, wantError: "outcome_unknown", wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Terminal}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			rig.server.connectorLedger = &ambiguousLifecycleDispatchLog{
				connectorReceiptLog: rig.server.connectorLedger, durable: test.durable,
			}
			body := []byte(`{"input":"work","session_id":"lifecycle-ambiguous-dispatch"}`)
			permit := taskPermitFor(t, rig, "task-lifecycle-ambiguous-dispatch", body, nil)

			first := invokeServiceTask(rig, body, permit)
			if first.Code != http.StatusServiceUnavailable || first.Header().Get(taskReceiptHeader) != "" ||
				!strings.Contains(first.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 1 {
				t.Fatalf("ambiguous status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), calls.Load())
			}
			replay := invokeServiceTask(rig, body, permit)
			if replay.Code != http.StatusServiceUnavailable || !strings.Contains(replay.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 1 {
				t.Fatalf("same-process replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), calls.Load())
			}
			otherBody := []byte(`{"input":"other","session_id":"lifecycle-ambiguous-dispatch"}`)
			otherPermit := taskPermitFor(t, rig, "task-after-lifecycle-ambiguous-dispatch", otherBody, nil)
			other := invokeServiceTask(rig, otherBody, otherPermit)
			if other.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
				t.Fatalf("distinct task status=%d body=%s calls=%d", other.Code, other.Body.String(), calls.Load())
			}

			reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
			reconciled := invokeServiceTask(rig, body, permit)
			if reconciled.Code != test.wantStatus || calls.Load() != 1 {
				t.Fatalf("reconciled status=%d body=%s calls=%d", reconciled.Code, reconciled.Body.String(), calls.Load())
			}
			if test.wantError != "" && !strings.Contains(reconciled.Body.String(), `"error":"`+test.wantError+`"`) {
				t.Fatalf("reconciled body=%s want error=%q", reconciled.Body.String(), test.wantError)
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), test.wantPhases...)
		})
	}
}

func TestLifecycleServiceTaskRecordsDirectFailuresWithoutFalseDispatch(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		encoding    string
		body        string
		errorCode   string
	}{
		{name: "redirect", status: http.StatusFound, contentType: "application/json", body: `{"run_id":"run_redirect"}`, errorCode: "redirect_denied"},
		{name: "rejected", status: http.StatusPartialContent, contentType: "application/json", body: `{"run_id":"run_rejected"}`, errorCode: "service_task_rejected"},
		{name: "missing run id", status: http.StatusAccepted, contentType: "application/json", body: `{"status":"queued"}`, errorCode: "outcome_unknown"},
		{name: "wrong media type", status: http.StatusAccepted, contentType: "text/plain", body: `{"run_id":"run_plain"}`, errorCode: "outcome_unknown"},
		{name: "encoded response", status: http.StatusAccepted, contentType: "application/json", encoding: "gzip", body: `{"run_id":"run_encoded"}`, errorCode: "outcome_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", test.contentType)
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"lifecycle-direct-failure"}`)
			permit := taskPermitFor(t, rig, "task-lifecycle-direct-"+strings.ReplaceAll(test.name, " ", "-"), body, nil)

			response := invokeServiceTask(rig, body, permit)
			if response.Code != http.StatusBadGateway || response.Header().Get(taskReceiptHeader) != "recorded" ||
				!strings.Contains(response.Body.String(), `"error":"`+test.errorCode+`"`) || calls.Load() != 1 {
				t.Fatalf("status=%d headers=%v body=%s calls=%d", response.Code, response.Header(), response.Body.String(), calls.Load())
			}
			records := lifecycleReceiptRecords(t, rig)
			requireLifecycleTaskChain(t, records, connectorledger.Authorize, connectorledger.Terminal)
			terminal := records[1].Receipt.Event
			if terminal.Outcome != connectorledger.Failed || terminal.ErrorCode != test.errorCode ||
				terminal.RunID != "" || terminal.TaskStatus != "" {
				t.Fatalf("terminal=%#v", terminal)
			}
		})
	}
}

func TestLifecycleServiceTaskAmbiguousTerminalReconcilesFromDurableLedger(t *testing.T) {
	for _, test := range []struct {
		name       string
		durable    bool
		wantError  string
		wantPhases []connectorledger.Phase
	}{
		{name: "durable terminal", durable: true, wantError: "task_already_spent", wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Terminal}},
		{name: "absent terminal", wantError: "outcome_unknown", wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Terminal}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte(`{"run_id":"run_rejected"}`))
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			rig.server.connectorLedger = &ambiguousLifecycleTerminalLog{
				connectorReceiptLog: rig.server.connectorLedger, durable: test.durable,
			}
			body := []byte(`{"input":"work","session_id":"lifecycle-ambiguous-terminal"}`)
			permit := taskPermitFor(t, rig, "task-lifecycle-ambiguous-terminal", body, nil)

			first := invokeServiceTask(rig, body, permit)
			if first.Code != http.StatusServiceUnavailable || first.Header().Get(taskReceiptHeader) != "" ||
				!strings.Contains(first.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 1 {
				t.Fatalf("ambiguous terminal status=%d headers=%v body=%s calls=%d", first.Code, first.Header(), first.Body.String(), calls.Load())
			}
			replay := invokeServiceTask(rig, body, permit)
			if replay.Code != http.StatusServiceUnavailable || !strings.Contains(replay.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 1 {
				t.Fatalf("same-process replay status=%d body=%s calls=%d", replay.Code, replay.Body.String(), calls.Load())
			}

			reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
			reconciled := invokeServiceTask(rig, body, permit)
			if reconciled.Code != http.StatusConflict || !strings.Contains(reconciled.Body.String(), `"error":"`+test.wantError+`"`) || calls.Load() != 1 {
				t.Fatalf("reconciled status=%d body=%s calls=%d", reconciled.Code, reconciled.Body.String(), calls.Load())
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), test.wantPhases...)
		})
	}
}

func TestLifecycleConnectorReceiptFormatInspectionReportsFour(t *testing.T) {
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := ServiceOperation{
		ServiceID: "hermes-api", ID: "hermes.run", Method: http.MethodPost, Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
		MaxSeconds: 5, MaxPermitSeconds: 300, TaskProtocol: TaskProtocolLifecycleV1,
		StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 5, PollIntervalSeconds: 1,
	}
	prospective := Config{
		ConnectorReceiptFile:   filepath.Join(t.TempDir(), "prospective-lifecycle.ndjson"),
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
		ServiceOperations: []ServiceOperation{operation}, connectorReceiptKey: receiptPrivate,
	}
	summary, err := InspectConnectorReceiptFormat(prospective)
	if err != nil || summary.Present || summary.FormatVersion != 4 {
		t.Fatalf("prospective lifecycle summary=%#v err=%v", summary, err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"lifecycle-format"}`)
	permit := taskPermitFor(t, rig, "task-lifecycle-format", body, nil)
	if response := invokeServiceTask(rig, body, permit); response.Code != http.StatusAccepted {
		t.Fatalf("dispatch status=%d body=%s", response.Code, response.Body.String())
	}
	before, err := os.ReadFile(rig.config.ConnectorReceiptFile)
	if err != nil {
		t.Fatal(err)
	}
	summary, err = InspectConnectorReceiptFormat(rig.config)
	if err != nil || !summary.Present || summary.FormatVersion != 4 {
		t.Fatalf("observed lifecycle summary=%#v err=%v", summary, err)
	}
	after, err := os.ReadFile(rig.config.ConnectorReceiptFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("lifecycle receipt format inspection changed the ledger")
	}

	// Format inspection reports the maximum observed schema, even when a
	// legacy v3 record follows v4 in the global chain.
	closeLifecycleTestServer(rig.server)
	ledger, err := connectorledger.Open(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey,
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	v3TaskDigest, err := connectorledger.TaskDigest("format-v3-after-v4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, Kind: connectorledger.ConnectorCall,
		TenantID: rig.grant.TenantID, RuntimeRef: rig.grant.RuntimeRef, CapsuleDigest: rig.grant.CapsuleDigest,
		PolicyDigest: rig.grant.PolicyDigest, RoutePolicyDigest: rig.server.policyDigestFor(rig.grant.GrantID),
		Generation: rig.grant.Generation, GrantID: rig.grant.GrantID, ConnectorID: "ticketing",
		OperationID: "read", TaskDigest: v3TaskDigest, ErrorCode: "policy_denied",
	}); err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err = InspectConnectorReceiptFormat(rig.config)
	if err != nil || !summary.Present || summary.FormatVersion != 4 {
		t.Fatalf("v4 then v3 summary=%#v err=%v", summary, err)
	}
}
