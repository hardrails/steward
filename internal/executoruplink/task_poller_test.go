package executoruplink

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

type fakeAsyncTaskGateway struct {
	submission gateway.ControlTaskSubmission
	status     gateway.TaskLifecycleStatus
	err        error
	body       []byte
}

func (gateway *fakeAsyncTaskGateway) SubmitTask(
	_ context.Context, _, _, _ string, body []byte,
) (gateway.ControlTaskSubmission, error) {
	gateway.body = append([]byte(nil), body...)
	return gateway.submission, gateway.err
}

func (gateway *fakeAsyncTaskGateway) ObserveTask(
	_ context.Context, _, _ string,
) (gateway.TaskLifecycleStatus, error) {
	return gateway.status, gateway.err
}

func TestAsyncTaskCourierMapsGatewayEvidenceAndBoundsTerminalResult(t *testing.T) {
	permitDigest := "sha256:" + strings.Repeat("a", 64)
	taskDigest := "sha256:" + strings.Repeat("b", 64)
	body := []byte(`{"input":"bounded research"}`)
	result := []byte(`{"secret":"relayed only on the result endpoint"}`)
	resultDigest := dsse.Digest(result)
	fake := &fakeAsyncTaskGateway{submission: gateway.ControlTaskSubmission{
		TaskDigest: taskDigest, PermitDigest: permitDigest, RunID: "run_research",
	}}
	poller := &Poller{taskGateway: fake}
	base := controlprotocol.ExecutorTaskDeliveryV1{
		SchemaVersion: controlprotocol.ExecutorTaskDeliverySchemaV1,
		DeliveryID:    "task-delivery-" + strings.Repeat("d", 64), DeliveryGeneration: 1,
		Action: controlprotocol.ExecutorTaskActionSubmit, TenantID: "tenant-a", NodeID: "node-1",
		TaskID: "research-1", GrantID: "grant-" + strings.Repeat("e", 64), OperationID: "hermes.run",
		TaskPermit: "permit", RequestBase64: base64.StdEncoding.EncodeToString(body), PermitDigest: permitDigest,
	}
	report := poller.executeTaskDelivery(context.Background(), base)
	if report.Validate() != nil || report.Status != controlprotocol.ExecutorTaskReportAccepted ||
		report.TaskDigest != taskDigest || report.RunID != "run_research" || string(fake.body) != string(body) {
		t.Fatalf("submission report = %+v, body=%q", report, fake.body)
	}

	fake.status = gateway.TaskLifecycleStatus{
		TaskDigest: taskDigest, PermitDigest: permitDigest, RunID: "run_research",
		State: "agent_reported_completed", TaskStatus: connectorledger.TaskStatusAgentReportedCompleted,
		ResultDigest: resultDigest, ResponseBytes: int64(len(result)),
		ObservationBase64: base64.StdEncoding.EncodeToString(result),
	}
	base.Action, base.TaskDigest = controlprotocol.ExecutorTaskActionObserve, taskDigest
	base.GrantID, base.OperationID, base.TaskPermit, base.RequestBase64 = "", "", "", ""
	report = poller.executeTaskDelivery(context.Background(), base)
	if report.Validate() != nil || report.Status != controlprotocol.ExecutorTaskReportObserved ||
		report.TaskStatus != string(connectorledger.TaskStatusAgentReportedCompleted) ||
		report.ResultDigest != resultDigest || report.ResponseBytes != int64(len(result)) ||
		report.ResultBase64 != base64.StdEncoding.EncodeToString(result) {
		t.Fatalf("observation report = %+v", report)
	}
	fake.status.ObservationBase64 = base64.StdEncoding.EncodeToString(make([]byte, controlprotocol.MaxExecutorTaskResultBytes+1))
	report = poller.executeTaskDelivery(context.Background(), base)
	if report.Validate() != nil || report.ResultBase64 != "" {
		t.Fatalf("oversized result was relayed: %+v", report)
	}
}

func TestAsyncTaskCourierRejectsMalformedDeliveryAndClassifiesGatewayFailure(t *testing.T) {
	permitDigest := "sha256:" + strings.Repeat("a", 64)
	taskDigest := "sha256:" + strings.Repeat("b", 64)
	fake := &fakeAsyncTaskGateway{}
	poller := &Poller{taskGateway: fake}
	delivery := controlprotocol.ExecutorTaskDeliveryV1{
		SchemaVersion: controlprotocol.ExecutorTaskDeliverySchemaV1,
		DeliveryID:    "task-delivery", DeliveryGeneration: 1,
		Action: controlprotocol.ExecutorTaskActionSubmit, TenantID: "tenant-a", NodeID: "node-1",
		TaskID: "task-a", GrantID: "grant-" + strings.Repeat("c", 64), OperationID: "hermes.run",
		TaskPermit: "permit", RequestBase64: "!!!!", PermitDigest: permitDigest,
	}
	report := poller.executeTaskDelivery(context.Background(), delivery)
	if report.Status != controlprotocol.ExecutorTaskReportRejected || report.ErrorCode != "invalid_request_encoding" {
		t.Fatalf("malformed request report=%+v", report)
	}
	delivery.RequestBase64 = base64.StdEncoding.EncodeToString([]byte(`{"input":"work"}`))
	fake.err = errors.New("socket closed")
	report = poller.executeTaskDelivery(context.Background(), delivery)
	if report.Status != controlprotocol.ExecutorTaskReportRetryable || report.ErrorCode != "gateway_transport_unavailable" {
		t.Fatalf("transport report=%+v", report)
	}
	delivery.Action, delivery.TaskDigest = controlprotocol.ExecutorTaskActionObserve, taskDigest
	delivery.GrantID, delivery.OperationID, delivery.TaskPermit, delivery.RequestBase64 = "", "", "", ""
	fake.err = &gateway.ControlAPIError{Status: http.StatusNotFound, Code: "task_not_found"}
	report = poller.executeTaskDelivery(context.Background(), delivery)
	if report.Status != controlprotocol.ExecutorTaskReportUncertain || report.ErrorCode != "task_not_found" || report.TaskDigest != taskDigest {
		t.Fatalf("uncertain observation report=%+v", report)
	}
	delivery.Action = "unknown"
	report = poller.executeTaskDelivery(context.Background(), delivery)
	if report.Status != controlprotocol.ExecutorTaskReportRejected || report.ErrorCode != "unsupported_delivery_action" {
		t.Fatalf("unknown action report=%+v", report)
	}
}

func TestAsyncTaskCourierClassifiesSafeReplayAndPermanentRejection(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		submitting bool
		wantStatus string
		wantCode   string
	}{
		{name: "transport replay", err: errors.New("socket closed"), submitting: true,
			wantStatus: controlprotocol.ExecutorTaskReportRetryable, wantCode: "gateway_transport_unavailable"},
		{name: "busy replay", err: &gateway.ControlAPIError{Status: http.StatusTooManyRequests, Code: "service_busy"}, submitting: true,
			wantStatus: controlprotocol.ExecutorTaskReportRetryable, wantCode: "service_busy"},
		{name: "invalid permit", err: &gateway.ControlAPIError{Status: http.StatusForbidden, Code: "permit_rejected"}, submitting: true,
			wantStatus: controlprotocol.ExecutorTaskReportRejected, wantCode: "permit_rejected"},
		{name: "lost observed identity", err: &gateway.ControlAPIError{Status: http.StatusNotFound, Code: "task_not_found"}, submitting: false,
			wantStatus: controlprotocol.ExecutorTaskReportUncertain, wantCode: "task_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, code := taskDeliveryError(test.err, test.submitting)
			if status != test.wantStatus || code != test.wantCode {
				t.Fatalf("taskDeliveryError = (%q, %q), want (%q, %q)", status, code, test.wantStatus, test.wantCode)
			}
		})
	}
}

func TestTaskReportAcknowledgementRequiresApplied(t *testing.T) {
	for name, test := range map[string]struct {
		raw  string
		want bool
	}{
		"applied":       {raw: `{"applied":true}`, want: true},
		"rejected":      {raw: `{"applied":false}`},
		"missing":       {raw: `{}`},
		"malformed":     {raw: `{"applied":`},
		"unknown field": {raw: `{"applied":true,"unexpected":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			if got := taskReportAcknowledged([]byte(test.raw)); got != test.want {
				t.Fatalf("taskReportAcknowledged() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAsyncTaskPollerCouriersSubmissionAndRequiresPositiveReportAck(t *testing.T) {
	permitDigest := "sha256:" + strings.Repeat("a", 64)
	taskDigest := "sha256:" + strings.Repeat("b", 64)
	body := []byte(`{"input":"remote"}`)
	delivery := controlprotocol.ExecutorTaskDeliveryV1{
		SchemaVersion: controlprotocol.ExecutorTaskDeliverySchemaV1,
		DeliveryID:    "task-delivery-" + strings.Repeat("d", 64), DeliveryGeneration: 1,
		Action: controlprotocol.ExecutorTaskActionSubmit, TenantID: "tenant-a", NodeID: "node-1",
		TaskID: "task-a", GrantID: "grant-" + strings.Repeat("e", 64), OperationID: "hermes.run",
		TaskPermit: "permit", RequestBase64: base64.StdEncoding.EncodeToString(body), PermitDigest: permitDigest,
	}
	reported := make(chan controlprotocol.ExecutorTaskReportV1, 1)
	acknowledge := true
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer bearer" || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers authorization=%q content-type=%q", request.Header.Get("Authorization"), request.Header.Get("Content-Type"))
		}
		switch request.URL.Path {
		case "/executor-uplink/tasks/poll":
			var poll controlprotocol.ExecutorTaskPollRequestV1
			if err := json.NewDecoder(request.Body).Decode(&poll); err != nil || poll.NodeID != "node-1" || poll.Limit != taskPollBatch {
				t.Errorf("poll=%+v err=%v", poll, err)
			}
			_ = json.NewEncoder(writer).Encode(controlprotocol.ExecutorTaskPollResponseV1{
				SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, Deliveries: []controlprotocol.ExecutorTaskDeliveryV1{delivery},
			})
		case "/executor-uplink/tasks/report":
			var report controlprotocol.ExecutorTaskReportV1
			if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reported <- report
			_ = json.NewEncoder(writer).Encode(struct {
				Applied bool `json:"applied"`
			}{Applied: acknowledge})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	credentialRaw := []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`)
	if err := os.WriteFile(credentialPath, credentialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	credential := &stewarduplink.Credential{Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer"}
	fake := &fakeAsyncTaskGateway{submission: gateway.ControlTaskSubmission{
		TaskDigest: taskDigest, PermitDigest: permitDigest, RunID: "run-a",
	}}
	poller := &Poller{
		taskPollURL: server.URL + "/executor-uplink/tasks/poll", taskReportURL: server.URL + "/executor-uplink/tasks/report",
		credentialPath: credentialPath, expected: credential, client: server.Client(), taskGateway: fake,
		security: stewarduplink.CredentialSecurity{SecureExecutor: true, ProtectedTransport: true},
	}
	if err := poller.pollTasksOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := <-reported
	if report.Status != controlprotocol.ExecutorTaskReportAccepted || report.TaskDigest != taskDigest || string(fake.body) != string(body) {
		t.Fatalf("report=%+v body=%q", report, fake.body)
	}
	acknowledge = false
	if err := poller.pollTasksOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Fatalf("negative acknowledgement error=%v", err)
	}
}

func TestTaskWireCallRejectsHTTPFailureAndOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/failed" {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":"unavailable","message":"retry"}`))
			return
		}
		_, _ = writer.Write([]byte(strings.Repeat("x", 65)))
	}))
	defer server.Close()
	poller := &Poller{client: server.Client()}
	if _, err := poller.taskWireCall(context.Background(), server.URL+"/failed", "bearer", nil, "test", 64); err == nil {
		t.Fatal("HTTP failure was accepted")
	}
	if _, err := poller.taskWireCall(context.Background(), server.URL+"/large", "bearer", nil, "test", 64); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

func TestAsyncTaskPollLoopStopsDuringBackoff(t *testing.T) {
	poller := &Poller{
		credentialPath: filepath.Join(t.TempDir(), "missing.json"), interval: time.Millisecond,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		poller.runTasks(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task poll loop did not stop after cancellation")
	}
}

func TestAsyncTaskPollerRejectsRotatedIdentityAndMalformedControlData(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	writeCredential := func(nodeID string) {
		raw := []byte(`{"version":2,"scope":"node","node_id":"` + nodeID + `","credential":"bearer"}`)
		if err := os.WriteFile(credentialPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCredential("node-2")
	response := `{"schema_version":"wrong","deliveries":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(response))
	}))
	defer server.Close()
	poller := &Poller{
		taskPollURL: server.URL, taskReportURL: server.URL, credentialPath: credentialPath,
		expected: &stewarduplink.Credential{Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer"},
		client:   server.Client(), taskGateway: &fakeAsyncTaskGateway{},
		security: stewarduplink.CredentialSecurity{SecureExecutor: true, ProtectedTransport: true},
	}
	if err := poller.pollTasksOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "changed task courier identity") {
		t.Fatalf("rotated identity error=%v", err)
	}
	writeCredential("node-1")
	if err := poller.pollTasksOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "poll response is invalid") {
		t.Fatalf("malformed poll error=%v", err)
	}
	response = `{"schema_version":"steward.executor-task-poll.v1","deliveries":[{"schema_version":"bad"}]}`
	if err := poller.pollTasksOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "delivery 0 is invalid") {
		t.Fatalf("malformed delivery error=%v", err)
	}
}
