package executoruplink

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
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
