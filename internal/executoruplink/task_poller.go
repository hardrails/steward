package executoruplink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

const taskPollBatch = 8

type taskGateway interface {
	SubmitTask(context.Context, string, string, string, []byte) (gateway.ControlTaskSubmission, error)
	ObserveTask(context.Context, string, string) (gateway.TaskLifecycleStatus, error)
}

func (p *Poller) runTasks(ctx context.Context) {
	failures := 0
	for {
		if err := p.pollTasksOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			p.logger.Warn("executor async task poll failed", "error", err, "failures", failures)
		} else {
			failures = 0
		}
		wait := p.interval
		for index := 0; index < failures && wait < maxBackoff; index++ {
			wait *= 2
			if wait > maxBackoff {
				wait = maxBackoff
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *Poller) pollTasksOnce(ctx context.Context) error {
	credential, err := stewarduplink.LoadCredentialWithSecurity(p.credentialPath, p.security)
	if err != nil {
		return err
	}
	if credential.Version != p.expected.Version || credential.Scope != p.expected.Scope ||
		credential.TenantID != p.expected.TenantID || credential.NodeID != p.expected.NodeID ||
		!credential.NodeScoped() {
		return errors.New("rotated uplink credential changed task courier identity; refusing it")
	}
	poll := controlprotocol.ExecutorTaskPollRequestV1{
		SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1,
		NodeID:        credential.NodeID,
		Limit:         taskPollBatch,
	}
	raw, err := json.Marshal(poll)
	if err != nil {
		return err
	}
	responseRaw, err := p.taskWireCall(
		ctx, p.taskPollURL, credential.Credential, raw, "task poll",
		controlprotocol.MaxExecutorTaskPollResponseBytes,
	)
	if err != nil {
		return err
	}
	var response controlprotocol.ExecutorTaskPollResponseV1
	if dsse.DecodeStrictInto(responseRaw, controlprotocol.MaxExecutorTaskPollResponseBytes, &response) != nil ||
		response.SchemaVersion != controlprotocol.ExecutorTaskPollSchemaV1 || response.Deliveries == nil ||
		len(response.Deliveries) > taskPollBatch {
		return errors.New("controller task poll response is invalid")
	}
	for index, delivery := range response.Deliveries {
		if delivery.Validate() != nil || delivery.NodeID != credential.NodeID {
			return fmt.Errorf("controller task delivery %d is invalid", index)
		}
		report := p.executeTaskDelivery(ctx, delivery)
		if report.Validate() != nil {
			return fmt.Errorf("executor task report %d is invalid", index)
		}
		reportRaw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		ackRaw, err := p.taskWireCall(ctx, p.taskReportURL, credential.Credential, reportRaw, "task report", maxWireBytes)
		if err != nil {
			return err
		}
		if !taskReportAcknowledged(ackRaw) {
			return errors.New("controller task report acknowledgement is invalid")
		}
	}
	return nil
}

func taskReportAcknowledged(raw []byte) bool {
	var acknowledgement struct {
		Applied bool `json:"applied"`
	}
	return dsse.DecodeStrictInto(raw, maxWireBytes, &acknowledgement) == nil && acknowledgement.Applied
}

func (p *Poller) executeTaskDelivery(ctx context.Context, delivery controlprotocol.ExecutorTaskDeliveryV1) controlprotocol.ExecutorTaskReportV1 {
	report := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		TenantID: delivery.TenantID, NodeID: delivery.NodeID, TaskID: delivery.TaskID,
		PermitDigest: delivery.PermitDigest,
	}
	switch delivery.Action {
	case controlprotocol.ExecutorTaskActionSubmit:
		requestBody, err := base64.StdEncoding.DecodeString(delivery.RequestBase64)
		if err != nil || base64.StdEncoding.EncodeToString(requestBody) != delivery.RequestBase64 {
			report.Status, report.ErrorCode = controlprotocol.ExecutorTaskReportRejected, "invalid_request_encoding"
			return report
		}
		submission, err := p.taskGateway.SubmitTask(
			ctx, delivery.GrantID, delivery.OperationID, delivery.TaskPermit, requestBody,
		)
		if err != nil {
			report.Status, report.ErrorCode = taskDeliveryError(err, true)
			return report
		}
		report.Status = controlprotocol.ExecutorTaskReportAccepted
		report.TaskDigest, report.PermitDigest, report.RunID = submission.TaskDigest, submission.PermitDigest, submission.RunID
	case controlprotocol.ExecutorTaskActionObserve:
		status, err := p.taskGateway.ObserveTask(ctx, delivery.TaskDigest, delivery.PermitDigest)
		if err != nil {
			report.Status, report.ErrorCode = taskDeliveryError(err, false)
			report.TaskDigest = delivery.TaskDigest
			return report
		}
		report.Status = controlprotocol.ExecutorTaskReportObserved
		report.TaskDigest, report.PermitDigest, report.RunID = status.TaskDigest, status.PermitDigest, status.RunID
		report.LifecycleState, report.TaskStatus = status.State, string(status.TaskStatus)
		report.ResultDigest, report.ResponseBytes, report.ErrorCode = status.ResultDigest, status.ResponseBytes, status.ErrorCode
		if raw, err := base64.StdEncoding.DecodeString(status.ObservationBase64); err == nil &&
			len(raw) > 0 && len(raw) <= controlprotocol.MaxExecutorTaskResultBytes &&
			base64.StdEncoding.EncodeToString(raw) == status.ObservationBase64 {
			report.ResultBase64 = status.ObservationBase64
		}
	default:
		report.Status, report.ErrorCode = controlprotocol.ExecutorTaskReportRejected, "unsupported_delivery_action"
	}
	return report
}

func taskDeliveryError(err error, submitting bool) (string, string) {
	var gatewayError *gateway.ControlAPIError
	if !errors.As(err, &gatewayError) {
		return controlprotocol.ExecutorTaskReportRetryable, "gateway_transport_unavailable"
	}
	code := gatewayError.Code
	if code == "" || len(code) > controlprotocol.MaxExecutorTaskErrorCodeBytes {
		code = "gateway_request_failed"
	}
	if gatewayError.Status == http.StatusTooManyRequests || gatewayError.Status >= 500 || gatewayError.Status == http.StatusConflict {
		return controlprotocol.ExecutorTaskReportRetryable, code
	}
	if submitting {
		return controlprotocol.ExecutorTaskReportRejected, code
	}
	return controlprotocol.ExecutorTaskReportUncertain, code
}

func (p *Poller) taskWireCall(ctx context.Context, target, credential string, body []byte, operation string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, wireError(operation, response)
	}
	raw, err := readBounded(response.Body, maximum)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", operation, err)
	}
	return raw, nil
}
