package controlprotocol

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	ExecutorTaskProtocolV1           = 1
	ExecutorTaskPollSchemaV1         = "steward.executor-task-poll.v1"
	ExecutorTaskDeliverySchemaV1     = "steward.executor-task-delivery.v1"
	ExecutorTaskReportSchemaV1       = "steward.executor-task-report.v1"
	ExecutorTaskActionSubmit         = "submit"
	ExecutorTaskActionObserve        = "observe"
	ExecutorTaskReportAccepted       = "accepted"
	ExecutorTaskReportObserved       = "observed"
	ExecutorTaskReportRetryable      = "retryable_error"
	ExecutorTaskReportRejected       = "rejected"
	ExecutorTaskReportUncertain      = "outcome_unknown"
	MaxExecutorTaskDeliveries        = 32
	MaxExecutorTaskDeliveryBytes     = 128 << 10
	MaxExecutorTaskPollResponseBytes = 1 << 20
	MaxExecutorTaskReportBytes       = 768 << 10
	MaxExecutorTaskResultBytes       = 512 << 10
	MaxExecutorTaskErrorCodeBytes    = 128
)

var taskDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type ExecutorTaskPollRequestV1 struct {
	SchemaVersion string `json:"schema_version"`
	NodeID        string `json:"node_id"`
	Limit         int    `json:"limit"`
}

func (request ExecutorTaskPollRequestV1) Validate() error {
	if request.SchemaVersion != ExecutorTaskPollSchemaV1 || !taskText(request.NodeID, 128) ||
		request.Limit <= 0 || request.Limit > MaxExecutorTaskDeliveries {
		return errors.New("executor task poll is invalid")
	}
	return nil
}

type ExecutorTaskDeliveryV1 struct {
	SchemaVersion      string `json:"schema_version"`
	DeliveryID         string `json:"delivery_id"`
	DeliveryGeneration uint64 `json:"delivery_generation"`
	Action             string `json:"action"`
	TenantID           string `json:"tenant_id"`
	NodeID             string `json:"node_id"`
	TaskID             string `json:"task_id"`
	GrantID            string `json:"grant_id,omitempty"`
	OperationID        string `json:"operation_id,omitempty"`
	TaskPermit         string `json:"task_permit,omitempty"`
	RequestBase64      string `json:"request_base64,omitempty"`
	TaskDigest         string `json:"task_digest,omitempty"`
	PermitDigest       string `json:"permit_digest"`
}

func (delivery ExecutorTaskDeliveryV1) Validate() error {
	if delivery.SchemaVersion != ExecutorTaskDeliverySchemaV1 ||
		!taskText(delivery.DeliveryID, 256) || delivery.DeliveryGeneration == 0 ||
		!taskText(delivery.TenantID, 128) || !taskText(delivery.NodeID, 128) ||
		!taskText(delivery.TaskID, 128) || !taskDigestPattern.MatchString(delivery.PermitDigest) {
		return errors.New("executor task delivery identity is invalid")
	}
	switch delivery.Action {
	case ExecutorTaskActionSubmit:
		if !strings.HasPrefix(delivery.GrantID, "grant-") || len(delivery.GrantID) != len("grant-")+64 ||
			!taskText(delivery.OperationID, 128) || delivery.TaskPermit == "" || delivery.TaskDigest != "" {
			return errors.New("executor task submission delivery is invalid")
		}
		raw, err := base64.StdEncoding.DecodeString(delivery.RequestBase64)
		if err != nil || len(raw) == 0 || int64(len(raw)) > taskpermit.MaxRequestBytes ||
			base64.StdEncoding.EncodeToString(raw) != delivery.RequestBase64 {
			return errors.New("executor task submission body is invalid")
		}
	case ExecutorTaskActionObserve:
		if !taskDigestPattern.MatchString(delivery.TaskDigest) || delivery.GrantID != "" ||
			delivery.OperationID != "" || delivery.TaskPermit != "" || delivery.RequestBase64 != "" {
			return errors.New("executor task observation delivery is invalid")
		}
	default:
		return errors.New("executor task delivery action is invalid")
	}
	return nil
}

type ExecutorTaskPollResponseV1 struct {
	SchemaVersion string                   `json:"schema_version"`
	Deliveries    []ExecutorTaskDeliveryV1 `json:"deliveries"`
}

type ExecutorTaskReportV1 struct {
	SchemaVersion      string `json:"schema_version"`
	DeliveryID         string `json:"delivery_id"`
	DeliveryGeneration uint64 `json:"delivery_generation"`
	TenantID           string `json:"tenant_id"`
	NodeID             string `json:"node_id"`
	TaskID             string `json:"task_id"`
	Status             string `json:"status"`
	TaskDigest         string `json:"task_digest,omitempty"`
	PermitDigest       string `json:"permit_digest"`
	RunID              string `json:"run_id,omitempty"`
	LifecycleState     string `json:"lifecycle_state,omitempty"`
	TaskStatus         string `json:"task_status,omitempty"`
	ResultDigest       string `json:"result_digest,omitempty"`
	ResponseBytes      int64  `json:"response_bytes,omitempty"`
	ResultBase64       string `json:"result_base64,omitempty"`
	ErrorCode          string `json:"error_code,omitempty"`
}

func (report ExecutorTaskReportV1) Validate() error {
	if report.SchemaVersion != ExecutorTaskReportSchemaV1 || !taskText(report.DeliveryID, 256) ||
		report.DeliveryGeneration == 0 || !taskText(report.TenantID, 128) ||
		!taskText(report.NodeID, 128) || !taskText(report.TaskID, 128) ||
		!taskDigestPattern.MatchString(report.PermitDigest) ||
		report.ErrorCode != "" && !taskText(report.ErrorCode, MaxExecutorTaskErrorCodeBytes) {
		return errors.New("executor task report identity is invalid")
	}
	switch report.Status {
	case ExecutorTaskReportAccepted:
		if !taskDigestPattern.MatchString(report.TaskDigest) || !taskText(report.RunID, 128) ||
			report.LifecycleState != "" || report.TaskStatus != "" || report.ResultDigest != "" ||
			report.ResponseBytes != 0 || report.ResultBase64 != "" || report.ErrorCode != "" {
			return errors.New("executor accepted task report is invalid")
		}
	case ExecutorTaskReportObserved:
		if !taskDigestPattern.MatchString(report.TaskDigest) || !taskText(report.RunID, 128) ||
			!taskText(report.LifecycleState, 128) || report.ResponseBytes < 0 ||
			report.ResultDigest != "" && !taskDigestPattern.MatchString(report.ResultDigest) {
			return errors.New("executor observed task report is invalid")
		}
		if report.ResultBase64 != "" {
			raw, err := base64.StdEncoding.DecodeString(report.ResultBase64)
			if err != nil || len(raw) == 0 || len(raw) > MaxExecutorTaskResultBytes ||
				base64.StdEncoding.EncodeToString(raw) != report.ResultBase64 ||
				int64(len(raw)) != report.ResponseBytes || dsse.Digest(raw) != report.ResultDigest ||
				(report.TaskStatus != "agent_reported_completed" && report.TaskStatus != "agent_reported_failed" &&
					report.TaskStatus != "agent_reported_cancelled") {
				return errors.New("executor observed task result is invalid")
			}
		}
	case ExecutorTaskReportRetryable, ExecutorTaskReportRejected, ExecutorTaskReportUncertain:
		if report.ErrorCode == "" || report.LifecycleState != "" || report.TaskStatus != "" ||
			report.ResultDigest != "" || report.ResponseBytes != 0 || report.ResultBase64 != "" {
			return errors.New("executor task failure report is invalid")
		}
	default:
		return errors.New("executor task report status is invalid")
	}
	return nil
}

func taskText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00') && strings.TrimSpace(value) == value
}
