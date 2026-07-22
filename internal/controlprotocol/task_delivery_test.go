package controlprotocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func TestExecutorTaskDeliveryClosedActionShapes(t *testing.T) {
	permitDigest := "sha256:" + strings.Repeat("a", 64)
	request := []byte(`{"input":"bounded"}`)
	base := ExecutorTaskDeliveryV1{
		SchemaVersion: ExecutorTaskDeliverySchemaV1,
		DeliveryID:    "task-delivery", DeliveryGeneration: 1,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "task-a", PermitDigest: permitDigest,
	}
	submit := base
	submit.Action = ExecutorTaskActionSubmit
	submit.GrantID = "grant-" + strings.Repeat("b", 64)
	submit.OperationID = "hermes.run"
	submit.TaskPermit = "permit"
	submit.RequestBase64 = base64.StdEncoding.EncodeToString(request)
	observe := base
	observe.Action = ExecutorTaskActionObserve
	observe.TaskDigest = "sha256:" + strings.Repeat("c", 64)
	if err := submit.Validate(); err != nil {
		t.Fatalf("valid submit: %v", err)
	}
	if err := observe.Validate(); err != nil {
		t.Fatalf("valid observe: %v", err)
	}
	for name, mutate := range map[string]func(*ExecutorTaskDeliveryV1){
		"identity":          func(value *ExecutorTaskDeliveryV1) { value.NodeID = "" },
		"action":            func(value *ExecutorTaskDeliveryV1) { value.Action = "delete" },
		"submit grant":      func(value *ExecutorTaskDeliveryV1) { value.GrantID = "grant-bad" },
		"submit body":       func(value *ExecutorTaskDeliveryV1) { value.RequestBase64 = "!!!!" },
		"submit digest":     func(value *ExecutorTaskDeliveryV1) { value.TaskDigest = observe.TaskDigest },
		"observe authority": func(value *ExecutorTaskDeliveryV1) { value.TaskPermit = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := submit
			if strings.HasPrefix(name, "observe") {
				candidate = observe
			}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid delivery accepted: %+v", candidate)
			}
		})
	}
}

func TestExecutorTaskReportsValidateEveryStatusShape(t *testing.T) {
	permitDigest := "sha256:" + strings.Repeat("a", 64)
	taskDigest := "sha256:" + strings.Repeat("b", 64)
	base := ExecutorTaskReportV1{
		SchemaVersion: ExecutorTaskReportSchemaV1,
		DeliveryID:    "task-delivery", DeliveryGeneration: 1,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "task-a", PermitDigest: permitDigest,
	}
	accepted := base
	accepted.Status, accepted.TaskDigest, accepted.RunID = ExecutorTaskReportAccepted, taskDigest, "run-a"
	if err := accepted.Validate(); err != nil {
		t.Fatalf("valid accepted report: %v", err)
	}
	result := []byte(`{"answer":"bounded"}`)
	observed := base
	observed.Status, observed.TaskDigest, observed.RunID = ExecutorTaskReportObserved, taskDigest, "run-a"
	observed.LifecycleState, observed.TaskStatus = "agent_reported_completed", "agent_reported_completed"
	observed.ResultDigest, observed.ResponseBytes = dsse.Digest(result), int64(len(result))
	observed.ResultBase64 = base64.StdEncoding.EncodeToString(result)
	if err := observed.Validate(); err != nil {
		t.Fatalf("valid observed report: %v", err)
	}
	for _, status := range []string{ExecutorTaskReportRetryable, ExecutorTaskReportRejected, ExecutorTaskReportUncertain} {
		failure := base
		failure.Status, failure.ErrorCode = status, "gateway_failed"
		if err := failure.Validate(); err != nil {
			t.Fatalf("valid %s report: %v", status, err)
		}
	}
	for name, candidate := range map[string]ExecutorTaskReportV1{
		"identity":          func() ExecutorTaskReportV1 { value := accepted; value.PermitDigest = "bad"; return value }(),
		"accepted result":   func() ExecutorTaskReportV1 { value := accepted; value.ResponseBytes = 1; return value }(),
		"observed identity": func() ExecutorTaskReportV1 { value := observed; value.RunID = ""; return value }(),
		"observed encoding": func() ExecutorTaskReportV1 { value := observed; value.ResultBase64 = "!!!!"; return value }(),
		"observed digest":   func() ExecutorTaskReportV1 { value := observed; value.ResultDigest = permitDigest; return value }(),
		"observed status":   func() ExecutorTaskReportV1 { value := observed; value.TaskStatus = "running"; return value }(),
		"failure fields": func() ExecutorTaskReportV1 {
			value := base
			value.Status = ExecutorTaskReportRetryable
			value.ErrorCode = "retry"
			value.ResponseBytes = 1
			return value
		}(),
		"unknown status": func() ExecutorTaskReportV1 { value := base; value.Status = "done"; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid report accepted: %+v", candidate)
			}
		})
	}
}
