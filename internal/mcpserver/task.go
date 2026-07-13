package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

const maxTaskObservationBytes = 1 << 20

// TaskGateway is the bounded Gateway task-lifecycle surface used by MCP. It
// deliberately excludes ambient HTTP operations and long-running polling.
type TaskGateway interface {
	Submit(context.Context, gatewayclient.TaskSubmission) (gatewayclient.TaskSubmissionResult, error)
	Status(context.Context, string, string) (gatewayclient.TaskLifecycleStatus, error)
	Observe(context.Context, string, string) (gatewayclient.TaskLifecycleStatus, error)
}

type taskSubmitArgs struct {
	ServicePath                string `json:"service_path"`
	OperationPath              string `json:"operation_path"`
	RequestBase64              string `json:"request_base64"`
	PermitBase64               string `json:"permit_base64"`
	AcknowledgeExternalEffects bool   `json:"acknowledge_external_effects"`
}

type taskReferenceArgs struct {
	TaskDigest   string `json:"task_digest"`
	PermitDigest string `json:"permit_digest"`
}

type taskObserveArgs struct {
	TaskDigest   string `json:"task_digest"`
	PermitDigest string `json:"permit_digest"`
}

type taskSubmissionMetadata struct {
	TaskDigest   string                    `json:"task_digest"`
	PermitDigest string                    `json:"permit_digest"`
	Receipt      gatewayclient.TaskReceipt `json:"receipt"`
}

// taskStatusMetadata intentionally has no field capable of carrying raw agent
// output. That output crosses the MCP boundary only as an owner-only path plus
// the durable digest and length that Gateway verified.
type taskStatusMetadata struct {
	SchemaVersion  string                        `json:"schema_version"`
	TaskDigest     string                        `json:"task_digest"`
	PermitDigest   string                        `json:"permit_digest"`
	Phase          gatewayclient.Phase           `json:"phase"`
	State          string                        `json:"state"`
	TaskStatus     gatewayclient.AgentTaskStatus `json:"task_status,omitempty"`
	ResultDigest   string                        `json:"result_digest,omitempty"`
	ResponseBytes  int64                         `json:"response_bytes,omitempty"`
	RetrySafety    string                        `json:"retry_safety,omitempty"`
	ObservedStatus gatewayclient.ObservedStatus  `json:"observed_status,omitempty"`
	ResultPath     string                        `json:"result_path,omitempty"`
}

func (s *Server) submitTask(ctx context.Context, raw []byte) (any, error) {
	var arguments taskSubmitArgs
	if decodeArguments(raw, &arguments) != nil || arguments.ServicePath == "" ||
		arguments.OperationPath == "" || !arguments.AcknowledgeExternalEffects {
		return nil, errors.New("steward_task_submit requires exact service_path, operation_path, request_base64, permit_base64, and acknowledge_external_effects=true")
	}
	request, err := decodeCanonicalTaskBase64(arguments.RequestBase64, int(taskpermit.MaxRequestBytes))
	if err != nil {
		return nil, errors.New("request_base64 is not canonical bounded base64")
	}
	permit, err := decodeCanonicalTaskBase64(arguments.PermitBase64, taskpermit.MaxEnvelopeBytes)
	if err != nil {
		return nil, errors.New("permit_base64 is not canonical bounded base64")
	}
	taskDigest, permitDigest, err := taskIdentityFromPermit(permit)
	if err != nil {
		return nil, errors.New("permit_base64 is not one canonical task permit envelope")
	}
	result, err := s.tasks.Submit(ctx, gatewayclient.TaskSubmission{
		ServicePath: arguments.ServicePath, OperationPath: arguments.OperationPath,
		ContentType: "application/json", Request: request, Permit: permit,
	})
	if err != nil {
		return nil, taskGatewayFailure("submission", err)
	}
	if !validTaskIdentifier(result.RunID, 128) ||
		result.Receipt != gatewayclient.TaskReceiptRecorded && result.Receipt != gatewayclient.TaskReceiptReplayed {
		return nil, errors.New("Gateway returned invalid task submission metadata")
	}
	return taskSubmissionMetadata{
		TaskDigest: taskDigest, PermitDigest: permitDigest,
		Receipt: result.Receipt,
	}, nil
}

// taskIdentityFromPermit derives only the lifecycle lookup coordinates. It
// does not authenticate the permit; Gateway does that before Submit returns a
// durable receipt. Canonical parsing prevents the MCP result from naming a
// different envelope or logical task than the exact bytes Gateway accepted.
func taskIdentityFromPermit(raw []byte) (string, string, error) {
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != taskpermit.PayloadType || len(envelope.Signatures) != 1 {
		return "", "", errors.New("invalid task permit envelope")
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", "", errors.New("task permit envelope is not canonical")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload || len(payload) > taskpermit.MaxEnvelopeBytes {
		return "", "", errors.New("task permit payload is invalid")
	}
	var statement taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &statement); err != nil ||
		strings.TrimSpace(statement.TenantID) == "" || strings.TrimSpace(statement.InstanceID) == "" || statement.TaskID == "" {
		return "", "", errors.New("task permit statement has no logical task identity")
	}
	return taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID), dsse.Digest(raw), nil
}

func (s *Server) taskStatus(ctx context.Context, raw []byte) (any, error) {
	var arguments taskReferenceArgs
	if decodeArguments(raw, &arguments) != nil || !validTaskDigest(arguments.TaskDigest) || !validTaskDigest(arguments.PermitDigest) {
		return nil, errors.New("steward_task_status requires canonical task_digest and permit_digest values")
	}
	status, err := s.tasks.Status(ctx, arguments.TaskDigest, arguments.PermitDigest)
	if err != nil {
		return nil, taskGatewayFailure("status", err)
	}
	if status.ObservationBase64 != "" {
		return nil, errors.New("Gateway durable task status unexpectedly contained agent output")
	}
	return taskMetadata(status, arguments.TaskDigest, arguments.PermitDigest)
}

func (s *Server) observeTask(ctx context.Context, raw []byte) (value any, resultErr error) {
	var arguments taskObserveArgs
	if decodeArguments(raw, &arguments) != nil || !validTaskDigest(arguments.TaskDigest) ||
		!validTaskDigest(arguments.PermitDigest) {
		return nil, errors.New("steward_task_observe requires canonical task_digest and permit_digest values")
	}
	reservation, err := s.resultStore.reserve(arguments.TaskDigest, arguments.PermitDigest)
	if err != nil {
		return nil, fmt.Errorf("reserve terminal result: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, reservation.discard())
		}
	}()

	status, err := s.tasks.Observe(ctx, arguments.TaskDigest, arguments.PermitDigest)
	if err != nil {
		return nil, taskGatewayFailure("observation", err)
	}
	metadata, err := taskMetadata(status, arguments.TaskDigest, arguments.PermitDigest)
	if err != nil {
		return nil, err
	}
	if status.ObservationBase64 == "" {
		return metadata, nil
	}
	rawResult, err := decodeCanonicalTaskBase64(status.ObservationBase64, maxTaskObservationBytes)
	if err != nil || status.Phase != gatewayclient.PhaseTerminal || int64(len(rawResult)) != status.ResponseBytes ||
		status.ResultDigest != dsse.Digest(rawResult) || !terminalObservationStatus(status.ObservedStatus) {
		return nil, errors.New("Gateway terminal observation did not match its verified metadata")
	}
	if err := reservation.commit(rawResult); err != nil {
		return nil, fmt.Errorf("write terminal result: %w", err)
	}
	committed = true
	metadata.ResultPath = reservation.path
	return metadata, nil
}

// taskGatewayFailure preserves bounded retry metadata while excluding the
// upstream error message. A compromised or buggy peer therefore cannot place
// agent output in MCP JSON through an error string.
func taskGatewayFailure(operation string, err error) error {
	var apiError *gatewayclient.APIError
	if errors.As(err, &apiError) && apiError.Status >= 400 && apiError.Status <= 599 {
		if apiError.RetryAfter > 0 {
			return fmt.Errorf("Gateway task %s failed: HTTP %d; retry after %s", operation, apiError.Status, apiError.RetryAfter)
		}
		return fmt.Errorf("Gateway task %s failed: HTTP %d", operation, apiError.Status)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("Gateway task %s was canceled", operation)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("Gateway task %s reached its deadline", operation)
	}
	return fmt.Errorf("Gateway task %s failed validation or transport", operation)
}

func taskMetadata(status gatewayclient.TaskLifecycleStatus, taskDigest, permitDigest string) (taskStatusMetadata, error) {
	if status.TaskDigest != taskDigest || status.PermitDigest != permitDigest || !validTaskDigest(status.TaskDigest) ||
		!validTaskDigest(status.PermitDigest) || status.SchemaVersion != "steward.task-status.v1" ||
		!validTaskPhase(status.Phase) || !validTaskState(status.State) ||
		status.RunID != "" && !validTaskIdentifier(status.RunID, 128) ||
		status.TaskStatus != "" && !validTaskAgentStatus(status.TaskStatus) ||
		status.ResultDigest != "" && !validTaskDigest(status.ResultDigest) ||
		status.ResponseBytes < 0 || status.ResponseBytes > maxTaskObservationBytes ||
		status.ErrorCode != "" && !validTaskIdentifier(status.ErrorCode, 128) ||
		!validTaskRetryMetadata(status) ||
		status.ObservedStatus != "" && !validTaskObservedStatus(status.ObservedStatus) {
		return taskStatusMetadata{}, errors.New("Gateway returned invalid task lifecycle metadata")
	}
	return taskStatusMetadata{
		SchemaVersion: status.SchemaVersion, TaskDigest: status.TaskDigest, PermitDigest: status.PermitDigest,
		Phase: status.Phase, State: status.State, TaskStatus: status.TaskStatus,
		ResultDigest: status.ResultDigest, ResponseBytes: status.ResponseBytes,
		RetrySafety: status.RetrySafety, ObservedStatus: status.ObservedStatus,
	}, nil
}

func decodeCanonicalTaskBase64(value string, maximum int) ([]byte, error) {
	if maximum <= 0 || value == "" || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errors.New("base64 value is empty or exceeds its limit")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64 value is not canonical")
	}
	return raw, nil
}

func validTaskDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validTaskIdentifier(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func terminalObservationStatus(status gatewayclient.ObservedStatus) bool {
	return status == gatewayclient.ObservedCompleted || status == gatewayclient.ObservedFailed || status == gatewayclient.ObservedCancelled
}

func validTaskPhase(phase gatewayclient.Phase) bool {
	return phase == gatewayclient.PhaseAuthorize || phase == gatewayclient.PhaseDispatch || phase == gatewayclient.PhaseTerminal
}

func validTaskState(state string) bool {
	switch state {
	case gatewayclient.StateAuthorizationRecorded, gatewayclient.StateDispatchAccepted,
		gatewayclient.StateFailedWithoutDispatchEvidence, gatewayclient.StateObservationFailed,
		string(gatewayclient.AgentReportedCompleted), string(gatewayclient.AgentReportedFailed),
		string(gatewayclient.AgentReportedCancelled):
		return true
	default:
		return false
	}
}

func validTaskRetrySafety(value string) bool {
	return value == gatewayclient.RetryReplacementSafeAfterNewAuthority || value == gatewayclient.RetryReplacementUnsafe
}

func validTaskRetryMetadata(status gatewayclient.TaskLifecycleStatus) bool {
	if status.RetrySafety != "" && !validTaskRetrySafety(status.RetrySafety) {
		return false
	}
	switch status.State {
	case gatewayclient.StateFailedWithoutDispatchEvidence:
		want := gatewayclient.RetryReplacementUnsafe
		if status.ErrorCode == "permit_expired" || status.ErrorCode == "grant_revoked" {
			want = gatewayclient.RetryReplacementSafeAfterNewAuthority
		}
		return status.ErrorCode != "" && status.RetrySafety == want
	case gatewayclient.StateObservationFailed:
		return status.ErrorCode != "" && status.RetrySafety == gatewayclient.RetryReplacementUnsafe
	default:
		return status.RetrySafety == ""
	}
}

func validTaskAgentStatus(status gatewayclient.AgentTaskStatus) bool {
	return status == gatewayclient.AgentReportedCompleted || status == gatewayclient.AgentReportedFailed ||
		status == gatewayclient.AgentReportedCancelled
}

func validTaskObservedStatus(status gatewayclient.ObservedStatus) bool {
	switch status {
	case gatewayclient.ObservedQueued, gatewayclient.ObservedRunning, gatewayclient.ObservedCompleted,
		gatewayclient.ObservedFailed, gatewayclient.ObservedCancelled:
		return true
	default:
		return false
	}
}

func taskTools() []any {
	digestSchema := map[string]any{"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}
	referenceProperties := map[string]any{"task_digest": digestSchema, "permit_digest": digestSchema}
	return []any{
		tool("steward_task_submit", "Submit authorized task",
			"Submit one exact signed task request. acknowledge_external_effects is a model-visible safety acknowledgment, not proof of human approval; the signed permit and Gateway policy are the authority boundary.",
			map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []string{"service_path", "operation_path", "request_base64", "permit_base64", "acknowledge_external_effects"},
				"properties": map[string]any{
					"service_path":                 map[string]any{"type": "string", "pattern": "^/v1/services/grant-[a-f0-9]{64}/$"},
					"operation_path":               map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "pattern": "^/"},
					"request_base64":               map[string]any{"type": "string", "minLength": 4, "maxLength": base64.StdEncoding.EncodedLen(int(taskpermit.MaxRequestBytes))},
					"permit_base64":                map[string]any{"type": "string", "minLength": 4, "maxLength": base64.StdEncoding.EncodedLen(taskpermit.MaxEnvelopeBytes)},
					"acknowledge_external_effects": map[string]any{"type": "boolean", "const": true},
				},
			}, false, true, true, true),
		tool("steward_task_status", "Inspect task evidence",
			"Read durable Gateway task lifecycle metadata without contacting the agent or returning agent output.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required": []string{"task_digest", "permit_digest"}, "properties": referenceProperties},
			true, false, true, false),
		tool("steward_task_observe", "Observe task once",
			"Make one bounded Gateway observation. A verified terminal result is saved once under a task-derived name in the fixed, quota-bounded result store; MCP receives only its path, digest, length, and status metadata.",
			map[string]any{"type": "object", "additionalProperties": false,
				"required": []string{"task_digest", "permit_digest"}, "properties": referenceProperties},
			false, false, false, true),
	}
}
