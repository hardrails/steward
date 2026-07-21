package executoruplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
	"github.com/hardrails/steward/internal/taskprotocol"
)

const (
	activationCheckpointRequestSchema       = "steward.executor-activation-checkpoint.v1"
	activationCanaryPreflightRequestSchema  = "steward.executor-activation-canary-preflight.v1"
	maxActivationCheckpointResponseBytes    = 4 << 10
	activationCanaryObservationRetryMinimum = 100 * time.Millisecond
	activationCanarySubmissionRetryMinimum  = time.Second
)

type activationCanaryGateway interface {
	SubmitTask(
		context.Context,
		string,
		string,
		string,
		[]byte,
	) (gateway.ControlTaskSubmission, error)
	TaskStatus(context.Context, string, string) (gateway.TaskLifecycleStatus, error)
	ObserveTask(context.Context, string, string) (gateway.TaskLifecycleStatus, error)
	ExportTaskEvidence(context.Context, string, string) ([]byte, error)
}

type activationCheckpointRequest struct {
	SchemaVersion    string `json:"schema_version"`
	ActivationID     string `json:"activation_id"`
	CheckpointDigest string `json:"checkpoint_digest"`
}

type activationCanaryPreflightRequest struct {
	SchemaVersion         string `json:"schema_version"`
	ActivationID          string `json:"activation_id"`
	ActivationBeginDigest string `json:"activation_begin_digest"`
}

type activationCanaryTerminalError struct {
	status connectorledger.TaskStatus
}

func (err activationCanaryTerminalError) Error() string {
	return "activation canary task ended as " + string(err.status)
}

type activationCanaryRejectedError struct {
	cause error
}

func (err activationCanaryRejectedError) Error() string {
	return "activation canary task was rejected before dispatch: " + err.cause.Error()
}

func (err activationCanaryRejectedError) Unwrap() error { return err.cause }

func (d *dispatcher) applyActivationCanary(
	ctx context.Context,
	cmd command,
	tenantID, instanceID, runtimeRef string,
) (string, *controlprotocol.ExecutorActivationCanaryResultV1, error) {
	if d.activationGateway == nil || d.now == nil {
		return "", nil, errors.New("activation canary execution is unavailable on this node")
	}
	parsed, err := activationcanary.ParseCommandV1(cmd.Payload)
	if err != nil {
		return "", nil, err
	}
	now := d.now().UTC()
	if now.IsZero() {
		return "", nil, errors.New("activation canary node time is unavailable")
	}
	verified, err := activationcanary.VerifyCommandV1(
		cmd.Payload,
		activationcanary.AdmissionContextV1{
			NodeID:     d.nodeID,
			TenantID:   tenantID,
			InstanceID: instanceID,
			Projection: parsed.Admission,
		},
		now,
		taskpermit.MaxValidity,
	)
	if err != nil {
		return "", nil, err
	}
	if parsed.Admission.RuntimeRef != runtimeRef ||
		parsed.Admission.Generation != cmd.InstanceGeneration {
		return "", nil, errors.New("activation canary admission does not match the signed outer runtime generation")
	}

	liveContext := executor.WithAdmissionPrincipal(
		ctx,
		tenantID,
		d.nodeID,
		cmd.InstanceGeneration,
	)
	live, err := d.preflightActivationCanary(
		liveContext,
		runtimeRef,
		activationCanaryPreflightRequest{
			SchemaVersion:         activationCanaryPreflightRequestSchema,
			ActivationID:          parsed.ActivationID,
			ActivationBeginDigest: parsed.Admission.ActivationBeginDigest,
		},
	)
	if err != nil {
		return "", nil, err
	}
	if err := correlateLiveActivationAdmission(parsed.Admission, live); err != nil {
		return "", nil, err
	}

	canaryContext, cancel := context.WithDeadline(ctx, verified.Deadline())
	defer cancel()
	commandValue := verified.Command()
	submission, err := d.submitActivationCanary(canaryContext, verified)
	if err != nil {
		var terminal activationCanaryTerminalError
		var rejected activationCanaryRejectedError
		if errors.As(err, &terminal) || errors.As(err, &rejected) {
			return "", nil, err
		}
		return "", nil, uncertainEffectError{cause: err}
	}
	receiptPublic, err := verifyActivationCanarySubmission(verified, submission)
	if err != nil {
		return "", nil, uncertainEffectError{cause: err}
	}
	terminal, err := d.observeActivationCanary(canaryContext, submission)
	if err != nil {
		var known activationCanaryTerminalError
		if errors.As(err, &known) {
			return "", nil, err
		}
		return "", nil, uncertainEffectError{cause: err}
	}
	receipts, err := d.activationGateway.ExportTaskEvidence(
		canaryContext,
		submission.TaskDigest,
		submission.PermitDigest,
	)
	if err != nil {
		return "", nil, uncertainEffectError{
			cause: fmt.Errorf("export activation canary Gateway evidence: %w", err),
		}
	}
	evidence, err := activationcanary.VerifyEvidenceV1(
		verified,
		submission.RunID,
		terminal,
		receipts,
		receiptPublic,
	)
	if err != nil {
		return "", nil, uncertainEffectError{
			cause: fmt.Errorf("verify activation canary evidence: %w", err),
		}
	}
	checkpointRaw, err := activationcanary.BuildCheckpointV1(verified, evidence)
	if err != nil {
		return "", nil, uncertainEffectError{
			cause: fmt.Errorf("build activation canary checkpoint: %w", err),
		}
	}
	_, result, err := activationcanary.BuildResultV1(
		verified,
		submission.RunID,
		terminal,
		receipts,
		checkpointRaw,
		receiptPublic,
	)
	if err != nil {
		return "", nil, uncertainEffectError{
			cause: fmt.Errorf("build activation canary result: %w", err),
		}
	}
	projection, err := projectActivationCanaryResult(result.Result())
	if err != nil {
		return "", nil, uncertainEffectError{
			cause: fmt.Errorf("project activation canary result: %w", err),
		}
	}
	checkpointDigest := dsse.Digest(checkpointRaw)
	if checkpointDigest != projection.ActivationCheckpointDigest {
		return "", nil, uncertainEffectError{
			cause: errors.New("activation canary checkpoint digest changed after verification"),
		}
	}
	checkpointContext := executor.WithAdmissionPrincipal(
		canaryContext,
		tenantID,
		d.nodeID,
		cmd.InstanceGeneration,
	)
	if err := d.appendActivationCheckpoint(
		checkpointContext,
		runtimeRef,
		activationCheckpointRequest{
			SchemaVersion:    activationCheckpointRequestSchema,
			ActivationID:     commandValue.ActivationID,
			CheckpointDigest: checkpointDigest,
		},
	); err != nil {
		return "", nil, err
	}
	return "running", projection, nil
}

func (d *dispatcher) preflightActivationCanary(
	ctx context.Context,
	runtimeRef string,
	preflight activationCanaryPreflightRequest,
) (controlprotocol.ExecutorAdmissionProjectionV1, error) {
	body, err := json.Marshal(preflight)
	if err != nil {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://executor.local/v1/workloads/"+runtimeRef+
			"/activation-canary-preflight",
		bytes.NewReader(body),
	)
	if err != nil {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	response := newLocalResponse(controlprotocol.MaxExecutorReportBytes)
	d.handler.ServeHTTP(response, req)
	if response.overflow {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, errLocalResponseLimit
	}
	if response.status != http.StatusOK {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, fmt.Errorf(
			"local executor returned HTTP %d while corroborating the activation runtime: %s",
			response.status,
			bytes.TrimSpace(response.body.Bytes()),
		)
	}
	var local executorAdmissionResponse
	if err := dsse.DecodeStrictInto(
		response.body.Bytes(),
		controlprotocol.MaxExecutorReportBytes,
		&local,
	); err != nil {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, fmt.Errorf(
			"decode strict local activation runtime response: %w",
			err,
		)
	}
	projection := executorAdmissionProjection(local)
	if err := projection.Validate(); err != nil {
		return controlprotocol.ExecutorAdmissionProjectionV1{}, fmt.Errorf(
			"validate local activation runtime projection: %w",
			err,
		)
	}
	return projection, nil
}

func correlateLiveActivationAdmission(
	admitted controlprotocol.ExecutorAdmissionProjectionV1,
	live controlprotocol.ExecutorAdmissionProjectionV1,
) error {
	if live.Status != "running" {
		return errors.New("activation canary requires the admitted workload to be running")
	}
	expected := cloneAdmissionProjection(&admitted)
	expected.Status = "running"
	expectedRaw, expectedErr := json.Marshal(expected)
	liveRaw, liveErr := json.Marshal(live)
	if expectedErr != nil || liveErr != nil || !bytes.Equal(expectedRaw, liveRaw) {
		return errors.New("live workload differs from the immutable activation admission")
	}
	return nil
}

func (d *dispatcher) submitActivationCanary(
	ctx context.Context,
	verified activationcanary.VerifiedCommandV1,
) (gateway.ControlTaskSubmission, error) {
	commandValue := verified.Command()
	for {
		submission, err := d.activationGateway.SubmitTask(
			ctx,
			commandValue.GrantID,
			commandValue.OperationID,
			commandValue.TaskPermit,
			verified.Request(),
		)
		if err == nil {
			return submission, nil
		}
		var apiError *gateway.ControlAPIError
		if errors.As(err, &apiError) {
			switch apiError.Code {
			case "invalid_task_submission", "method_not_allowed", "service_operation_not_found":
				return gateway.ControlTaskSubmission{}, activationCanaryRejectedError{
					cause: err,
				}
			case "service_busy":
				delay := apiError.RetryAfter
				if delay == 0 {
					delay = activationCanarySubmissionRetryMinimum
				}
				if waitErr := d.waitActivationCanary(ctx, delay); waitErr != nil {
					return gateway.ControlTaskSubmission{}, waitErr
				}
				continue
			}
		}
		return gateway.ControlTaskSubmission{}, fmt.Errorf(
			"submit activation canary task: %w",
			err,
		)
	}
}

func verifyActivationCanarySubmission(
	verified activationcanary.VerifiedCommandV1,
	submission gateway.ControlTaskSubmission,
) (ed25519.PublicKey, error) {
	commandValue := verified.Command()
	statement := verified.Permit().Statement
	expectedTaskDigest := taskpermit.TaskDigest(
		statement.TenantID,
		statement.InstanceID,
		statement.TaskID,
	)
	publicRaw, err := base64.StdEncoding.DecodeString(submission.ReceiptPublicKey)
	if err != nil || len(publicRaw) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(publicRaw) != submission.ReceiptPublicKey ||
		submission.SchemaVersion != gateway.ControlTaskSubmissionSchemaV1 ||
		submission.TaskDigest != expectedTaskDigest ||
		submission.PermitDigest != verified.Permit().EnvelopeDigest ||
		!validActivationCanaryRunID(submission.RunID) ||
		submission.ReceiptNodeID != commandValue.ReceiptAuthority.NodeID ||
		submission.ReceiptEpoch != commandValue.ReceiptAuthority.Epoch ||
		controlprotocol.ExecutorEvidencePublicKeySHA256(publicRaw) !=
			commandValue.ReceiptAuthority.PublicKeySHA256 {
		return nil, errors.New("Gateway task submission changed a canary or receipt-authority binding")
	}
	return ed25519.PublicKey(append([]byte(nil), publicRaw...)), nil
}

func (d *dispatcher) observeActivationCanary(
	ctx context.Context,
	submission gateway.ControlTaskSubmission,
) ([]byte, error) {
	status, err := d.activationGateway.TaskStatus(
		ctx,
		submission.TaskDigest,
		submission.PermitDigest,
	)
	if err != nil {
		return nil, fmt.Errorf("read activation canary task status: %w", err)
	}
	for {
		if err := validateActivationCanaryStatus(submission, status); err != nil {
			return nil, err
		}
		if status.Phase == connectorledger.Terminal {
			switch status.TaskStatus {
			case connectorledger.TaskStatusAgentReportedFailed,
				connectorledger.TaskStatusAgentReportedCancelled:
				return nil, activationCanaryTerminalError{status: status.TaskStatus}
			case "":
				return nil, errors.New(
					"Gateway recorded an ambiguous terminal canary without a qualified agent result",
				)
			case connectorledger.TaskStatusAgentReportedCompleted:
				if status.ObservationBase64 != "" {
					return decodeActivationCanaryObservation(submission, status)
				}
			default:
				return nil, errors.New("Gateway returned an unsupported terminal canary status")
			}
		}

		observed, observeErr := d.activationGateway.ObserveTask(
			ctx,
			submission.TaskDigest,
			submission.PermitDigest,
		)
		if observeErr != nil {
			var apiError *gateway.ControlAPIError
			if !errors.As(observeErr, &apiError) ||
				(apiError.Code != "task_observation_throttled" &&
					apiError.Code != "service_busy") ||
				apiError.RetryAfter <= 0 {
				return nil, fmt.Errorf("observe activation canary task: %w", observeErr)
			}
			if err := d.waitActivationCanary(ctx, apiError.RetryAfter); err != nil {
				return nil, err
			}
		} else {
			status = observed
			if err := validateActivationCanaryStatus(submission, status); err != nil {
				return nil, err
			}
			if status.Phase == connectorledger.Terminal {
				if status.TaskStatus == connectorledger.TaskStatusAgentReportedCompleted &&
					status.ObservationBase64 == "" {
					return nil, errors.New(
						"Gateway returned a completed canary without its terminal observation",
					)
				}
				continue
			}
			if err := d.waitActivationCanary(
				ctx,
				activationCanaryObservationRetryMinimum,
			); err != nil {
				return nil, err
			}
		}
		status, err = d.activationGateway.TaskStatus(
			ctx,
			submission.TaskDigest,
			submission.PermitDigest,
		)
		if err != nil {
			return nil, fmt.Errorf("refresh activation canary task status: %w", err)
		}
	}
}

func validateActivationCanaryStatus(
	submission gateway.ControlTaskSubmission,
	status gateway.TaskLifecycleStatus,
) error {
	if status.SchemaVersion != gateway.TaskStatusSchemaV1 ||
		status.TaskDigest != submission.TaskDigest ||
		status.PermitDigest != submission.PermitDigest ||
		status.RunID != submission.RunID {
		return errors.New("Gateway task status changed the activation canary identity")
	}
	switch status.Phase {
	case connectorledger.Dispatch:
		if status.State != gateway.TaskStateDispatchAccepted ||
			status.TaskStatus != "" ||
			status.ResultDigest != "" ||
			status.ResponseBytes != 0 ||
			status.ErrorCode != "" ||
			status.RetrySafety != "" ||
			status.ObservationBase64 != "" ||
			status.ObservedStatus != "" &&
				status.ObservedStatus != taskprotocol.StatusQueued &&
				status.ObservedStatus != taskprotocol.StatusRunning {
			return errors.New("Gateway returned an inconsistent dispatched canary state")
		}
	case connectorledger.Terminal:
		if status.ObservedStatus != "" && !status.ObservedStatus.Terminal() {
			return errors.New("Gateway returned a nonterminal observation with terminal evidence")
		}
		if status.ObservedStatus != "" &&
			(status.TaskStatus == connectorledger.TaskStatusAgentReportedCompleted &&
				status.ObservedStatus != taskprotocol.StatusCompleted ||
				status.TaskStatus == connectorledger.TaskStatusAgentReportedFailed &&
					status.ObservedStatus != taskprotocol.StatusFailed ||
				status.TaskStatus == connectorledger.TaskStatusAgentReportedCancelled &&
					status.ObservedStatus != taskprotocol.StatusCancelled) {
			return errors.New("Gateway terminal observation disagrees with its durable task status")
		}
		if status.TaskStatus == connectorledger.TaskStatusAgentReportedCompleted ||
			status.TaskStatus == connectorledger.TaskStatusAgentReportedFailed ||
			status.TaskStatus == connectorledger.TaskStatusAgentReportedCancelled {
			if !controlprotocol.ValidSHA256Digest(status.ResultDigest) ||
				status.ResponseBytes <= 0 {
				return errors.New("Gateway terminal canary state omits its result binding")
			}
		} else if status.TaskStatus == "" &&
			(status.State != gateway.TaskStateObservationFailed ||
				status.RetrySafety != gateway.TaskRetryReplacementUnsafe ||
				status.ResultDigest != "" ||
				status.ResponseBytes != 0 ||
				status.ObservedStatus != "" ||
				status.ObservationBase64 != "") {
			return errors.New("Gateway returned an inconsistent ambiguous terminal canary state")
		}
	default:
		return errors.New("Gateway canary task has no durable dispatch")
	}
	return nil
}

func decodeActivationCanaryObservation(
	submission gateway.ControlTaskSubmission,
	status gateway.TaskLifecycleStatus,
) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(status.ObservationBase64)
	if err != nil || len(raw) == 0 ||
		len(raw) > activationcanary.MaxTerminalResultBytes ||
		base64.StdEncoding.EncodeToString(raw) != status.ObservationBase64 ||
		status.ResponseBytes != int64(len(raw)) ||
		status.ResultDigest != dsse.Digest(raw) {
		return nil, errors.New("Gateway returned an invalid terminal canary observation")
	}
	report, err := taskprotocol.ParseReport(
		raw,
		activationcanary.MaxTerminalResultBytes,
		submission.RunID,
	)
	if err != nil || report.Status != taskprotocol.StatusCompleted ||
		status.ObservedStatus != taskprotocol.StatusCompleted {
		return nil, errors.New("Gateway terminal canary observation is not a completed task")
	}
	return raw, nil
}

func (d *dispatcher) appendActivationCheckpoint(
	ctx context.Context,
	runtimeRef string,
	checkpoint activationCheckpointRequest,
) error {
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		return uncertainEffectError{cause: err}
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://executor.local/v1/workloads/"+runtimeRef+"/activation-checkpoints",
		bytes.NewReader(raw),
	)
	if err != nil {
		return uncertainEffectError{cause: err}
	}
	request.Header.Set("Authorization", "Bearer "+d.token)
	request.Header.Set("Content-Type", "application/json")
	response := newLocalResponse(maxActivationCheckpointResponseBytes)
	d.handler.ServeHTTP(response, request)
	if response.overflow {
		return uncertainEffectError{cause: errLocalResponseLimit}
	}
	if response.status != http.StatusCreated {
		return uncertainEffectError{cause: fmt.Errorf(
			"local executor returned HTTP %d while appending the activation checkpoint: %s",
			response.status,
			bytes.TrimSpace(response.body.Bytes()),
		)}
	}
	var echoed activationCheckpointRequest
	if err := dsse.DecodeStrictInto(
		response.body.Bytes(),
		maxActivationCheckpointResponseBytes,
		&echoed,
	); err != nil || echoed != checkpoint {
		return uncertainEffectError{
			cause: errors.New("local executor activation checkpoint acknowledgement is invalid"),
		}
	}
	return nil
}

func projectActivationCanaryResult(
	result activationcanary.ResultV1,
) (*controlprotocol.ExecutorActivationCanaryResultV1, error) {
	projection := controlprotocol.ExecutorActivationCanaryResultV1{
		SchemaVersion:              result.SchemaVersion,
		ActivationID:               result.ActivationID,
		AdmissionDigest:            result.AdmissionDigest,
		TaskDigest:                 result.TaskDigest,
		PermitDigest:               result.PermitDigest,
		RunID:                      result.RunID,
		TerminalResultDigest:       result.TerminalResultDigest,
		TerminalResultBytes:        result.TerminalResultBytes,
		TerminalResultBase64:       result.TerminalResultBase64,
		GatewayEvidenceBase64:      result.GatewayEvidenceBase64,
		ActivationCheckpointDigest: result.ActivationCheckpointDigest,
		Qualified:                  result.Qualified,
	}
	if err := projection.Validate(); err != nil {
		return nil, err
	}
	return &projection, nil
}

func executorAdmissionProjection(
	local executorAdmissionResponse,
) controlprotocol.ExecutorAdmissionProjectionV1 {
	return controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion:         controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:            local.RuntimeRef,
		Status:                local.Status,
		CapsuleDigest:         local.CapsuleDigest,
		PolicyDigest:          local.PolicyDigest,
		Generation:            local.Generation,
		EvidenceKeyID:         local.EvidenceKeyID,
		GrantID:               local.GrantID,
		ServicePath:           local.ServicePath,
		ServiceID:             local.ServiceID,
		TaskAuthorities:       append([]controlprotocol.ExecutorTaskAuthorityV1(nil), local.TaskAuthorities...),
		EgressProxy:           local.EgressProxy,
		EgressRouteIDs:        append([]string(nil), local.EgressRouteIDs...),
		ConnectorURL:          local.ConnectorURL,
		ConnectorIDs:          append([]string(nil), local.ConnectorIDs...),
		EventURL:              local.EventURL,
		RoutePolicyDigest:     local.RoutePolicyDigest,
		ActivationID:          local.ActivationID,
		ActivationBeginDigest: local.ActivationBeginDigest,
	}
}

func validActivationCanaryRunID(value string) bool {
	if len(value) != len("run_")+32 || value[:len("run_")] != "run_" {
		return false
	}
	for _, character := range value[len("run_"):] {
		if character < '0' || character > '9' && character < 'a' ||
			character > 'f' {
			return false
		}
	}
	return true
}

func (d *dispatcher) waitActivationCanary(
	ctx context.Context,
	duration time.Duration,
) error {
	if duration <= 0 {
		return errors.New("activation canary retry delay is invalid")
	}
	if d.wait != nil {
		return d.wait(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
