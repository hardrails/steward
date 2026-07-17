package executoruplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
	"github.com/hardrails/steward/internal/taskprotocol"
)

const nodeCanaryRunID = "run_0123456789abcdef0123456789abcdef"

type nodeCanaryFixture struct {
	now            time.Time
	command        activationcanary.CommandV1
	commandRaw     []byte
	verified       activationcanary.VerifiedCommandV1
	statement      taskpermit.Statement
	receiptPublic  ed25519.PublicKey
	receiptPrivate ed25519.PrivateKey
	terminal       []byte
	receipts       []byte
	submission     gateway.ControlTaskSubmission
	live           executorAdmissionResponse
	outer          command
	runtimeRef     string
}

type nodeCanaryGateway struct {
	submission gateway.ControlTaskSubmission
	status     gateway.TaskLifecycleStatus
	observed   gateway.TaskLifecycleStatus
	evidence   []byte

	submitErr  error
	statusErr  error
	observeErr error
	exportErr  error

	submitCalls  int
	statusCalls  int
	observeCalls int
	exportCalls  int

	grantID     string
	operationID string
	permit      string
	request     []byte
}

func (gatewayFixture *nodeCanaryGateway) SubmitTask(
	_ context.Context,
	grantID, operationID, permit string,
	request []byte,
) (gateway.ControlTaskSubmission, error) {
	gatewayFixture.submitCalls++
	gatewayFixture.grantID = grantID
	gatewayFixture.operationID = operationID
	gatewayFixture.permit = permit
	gatewayFixture.request = append([]byte(nil), request...)
	return gatewayFixture.submission, gatewayFixture.submitErr
}

func (gatewayFixture *nodeCanaryGateway) TaskStatus(
	_ context.Context,
	_, _ string,
) (gateway.TaskLifecycleStatus, error) {
	gatewayFixture.statusCalls++
	return gatewayFixture.status, gatewayFixture.statusErr
}

func (gatewayFixture *nodeCanaryGateway) ObserveTask(
	_ context.Context,
	_, _ string,
) (gateway.TaskLifecycleStatus, error) {
	gatewayFixture.observeCalls++
	return gatewayFixture.observed, gatewayFixture.observeErr
}

func (gatewayFixture *nodeCanaryGateway) ExportTaskEvidence(
	_ context.Context,
	_, _ string,
) ([]byte, error) {
	gatewayFixture.exportCalls++
	return append([]byte(nil), gatewayFixture.evidence...), gatewayFixture.exportErr
}

func (gatewayFixture *nodeCanaryGateway) totalCalls() int {
	return gatewayFixture.submitCalls + gatewayFixture.statusCalls +
		gatewayFixture.observeCalls + gatewayFixture.exportCalls
}

type nodeCanaryLocalHandler struct {
	t               *testing.T
	live            executorAdmissionResponse
	checkpointMode  string
	preflightStatus int
	preflightCalls  int
	postCalls       int
	checkpoint      activationCheckpointRequest
}

func (handler *nodeCanaryLocalHandler) ServeHTTP(
	w http.ResponseWriter,
	request *http.Request,
) {
	handler.t.Helper()
	if request.Header.Get("Authorization") != "Bearer local-token" {
		handler.t.Errorf("local Authorization = %q", request.Header.Get("Authorization"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expectedPath := "/v1/workloads/" + handler.live.RuntimeRef
	switch {
	case request.Method == http.MethodPost &&
		request.URL.Path == expectedPath+"/activation-canary-preflight":
		handler.preflightCalls++
		if handler.preflightStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(handler.preflightStatus)
			_, _ = w.Write([]byte(`{"error":"preflight_denied","message":"preflight denied for test"}`))
			return
		}
		var preflight activationCanaryPreflightRequest
		if err := json.NewDecoder(request.Body).Decode(&preflight); err != nil ||
			preflight.SchemaVersion != activationCanaryPreflightRequestSchema ||
			preflight.ActivationID != handler.live.ActivationID ||
			preflight.ActivationBeginDigest !=
				handler.live.ActivationBeginDigest {
			handler.t.Errorf("activation canary preflight = %#v err=%v", preflight, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(nodeCanaryJSON(handler.t, handler.live))
	case request.Method == http.MethodPost &&
		request.URL.Path == expectedPath+"/activation-checkpoints":
		handler.postCalls++
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			handler.t.Errorf("read activation checkpoint: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := dsse.DecodeStrictInto(
			raw,
			maxActivationCheckpointResponseBytes,
			&handler.checkpoint,
		); err != nil {
			handler.t.Errorf("decode activation checkpoint: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if handler.checkpointMode == "service-unavailable" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"checkpoint unavailable"}`))
			return
		}
		echoed := handler.checkpoint
		if handler.checkpointMode == "wrong-acknowledgement" {
			echoed.CheckpointDigest = "sha256:" + strings.Repeat("0", 64)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(nodeCanaryJSON(handler.t, echoed))
	default:
		handler.t.Errorf("unexpected local request %s %s", request.Method, request.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestNodeActivationCanaryCompletesProofCarryingReport(t *testing.T) {
	fixture := newNodeCanaryFixture(t)
	handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
	gatewayFixture := newNodeCanaryGateway(fixture)
	dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

	local := dispatch.execute(context.Background(), fixture.outer)
	if local.Status != controlprotocol.ExecutorStatusDone ||
		local.ReportedStatus != "running" || local.effectUncertain ||
		local.Result["runtime_ref"] != fixture.runtimeRef ||
		local.activationCanary == nil {
		t.Fatalf("local canary report = %#v", local)
	}
	if handler.preflightCalls != 1 || handler.postCalls != 1 ||
		gatewayFixture.submitCalls != 1 || gatewayFixture.statusCalls != 1 ||
		gatewayFixture.observeCalls != 1 || gatewayFixture.exportCalls != 1 {
		t.Fatalf(
			"local calls=get:%d checkpoint:%d Gateway calls=submit:%d status:%d observe:%d export:%d",
			handler.preflightCalls,
			handler.postCalls,
			gatewayFixture.submitCalls,
			gatewayFixture.statusCalls,
			gatewayFixture.observeCalls,
			gatewayFixture.exportCalls,
		)
	}
	if gatewayFixture.grantID != fixture.command.GrantID ||
		gatewayFixture.operationID != agentrelease.HermesOperationID ||
		gatewayFixture.permit != fixture.command.TaskPermit ||
		!bytes.Equal(gatewayFixture.request, fixture.verified.Request()) {
		t.Fatal("Gateway submission did not preserve the verified closed canary request")
	}
	if handler.checkpoint.SchemaVersion != activationCheckpointRequestSchema ||
		handler.checkpoint.ActivationID != fixture.command.ActivationID ||
		handler.checkpoint.CheckpointDigest !=
			local.activationCanary.ActivationCheckpointDigest {
		t.Fatalf("checkpoint request = %#v", handler.checkpoint)
	}

	projectionRaw := nodeCanaryJSON(t, local.activationCanary)
	verifiedResult, err := activationcanary.VerifyResultV1(
		fixture.verified,
		projectionRaw,
		fixture.receiptPublic,
	)
	if err != nil {
		t.Fatalf("verify projected canary result: %v", err)
	}
	verifiedEvidence, err := activationcanary.VerifyEvidenceV1(
		fixture.verified,
		nodeCanaryRunID,
		fixture.terminal,
		fixture.receipts,
		fixture.receiptPublic,
	)
	if err != nil {
		t.Fatalf("verify fixture evidence: %v", err)
	}
	checkpointRaw, err := activationcanary.BuildCheckpointV1(
		fixture.verified,
		verifiedEvidence,
	)
	if err != nil {
		t.Fatalf("build expected checkpoint: %v", err)
	}
	if err := activationcanary.VerifyCheckpointV1(
		fixture.verified,
		verifiedResult,
		checkpointRaw,
	); err != nil {
		t.Fatalf("verify checkpoint joined to projected result: %v", err)
	}
	if dsse.Digest(checkpointRaw) != handler.checkpoint.CheckpointDigest {
		t.Fatal("Executor checkpoint request did not identify the qualified proof")
	}

	delivery := nodeCanaryDelivery(fixture)
	wire := makeReportV4(delivery, local, "activation-canary")
	if err := wire.Validate(); err != nil {
		t.Fatalf("validate protocol-4 canary report: %v", err)
	}
	if wire.Status != controlprotocol.ExecutorStatusDone ||
		wire.ReportedStatus != "running" || wire.Result.ActivationCanary == nil ||
		!reflect.DeepEqual(wire.Result.ActivationCanary, local.activationCanary) {
		t.Fatalf("protocol-4 canary report = %#v", wire)
	}

	legacyRaw := nodeCanaryJSON(t, local)
	if bytes.Contains(legacyRaw, []byte("activation_canary")) ||
		bytes.Contains(legacyRaw, []byte(local.activationCanary.TerminalResultBase64)) ||
		bytes.Contains(legacyRaw, []byte(local.activationCanary.GatewayEvidenceBase64)) {
		t.Fatalf("legacy report leaked protocol-4 canary evidence: %s", legacyRaw)
	}
	original := *local.activationCanary
	wire.Result.ActivationCanary.ActivationID = "mutated-wire"
	if *local.activationCanary != original {
		t.Fatal("wire report aliases the dispatcher's retained canary projection")
	}
	wire = makeReportV4(delivery, local, "activation-canary")
	local.activationCanary.ActivationID = "mutated-local"
	if wire.Result.ActivationCanary.ActivationID != original.ActivationID {
		t.Fatal("dispatcher's retained projection aliases the wire report")
	}
	local.activationCanary = &original
	if leaked := makeReportV4(delivery, local, "read"); leaked.Result.ActivationCanary != nil {
		t.Fatal("activation canary projection escaped a different command kind")
	}
}

func TestNodeActivationCanaryDoesNotContactGatewayBeforeValidation(t *testing.T) {
	for _, test := range []struct {
		name              string
		mutate            func(*nodeCanaryFixture, *nodeCanaryLocalHandler)
		wantPreflightCall int
	}{
		{
			name: "noncanonical command",
			mutate: func(fixture *nodeCanaryFixture, _ *nodeCanaryLocalHandler) {
				fixture.outer.Payload = append(
					append([]byte(nil), fixture.outer.Payload...),
					' ',
				)
			},
		},
		{
			name: "stale lifecycle fence",
			mutate: func(fixture *nodeCanaryFixture, _ *nodeCanaryLocalHandler) {
				fixture.outer.CommandSequence = 4
			},
		},
		{
			name: "live workload drift",
			mutate: func(_ *nodeCanaryFixture, handler *nodeCanaryLocalHandler) {
				handler.live.CapsuleDigest = dsse.Digest([]byte("drifted capsule"))
			},
			wantPreflightCall: 1,
		},
		{
			name: "current policy denied",
			mutate: func(_ *nodeCanaryFixture, handler *nodeCanaryLocalHandler) {
				handler.preflightStatus = http.StatusForbidden
			},
			wantPreflightCall: 1,
		},
		{
			name: "reconciliation degraded",
			mutate: func(_ *nodeCanaryFixture, handler *nodeCanaryLocalHandler) {
				handler.preflightStatus = http.StatusServiceUnavailable
			},
			wantPreflightCall: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeCanaryFixture(t)
			handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
			test.mutate(&fixture, handler)
			gatewayFixture := newNodeCanaryGateway(fixture)
			dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

			local := dispatch.execute(context.Background(), fixture.outer)
			if local.Status != controlprotocol.ExecutorStatusFailed ||
				local.effectUncertain || local.activationCanary != nil {
				t.Fatalf("pre-effect report = %#v", local)
			}
			if gatewayFixture.totalCalls() != 0 {
				t.Fatalf("Gateway was contacted %d times", gatewayFixture.totalCalls())
			}
			if handler.preflightCalls != test.wantPreflightCall ||
				handler.postCalls != 0 {
				t.Fatalf(
					"local calls=preflight:%d checkpoint:%d",
					handler.preflightCalls,
					handler.postCalls,
				)
			}
			wire := makeReportV4(
				nodeCanaryDelivery(fixture),
				local,
				"activation-canary",
			)
			if wire.Status != controlprotocol.ExecutorStatusRejected ||
				wire.ErrorCode != "executor_command_rejected" ||
				wire.Result.ActivationCanary != nil {
				t.Fatalf("wire pre-effect report = %#v", wire)
			}
		})
	}
}

func TestNodeActivationCanaryReceiptAuthoritySubstitutionIsUncertain(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*gateway.ControlTaskSubmission)
	}{
		{
			name: "public key",
			mutate: func(submission *gateway.ControlTaskSubmission) {
				otherPublic, _ := nodeCanaryKey(t)
				submission.ReceiptPublicKey = base64.StdEncoding.EncodeToString(otherPublic)
			},
		},
		{
			name: "node identity",
			mutate: func(submission *gateway.ControlTaskSubmission) {
				submission.ReceiptNodeID = "node-other/gateway"
			},
		},
		{
			name: "epoch",
			mutate: func(submission *gateway.ControlTaskSubmission) {
				submission.ReceiptEpoch++
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeCanaryFixture(t)
			handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
			gatewayFixture := newNodeCanaryGateway(fixture)
			test.mutate(&gatewayFixture.submission)
			dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

			local := dispatch.execute(context.Background(), fixture.outer)
			if local.Status != controlprotocol.ExecutorStatusFailed ||
				!local.effectUncertain || local.activationCanary != nil {
				t.Fatalf("substituted receipt report = %#v", local)
			}
			if gatewayFixture.submitCalls != 1 || gatewayFixture.statusCalls != 0 ||
				gatewayFixture.observeCalls != 0 || gatewayFixture.exportCalls != 0 ||
				handler.postCalls != 0 {
				t.Fatalf(
					"calls=submit:%d status:%d observe:%d export:%d checkpoint:%d",
					gatewayFixture.submitCalls,
					gatewayFixture.statusCalls,
					gatewayFixture.observeCalls,
					gatewayFixture.exportCalls,
					handler.postCalls,
				)
			}
			wire := makeReportV4(
				nodeCanaryDelivery(fixture),
				local,
				"activation-canary",
			)
			if wire.Status != controlprotocol.ExecutorStatusOutcomeUnknown ||
				wire.ErrorCode != "outcome_unknown" ||
				wire.Result.ActivationCanary != nil {
				t.Fatalf("wire substituted receipt report = %#v", wire)
			}
		})
	}
}

func TestNodeActivationCanaryKnownTerminalFailureIsReported(t *testing.T) {
	for _, taskStatus := range []connectorledger.TaskStatus{
		connectorledger.TaskStatusAgentReportedFailed,
		connectorledger.TaskStatusAgentReportedCancelled,
	} {
		t.Run(string(taskStatus), func(t *testing.T) {
			fixture := newNodeCanaryFixture(t)
			handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
			gatewayFixture := newNodeCanaryGateway(fixture)
			gatewayFixture.status = nodeCanaryTerminalStatus(
				fixture,
				taskStatus,
			)
			dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

			local := dispatch.execute(context.Background(), fixture.outer)
			if local.Status != controlprotocol.ExecutorStatusFailed ||
				local.effectUncertain || local.activationCanary != nil {
				t.Fatalf("known terminal report = %#v", local)
			}
			if gatewayFixture.submitCalls != 1 || gatewayFixture.statusCalls != 1 ||
				gatewayFixture.observeCalls != 0 || gatewayFixture.exportCalls != 0 ||
				handler.postCalls != 0 {
				t.Fatalf(
					"calls=submit:%d status:%d observe:%d export:%d checkpoint:%d",
					gatewayFixture.submitCalls,
					gatewayFixture.statusCalls,
					gatewayFixture.observeCalls,
					gatewayFixture.exportCalls,
					handler.postCalls,
				)
			}
			wire := makeReportV4(
				nodeCanaryDelivery(fixture),
				local,
				"activation-canary",
			)
			expectedCode := "activation_canary_failed"
			expectedReportedStatus := "failed"
			if taskStatus == connectorledger.TaskStatusAgentReportedCancelled {
				expectedCode = "activation_canary_cancelled"
				expectedReportedStatus = "cancelled"
			}
			if wire.Status != controlprotocol.ExecutorStatusFailed ||
				wire.ErrorCode != expectedCode ||
				wire.ReportedStatus != expectedReportedStatus ||
				wire.Result.ActivationCanary != nil {
				t.Fatalf("wire known terminal report = %#v", wire)
			}
		})
	}
}

func TestNodeActivationCanaryAmbiguousTerminalIsOutcomeUnknown(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(nodeCanaryFixture, *nodeCanaryGateway)
	}{
		{
			name: "observation failed after dispatch",
			mutate: func(
				fixture nodeCanaryFixture,
				gatewayFixture *nodeCanaryGateway,
			) {
				gatewayFixture.status = gateway.TaskLifecycleStatus{
					SchemaVersion: gateway.TaskStatusSchemaV1,
					TaskDigest:    fixture.submission.TaskDigest,
					PermitDigest:  fixture.submission.PermitDigest,
					Phase:         connectorledger.Terminal,
					State:         gateway.TaskStateObservationFailed,
					RunID:         fixture.submission.RunID,
					ErrorCode:     "outcome_unknown",
					RetrySafety:   gateway.TaskRetryReplacementUnsafe,
				}
			},
		},
		{
			name: "completed without retrievable observation",
			mutate: func(
				_ nodeCanaryFixture,
				gatewayFixture *nodeCanaryGateway,
			) {
				gatewayFixture.observed.ObservationBase64 = ""
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNodeCanaryFixture(t)
			handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
			gatewayFixture := newNodeCanaryGateway(fixture)
			test.mutate(fixture, gatewayFixture)
			dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

			local := dispatch.execute(context.Background(), fixture.outer)
			if local.Status != controlprotocol.ExecutorStatusFailed ||
				!local.effectUncertain || local.activationCanary != nil {
				t.Fatalf("ambiguous terminal report = %#v", local)
			}
			if gatewayFixture.submitCalls != 1 ||
				gatewayFixture.statusCalls != 1 ||
				gatewayFixture.exportCalls != 0 ||
				handler.postCalls != 0 {
				t.Fatalf(
					"calls=submit:%d status:%d observe:%d export:%d checkpoint:%d",
					gatewayFixture.submitCalls,
					gatewayFixture.statusCalls,
					gatewayFixture.observeCalls,
					gatewayFixture.exportCalls,
					handler.postCalls,
				)
			}
			if test.name == "observation failed after dispatch" &&
				gatewayFixture.observeCalls != 0 {
				t.Fatalf(
					"ambiguous terminal was observed again %d times",
					gatewayFixture.observeCalls,
				)
			}
			if test.name == "completed without retrievable observation" &&
				gatewayFixture.observeCalls != 1 {
				t.Fatalf(
					"missing terminal observation was retried %d times",
					gatewayFixture.observeCalls,
				)
			}
			wire := makeReportV4(
				nodeCanaryDelivery(fixture),
				local,
				"activation-canary",
			)
			if wire.Status != controlprotocol.ExecutorStatusOutcomeUnknown ||
				wire.ErrorCode != "outcome_unknown" ||
				wire.Result.ActivationCanary != nil {
				t.Fatalf("wire ambiguous terminal report = %#v", wire)
			}
		})
	}
}

func TestNodeActivationCanaryCheckpointAcknowledgementIsUncertain(t *testing.T) {
	for _, mode := range []string{"wrong-acknowledgement", "service-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newNodeCanaryFixture(t)
			handler := &nodeCanaryLocalHandler{
				t:              t,
				live:           fixture.live,
				checkpointMode: mode,
			}
			gatewayFixture := newNodeCanaryGateway(fixture)
			dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)

			local := dispatch.execute(context.Background(), fixture.outer)
			if local.Status != controlprotocol.ExecutorStatusFailed ||
				!local.effectUncertain || local.activationCanary != nil {
				t.Fatalf("ambiguous checkpoint report = %#v", local)
			}
			if handler.postCalls != 1 || gatewayFixture.exportCalls != 1 ||
				!controlprotocol.ValidSHA256Digest(handler.checkpoint.CheckpointDigest) {
				t.Fatalf(
					"checkpoint=%#v calls=%d export=%d",
					handler.checkpoint,
					handler.postCalls,
					gatewayFixture.exportCalls,
				)
			}
			wire := makeReportV4(
				nodeCanaryDelivery(fixture),
				local,
				"activation-canary",
			)
			if wire.Status != controlprotocol.ExecutorStatusOutcomeUnknown ||
				wire.ErrorCode != "outcome_unknown" ||
				wire.Result.ActivationCanary != nil {
				t.Fatalf("wire ambiguous checkpoint report = %#v", wire)
			}
		})
	}
}

func newNodeCanaryFixture(t *testing.T) nodeCanaryFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	activationID := "activation-001"
	request, err := agentrelease.BuildCanaryRequest(
		agentrelease.RequestRecipe{
			Input:           agentrelease.HermesWorkspaceAuditInput,
			SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
		},
		activationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	taskPublic, taskPrivate := nodeCanaryKey(t)
	receiptPublic, receiptPrivate := nodeCanaryKey(t)
	runtimeRef := executor.RuntimeRef("tenant-a", "hermes-a")
	statement := taskpermit.Statement{
		SchemaVersion:         taskpermit.SchemaV1,
		NodeID:                "node-a",
		TenantID:              "tenant-a",
		InstanceID:            "hermes-a",
		RuntimeRef:            runtimeRef,
		GrantID:               gateway.GrantID("tenant-a", "hermes-a", 7),
		Generation:            7,
		CapsuleDigest:         dsse.Digest([]byte("capsule")),
		PolicyDigest:          dsse.Digest([]byte("policy")),
		RoutePolicyDigest:     dsse.Digest([]byte("route")),
		ServiceID:             agentrelease.HermesServiceID,
		OperationID:           agentrelease.HermesOperationID,
		OperationPolicyDigest: dsse.Digest([]byte("operation")),
		TaskID:                "activation-task",
		RequestDigest:         taskpermit.RequestDigest(request),
		RequestBytes:          int64(len(request)),
		ContentType:           "application/json",
		NotBefore:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:             now.Add(5 * time.Minute).Format(time.RFC3339),
	}
	binding := activation.BindingV1{
		ActivationID:  activationID,
		PlanDigest:    dsse.Digest([]byte("plan")),
		ReleaseDigest: dsse.Digest([]byte("release")),
		PolicyDigest:  statement.PolicyDigest,
		IntentDigest:  dsse.Digest([]byte("intent")),
		Archive: activation.ArchiveV1{
			Digest: dsse.Digest([]byte("archive")),
			Bytes:  1024,
		},
		TenantID:   statement.TenantID,
		NodeID:     statement.NodeID,
		InstanceID: statement.InstanceID,
		Generation: statement.Generation,
	}
	beginRaw, err := activation.MarshalExecutorBeginV1(
		binding,
		runtimeRef,
		"steward-state-"+strings.Repeat("b", 64),
		statement.CapsuleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    runtimeRef,
		Status:        "created",
		CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest:  statement.PolicyDigest,
		Generation:    statement.Generation,
		EvidenceKeyID: strings.Repeat("a", 32),
		GrantID:       statement.GrantID,
		ServicePath:   "/v1/services/" + statement.GrantID + "/",
		ServiceID:     statement.ServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID:     "tenant-task",
			PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest:     statement.RoutePolicyDigest,
		ActivationID:          activationID,
		ActivationBeginDigest: dsse.Digest(beginRaw),
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("validate admission projection: %v", err)
	}
	projectionRaw := nodeCanaryJSON(t, projection)
	commandValue := activationcanary.CommandV1{
		SchemaVersion:       activationcanary.CommandSchemaV1,
		ActivationID:        activationID,
		AdmissionDigest:     dsse.Digest(projectionRaw),
		Admission:           projection,
		ExecutorBeginBase64: base64.StdEncoding.EncodeToString(beginRaw),
		GrantID:             statement.GrantID,
		OperationID:         statement.OperationID,
		TaskPermit: nodeCanaryTaskPermit(
			t,
			statement,
			"tenant-task",
			taskPrivate,
		),
		RequestBase64: base64.StdEncoding.EncodeToString(request),
		Deadline:      now.Add(4 * time.Minute).Format(time.RFC3339Nano),
		ReceiptAuthority: activationcanary.ReceiptAuthorityV1{
			NodeID:          gateway.ServiceTaskReceiptNodeID(statement.NodeID),
			Epoch:           7,
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
		},
	}
	commandRaw, err := activationcanary.MarshalCommandV1(commandValue)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := activationcanary.VerifyCommandV1(
		commandRaw,
		activationcanary.AdmissionContextV1{
			NodeID:     statement.NodeID,
			TenantID:   statement.TenantID,
			InstanceID: statement.InstanceID,
			Projection: projection,
		},
		now,
		taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	terminal := nodeCanaryTerminal(t, activationID)
	fixture := nodeCanaryFixture{
		now:            now,
		command:        commandValue,
		commandRaw:     commandRaw,
		verified:       verified,
		statement:      statement,
		receiptPublic:  receiptPublic,
		receiptPrivate: receiptPrivate,
		terminal:       terminal,
		runtimeRef:     runtimeRef,
		live: executorAdmissionResponse{
			RuntimeRef:            projection.RuntimeRef,
			Status:                "running",
			CapsuleDigest:         projection.CapsuleDigest,
			PolicyDigest:          projection.PolicyDigest,
			Generation:            projection.Generation,
			EvidenceKeyID:         projection.EvidenceKeyID,
			GrantID:               projection.GrantID,
			ServicePath:           projection.ServicePath,
			ServiceID:             projection.ServiceID,
			TaskAuthorities:       append([]controlprotocol.ExecutorTaskAuthorityV1(nil), projection.TaskAuthorities...),
			RoutePolicyDigest:     projection.RoutePolicyDigest,
			ActivationID:          projection.ActivationID,
			ActivationBeginDigest: projection.ActivationBeginDigest,
		},
	}
	fixture.receipts = nodeCanaryGatewayReceipts(t, fixture)
	fixture.submission = gateway.ControlTaskSubmission{
		SchemaVersion:    gateway.ControlTaskSubmissionSchemaV1,
		TaskDigest:       taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		PermitDigest:     verified.Permit().EnvelopeDigest,
		RunID:            nodeCanaryRunID,
		ReceiptNodeID:    commandValue.ReceiptAuthority.NodeID,
		ReceiptEpoch:     commandValue.ReceiptAuthority.Epoch,
		ReceiptPublicKey: base64.StdEncoding.EncodeToString(receiptPublic),
	}
	outerRuntimeRef, err := RuntimeRefV2(
		statement.TenantID,
		statement.NodeID,
		statement.InstanceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.outer = command{
		CommandID:          "activation-canary-command",
		TenantID:           statement.TenantID,
		NodeID:             statement.NodeID,
		InstanceID:         statement.InstanceID,
		RuntimeRef:         outerRuntimeRef,
		Kind:               "activation-canary",
		Payload:            append([]byte(nil), commandRaw...),
		ClaimGeneration:    3,
		InstanceGeneration: statement.Generation,
		CommandSequence:    5,
		signed:             true,
	}
	return fixture
}

func newNodeCanaryGateway(fixture nodeCanaryFixture) *nodeCanaryGateway {
	dispatchStatus := gateway.TaskLifecycleStatus{
		SchemaVersion:  gateway.TaskStatusSchemaV1,
		TaskDigest:     fixture.submission.TaskDigest,
		PermitDigest:   fixture.submission.PermitDigest,
		Phase:          connectorledger.Dispatch,
		State:          gateway.TaskStateDispatchAccepted,
		RunID:          fixture.submission.RunID,
		ObservedStatus: taskprotocol.StatusRunning,
	}
	terminalStatus := gateway.TaskLifecycleStatus{
		SchemaVersion:     gateway.TaskStatusSchemaV1,
		TaskDigest:        fixture.submission.TaskDigest,
		PermitDigest:      fixture.submission.PermitDigest,
		Phase:             connectorledger.Terminal,
		State:             string(connectorledger.TaskStatusAgentReportedCompleted),
		RunID:             fixture.submission.RunID,
		TaskStatus:        connectorledger.TaskStatusAgentReportedCompleted,
		ResultDigest:      dsse.Digest(fixture.terminal),
		ResponseBytes:     int64(len(fixture.terminal)),
		ObservedStatus:    taskprotocol.StatusCompleted,
		ObservationBase64: base64.StdEncoding.EncodeToString(fixture.terminal),
	}
	return &nodeCanaryGateway{
		submission: fixture.submission,
		status:     dispatchStatus,
		observed:   terminalStatus,
		evidence:   append([]byte(nil), fixture.receipts...),
	}
}

func newNodeCanaryDispatcher(
	t *testing.T,
	fixture nodeCanaryFixture,
	handler *nodeCanaryLocalHandler,
	gatewayFixture *nodeCanaryGateway,
) dispatcher {
	t.Helper()
	state := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := state.advance(
		fixture.statement.TenantID,
		fixture.statement.InstanceID,
		position{
			ClaimGeneration: fixture.outer.ClaimGeneration,
			Generation:      fixture.outer.InstanceGeneration,
			Sequence:        4,
			ReportedStatus:  "running",
		},
	); err != nil {
		t.Fatal(err)
	}
	return dispatcher{
		handler:           handler,
		token:             "local-token",
		nodeID:            fixture.statement.NodeID,
		nodeScoped:        true,
		projectAdmission:  true,
		activationGateway: gatewayFixture,
		now:               func() time.Time { return fixture.now },
		wait: func(context.Context, time.Duration) error {
			return nil
		},
		state: state,
	}
}

func nodeCanaryTerminalStatus(
	fixture nodeCanaryFixture,
	status connectorledger.TaskStatus,
) gateway.TaskLifecycleStatus {
	observed := taskprotocol.StatusFailed
	if status == connectorledger.TaskStatusAgentReportedCancelled {
		observed = taskprotocol.StatusCancelled
	}
	result := []byte("terminal " + status)
	return gateway.TaskLifecycleStatus{
		SchemaVersion:  gateway.TaskStatusSchemaV1,
		TaskDigest:     fixture.submission.TaskDigest,
		PermitDigest:   fixture.submission.PermitDigest,
		Phase:          connectorledger.Terminal,
		State:          string(status),
		RunID:          fixture.submission.RunID,
		TaskStatus:     status,
		ResultDigest:   dsse.Digest(result),
		ResponseBytes:  int64(len(result)),
		ObservedStatus: observed,
	}
}

func nodeCanaryGatewayReceipts(
	t *testing.T,
	fixture nodeCanaryFixture,
) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(
		path,
		fixture.receiptPrivate,
		fixture.command.ReceiptAuthority.NodeID,
		fixture.command.ReceiptAuthority.Epoch,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement := fixture.statement
	taskDigest := taskpermit.TaskDigest(
		statement.TenantID,
		statement.InstanceID,
		statement.TaskID,
	)
	authorize := connectorledger.Event{
		Phase:                 connectorledger.Authorize,
		Outcome:               connectorledger.Allowed,
		Kind:                  connectorledger.ServiceTask,
		TenantID:              statement.TenantID,
		RuntimeRef:            statement.RuntimeRef,
		CapsuleDigest:         statement.CapsuleDigest,
		PolicyDigest:          statement.PolicyDigest,
		RoutePolicyDigest:     statement.RoutePolicyDigest,
		Generation:            statement.Generation,
		GrantID:               statement.GrantID,
		ServiceID:             statement.ServiceID,
		OperationID:           statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest:            taskDigest,
		AuthorityKeyID:        fixture.verified.Permit().KeyID,
		PermitDigest:          fixture.verified.Permit().EnvelopeDigest,
		RequestDigest:         statement.RequestDigest,
		RequestBytes:          statement.RequestBytes,
		TaskProtocol:          connectorledger.TaskProtocolLifecycleV1,
	}
	if _, err := log.Begin(authorize); err != nil {
		t.Fatal(err)
	}
	dispatched := authorize
	dispatched.Phase = connectorledger.Dispatch
	dispatched.Outcome = connectorledger.Responded
	dispatched.HTTPStatus = http.StatusAccepted
	dispatched.ResponseBytes = 96
	dispatched.RunID = nodeCanaryRunID
	if _, err := log.Dispatch(dispatched); err != nil {
		t.Fatal(err)
	}
	terminal := dispatched
	terminal.Phase = connectorledger.Terminal
	terminal.Outcome = connectorledger.Responded
	terminal.HTTPStatus = http.StatusOK
	terminal.ResponseBytes = int64(len(fixture.terminal))
	terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	terminal.ResultDigest = dsse.Digest(fixture.terminal)
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var selected []connectorledger.VerifiedReceipt
	if _, err := connectorledger.VerifyRecords(
		path,
		fixture.receiptPublic,
		fixture.command.ReceiptAuthority.NodeID,
		fixture.command.ReceiptAuthority.Epoch,
		func(record connectorledger.VerifiedReceipt) error {
			if record.Receipt.Event.TaskDigest == taskDigest {
				selected = append(selected, record)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	receipts, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	return receipts
}

func nodeCanaryTerminal(t *testing.T, activationID string) []byte {
	t.Helper()
	workspace := struct {
		Entries        []any  `json:"entries"`
		FileCount      int    `json:"file_count"`
		ManifestDigest string `json:"manifest_digest"`
		Root           string `json:"root"`
		SchemaVersion  string `json:"schema_version"`
		TotalBytes     int64  `json:"total_bytes"`
	}{
		Entries:        []any{},
		ManifestDigest: agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
		Root:           activation.HermesWorkspaceRoot,
		SchemaVersion:  activation.HermesWorkspaceSchemaV1,
	}
	workspaceRaw := nodeCanaryJSON(t, workspace)
	terminal := struct {
		Object    string `json:"object"`
		RunID     string `json:"run_id"`
		Status    string `json:"status"`
		UpdatedAt int64  `json:"updated_at"`
		CreatedAt int64  `json:"created_at"`
		SessionID string `json:"session_id"`
		Model     string `json:"model"`
		Output    string `json:"output"`
		Usage     struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
		LastEvent string `json:"last_event"`
	}{
		Object:    activation.HermesRunObject,
		RunID:     nodeCanaryRunID,
		Status:    activation.HermesCompletedStatus,
		UpdatedAt: 2,
		CreatedAt: 1,
		SessionID: agentrelease.HermesSessionIDPrefix + "-" + activationID,
		Model:     "steward-fixture-model",
		Output:    string(workspaceRaw),
		LastEvent: activation.HermesCompletedEvent,
	}
	terminal.Usage.InputTokens = 2
	terminal.Usage.OutputTokens = 1
	terminal.Usage.TotalTokens = 3
	return nodeCanaryJSON(t, terminal)
}

func nodeCanaryTaskPermit(
	t *testing.T,
	statement taskpermit.Statement,
	keyID string,
	private ed25519.PrivateKey,
) string {
	t.Helper()
	envelope, err := dsse.Sign(
		taskpermit.PayloadType,
		nodeCanaryJSON(t, statement),
		keyID,
		private,
	)
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

func nodeCanaryKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func nodeCanaryDelivery(
	fixture nodeCanaryFixture,
) controlprotocol.ExecutorDeliveryV4 {
	return controlprotocol.ExecutorDeliveryV4{
		DeliveryID:         "activation-canary-delivery",
		DeliveryGeneration: 1,
		CommandID:          fixture.outer.CommandID,
		CommandDigest:      dsse.Digest(fixture.commandRaw),
		CommandDSSEBase64:  base64.StdEncoding.EncodeToString([]byte("signed command")),
	}
}

func nodeCanaryJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var _ activationCanaryGateway = (*nodeCanaryGateway)(nil)
var _ http.Handler = (*nodeCanaryLocalHandler)(nil)
