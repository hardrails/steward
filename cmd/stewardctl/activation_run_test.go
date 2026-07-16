package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestPreflightActivationArchiveHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := preflightActivationArchive(
		ctx, verifiedActivationInputs{},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("preflight error=%v, want context canceled", err)
	}
}

func TestValidateActivationAdmissionRequiresExactAuthorityAndCapabilityResult(t *testing.T) {
	admitted, inputs, evidenceKeyID := activationAdmissionValidationFixture(t)
	if err := validateActivationAdmission(admitted, inputs, evidenceKeyID, false); err != nil {
		t.Fatalf("valid admission: %v", err)
	}

	tests := map[string]func(*permitAdmission, *verifiedActivationInputs, *string){
		"task authority widening": func(value *permitAdmission, _ *verifiedActivationInputs, _ *string) {
			value.TaskAuthorities = append(
				append([]gateway.TaskAuthority(nil), value.TaskAuthorities...),
				gateway.TaskAuthority{
					KeyID:     "unexpected-authority",
					PublicKey: value.TaskAuthorities[0].PublicKey,
				},
			)
		},
		"evidence key mismatch": func(_ *permitAdmission, _ *verifiedActivationInputs, expected *string) {
			*expected = digest('f')
		},
		"unrequested egress": func(value *permitAdmission, _ *verifiedActivationInputs, _ *string) {
			value.EgressProxy = "http://steward-relay:8082"
			value.EgressRouteIDs = []string{"route-a"}
		},
		"unrequested connector": func(value *permitAdmission, _ *verifiedActivationInputs, _ *string) {
			value.ConnectorURL = "http://steward-relay:8081"
			value.ConnectorIDs = []string{"connector-a"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := admitted
			candidate.TaskAuthorities = append(
				[]gateway.TaskAuthority(nil), admitted.TaskAuthorities...,
			)
			candidate.EgressRouteIDs = append([]string(nil), admitted.EgressRouteIDs...)
			candidate.ConnectorIDs = append([]string(nil), admitted.ConnectorIDs...)
			candidateInputs := inputs
			expected := evidenceKeyID
			mutate(&candidate, &candidateInputs, &expected)
			if err := validateActivationAdmission(
				candidate, candidateInputs, expected, false,
			); err == nil {
				t.Fatal("mutated Executor admission was accepted")
			}
		})
	}

	created := admitted
	created.Status = "created"
	if err := validateActivationAdmission(created, inputs, evidenceKeyID, true); err == nil {
		t.Fatal("created runtime was accepted as started")
	}
	running := admitted
	running.Status = "running"
	if err := validateActivationAdmission(running, inputs, evidenceKeyID, true); err != nil {
		t.Fatalf("running admission: %v", err)
	}
}

func TestValidateActivationNodeIdentityRequiresExactActivation(t *testing.T) {
	beginDigest := digest('a')
	valid := nodeclient.State{
		ActivationID:          "activation-test",
		ActivationBeginDigest: beginDigest,
	}
	if err := validateActivationNodeIdentity(
		valid, valid.ActivationID, beginDigest,
	); err != nil {
		t.Fatalf("valid identity: %v", err)
	}
	for name, mutate := range map[string]func(*nodeclient.State){
		"activation": func(state *nodeclient.State) {
			state.ActivationID = "activation-other"
		},
		"begin digest": func(state *nodeclient.State) {
			state.ActivationBeginDigest = digest('b')
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateActivationNodeIdentity(
				candidate, valid.ActivationID, beginDigest,
			); err == nil {
				t.Fatal("changed activation runtime identity was accepted")
			}
		})
	}
}

func TestRecoverActivationAdmissionStateRequiresExactPersistedIdentity(t *testing.T) {
	runtimeReference := "executor-" + strings.Repeat("a", 64)
	activationID := "activation-test"
	beginDigest := digest('a')
	for _, test := range []struct {
		name      string
		status    int
		body      string
		wantFound bool
		wantErr   bool
	}{
		{
			name:   "exact activation",
			status: http.StatusOK,
			body: fmt.Sprintf(
				`{"runtime_ref":%q,"status":"created","activation_id":%q,"activation_begin_digest":%q}`,
				runtimeReference, activationID, beginDigest,
			),
			wantFound: true,
		},
		{
			name:   "missing runtime",
			status: http.StatusNotFound,
			body:   `{"error":"not_found","message":"runtime does not exist"}`,
		},
		{
			name:   "different activation",
			status: http.StatusOK,
			body: fmt.Sprintf(
				`{"runtime_ref":%q,"status":"created","activation_id":"activation-other","activation_begin_digest":%q}`,
				runtimeReference, beginDigest,
			),
			wantFound: true,
			wantErr:   true,
		},
		{
			name:    "executor unavailable",
			status:  http.StatusServiceUnavailable,
			body:    `{"error":"reconciliation_required","message":"try later"}`,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				if request.Method != http.MethodGet ||
					request.URL.Path != "/v1/workloads/"+runtimeReference {
					t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client, err := nodeclient.New(server.URL, "activation-token")
			if err != nil {
				t.Fatal(err)
			}
			state, found, err := recoverActivationAdmissionState(
				context.Background(), client, runtimeReference,
				activationID, beginDigest,
			)
			if found != test.wantFound || (err != nil) != test.wantErr {
				t.Fatalf(
					"state=%#v found=%t err=%v, want found=%t err=%t",
					state, found, err, test.wantFound, test.wantErr,
				)
			}
		})
	}
}

func TestActivationAdmissionRecoveryAllowsOnlyAmbiguousTransportFailure(t *testing.T) {
	if !activationAdmissionRecoveryAllowed(
		context.Background(), errors.New("connection reset"),
	) {
		t.Fatal("ambiguous transport failure was not recoverable")
	}
	if activationAdmissionRecoveryAllowed(
		context.Background(),
		&nodeclient.APIError{
			Status:  http.StatusConflict,
			Code:    "workload_conflict",
			Message: "different activation",
		},
	) {
		t.Fatal("definitive Executor API rejection was treated as ambiguous")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if activationAdmissionRecoveryAllowed(ctx, errors.New("connection reset")) {
		t.Fatal("expired admission budget was extended for recovery")
	}
}

func TestActivationInputVerificationTimeUsesReleaseCheckpoint(t *testing.T) {
	initialAt := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	current := initialAt.Add(time.Hour)
	newChain := activationStateChain{
		states: []activation.StateV1{{
			Phase:     activation.PhaseNew,
			UpdatedAt: initialAt.Format(time.RFC3339Nano),
		}},
	}
	selected, err := activationInputVerificationTime(newChain, current)
	if err != nil || !selected.Equal(current) {
		t.Fatalf("new selected=%v err=%v", selected, err)
	}

	verifiedAt := initialAt.Add(time.Minute)
	resumed := activationStateChain{
		states: []activation.StateV1{
			newChain.states[0],
			{
				Phase:     activation.PhaseReleaseVerified,
				UpdatedAt: verifiedAt.Format(time.RFC3339Nano),
			},
			{
				Phase:     activation.PhasePassed,
				UpdatedAt: current.Format(time.RFC3339Nano),
			},
		},
	}
	selected, err = activationInputVerificationTime(
		resumed, current.Add(time.Hour),
	)
	if err != nil || !selected.Equal(verifiedAt) {
		t.Fatalf("resume selected=%v err=%v", selected, err)
	}
	if _, err := activationInputVerificationTime(
		resumed, initialAt,
	); err == nil {
		t.Fatal("future release_verified checkpoint was accepted")
	}
}

func TestEnsureActivationHandoffIsIdempotentAndBindsExactBytes(t *testing.T) {
	fixture := newActivationTaskFixture(t)
	intentRaw, err := json.Marshal(fixture.inputs.intent)
	if err != nil {
		t.Fatal(err)
	}
	fixture.inputs.intentRaw = intentRaw
	admissionRaw, err := json.Marshal(fixture.admitted)
	if err != nil {
		t.Fatal(err)
	}
	store := newActivationRunStore(t)

	requestRaw, challengeRaw, challenge, err := ensureActivationHandoff(
		store,
		fixture.inputs,
		fixture.admitted,
		admissionRaw,
		fixture.serviceTrustRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedRequest, err := agentrelease.BuildCanaryRequest(
		fixture.inputs.release.Release.Canary.Request,
		fixture.inputs.plan.ActivationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedAuthorities, err := activationTaskAuthorities(fixture.admitted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestRaw, expectedRequest) ||
		challenge.PlanDigest != dsse.Digest(fixture.inputs.planRaw) ||
		challenge.ReleaseDigest != fixture.inputs.release.EnvelopeDigest ||
		challenge.AdmissionDigest != dsse.Digest(admissionRaw) ||
		challenge.IntentDigest != dsse.Digest(intentRaw) ||
		challenge.ServiceTrustDigest != dsse.Digest(fixture.serviceTrustRaw) ||
		challenge.RequestDigest != taskpermit.RequestDigest(expectedRequest) ||
		challenge.RuntimeRef != fixture.admitted.RuntimeRef ||
		challenge.GrantID != fixture.admitted.GrantID ||
		!slices.Equal(challenge.TaskAuthorities, expectedAuthorities) {
		t.Fatalf("challenge=%#v", challenge)
	}

	firstCreatedAt := challenge.CreatedAt
	priorNow := timeNow
	timeNow = func() time.Time { return fixtureTime().Add(time.Hour) }
	t.Cleanup(func() { timeNow = priorNow })
	requestAgain, challengeAgainRaw, challengeAgain, err := ensureActivationHandoff(
		store,
		fixture.inputs,
		fixture.admitted,
		admissionRaw,
		fixture.serviceTrustRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestAgain, requestRaw) ||
		!bytes.Equal(challengeAgainRaw, challengeRaw) ||
		challengeAgain.CreatedAt != firstCreatedAt {
		t.Fatal("idempotent handoff changed retained request or challenge bytes")
	}

	if _, _, _, err := ensureActivationHandoff(
		store,
		fixture.inputs,
		fixture.admitted,
		append(append([]byte(nil), admissionRaw...), ' '),
		fixture.serviceTrustRaw,
	); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed admission bytes error=%v", err)
	}
}

func TestParseActivationSubmitRequiresCanonicalExactRecord(t *testing.T) {
	_, task := verifiedActivationRunTask(t)
	record := activationSubmitForTask(task)
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseActivationSubmit(raw, task)
	if err != nil || parsed != record {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	replayed := record
	replayed.Receipt = gatewayclient.TaskReceiptReplayed
	replayedRaw := mustActivationRunJSON(t, replayed)
	if parsed, err := parseActivationSubmit(replayedRaw, task); err != nil || parsed != replayed {
		t.Fatalf("replayed=%#v err=%v", parsed, err)
	}

	wrongDigest := record
	wrongDigest.TaskDigest = digest('f')
	wrongReceipt := record
	wrongReceipt.Receipt = gatewayclient.TaskReceipt("accepted")
	wrongRun := record
	wrongRun.RunID = "invalid/run"
	wrongEpoch := record
	wrongEpoch.ReceiptEpoch = 0
	wrongNode := record
	wrongNode.ReceiptNodeID = "other-node/gateway"
	wrongKey := record
	wrongKey.ReceiptPublicKeyBase64 = "AA=="
	candidates := map[string][]byte{
		"trailing whitespace": append(append([]byte(nil), raw...), ' '),
		"reordered fields": []byte(fmt.Sprintf(
			`{"receipt":%q,"run_id":%q,"permit_digest":%q,"task_digest":%q}`,
			record.Receipt, record.RunID, record.PermitDigest, record.TaskDigest,
		)),
		"wrong task digest": mustActivationRunJSON(t, wrongDigest),
		"wrong receipt":     mustActivationRunJSON(t, wrongReceipt),
		"wrong run ID":      mustActivationRunJSON(t, wrongRun),
		"wrong epoch":       mustActivationRunJSON(t, wrongEpoch),
		"wrong node":        mustActivationRunJSON(t, wrongNode),
		"wrong key":         mustActivationRunJSON(t, wrongKey),
	}
	for name, candidate := range candidates {
		t.Run(name, func(t *testing.T) {
			if _, err := parseActivationSubmit(candidate, task); err == nil {
				t.Fatal("invalid activation submit record was accepted")
			}
		})
	}
}

func TestEnsureActivationSubmitStopsOnDurableSpentPermit(t *testing.T) {
	_, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	store := newActivationRunStore(t)
	var submitCalls, statusCalls int
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			submitCalls++
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(
				writer,
				`{"error":"permit_expired","message":"task permit expired before dispatch"}`,
			)
		case http.MethodGet:
			statusCalls++
			writeActivationGatewayResponse(
				t, writer, submit,
				`"phase":"terminal","state":"failed_without_dispatch_evidence",`+
					`"error_code":"permit_expired",`+
					`"retry_safety":"replacement_safe_after_new_authority"`,
			)
		default:
			t.Errorf("unexpected Gateway method %s", request.Method)
			http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	client, err := gatewayclient.New(server.URL, "activation-token")
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensureActivationSubmit(
		store,
		task,
		activationGatewayLocal{
			config: gateway.Config{
				ConnectorReceiptEpoch: submit.ReceiptEpoch,
			},
			client:        client,
			receiptPublic: receiptPublic,
		},
		time.Now().Add(5*time.Second),
		allowActivationSubmit,
	)
	var terminal *activationCanaryTerminalError
	if !errors.As(err, &terminal) ||
		terminal.state != gatewayclient.StateFailedWithoutDispatchEvidence ||
		terminal.code != "permit_expired" ||
		submitCalls != 1 || statusCalls != 1 {
		t.Fatalf(
			"terminal=%#v err=%v submitCalls=%d statusCalls=%d",
			terminal, err, submitCalls, statusCalls,
		)
	}
	statusRaw, err := store.Read(
		activationstore.CanaryStatusFileName, maxArtifactBytes,
	)
	if err != nil || !bytes.Contains(statusRaw, []byte(`"error_code":"permit_expired"`)) {
		t.Fatalf("stored status=%s err=%v", statusRaw, err)
	}
	assertActivationStoreArtifactMissing(
		t, store, activationstore.CanarySubmitFileName,
	)
}

func TestEnsureActivationSubmitRecoversDurableDispatchAfterLostResponse(t *testing.T) {
	tests := []struct {
		name               string
		statusFields       string
		wantTerminalStatus bool
	}{
		{
			name: "dispatch accepted",
			statusFields: `"phase":"dispatch","state":"dispatch_accepted",` +
				`"run_id":"run_0123456789abcdef0123456789abcdef"`,
		},
		{
			name: "completed before status query",
			statusFields: `"phase":"terminal","state":"agent_reported_completed",` +
				`"run_id":"run_0123456789abcdef0123456789abcdef",` +
				`"task_status":"agent_reported_completed",` +
				`"result_digest":` + fmt.Sprintf("%q", digest('e')) + `,` +
				`"response_bytes":17`,
			wantTerminalStatus: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, task := verifiedActivationRunTask(t)
			submit := activationSubmitForTask(task)
			store := newActivationRunStore(t)
			var submitCalls, statusCalls int
			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.Method {
				case http.MethodPost:
					submitCalls++
					writer.WriteHeader(http.StatusBadGateway)
					_, _ = io.WriteString(
						writer,
						`{"error":"upstream_unavailable","message":"response was lost"}`,
					)
				case http.MethodGet:
					statusCalls++
					writeActivationGatewayResponse(
						t, writer, submit, test.statusFields,
					)
				default:
					t.Errorf("unexpected Gateway method %s", request.Method)
					http.Error(writer, "unexpected", http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			client, err := gatewayclient.New(server.URL, "activation-token")
			if err != nil {
				t.Fatal(err)
			}
			receiptPublic, err := activationSubmitReceiptPublicKey(submit)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := ensureActivationSubmit(
				store,
				task,
				activationGatewayLocal{
					config: gateway.Config{
						ConnectorReceiptEpoch: submit.ReceiptEpoch,
					},
					client:        client,
					receiptPublic: receiptPublic,
				},
				time.Now().Add(5*time.Second),
				allowActivationSubmit,
			)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Receipt != activationTaskReceiptRecovered ||
				recovered.RunID != "run_0123456789abcdef0123456789abcdef" ||
				submitCalls != 1 || statusCalls != 1 {
				t.Fatalf(
					"recovered=%#v submitCalls=%d statusCalls=%d",
					recovered, submitCalls, statusCalls,
				)
			}
			stored, err := readActivationSubmit(store, task)
			if err != nil || stored != recovered {
				t.Fatalf("stored=%#v err=%v", stored, err)
			}
			_, statusPresent, err := readOptionalActivationArtifact(
				store, activationstore.CanaryStatusFileName, maxArtifactBytes,
			)
			if err != nil || statusPresent != test.wantTerminalStatus {
				t.Fatalf(
					"terminal status present=%v want=%v err=%v",
					statusPresent, test.wantTerminalStatus, err,
				)
			}
		})
	}
}

func TestEnsureActivationSubmitUsesRetainedTerminalStatusBeforeNetwork(t *testing.T) {
	tests := []struct {
		name          string
		status        gatewayclient.TaskLifecycleStatus
		wantRecovered bool
		wantState     string
	}{
		{
			name: "completed status recovers submit",
			status: gatewayclient.TaskLifecycleStatus{
				Phase:         gatewayclient.PhaseTerminal,
				State:         string(gatewayclient.AgentReportedCompleted),
				RunID:         "run_0123456789abcdef0123456789abcdef",
				TaskStatus:    gatewayclient.AgentReportedCompleted,
				ResultDigest:  digest('e'),
				ResponseBytes: 17,
			},
			wantRecovered: true,
		},
		{
			name: "terminal failure stops submit",
			status: gatewayclient.TaskLifecycleStatus{
				Phase:       gatewayclient.PhaseTerminal,
				State:       gatewayclient.StateFailedWithoutDispatchEvidence,
				ErrorCode:   "permit_expired",
				RetrySafety: gatewayclient.RetryReplacementSafeAfterNewAuthority,
			},
			wantState: gatewayclient.StateFailedWithoutDispatchEvidence,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, task := verifiedActivationRunTask(t)
			submit := activationSubmitForTask(task)
			store := newActivationRunStore(t)
			status := test.status
			status.SchemaVersion = activationTaskStatusSchemaV1
			status.TaskDigest = submit.TaskDigest
			status.PermitDigest = submit.PermitDigest
			if err := storeActivationTerminalStatus(store, status); err != nil {
				t.Fatal(err)
			}

			var networkCalls, authorizationChecks int
			server := httptest.NewServer(http.HandlerFunc(func(
				writer http.ResponseWriter,
				_ *http.Request,
			) {
				networkCalls++
				http.Error(writer, "unexpected", http.StatusInternalServerError)
			}))
			defer server.Close()
			client, err := gatewayclient.New(server.URL, "activation-token")
			if err != nil {
				t.Fatal(err)
			}
			receiptPublic, err := activationSubmitReceiptPublicKey(submit)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ensureActivationSubmit(
				store,
				task,
				activationGatewayLocal{
					config: gateway.Config{
						ConnectorReceiptEpoch: submit.ReceiptEpoch,
					},
					client:        client,
					receiptPublic: receiptPublic,
				},
				time.Now().Add(5*time.Second),
				func(time.Time) error {
					authorizationChecks++
					return nil
				},
			)
			if test.wantRecovered {
				if err != nil ||
					got.RunID != status.RunID ||
					got.Receipt != activationTaskReceiptRecovered {
					t.Fatalf("recovered=%#v err=%v", got, err)
				}
				stored, readErr := readActivationSubmit(store, task)
				if readErr != nil || stored != got {
					t.Fatalf("stored=%#v err=%v", stored, readErr)
				}
			} else {
				var terminal *activationCanaryTerminalError
				if !errors.As(err, &terminal) ||
					terminal.state != test.wantState {
					t.Fatalf("terminal=%#v err=%v", terminal, err)
				}
				assertActivationStoreArtifactMissing(
					t, store, activationstore.CanarySubmitFileName,
				)
			}
			if networkCalls != 0 || authorizationChecks != 0 {
				t.Fatalf(
					"networkCalls=%d authorizationChecks=%d",
					networkCalls, authorizationChecks,
				)
			}
		})
	}
}

func TestEnsureActivationSubmitValidatesCurrentAuthorityImmediatelyBeforeSubmit(t *testing.T) {
	_, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	store := newActivationRunStore(t)
	var networkCalls, authorizationChecks int
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		networkCalls++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := gatewayclient.New(server.URL, "activation-token")
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("release expired")
	_, err = ensureActivationSubmit(
		store,
		task,
		activationGatewayLocal{
			config: gateway.Config{
				ConnectorReceiptEpoch: submit.ReceiptEpoch,
			},
			client:        client,
			receiptPublic: receiptPublic,
		},
		time.Now().Add(5*time.Second),
		func(at time.Time) error {
			authorizationChecks++
			if at.IsZero() {
				t.Fatal("authorization time is zero")
			}
			return sentinel
		},
	)
	var invalid *activationCanaryAuthorizationInvalidError
	if !errors.As(err, &invalid) || !errors.Is(err, sentinel) ||
		authorizationChecks != 1 || networkCalls != 0 {
		t.Fatalf(
			"invalid=%#v err=%v checks=%d network=%d",
			invalid, err, authorizationChecks, networkCalls,
		)
	}
}

func TestEnsureActivationSubmitRejectsInvalidRetainedStatusWithoutNetwork(t *testing.T) {
	_, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	store := newActivationRunStore(t)
	status := gatewayclient.TaskLifecycleStatus{
		SchemaVersion: activationTaskStatusSchemaV1,
		TaskDigest:    digest('f'),
		PermitDigest:  submit.PermitDigest,
		Phase:         gatewayclient.PhaseTerminal,
		State:         string(gatewayclient.AgentReportedCompleted),
		RunID:         submit.RunID,
		TaskStatus:    gatewayclient.AgentReportedCompleted,
		ResultDigest:  digest('e'),
		ResponseBytes: 17,
	}
	if err := store.WriteOnce(
		activationstore.CanaryStatusFileName,
		mustActivationRunJSON(t, status),
	); err != nil {
		t.Fatal(err)
	}
	var networkCalls int
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		networkCalls++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := gatewayclient.New(server.URL, "activation-token")
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensureActivationSubmit(
		store,
		task,
		activationGatewayLocal{
			config: gateway.Config{
				ConnectorReceiptEpoch: submit.ReceiptEpoch,
			},
			client:        client,
			receiptPublic: receiptPublic,
		},
		time.Now().Add(5*time.Second),
		allowActivationSubmit,
	)
	var invalid *activationCanaryRetainedInvalidError
	if !errors.As(err, &invalid) ||
		!activationCanaryFailureIsSticky(err) ||
		networkCalls != 0 {
		t.Fatalf(
			"invalid=%#v err=%v network=%d",
			invalid, err, networkCalls,
		)
	}
}

func TestActivationCanaryDeadlineUsesAuthorizedCheckpoint(t *testing.T) {
	authorizedAt := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	chain := activationStateChain{
		states: []activation.StateV1{
			{
				Phase:     activation.PhaseNew,
				UpdatedAt: authorizedAt.Add(-time.Minute).Format(time.RFC3339Nano),
			},
			{
				Phase:     activation.PhaseCanaryAuthorized,
				UpdatedAt: authorizedAt.Format(time.RFC3339Nano),
			},
			{
				Phase:     activation.PhaseCanaryDispatched,
				UpdatedAt: authorizedAt.Add(time.Second).Format(time.RFC3339Nano),
			},
		},
	}
	got, err := activationCanaryDeadline(chain, 5*time.Minute)
	if err != nil || !got.Equal(authorizedAt.Add(5*time.Minute)) {
		t.Fatalf("deadline=%v err=%v", got, err)
	}
}

func TestActivationNodePrerequisiteErrorsAreActionable(t *testing.T) {
	tests := []struct {
		name     string
		api      *nodeclient.APIError
		contains string
	}{
		{
			name: "local tenant identity",
			api: &nodeclient.APIError{
				Status:  http.StatusForbidden,
				Code:    "tenant_identity_required",
				Message: "signed admission requires an authenticated uplink principal",
			},
			contains: "-admission-allow-host-admin-intent",
		},
		{
			name: "local lifecycle identity",
			api: &nodeclient.APIError{
				Status:  http.StatusForbidden,
				Code:    "signed_lifecycle_required",
				Message: "workload is not bound to the current authenticated signed admission",
			},
			contains: "-admission-allow-host-admin-intent",
		},
		{
			name: "dedicated state",
			api: &nodeclient.APIError{
				Status:  http.StatusNotImplemented,
				Code:    "capability_unavailable",
				Message: "persistent state is disabled because the configured Docker volume has no hard byte or inode quota",
			},
			contains: "-allow-unquotaed-state-on-dedicated-host",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := activationNodePrerequisiteError(test.api)
			if err == nil || !strings.Contains(err.Error(), test.contains) ||
				!errors.Is(err, test.api) {
				t.Fatalf("prerequisite error=%v", err)
			}
		})
	}
	if err := activationNodePrerequisiteError(errors.New("transport")); err != nil {
		t.Fatalf("transport classified as prerequisite: %v", err)
	}
}

func TestRequireDedicatedActivationPolicy(t *testing.T) {
	if err := requireDedicatedActivationPolicy(admission.SitePolicy{
		Tenants: []admission.TenantRule{{TenantID: "tenant-a"}},
	}); err != nil {
		t.Fatalf("one-tenant policy rejected: %v", err)
	}
	err := requireDedicatedActivationPolicy(admission.SitePolicy{
		Tenants: []admission.TenantRule{
			{TenantID: "tenant-a"},
			{TenantID: "tenant-b"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "one-tenant dedicated-host") {
		t.Fatalf("shared-host policy error=%v", err)
	}
}

func TestActivationCanaryDeadlineDoesNotResetAcrossSubmitRecovery(t *testing.T) {
	_, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	store := newActivationRunStore(t)
	var submitCalls, statusCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			submitCalls.Add(1)
			time.Sleep(200 * time.Millisecond)
			writer.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(
				writer,
				`{"error":"upstream_unavailable","message":"response was lost"}`,
			)
		case http.MethodGet:
			statusCalls.Add(1)
			select {
			case <-request.Context().Done():
			case <-time.After(200 * time.Millisecond):
				writeActivationGatewayResponse(
					t, writer, submit,
					`"phase":"dispatch","state":"dispatch_accepted",`+
						`"run_id":"run_0123456789abcdef0123456789abcdef"`,
				)
			}
		default:
			t.Errorf("unexpected Gateway method %s", request.Method)
		}
	}))
	defer server.Close()
	client, err := gatewayclient.New(server.URL, "activation-token")
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, err := activationSubmitReceiptPublicKey(submit)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	deadline := started.Add(300 * time.Millisecond)
	_, err = ensureActivationSubmit(
		store,
		task,
		activationGatewayLocal{
			config: gateway.Config{
				ConnectorReceiptEpoch: submit.ReceiptEpoch,
			},
			client:        client,
			receiptPublic: receiptPublic,
		},
		deadline,
		allowActivationSubmit,
	)
	var timeout *activationCanaryTimeoutError
	if !errors.As(err, &timeout) ||
		submitCalls.Load() != 1 || statusCalls.Load() != 1 ||
		time.Since(started) > 450*time.Millisecond {
		t.Fatalf(
			"timeout=%#v err=%v submitCalls=%d statusCalls=%d elapsed=%v",
			timeout, err, submitCalls.Load(), statusCalls.Load(), time.Since(started),
		)
	}
}

func TestEnsureActivationCanaryResultAcceptsOnlyClosedTerminalEvidence(t *testing.T) {
	t.Run("completed exact result", func(t *testing.T) {
		fixture, task := verifiedActivationRunTask(t)
		fixture.inputs.plan.Timeouts.CanarySeconds = 5
		submit := activationSubmitForTask(task)
		resultRaw := activationHermesResult(
			t, fixture.inputs.plan.ActivationID, submit.RunID,
		)
		store := newActivationRunStore(t)
		var statusCalls, observeCalls int
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer activation-token" {
				t.Errorf("authorization=%q", request.Header.Get("Authorization"))
			}
			switch {
			case request.Method == http.MethodGet:
				statusCalls++
				writeActivationGatewayResponse(
					t, writer, submit,
					fmt.Sprintf(
						`"phase":"dispatch","state":"dispatch_accepted","run_id":%q`,
						submit.RunID,
					),
				)
			case request.Method == http.MethodPost &&
				strings.HasSuffix(request.URL.Path, "/observe"):
				observeCalls++
				writeActivationGatewayResponse(
					t, writer, submit,
					activationGatewayTerminalFields(
						resultRaw, "completed", true, submit.RunID,
					),
				)
			default:
				t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
				http.Error(writer, "unexpected", http.StatusNotFound)
			}
		}))
		defer server.Close()
		client, err := gatewayclient.New(server.URL, "activation-token")
		if err != nil {
			t.Fatal(err)
		}
		got, status, err := ensureActivationCanaryResult(
			store, fixture.inputs, task, submit, client,
			time.Now().Add(5*time.Second),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, resultRaw) ||
			status.State != string(gatewayclient.AgentReportedCompleted) ||
			statusCalls != 1 || observeCalls != 1 {
			t.Fatalf(
				"result=%s status=%#v statusCalls=%d observeCalls=%d",
				got, status, statusCalls, observeCalls,
			)
		}
		stored, err := store.Read(
			activationstore.CanaryResultFileName,
			activation.MaxCanaryResultBytes,
		)
		if err != nil || !bytes.Equal(stored, resultRaw) {
			t.Fatalf("stored result=%s err=%v", stored, err)
		}
		statusRaw, err := store.Read(
			activationstore.CanaryStatusFileName, maxArtifactBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(statusRaw, []byte("observation_base64")) ||
			bytes.Contains(statusRaw, []byte("observed_status")) {
			t.Fatalf("stored status retained live observation: %s", statusRaw)
		}
	})

	t.Run("terminal failure", func(t *testing.T) {
		fixture, task := verifiedActivationRunTask(t)
		fixture.inputs.plan.Timeouts.CanarySeconds = 5
		submit := activationSubmitForTask(task)
		resultRaw := activationHermesResult(
			t, fixture.inputs.plan.ActivationID, submit.RunID,
		)
		store := newActivationRunStore(t)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeActivationGatewayResponse(
				t, writer, submit,
				activationGatewayTerminalFields(
					resultRaw, "failed", false, submit.RunID,
				),
			)
		}))
		defer server.Close()
		client, err := gatewayclient.New(server.URL, "activation-token")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ensureActivationCanaryResult(
			store, fixture.inputs, task, submit, client,
			time.Now().Add(5*time.Second),
		)
		var terminal *activationCanaryTerminalError
		if !errors.As(err, &terminal) || terminal.state != string(gatewayclient.AgentReportedFailed) {
			t.Fatalf("terminal error=%v", err)
		}
		if _, err := store.Read(
			activationstore.CanaryStatusFileName, maxArtifactBytes,
		); err != nil {
			t.Fatalf("terminal status was not retained: %v", err)
		}
		assertActivationStoreArtifactMissing(
			t, store, activationstore.CanaryResultFileName,
		)
	})

	t.Run("wrong closed result", func(t *testing.T) {
		fixture, task := verifiedActivationRunTask(t)
		fixture.inputs.plan.Timeouts.CanarySeconds = 5
		submit := activationSubmitForTask(task)
		wrongResult := activationHermesResult(
			t, "different-activation", submit.RunID,
		)
		store := newActivationRunStore(t)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet {
				writeActivationGatewayResponse(
					t, writer, submit,
					fmt.Sprintf(
						`"phase":"dispatch","state":"dispatch_accepted","run_id":%q`,
						submit.RunID,
					),
				)
				return
			}
			writeActivationGatewayResponse(
				t, writer, submit,
				activationGatewayTerminalFields(
					wrongResult, "completed", true, submit.RunID,
				),
			)
		}))
		defer server.Close()
		client, err := gatewayclient.New(server.URL, "activation-token")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ensureActivationCanaryResult(
			store, fixture.inputs, task, submit, client,
			time.Now().Add(5*time.Second),
		)
		var terminal *activationCanaryTerminalError
		if !errors.As(err, &terminal) ||
			terminal.code != "closed_canary_invalid" {
			t.Fatalf("wrong result error=%v", err)
		}
		if _, err := store.Read(
			activationstore.CanaryStatusFileName, maxArtifactBytes,
		); err != nil {
			t.Fatalf("invalid terminal status was not retained: %v", err)
		}
		assertActivationStoreArtifactMissing(
			t, store, activationstore.CanaryResultFileName,
		)
	})

	t.Run("retained result metadata mismatch", func(t *testing.T) {
		fixture, task := verifiedActivationRunTask(t)
		fixture.inputs.plan.Timeouts.CanarySeconds = 5
		submit := activationSubmitForTask(task)
		resultRaw := activationHermesResult(
			t, fixture.inputs.plan.ActivationID, submit.RunID,
		)
		store := newActivationRunStore(t)
		if err := store.WriteOnce(
			activationstore.CanaryResultFileName, resultRaw,
		); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeActivationGatewayResponse(
				t, writer, submit,
				fmt.Sprintf(
					`"phase":"terminal","state":"agent_reported_completed","run_id":%q,`+
						`"task_status":"agent_reported_completed","result_digest":%q,"response_bytes":%d`,
					submit.RunID, digest('f'), len(resultRaw),
				),
			)
		}))
		defer server.Close()
		client, err := gatewayclient.New(server.URL, "activation-token")
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ensureActivationCanaryResult(
			store, fixture.inputs, task, submit, client,
			time.Now().Add(5*time.Second),
		)
		var terminal *activationCanaryTerminalError
		if !errors.As(err, &terminal) ||
			terminal.code != "retained_result_mismatch" {
			t.Fatalf("metadata mismatch error=%v", err)
		}
		if _, err := store.Read(
			activationstore.CanaryStatusFileName, maxArtifactBytes,
		); err != nil {
			t.Fatalf("mismatched terminal status was not retained: %v", err)
		}
	})
}

func TestEnsureActivationCanaryResultDoesNotResetExpiredDeadline(t *testing.T) {
	fixture, task := verifiedActivationRunTask(t)
	submit := activationSubmitForTask(task)
	store := newActivationRunStore(t)
	var networkCalls int
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		networkCalls++
		http.Error(writer, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := gatewayclient.New(server.URL, "activation-token")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ensureActivationCanaryResult(
		store, fixture.inputs, task, submit, client,
		time.Now().Add(-time.Second),
	)
	var timeout *activationCanaryTimeoutError
	if !errors.As(err, &timeout) || networkCalls != 0 {
		t.Fatalf(
			"timeout=%#v err=%v networkCalls=%d",
			timeout, err, networkCalls,
		)
	}
}

func TestActivationCanaryArtifactConflictIsSticky(t *testing.T) {
	err := &activationArtifactConflictError{
		name: activationstore.CanaryResultFileName,
	}
	if !activationCanaryFailureIsSticky(err) {
		t.Fatal("canary result write-once conflict was not classified as sticky")
	}
}

func TestFinalizeActivationProofRecoversProofBeforePassedState(t *testing.T) {
	fixture := newActivationStatusFixture(
		t, activation.PhaseEvidenceCollected, "node-a",
	)
	store, err := activationstore.Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inputs, chain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		t.Fatal(err)
	}
	executorResult, gatewayResult := activationProofEvidenceResults(
		chain.latest().Binding,
		chain.latest().UpdatedAt,
	)
	next := chain.latest()
	next.Phase = activation.PhasePassed
	next.UpdatedAt = "2026-07-16T01:00:11Z"
	nextRaw, err := activation.MarshalStateV1(next)
	if err != nil {
		t.Fatal(err)
	}
	proof := activation.ProofV1{
		SchemaVersion:            activation.ProofSchemaV1,
		Binding:                  chain.latest().Binding,
		StateDigest:              dsse.Digest(nextRaw),
		RuntimeRef:               chain.latest().RuntimeRef,
		Canary:                   gatewayResult.Canary,
		ExecutorBeginDigest:      digest('6'),
		ExecutorCheckpointDigest: digest('7'),
		ExecutorEvidence:         executorResult.Coordinate,
		GatewayEvidence:          gatewayResult.Coordinate,
		Witness:                  executorResult.Witness,
		CompletedAt:              next.UpdatedAt,
	}
	proofRaw, err := activation.MarshalProofV1(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(activationstore.ProofFileName, proofRaw); err != nil {
		t.Fatal(err)
	}

	recovered, err := finalizeActivationProof(
		store, &chain, inputs, digest('6'), digest('7'),
		executorResult, gatewayResult,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, proofRaw) ||
		chain.latest().Phase != activation.PhasePassed ||
		chain.latest().UpdatedAt != proof.CompletedAt {
		t.Fatalf("recovered=%s latest=%#v", recovered, chain.latest())
	}
	storedProof, err := store.Read(
		activationstore.ProofFileName, activation.MaxProofBytes,
	)
	if err != nil || !bytes.Equal(storedProof, proofRaw) {
		t.Fatalf("stored proof=%s err=%v", storedProof, err)
	}
	if _, err := activation.CorrelateProofV1(
		inputs.planRaw, chain.latestRaw(), storedProof,
	); err != nil {
		t.Fatalf("correlate recovered proof: %v", err)
	}
}

func activationAdmissionValidationFixture(
	t *testing.T,
) (permitAdmission, verifiedActivationInputs, string) {
	t.Helper()
	fixture := newActivationTaskFixture(t)
	admitted := fixture.admitted
	taskKey := admitted.TaskAuthorities[0]
	fixture.inputs.effective = admission.EffectiveAdmission{
		CapsuleDigest: admitted.CapsuleDigest,
		PolicyDigest:  admitted.PolicyDigest,
		Intent:        fixture.inputs.intent,
		SitePolicy: admission.SitePolicy{
			Tenants: []admission.TenantRule{{
				TenantID:   fixture.inputs.intent.TenantID,
				ServiceIDs: []string{fixture.inputs.intent.ServiceID},
				TaskKeys: []admission.TaskKey{{
					KeyID: taskKey.KeyID, PublicKey: taskKey.PublicKey,
					ServiceIDs: []string{fixture.inputs.intent.ServiceID},
				}},
			}},
		},
	}
	return admitted, fixture.inputs, admitted.EvidenceKeyID
}

func verifiedActivationRunTask(
	t *testing.T,
) (activationTaskFixture, verifiedTaskBundle) {
	t.Helper()
	fixture := newActivationTaskFixture(t)
	task, err := verifyActivationTask(
		fixture.taskRaw,
		fixture.challenge,
		fixture.admitted,
		fixture.inputs,
		fixture.serviceTrustRaw,
		fixture.requestRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, task
}

func newActivationRunStore(t *testing.T) *activationstore.Store {
	t.Helper()
	store, err := activationstore.Create(
		filepath.Join(t.TempDir(), "activation"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close activation store: %v", err)
		}
	})
	return store
}

func activationSubmitForTask(task verifiedTaskBundle) activationSubmitRecord {
	statement := task.Verified.Statement
	public := bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize)
	return activationSubmitRecord{
		SchemaVersion: activationSubmitSchemaV1,
		TaskDigest: taskpermit.TaskDigest(
			statement.TenantID, statement.InstanceID, statement.TaskID,
		),
		PermitDigest:  task.Verified.EnvelopeDigest,
		RunID:         "run_0123456789abcdef0123456789abcdef",
		Receipt:       gatewayclient.TaskReceiptRecorded,
		ReceiptNodeID: gateway.ServiceTaskReceiptNodeID(statement.NodeID),
		ReceiptEpoch:  1,
		ReceiptPublicKeyBase64: base64.StdEncoding.EncodeToString(
			public,
		),
	}
}

func activationHermesResult(
	t *testing.T,
	activationID, runID string,
) []byte {
	t.Helper()
	workspaceRaw, err := json.Marshal(struct {
		Entries        []struct{} `json:"entries"`
		FileCount      int        `json:"file_count"`
		ManifestDigest string     `json:"manifest_digest"`
		Root           string     `json:"root"`
		SchemaVersion  string     `json:"schema_version"`
		TotalBytes     int64      `json:"total_bytes"`
	}{
		Entries:        []struct{}{},
		ManifestDigest: agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
		Root:           activation.HermesWorkspaceRoot,
		SchemaVersion:  activation.HermesWorkspaceSchemaV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Object    string  `json:"object"`
		RunID     string  `json:"run_id"`
		Status    string  `json:"status"`
		UpdatedAt float64 `json:"updated_at"`
		CreatedAt float64 `json:"created_at"`
		SessionID string  `json:"session_id"`
		Model     string  `json:"model"`
		Output    string  `json:"output"`
		Usage     struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		} `json:"usage"`
		LastEvent string `json:"last_event"`
	}{
		Object:    activation.HermesRunObject,
		RunID:     runID,
		Status:    activation.HermesCompletedStatus,
		UpdatedAt: 2,
		CreatedAt: 1,
		SessionID: agentrelease.HermesSessionIDPrefix + "-" + activationID,
		Model:     "steward-fixture-model",
		Output:    string(workspaceRaw),
		Usage: struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
			TotalTokens  int64 `json:"total_tokens"`
		}{InputTokens: 2, OutputTokens: 1, TotalTokens: 3},
		LastEvent: activation.HermesCompletedEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func activationGatewayTerminalFields(
	raw []byte,
	status string,
	includeObservation bool,
	runID string,
) string {
	state := "agent_reported_" + status
	fields := fmt.Sprintf(
		`"phase":"terminal","state":%q,"run_id":%q,`+
			`"task_status":%q,"result_digest":%q,"response_bytes":%d`,
		state, runID, state, dsse.Digest(raw), len(raw),
	)
	if includeObservation {
		fields += fmt.Sprintf(
			`,"observed_status":%q,"observation_base64":%q`,
			status, base64.StdEncoding.EncodeToString(raw),
		)
	}
	return fields
}

func writeActivationGatewayResponse(
	t *testing.T,
	writer http.ResponseWriter,
	submit activationSubmitRecord,
	fields string,
) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(
		writer,
		fmt.Sprintf(
			`{"schema_version":"steward.task-status.v1","task_digest":%q,`+
				`"permit_digest":%q,%s}`,
			submit.TaskDigest, submit.PermitDigest, fields,
		),
	); err != nil {
		t.Errorf("write Gateway response: %v", err)
	}
}

func assertActivationStoreArtifactMissing(
	t *testing.T,
	store *activationstore.Store,
	name string,
) {
	t.Helper()
	if _, err := store.Read(
		name, activationstore.MaxSmallArtifactBytes,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact %q exists or returned unexpected error: %v", name, err)
	}
}

func activationProofEvidenceResults(
	binding activation.BindingV1,
	witnessedAt string,
) (activation.ExecutorEvidenceResultV1, activation.GatewayEvidenceResultV1) {
	executor := activation.ReceiptCoordinateV1{
		ReceiptNodeID:   binding.NodeID,
		ReceiptEpoch:    1,
		Sequence:        7,
		ChainHash:       digest('1'),
		PublicKeySHA256: digest('2'),
	}
	return activation.ExecutorEvidenceResultV1{
			Coordinate: executor,
			Witness: activation.WitnessCoordinateV1{
				ControllerInstanceID:   "controller-a",
				ControlNodeID:          binding.NodeID,
				ReceiptNodeID:          executor.ReceiptNodeID,
				ReceiptEpoch:           executor.ReceiptEpoch,
				Sequence:               executor.Sequence,
				ChainHash:              executor.ChainHash,
				ReceiptPublicKeySHA256: executor.PublicKeySHA256,
				WitnessPublicKeySHA256: digest('3'),
				WitnessExportDigest:    digest('4'),
				WitnessedAt:            witnessedAt,
			},
		}, activation.GatewayEvidenceResultV1{
			Coordinate: activation.ReceiptCoordinateV1{
				ReceiptNodeID:   binding.NodeID + "/gateway",
				ReceiptEpoch:    1,
				Sequence:        9,
				ChainHash:       digest('5'),
				PublicKeySHA256: digest('6'),
			},
			Canary: activation.CanaryProofV1{
				Kind:         activation.CanaryHermesWorkspaceAuditV1,
				TaskDigest:   digest('7'),
				PermitDigest: digest('8'),
				ResultDigest: digest('9'),
				ResultBytes:  1,
			},
		}
}

func mustActivationRunJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func allowActivationSubmit(time.Time) error {
	return nil
}
