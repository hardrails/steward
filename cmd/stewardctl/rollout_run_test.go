package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlcapture"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

func TestRolloutRunExecutesFreshTargetThroughProtocolFourAndOfflineProof(t *testing.T) {
	fixture := newRolloutRunPlannedFixture(t)
	run := loadRolloutRunTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	target := prepared.Target()

	taskPrivate, err := readPrivateKey(fixture.taskPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	taskPublic := taskPrivate.Public().(ed25519.PublicKey)
	gatewayPrivate, err := readPrivateKey(fixture.gatewayPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPublic := gatewayPrivate.Public().(ed25519.PublicKey)
	witnessPrivate, err := readPrivateKey(fixture.witnessPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    prepared.RuntimeRef(), Status: "created",
		CapsuleDigest: prepared.CapsuleDigest(), PolicyDigest: run.plan.PolicyDigest,
		Generation: target.InstanceGeneration, EvidenceKeyID: evidence.KeyID(receiptPublic),
		GrantID:   gateway.GrantID(run.plan.TenantID, target.InstanceID, target.InstanceGeneration),
		ServiceID: agentrelease.HermesServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID: fixture.taskKeyID, PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest:     dsse.Digest([]byte("rollout-run-route-policy")),
		ActivationID:          target.ActivationID,
		ActivationBeginDigest: prepared.ExecutorBeginDigest(),
	}
	projection.ServicePath = "/v1/services/" + projection.GrantID + "/"
	if err := rolloutdriver.VerifyAdmissionV1(prepared, projection); err != nil {
		t.Fatal(err)
	}

	type controllerState struct {
		sync.Mutex
		commands       map[string][]byte
		canaryResult   *controlprotocol.ExecutorActivationCanaryResultV1
		captureExport  *controlprotocol.ControllerEvidenceCaptureV1
		armed          controlstore.EvidenceCapture
		capturePolls   int
		sealCalls      int
		commandSubmits []string
	}
	state := &controllerState{commands: make(map[string][]byte)}
	previousSleep := rolloutPollSleep
	rolloutPollSleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { rolloutPollSleep = previousSleep })

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state.Lock()
		defer state.Unlock()
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/nodes/"+target.NodeID):
			writeRolloutRunJSON(t, writer, controlclient.Node{
				NodeID: target.NodeID, TenantIDs: []string{run.plan.TenantID}, State: "active",
				Capabilities: []string{
					controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
					controlprotocol.ExecutorCapabilityActivationCanaryV1,
					controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
				},
			})

		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/captures"):
			var input struct {
				CaptureID             string `json:"capture_id"`
				RequestID             string `json:"request_id"`
				TenantID              string `json:"tenant_id"`
				RuntimeRef            string `json:"runtime_ref"`
				Generation            uint64 `json:"generation"`
				ActivationID          string `json:"activation_id"`
				ActivationBeginDigest string `json:"activation_begin_digest"`
				TTLSeconds            int64  `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode capture arm: %v", err)
				return
			}
			armedAt, _ := time.Parse(time.RFC3339Nano, run.plan.CreatedAt)
			head := controlprotocol.ExecutorEvidenceHeadV1{
				Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: target.NodeID,
				ReceiptEpoch: 1, Sequence: 0,
				ChainHash:       "sha256:" + strings.Repeat("0", 64),
				PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
			}
			state.armed = controlstore.EvidenceCapture{
				CaptureID: input.CaptureID, RequestID: input.RequestID, NodeID: target.NodeID,
				TenantID: input.TenantID, RuntimeRef: input.RuntimeRef, Generation: input.Generation,
				ActivationID: input.ActivationID, ActivationBeginDigest: input.ActivationBeginDigest,
				State: controlstore.EvidenceCaptureArmed, BaselineHead: head, FinalHead: head,
				ArmedAt:   armedAt.Format(time.RFC3339Nano),
				ExpiresAt: armedAt.Add(time.Duration(input.TTLSeconds) * time.Second).Format(time.RFC3339Nano),
			}
			writeRolloutRunJSON(t, writer, state.armed)

		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/commands"):
			raw := rolloutRunSubmittedCommand(t, request)
			statement := rolloutRunCommandStatement(t, raw)
			state.commands[statement.CommandID] = raw
			state.commandSubmits = append(state.commandSubmits, statement.Kind)
			if statement.Kind == "activation-canary" {
				result, capture := buildRolloutRunCanaryEvidence(
					t, fixture, run, 0, projection, statement.Payload,
					gatewayPublic, gatewayPrivate, receiptPublic, receiptPrivate, witnessPrivate,
				)
				state.canaryResult = &result
				state.captureExport = &capture
			}
			writeRolloutRunJSON(t, writer, rolloutRunControlCommand(
				statement, raw, prepared.RuntimeRef(), false, projection, state.canaryResult,
			))

		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/commands/"):
			commandID := filepath.Base(request.URL.Path)
			raw := state.commands[commandID]
			if len(raw) == 0 {
				http.NotFound(writer, request)
				return
			}
			statement := rolloutRunCommandStatement(t, raw)
			writeRolloutRunJSON(t, writer, rolloutRunControlCommand(
				statement, raw, prepared.RuntimeRef(), true, projection, state.canaryResult,
			))

		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/captures/"+rolloutCaptureID(run.plan, 0)):
			state.capturePolls++
			if state.capturePolls == 1 {
				writeRolloutRunJSON(t, writer, state.armed)
				return
			}
			writeRolloutRunJSON(t, writer, rolloutRunCaptureView(
				state.armed, *state.captureExport, controlstore.EvidenceCaptureObserved,
			))

		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/seal"):
			state.sealCalls++
			writeRolloutRunJSON(t, writer, rolloutRunCaptureView(
				state.armed, *state.captureExport, controlstore.EvidenceCaptureSealed,
			))

		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/export"):
			writeRolloutRunJSON(t, writer, state.captureExport)

		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	var output bytes.Buffer
	if err := runRollout(rolloutRunTestArguments(t, fixture, server.URL), &output); err != nil {
		t.Fatal(err)
	}
	state.Lock()
	if !slices.Equal(state.commandSubmits, []string{"admit", "start", "activation-canary"}) ||
		state.capturePolls != 2 || state.sealCalls != 1 {
		t.Fatalf("controller journey commands=%v capture_polls=%d seals=%d", state.commandSubmits, state.capturePolls, state.sealCalls)
	}
	state.Unlock()
	latest, count := rolloutRunLatestState(t, fixture.workspace)
	if latest.Phase != rollout.PhasePassed || count != 12 {
		t.Fatalf("fresh rollout latest=%#v count=%d", latest, count)
	}
	if _, err := os.Stat(filepath.Join(fixture.workspace, rolloutstore.ProofFileName)); err != nil {
		t.Fatalf("aggregate proof missing: %v", err)
	}
	var verifyOutput bytes.Buffer
	if err := verifyRollout(fixture.arguments, &verifyOutput); err != nil {
		t.Fatalf("offline verify fresh rollout: %v", err)
	}
}

func TestRolloutRunCompletedWorkspaceIsOfflineAndIdempotent(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	proofBefore := offlineRead(t, filepath.Join(fixture.workspace, rolloutstore.ProofFileName))

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	var output bytes.Buffer
	if err := runRollout(rolloutRunTestArguments(t, fixture, server.URL), &output); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("completed rollout contacted controller %d times", requests.Load())
	}
	if !bytes.Equal(
		proofBefore,
		offlineRead(t, filepath.Join(fixture.workspace, rolloutstore.ProofFileName)),
	) {
		t.Fatal("idempotent rollout run changed the aggregate proof")
	}
	var status rolloutStatusOutput
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Phase != rollout.PhasePassed || !status.Verified ||
		status.Verification != "authenticated_retained_progress" {
		t.Fatalf("completed rollout status=%#v", status)
	}
}

func TestRolloutRunRecoversActivationProofCrashWindowOffline(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	proofPath := rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetActivationProofKind)
	proofBefore := offlineRead(t, proofPath)
	truncateRolloutRunFixture(t, fixture.workspace, 10)
	removeRolloutRunFiles(t, proofPath, filepath.Join(fixture.workspace, rolloutstore.ProofFileName))

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	if err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("proof recovery contacted controller %d times", requests.Load())
	}
	if !bytes.Equal(proofBefore, offlineRead(t, proofPath)) {
		t.Fatal("proof recovery did not reproduce the exact activation proof")
	}
	aggregateAfter := offlineRead(t, filepath.Join(fixture.workspace, rolloutstore.ProofFileName))
	if err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	); err != nil {
		t.Fatalf("second proof recovery run: %v", err)
	}
	if !bytes.Equal(
		aggregateAfter,
		offlineRead(t, filepath.Join(fixture.workspace, rolloutstore.ProofFileName)),
	) {
		t.Fatal("second recovery run changed the recovered aggregate proof")
	}
	state, count := rolloutRunLatestState(t, fixture.workspace)
	if state.Phase != rollout.PhasePassed || count != 12 {
		t.Fatalf("recovered state=%#v count=%d", state, count)
	}
}

func TestRolloutRunReplaysExactAdmitAfterAmbiguousSubmitThenSticks(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	truncateRolloutRunFixture(t, fixture.workspace, 2)
	removeRolloutRunExecutionAfterAdmit(t, fixture.workspace)
	admitRaw := offlineRead(
		t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmitCommandKind),
	)
	statement := rolloutRunCommandStatement(t, admitRaw)
	plan := rolloutRunPlan(t, fixture.workspace)

	var mutex sync.Mutex
	var submitted [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/commands") {
			var input struct {
				Command string `json:"command_dsse_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode command submit: %v", err)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(input.Command)
			if err != nil {
				t.Errorf("decode submitted command: %v", err)
				return
			}
			mutex.Lock()
			submitted = append(submitted, append([]byte(nil), raw...))
			attempt := len(submitted)
			mutex.Unlock()
			if attempt == 1 {
				hijacker, ok := writer.(http.Hijacker)
				if !ok {
					t.Error("test server cannot simulate an ambiguous connection close")
					return
				}
				connection, _, err := hijacker.Hijack()
				if err != nil {
					t.Errorf("hijack submit connection: %v", err)
					return
				}
				_ = connection.Close()
				return
			}
			writeRolloutRunJSON(t, writer, rolloutRunFailedCommand(plan, statement, admitRaw))
			return
		}
		if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/commands/") {
			writeRolloutRunJSON(t, writer, rolloutRunFailedCommand(plan, statement, admitRaw))
			return
		}
		http.NotFound(writer, request)
	}))
	t.Cleanup(server.Close)
	arguments := rolloutRunTestArguments(t, fixture, server.URL)

	firstErr := runRollout(arguments, &bytes.Buffer{})
	if firstErr == nil || !strings.Contains(firstErr.Error(), "submit exact admit") {
		t.Fatalf("ambiguous submit error=%v", firstErr)
	}
	state, firstCount := rolloutRunLatestState(t, fixture.workspace)
	if state.Phase != rollout.PhaseEvidenceCaptureArmed || firstCount != 3 {
		t.Fatalf("ambiguous submit consumed state=%#v count=%d", state, firstCount)
	}

	var output bytes.Buffer
	secondErr := runRollout(arguments, &output)
	if secondErr == nil || !strings.Contains(secondErr.Error(), "admit command ended with failed") {
		t.Fatalf("terminal submit error=%v", secondErr)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(submitted) != 2 || !bytes.Equal(submitted[0], admitRaw) ||
		!bytes.Equal(submitted[1], admitRaw) {
		t.Fatalf("exact replay submissions=%d", len(submitted))
	}
	state, count := rolloutRunLatestState(t, fixture.workspace)
	if state.Phase != rollout.PhaseActionRequired ||
		state.ActionRequiredReason != reasonAdmitTerminal || count != 5 {
		t.Fatalf("sticky terminal state=%#v count=%d", state, count)
	}
}

func TestRolloutRunKeepsAuthenticationFailuresRetryable(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	truncateRolloutRunFixture(t, fixture.workspace, 2)
	removeRolloutRunExecutionAfterAdmit(t, fixture.workspace)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":"unauthorized","message":"bad operator token"}`))
	}))
	t.Cleanup(server.Close)

	before, beforeCount := rolloutRunLatestState(t, fixture.workspace)
	err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "control HTTP 401") {
		t.Fatalf("authentication error=%v", err)
	}
	after, afterCount := rolloutRunLatestState(t, fixture.workspace)
	if after != before || afterCount != beforeCount {
		t.Fatalf("retryable authentication failure changed state from %#v/%d to %#v/%d", before, beforeCount, after, afterCount)
	}
}

func TestExecuteVerifiedRolloutReportsEarlierStickyTargetBeforeLaterPlannedTarget(t *testing.T) {
	fixture := newRolloutVerifyTestFixtureTargets(t, 2)
	run := loadRolloutRunTestFixture(t, fixture)
	run.states[0].Phase = rollout.PhaseActionRequired
	run.states[0].ActionRequiredReason = reasonNodePreflightFailed
	if run.states[1].Phase != rollout.PhasePlanned {
		t.Fatalf("later target phase=%q, want planned", run.states[1].Phase)
	}

	var output bytes.Buffer
	err := executeVerifiedRollout(
		nil,
		&run,
		rolloutRunKeys{},
		nil,
		&output,
		true,
	)
	if err == nil || !strings.Contains(err.Error(), "sticky action_required") {
		t.Fatalf("retained action_required error=%v", err)
	}
	if strings.Contains(err.Error(), "clock precedes") {
		t.Fatalf("later planned target masked retained action_required: %v", err)
	}
	if !strings.Contains(output.String(), `"phase":"action_required"`) ||
		!strings.Contains(output.String(), `"total_targets":2`) {
		t.Fatalf("retained action_required status=%q", output.String())
	}
}

func TestExecuteVerifiedRolloutRejectsClockRollbackAfterAuthorizationBeforeSigning(t *testing.T) {
	fixture := newRolloutVerifyTestFixture(t)
	run := loadRolloutRunTestFixture(t, fixture)
	authorizedAt := timeNow().UTC().Add(time.Second)
	keys := rolloutRunKeys{
		authorizationContextDigest: dsse.Digest([]byte("signed-plan-authorization")),
		authorizationContextTime:   authorizedAt,
	}

	var output bytes.Buffer
	err := executeVerifiedRollout(nil, &run, keys, nil, &output, true)
	if err == nil || !strings.Contains(err.Error(), "clock precedes the active rollout authorization") {
		t.Fatalf("post-authorization clock rollback error=%v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("post-authorization clock rollback emitted output %q", output.String())
	}
	if _, err := os.Stat(rolloutRunTargetPathFor(
		t, fixture.workspace, 0, rolloutstore.TargetAdmitCommandKind,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-authorization clock rollback wrote a command: %v", err)
	}
}

func TestRolloutCommandConflictReasonsRemainPhaseSpecific(t *testing.T) {
	for kind, want := range map[string]string{
		"admit":             reasonAdmitConflict,
		"start":             reasonStartConflict,
		"activation-canary": reasonCanaryConflict,
	} {
		if got := rolloutCommandConflictReason(kind); got != want {
			t.Fatalf("kind %q conflict reason=%q, want %q", kind, got, want)
		}
	}
}

func TestRolloutRunMakesStoredCommandExpiryStickyWithoutControllerContact(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	truncateRolloutRunFixture(t, fixture.workspace, 2)
	removeRolloutRunExecutionAfterAdmit(t, fixture.workspace)
	admitRaw := offlineRead(
		t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmitCommandKind),
	)
	statement := rolloutRunCommandStatement(t, admitRaw)
	expires, err := time.Parse(time.RFC3339Nano, statement.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	previousNow := timeNow
	timeNow = func() time.Time { return expires.Add(time.Nanosecond) }
	t.Cleanup(func() { timeNow = previousNow })

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	err = runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "stored rollout command authority expired") {
		t.Fatalf("expired command error=%v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expired command contacted controller %d times", requests.Load())
	}
	state, count := rolloutRunLatestState(t, fixture.workspace)
	if state.Phase != rollout.PhaseActionRequired ||
		state.ActionRequiredReason != reasonPhaseTimeout || count != 4 {
		t.Fatalf("expired command state=%#v count=%d", state, count)
	}
}

func TestRolloutRunRejectsOutOfPlanInventoryBeforeControllerContact(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	extra, err := rolloutstore.TargetArtifactName(1, rolloutstore.TargetAdmissionKind)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.workspace, extra), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	err = runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "outside the plan") {
		t.Fatalf("out-of-plan inventory error=%v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("hostile inventory contacted controller %d times", requests.Load())
	}
}

func TestNodeSupportsRolloutRequiresAllProtocolFourCapabilities(t *testing.T) {
	base := controlclient.Node{
		NodeID: "node-a", TenantIDs: []string{"tenant-a"}, State: "active",
		Capabilities: []string{
			controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
			controlprotocol.ExecutorCapabilityActivationCanaryV1,
			controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
		},
	}
	if !nodeSupportsRollout(base, "tenant-a", false) {
		t.Fatal("fully capable active tenant node was rejected")
	}
	for _, missing := range []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityActivationCanaryV1,
		controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
	} {
		node := base
		node.Capabilities = slices.DeleteFunc(
			append([]string(nil), base.Capabilities...),
			func(capability string) bool { return capability == missing },
		)
		if nodeSupportsRollout(node, "tenant-a", false) {
			t.Fatalf("node missing %q was accepted", missing)
		}
	}
	if nodeSupportsRollout(base, "tenant-a", true) {
		t.Fatal("authorized-effects rollout accepted a node without the capability")
	}
	base.Capabilities = append(
		base.Capabilities,
		controlprotocol.ExecutorCapabilityAuthorizedEffectsV1,
	)
	if !nodeSupportsRollout(base, "tenant-a", true) {
		t.Fatal("authorized-effects capable node was rejected")
	}
}

func TestRolloutRunRejectsExpiredCaptureReplayBeforeSigningOrSubmit(t *testing.T) {
	fixture := newRolloutRunPlannedFixture(t)
	run := loadRolloutRunTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	target := prepared.Target()
	receiptPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var commandSubmits atomic.Int32
	var armMutex sync.Mutex
	var armBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/nodes/"+target.NodeID):
			writeRolloutRunJSON(t, writer, controlclient.Node{
				NodeID: target.NodeID, TenantIDs: []string{run.plan.TenantID}, State: "active",
				Capabilities: []string{
					controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
					controlprotocol.ExecutorCapabilityActivationCanaryV1,
					controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
				},
			})
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/captures"):
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var input struct {
				CaptureID             string `json:"capture_id"`
				RequestID             string `json:"request_id"`
				TenantID              string `json:"tenant_id"`
				RuntimeRef            string `json:"runtime_ref"`
				Generation            uint64 `json:"generation"`
				ActivationID          string `json:"activation_id"`
				ActivationBeginDigest string `json:"activation_begin_digest"`
				TTLSeconds            int64  `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.CaptureID != rolloutCaptureID(run.plan, 0) ||
				input.RequestID != rolloutCaptureRequestID(run.plan, 0) ||
				input.TenantID != run.plan.TenantID || input.RuntimeRef != prepared.RuntimeRef() ||
				input.Generation != target.InstanceGeneration ||
				input.ActivationID != target.ActivationID ||
				input.ActivationBeginDigest != prepared.ExecutorBeginDigest() {
				t.Errorf("capture arm request changed deterministic target: %#v", input)
			}
			armMutex.Lock()
			armBodies = append(armBodies, append([]byte(nil), raw...))
			attempt := len(armBodies)
			armMutex.Unlock()
			if attempt == 1 {
				hijacker, ok := writer.(http.Hijacker)
				if !ok {
					t.Fatal("test server cannot simulate an ambiguous capture arm")
				}
				connection, _, err := hijacker.Hijack()
				if err != nil {
					t.Fatal(err)
				}
				_ = connection.Close()
				return
			}
			armed, _ := time.Parse(time.RFC3339Nano, run.plan.CreatedAt)
			expires := armed.Add(time.Duration(input.TTLSeconds) * time.Second)
			head := controlprotocol.ExecutorEvidenceHeadV1{
				Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: target.NodeID,
				ReceiptEpoch: 1, ChainHash: "sha256:" + strings.Repeat("0", 64),
				PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
			}
			writeRolloutRunJSON(t, writer, controlstore.EvidenceCapture{
				CaptureID: input.CaptureID, RequestID: input.RequestID, NodeID: target.NodeID,
				TenantID: input.TenantID, RuntimeRef: input.RuntimeRef, Generation: input.Generation,
				ActivationID: input.ActivationID, ActivationBeginDigest: input.ActivationBeginDigest,
				State: controlstore.EvidenceCaptureExpired, BaselineHead: head, FinalHead: head,
				ArmedAt: armed.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano),
				ExpiredAt: expires.Format(time.RFC3339Nano),
			})
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/commands"):
			commandSubmits.Add(1)
			http.Error(writer, "unexpected command", http.StatusInternalServerError)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	arguments := rolloutRunTestArguments(t, fixture, server.URL)
	firstErr := runRollout(arguments, &bytes.Buffer{})
	if firstErr == nil || !strings.Contains(firstErr.Error(), "arm rollout evidence capture") {
		t.Fatalf("ambiguous capture arm error=%v", firstErr)
	}
	firstState, firstCount := rolloutRunLatestState(t, fixture.workspace)
	if firstState.Phase != rollout.PhasePreflightPassed || firstCount != 2 {
		t.Fatalf("ambiguous capture arm consumed state=%#v count=%d", firstState, firstCount)
	}
	err = runRollout(arguments, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "fixed unexpired expiry") {
		t.Fatalf("expired capture replay error=%v", err)
	}
	if commandSubmits.Load() != 0 {
		t.Fatalf("expired capture replay submitted %d commands", commandSubmits.Load())
	}
	armMutex.Lock()
	if len(armBodies) != 2 || !bytes.Equal(armBodies[0], armBodies[1]) {
		t.Fatalf("capture arm retry changed exact request across %d attempts", len(armBodies))
	}
	armMutex.Unlock()
	if _, err := os.Stat(rolloutRunTargetPath(
		t, fixture.workspace, rolloutstore.TargetAdmitCommandKind,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired capture replay wrote an admit command: %v", err)
	}
	state, count := rolloutRunLatestState(t, fixture.workspace)
	if state.Phase != rollout.PhaseActionRequired ||
		state.ActionRequiredReason != reasonCaptureArmConflict || count != 3 {
		t.Fatalf("expired capture replay state=%#v count=%d", state, count)
	}
}

func TestRolloutCaptureCorrelationBindsDeterministicIDAndAdmissionEvidenceKey(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutRunTestFixture(t, fixture)
	store, err := rolloutstore.Open(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	keys := rolloutRunTestKeys(t, fixture)
	if err := verifyRetainedRolloutExecution(store, &run, keys); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	capture, err := controlcapture.VerifyJSONV1(run.targets[0].captureRaw, run.witnessPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := correlateRolloutCapture(&run.targets[0], capture); err != nil {
		t.Fatalf("valid capture correlation: %v", err)
	}
	wrongID := capture
	wrongID.Statement.CaptureID = "capture-substituted"
	if err := correlateRolloutCapture(&run.targets[0], wrongID); err == nil ||
		!strings.Contains(err.Error(), "prepared target") {
		t.Fatalf("substituted capture ID error=%v", err)
	}
	wrongKey := run.targets[0]
	projection := *wrongKey.admission
	projection.EvidenceKeyID = strings.Repeat("f", 32)
	wrongKey.admission = &projection
	if err := correlateRolloutCapture(&wrongKey, capture); err == nil ||
		!strings.Contains(err.Error(), "different Executor evidence identity") {
		t.Fatalf("substituted evidence key error=%v", err)
	}
}

func TestRolloutRunAuthenticatesArchiveAndCanonicalRetainedJSONBeforeController(t *testing.T) {
	t.Run("release archive mismatch", func(t *testing.T) {
		fixture := newRolloutRunPlannedFixture(t)
		planPath := filepath.Join(fixture.workspace, rolloutstore.PlanFileName)
		plan := rolloutRunPlan(t, fixture.workspace)
		plan.Archive.Digest = dsse.Digest([]byte("different-release-archive"))
		planRaw, err := rollout.MarshalPlanV1(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		statePath, err := rolloutstore.TargetStateName(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		stateRaw := offlineRead(t, filepath.Join(fixture.workspace, statePath))
		state, err := rollout.ParseTargetStateV1(stateRaw)
		if err != nil {
			t.Fatal(err)
		}
		state.Binding.PlanDigest = dsse.Digest(planRaw)
		stateRaw, err = rollout.MarshalTargetStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.workspace, statePath), stateRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRolloutRunPreNetworkError(t, fixture, "archive differs from the authenticated release")
	})

	t.Run("noncanonical state", func(t *testing.T) {
		fixture := newRolloutRunPlannedFixture(t)
		stateName, err := rolloutstore.TargetStateName(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixture.workspace, stateName)
		if err := os.WriteFile(path, append(offlineRead(t, path), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRolloutRunPreNetworkError(t, fixture, "not canonical JSON")
	})

	t.Run("noncanonical aggregate proof", func(t *testing.T) {
		fixture := newRolloutRunCompleteFixture(t)
		path := filepath.Join(fixture.workspace, rolloutstore.ProofFileName)
		if err := os.WriteFile(path, append(offlineRead(t, path), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRolloutRunPreNetworkError(t, fixture, "aggregate rollout proof is not canonical JSON")
	})
}

func TestRolloutBatchContainingKeepsCanaryAloneAndUsesRealBatchSize(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	plan := rolloutRunPlan(t, fixture.workspace)
	base := plan.Targets[0]
	for index := 1; index < 5; index++ {
		target := base
		target.NodeID = "node-" + string(rune('a'+index))
		target.InstanceID = "hermes-" + string(rune('a'+index))
		target.ActivationID = "activation-" + string(rune('a'+index))
		target.AdmitCommandID, target.StartCommandID, target.CanaryCommandID =
			rollout.TargetCommandIDsV1(plan.RolloutID, index, target.NodeID)
		plan.Targets = append(plan.Targets, target)
	}
	plan.BatchSize = 2

	tests := []struct {
		target     int
		wantNumber uint16
		wantStart  int
		wantEnd    int
	}{
		{target: 0, wantNumber: 0, wantStart: 0, wantEnd: 1},
		{target: 1, wantNumber: 1, wantStart: 1, wantEnd: 3},
		{target: 2, wantNumber: 1, wantStart: 1, wantEnd: 3},
		{target: 3, wantNumber: 2, wantStart: 3, wantEnd: 5},
	}
	for _, test := range tests {
		batch, err := rolloutBatchContaining(plan, test.target)
		if err != nil {
			t.Fatalf("target %d: %v", test.target, err)
		}
		if batch.Number != test.wantNumber || batch.Start != test.wantStart || batch.End != test.wantEnd {
			t.Fatalf("target %d batch=%#v", test.target, batch)
		}
	}
	states := make([]rollout.TargetStateV1, len(plan.Targets))
	for index := range states {
		states[index].Phase = rollout.PhasePlanned
	}
	pending, err := rolloutCurrentBatchTargets(plan, states)
	if err != nil || !slices.Equal(pending, []int{0}) {
		t.Fatalf("first invocation targets=%v error=%v, want canary only", pending, err)
	}
	states[0].Phase = rollout.PhasePassed
	pending, err = rolloutCurrentBatchTargets(plan, states)
	if err != nil || !slices.Equal(pending, []int{1, 2}) {
		t.Fatalf("second invocation targets=%v error=%v, want first real batch", pending, err)
	}
	states[1].Phase = rollout.PhasePassed
	pending, err = rolloutCurrentBatchTargets(plan, states)
	if err != nil || !slices.Equal(pending, []int{2}) {
		t.Fatalf("resumed batch targets=%v error=%v, want unfinished member only", pending, err)
	}
	states[2].Phase = rollout.PhasePassed
	pending, err = rolloutCurrentBatchTargets(plan, states)
	if err != nil || !slices.Equal(pending, []int{3, 4}) {
		t.Fatalf("later invocation targets=%v error=%v, want later batch untouched until promotion", pending, err)
	}
}

func newRolloutRunCompleteFixture(t *testing.T) rolloutVerifyTestFixture {
	t.Helper()
	previousNow := timeNow
	fixture := completeRolloutVerifyTestFixture(t, newRolloutVerifyTestFixture(t))
	t.Cleanup(func() { timeNow = previousNow })
	return fixture
}

func newRolloutRunPlannedFixture(t *testing.T) rolloutVerifyTestFixture {
	t.Helper()
	previousNow := timeNow
	fixture := newRolloutVerifyTestFixture(t)
	t.Cleanup(func() { timeNow = previousNow })
	return fixture
}

func loadRolloutRunTestFixture(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
) verifiedRolloutRun {
	t.Helper()
	publisher, err := readPublicKey(rolloutVerifyArgumentValue(
		t, fixture.arguments, "-publisher-public-key",
	))
	if err != nil {
		t.Fatal(err)
	}
	siteRoot, err := readPublicKey(rolloutVerifyArgumentValue(
		t, fixture.arguments, "-site-root-public-key",
	))
	if err != nil {
		t.Fatal(err)
	}
	witness, err := controlwitness.LoadPublic(rolloutVerifyArgumentValue(
		t, fixture.arguments, "-witness-public-key",
	))
	if err != nil {
		t.Fatal(err)
	}
	store, err := rolloutstore.Open(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	run, loadErr := loadVerifiedRolloutRun(
		store, "publisher-a", publisher, "site-root", siteRoot, witness,
	)
	closeErr := store.Close()
	if loadErr != nil || closeErr != nil {
		t.Fatal(errors.Join(loadErr, closeErr))
	}
	return run
}

func rolloutRunSubmittedCommand(t *testing.T, request *http.Request) []byte {
	t.Helper()
	var input struct {
		Command string `json:"command_dsse_base64"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(input.Command)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != input.Command {
		t.Fatalf("submitted command is not canonical base64: %v", err)
	}
	return raw
}

func buildRolloutRunCanaryEvidence(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	run verifiedRolloutRun,
	targetIndex uint16,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
	canaryRaw []byte,
	gatewayPublic ed25519.PublicKey,
	gatewayPrivate ed25519.PrivateKey,
	receiptPublic ed25519.PublicKey,
	receiptPrivate ed25519.PrivateKey,
	witnessPrivate ed25519.PrivateKey,
) (controlprotocol.ExecutorActivationCanaryResultV1, controlprotocol.ControllerEvidenceCaptureV1) {
	t.Helper()
	prepared := run.targets[targetIndex].prepared
	target := prepared.Target()
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		canaryRaw,
		activationcanary.AdmissionContextV1{
			NodeID: target.NodeID, TenantID: run.plan.TenantID,
			InstanceID: target.InstanceID, Projection: projection,
		},
		rolloutCommandMaximumValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	terminal := offlineHermesResult(t, target.ActivationID)
	receipts := rolloutVerifyGatewayReceipts(
		t, verifiedCommand, terminal,
		target.GatewayReceiptEpoch, gatewayPublic, gatewayPrivate,
	)
	verifiedEvidence, err := activationcanary.VerifyEvidenceV1(
		verifiedCommand, "run_0123456789abcdef0123456789abcdef",
		terminal, receipts, gatewayPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRaw, err := activationcanary.BuildCheckpointV1(verifiedCommand, verifiedEvidence)
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, verifiedResult, err := activationcanary.BuildResultV1(
		verifiedCommand, "run_0123456789abcdef0123456789abcdef",
		terminal, receipts, checkpointRaw, gatewayPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	var result controlprotocol.ExecutorActivationCanaryResultV1
	if err := dsse.DecodeStrictInto(
		resultRaw, controlprotocol.MaxExecutorActivationCanaryResultBytes, &result,
	); err != nil {
		t.Fatal(err)
	}
	captureRaw := rolloutVerifyControllerCapture(
		t, run.plan, targetIndex, prepared, projection, checkpointRaw,
		verifiedResult.Gateway(), receiptPublic, receiptPrivate, witnessPrivate,
	)
	var capture controlprotocol.ControllerEvidenceCaptureV1
	if err := dsse.DecodeStrictInto(
		captureRaw, controlprotocol.MaxControllerEvidenceCaptureJSONBytes, &capture,
	); err != nil {
		t.Fatal(err)
	}
	return result, capture
}

func rolloutRunControlCommand(
	statement admission.CommandStatement,
	raw []byte,
	executorRuntimeRef string,
	terminal bool,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
	canaryResult *controlprotocol.ExecutorActivationCanaryResultV1,
) controlclient.Command {
	command := controlclient.Command{
		CommandID: statement.CommandID, TenantID: statement.TenantID, NodeID: statement.NodeID,
		CommandDigest: dsse.Digest(raw), CommandKind: statement.Kind,
		SignedRuntimeRef:         statement.RuntimeRef,
		SignedClaimGeneration:    statement.ClaimGeneration,
		SignedInstanceGeneration: statement.InstanceGeneration,
		State:                    string(controlstore.CommandPending), DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
	}
	if !terminal {
		return command
	}
	claim := statement.ClaimGeneration
	command.State = string(controlstore.CommandTerminal)
	command.TerminalStatus = controlprotocol.ExecutorStatusDone
	command.ClaimGeneration = &claim
	command.Result = &controlclient.CommandResult{RuntimeRef: executorRuntimeRef}
	switch statement.Kind {
	case "admit":
		command.ReportedStatus = "stopped"
		command.AdmissionProjectionState = "present"
		command.Result.Admission = &projection
	case "start":
		command.ReportedStatus = "running"
	case "activation-canary":
		command.ReportedStatus = "running"
		command.ActivationCanaryProjectionState = "present"
		command.Result.ActivationCanary = canaryResult
	}
	return command
}

func rolloutRunCaptureView(
	armed controlstore.EvidenceCapture,
	capture controlprotocol.ControllerEvidenceCaptureV1,
	state controlstore.EvidenceCaptureState,
) controlstore.EvidenceCapture {
	statement := capture.Statement
	view := armed
	view.State = state
	view.BaselineHead = statement.BaselineHead
	view.FinalHead = statement.FinalHead
	view.FrameCount = int(statement.FrameCount)
	view.CapturedBytes = 1
	view.ActivationBeginSequence = statement.ActivationBeginSequence
	view.CapsuleDigest = statement.CapsuleDigest
	view.PolicyDigest = statement.PolicyDigest
	view.ActivationCheckpointDigest = statement.ActivationCheckpointDigest
	view.ObservedAt = statement.ObservedAt
	if state == controlstore.EvidenceCaptureSealed {
		view.CanaryCommandID = statement.CanaryCommandID
		view.SealedAt = statement.SealedAt
	}
	return view
}

func rolloutRunTestArguments(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	controlURL string,
) []string {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("rollout-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{
		"-dir", fixture.workspace,
		"-publisher-public-key", rolloutVerifyArgumentValue(t, fixture.arguments, "-publisher-public-key"),
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", rolloutVerifyArgumentValue(t, fixture.arguments, "-site-root-public-key"),
		"-site-root-key-id", "site-root",
		"-witness-public-key", rolloutVerifyArgumentValue(t, fixture.arguments, "-witness-public-key"),
		"-command-private-key", fixture.commandPrivatePath,
		"-command-key-id", fixture.commandKeyID,
		"-task-private-key", fixture.taskPrivatePath,
		"-task-key-id", fixture.taskKeyID,
		"-control-url", controlURL,
		"-token-file", tokenPath,
		"-json",
	}
}

func rolloutRunTestKeys(t *testing.T, fixture rolloutVerifyTestFixture) rolloutRunKeys {
	t.Helper()
	commandPrivate, err := readPrivateKey(fixture.commandPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	taskPrivate, err := readPrivateKey(fixture.taskPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	return rolloutRunKeys{
		commandID: fixture.commandKeyID, commandPrivate: commandPrivate,
		commandPublic: commandPrivate.Public().(ed25519.PublicKey),
		taskID:        fixture.taskKeyID, taskPrivate: taskPrivate,
		taskPublic: taskPrivate.Public().(ed25519.PublicKey),
	}
}

func assertRolloutRunPreNetworkError(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	want string,
) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("rollout run error=%v, want fragment %q", err, want)
	}
	if requests.Load() != 0 {
		t.Fatalf("pre-network rejection contacted controller %d times", requests.Load())
	}
}

func truncateRolloutRunFixture(t *testing.T, workspace string, keepSequence int) {
	t.Helper()
	store, err := rolloutstore.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	names, err := store.ListTargetStates(0)
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	for sequence, name := range names {
		if sequence > keepSequence {
			removeRolloutRunFiles(t, filepath.Join(workspace, name))
		}
	}
}

func removeRolloutRunExecutionAfterAdmit(t *testing.T, workspace string) {
	t.Helper()
	for _, kind := range []string{
		rolloutstore.TargetAdmissionKind,
		rolloutstore.TargetStartCommandKind,
		rolloutstore.TargetCanaryCommandKind,
		rolloutstore.TargetCanaryResultKind,
		rolloutstore.TargetCaptureExportKind,
		rolloutstore.TargetActivationStateKind,
		rolloutstore.TargetActivationProofKind,
	} {
		removeRolloutRunFiles(t, rolloutRunTargetPath(t, workspace, kind))
	}
	removeRolloutRunFiles(t, filepath.Join(workspace, rolloutstore.ProofFileName))
}

func removeRolloutRunFiles(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func rolloutRunLatestState(t *testing.T, workspace string) (rollout.TargetStateV1, int) {
	t.Helper()
	store, err := rolloutstore.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	names, err := store.ListTargetStates(0)
	if err != nil || len(names) == 0 {
		_ = store.Close()
		t.Fatal(errors.Join(err, errors.New("rollout target state chain is empty")))
	}
	raw, err := store.Read(names[len(names)-1], rollout.MaxTargetStateBytes)
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	state, err := rollout.ParseTargetStateV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return state, len(names)
}

func rolloutRunPlan(t *testing.T, workspace string) rollout.PlanV1 {
	t.Helper()
	raw := offlineRead(t, filepath.Join(workspace, rolloutstore.PlanFileName))
	plan, err := rollout.ParsePlanV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func rolloutRunTargetPath(t *testing.T, workspace, kind string) string {
	t.Helper()
	name, err := rolloutstore.TargetArtifactName(0, kind)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(workspace, name)
}

func rolloutRunCommandStatement(t *testing.T, raw []byte) admission.CommandStatement {
	t.Helper()
	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		t.Fatal(err)
	}
	return statement
}

func rolloutRunFailedCommand(
	plan rollout.PlanV1,
	statement admission.CommandStatement,
	raw []byte,
) controlclient.Command {
	return controlclient.Command{
		CommandID: statement.CommandID, TenantID: plan.TenantID, NodeID: statement.NodeID,
		CommandDigest: dsse.Digest(raw), CommandKind: statement.Kind,
		SignedRuntimeRef:         statement.RuntimeRef,
		SignedClaimGeneration:    statement.ClaimGeneration,
		SignedInstanceGeneration: statement.InstanceGeneration,
		State:                    string(controlstore.CommandTerminal), DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
		TerminalStatus: "failed", ReportedStatus: "failed", ErrorCode: "test_failure",
	}
}

func writeRolloutRunJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("write test response: %v", err)
	}
}
