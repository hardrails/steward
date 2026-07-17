package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

func TestWaitRolloutCommandClassifiesControllerAndTerminalFailures(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	raw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, "admit-command.dsse.json"))
	statement := rolloutRunCommandStatement(t, raw)
	validPending := rolloutRunControlCommand(
		statement, raw, prepared.RuntimeRef(), false,
		controlprotocol.ExecutorAdmissionProjectionV1{}, nil,
	)
	projection, err := parseCanonicalRolloutAdmission(run.targets[0].admissionRaw)
	if err != nil {
		t.Fatal(err)
	}
	validDone := rolloutRunControlCommand(
		statement, raw, prepared.RuntimeRef(), true,
		projection, nil,
	)
	validFailed := validPending
	validFailed.State = string(controlstore.CommandTerminal)
	validFailed.TerminalStatus = "failed"

	tests := []struct {
		name       string
		kind       string
		status     int
		command    controlclient.Command
		deadline   time.Time
		wantReason string
		want       string
		wantOK     bool
	}{
		{name: "expired deadline", kind: "admit", deadline: timeNow().UTC(), wantReason: reasonPhaseTimeout, want: "deadline expired"},
		{name: "permanent controller conflict", kind: "admit", status: http.StatusConflict, deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonAdmitConflict, want: "control HTTP 409"},
		{name: "retryable controller failure", kind: "admit", status: http.StatusInternalServerError, deadline: timeNow().UTC().Add(time.Minute), want: "observe admit rollout command"},
		{name: "projection substitution", kind: "admit", command: func() controlclient.Command {
			value := validPending
			value.CommandDigest = dsse.Digest([]byte("substituted"))
			return value
		}(), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonAdmitConflict, want: "projection differs"},
		{name: "admit terminal failure", kind: "admit", command: validFailed, deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonAdmitTerminal, want: "admit command ended"},
		{name: "start terminal failure", kind: "start", command: commandForKind(validFailed, prepared, raw, "start", "failed"), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonStartTerminal, want: "start command ended"},
		{name: "canary terminal failure", kind: "activation-canary", command: commandForKind(validFailed, prepared, raw, "activation-canary", "failed"), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonCanaryTerminal, want: "activation-canary command ended"},
		{name: "unknown state", kind: "admit", command: func() controlclient.Command { value := validPending; value.State = "invented"; return value }(), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonAdmitConflict, want: "unknown controller state"},
		{name: "terminal success", kind: "admit", command: validDone, deadline: timeNow().UTC().Add(time.Minute), wantOK: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := rolloutResponseClient(t, test.status, test.command)
			got, err := waitRolloutCommand(client, run.plan, prepared, raw, test.kind, test.deadline)
			if test.wantOK {
				if err != nil || got.State != string(controlstore.CommandTerminal) {
					t.Fatalf("successful terminal command=(%#v, %v)", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
			var sticky *rolloutStickyError
			if test.wantReason != "" {
				if !errors.As(err, &sticky) || sticky.reason != test.wantReason {
					t.Fatalf("sticky error=%#v, want reason %q", sticky, test.wantReason)
				}
			} else if errors.As(err, &sticky) {
				t.Fatalf("retryable error became sticky: %#v", sticky)
			}
		})
	}
}

func TestWaitRolloutCommandPendingPollFailureIsSticky(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	raw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, "admit-command.dsse.json"))
	statement := rolloutRunCommandStatement(t, raw)
	pending := rolloutRunControlCommand(statement, raw, prepared.RuntimeRef(), false, controlprotocol.ExecutorAdmissionProjectionV1{}, nil)
	client := rolloutResponseClient(t, http.StatusOK, pending)
	previousSleep := rolloutPollSleep
	rolloutPollSleep = func(context.Context, time.Duration) error { return context.Canceled }
	t.Cleanup(func() { rolloutPollSleep = previousSleep })
	_, err := waitRolloutCommand(client, run.plan, prepared, raw, "admit", timeNow().UTC().Add(time.Minute))
	var sticky *rolloutStickyError
	if !errors.As(err, &sticky) || sticky.reason != reasonPhaseTimeout || !errors.Is(err, context.Canceled) {
		t.Fatalf("pending poll error=%v", err)
	}
}

func TestWaitRolloutEvidenceCaptureRejectsChangedOrFailedCapture(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	valid := rolloutTestCaptureProjection(t, run, controlstore.EvidenceCaptureObserved)
	tests := []struct {
		name       string
		status     int
		capture    controlstore.EvidenceCapture
		deadline   time.Time
		wantReason string
		want       string
		wantOK     bool
	}{
		{name: "expired deadline", deadline: timeNow().UTC(), wantReason: reasonPhaseTimeout, want: "publication deadline expired"},
		{name: "permanent missing capture", status: http.StatusNotFound, deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonEvidenceInvalid, want: "control HTTP 404"},
		{name: "retryable server failure", status: http.StatusInternalServerError, deadline: timeNow().UTC().Add(time.Minute), want: "observe rollout evidence capture"},
		{name: "changed binding", capture: func() controlstore.EvidenceCapture {
			value := valid
			value.RuntimeRef = "executor-" + strings.Repeat("f", 64)
			return value
		}(), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonEvidenceInvalid, want: "changed its prepared target binding"},
		{name: "failed", capture: rolloutTestCaptureProjection(t, run, controlstore.EvidenceCaptureFailed), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonEvidenceInvalid, want: "ended in failed"},
		{name: "expired", capture: rolloutTestCaptureProjection(t, run, controlstore.EvidenceCaptureExpired), deadline: timeNow().UTC().Add(time.Minute), wantReason: reasonEvidenceInvalid, want: "ended in expired"},
		{name: "observed", capture: valid, deadline: timeNow().UTC().Add(time.Minute), wantOK: true},
		{name: "sealed", capture: rolloutTestCaptureProjection(t, run, controlstore.EvidenceCaptureSealed), deadline: timeNow().UTC().Add(time.Minute), wantOK: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := rolloutResponseClient(t, test.status, test.capture)
			got, err := waitRolloutEvidenceCapture(client, run.plan, prepared, test.deadline)
			if test.wantOK {
				if err != nil || got.State != test.capture.State {
					t.Fatalf("successful capture=(%#v, %v)", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
			var sticky *rolloutStickyError
			if test.wantReason != "" {
				if !errors.As(err, &sticky) || sticky.reason != test.wantReason {
					t.Fatalf("sticky error=%#v, want reason %q", sticky, test.wantReason)
				}
			} else if errors.As(err, &sticky) {
				t.Fatalf("retryable error became sticky: %#v", sticky)
			}
		})
	}
}

func TestWaitRolloutEvidenceCaptureArmedPollFailureIsSticky(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	armed := rolloutTestCaptureProjection(t, run, controlstore.EvidenceCaptureArmed)
	client := rolloutResponseClient(t, http.StatusOK, armed)
	previousSleep := rolloutPollSleep
	rolloutPollSleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	t.Cleanup(func() { rolloutPollSleep = previousSleep })
	_, err := waitRolloutEvidenceCapture(client, run.plan, prepared, timeNow().UTC().Add(time.Minute))
	var sticky *rolloutStickyError
	if !errors.As(err, &sticky) || sticky.reason != reasonPhaseTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("armed poll error=%v", err)
	}
}

func TestRolloutExecutionValidationUtilitiesFailClosed(t *testing.T) {
	fixture := newRolloutRunCompleteFixture(t)
	run := loadRolloutExecutionTestFixture(t, fixture)
	prepared := run.targets[0].prepared
	raw := offlineRead(t, rolloutRunTargetPath(t, fixture.workspace, "admit-command.dsse.json"))
	statement := rolloutRunCommandStatement(t, raw)
	valid := rolloutRunControlCommand(statement, raw, prepared.RuntimeRef(), false, controlprotocol.ExecutorAdmissionProjectionV1{}, nil)

	if (&rolloutStickyError{}).Error() != "rollout requires operator action" || (*rolloutStickyError)(nil).Error() != "rollout requires operator action" {
		t.Fatal("nil sticky errors must retain a safe diagnostic")
	}
	cause := errors.New("exact failure")
	sticky := &rolloutStickyError{reason: reasonAdmitConflict, cause: cause}
	if sticky.Error() != cause.Error() || !errors.Is(sticky, cause) {
		t.Fatalf("sticky error did not preserve cause: %v", sticky)
	}
	for _, kind := range []string{"admit", "start", "activation-canary"} {
		if preparedCommandID(prepared, kind) == "" {
			t.Fatalf("prepared command id missing for %q", kind)
		}
	}
	if preparedCommandID(prepared, "unknown") != "" {
		t.Fatal("unknown command kind acquired authority")
	}

	wrongProtocol := valid
	wrongProtocol.DeliveryProtocol = 3
	if err := validateRolloutControlCommand(wrongProtocol, run.plan, prepared, raw, "admit"); err == nil || !strings.Contains(err.Error(), "non-protocol-4") {
		t.Fatalf("wrong protocol error=%v", err)
	}
	for _, mutate := range []func(*controlclient.Command){
		func(value *controlclient.Command) { value.CommandID = "wrong" },
		func(value *controlclient.Command) { value.TenantID = "wrong" },
		func(value *controlclient.Command) { value.NodeID = "wrong" },
		func(value *controlclient.Command) { value.CommandDigest = "sha256:" + strings.Repeat("0", 64) },
		func(value *controlclient.Command) { value.CommandKind = "start" },
		func(value *controlclient.Command) { value.SignedRuntimeRef = "wrong" },
		func(value *controlclient.Command) { value.SignedClaimGeneration++ },
		func(value *controlclient.Command) { value.SignedInstanceGeneration++ },
	} {
		changed := valid
		mutate(&changed)
		if err := validateRolloutControlCommand(changed, run.plan, prepared, raw, "admit"); err == nil {
			t.Fatal("changed command projection was accepted")
		}
	}

	now := timeNow().UTC()
	if _, _, err := rolloutControlContext(now); err == nil {
		t.Fatal("expired control context accepted")
	}
	ctx, cancel, err := rolloutControlContext(now.Add(time.Second))
	if err != nil || ctx == nil || cancel == nil {
		t.Fatalf("live control context=(%v, %v)", ctx, err)
	}
	cancel()
	if rolloutPermanentControlError(errors.New("transport")) {
		t.Fatal("transport error became permanent")
	}
	for _, status := range []int{http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusUnprocessableEntity} {
		if !rolloutPermanentControlError(&controlclient.APIError{Status: status}) {
			t.Fatalf("status %d was not permanent", status)
		}
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		if rolloutPermanentControlError(&controlclient.APIError{Status: status}) {
			t.Fatalf("status %d became permanent", status)
		}
	}

	badPlan := run.plan
	badPlan.Deadline = now.Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := rolloutPhaseDeadlineFromNow(badPlan, 1); err == nil {
		t.Fatal("expired global deadline accepted")
	}
	if _, err := rolloutPhaseDeadlineFromNow(run.plan, 0); err == nil {
		t.Fatal("zero phase timeout accepted")
	}
	state := run.states[0]
	state.UpdatedAt = "invalid"
	if _, err := rolloutTargetPhaseDeadline(run.plan, state, 1); err == nil {
		t.Fatal("invalid phase checkpoint time accepted")
	}
	state.UpdatedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := rolloutTargetPhaseDeadline(run.plan, state, 1); err == nil {
		t.Fatal("expired fixed phase deadline accepted")
	}

	if _, err := rolloutStoredCommandDeadline(nil, false); err == nil {
		t.Fatal("missing retained command accepted")
	}
	if _, err := rolloutStoredCommandDeadline([]byte("not dsse"), false); err == nil {
		t.Fatal("malformed retained command accepted")
	}
	if _, err := rolloutBatchContaining(run.plan, len(run.plan.Targets)); err == nil {
		t.Fatal("out-of-range target acquired a deterministic batch")
	}
	if _, err := rolloutCurrentBatchTargets(run.plan, nil); err == nil {
		t.Fatal("state count mismatch accepted")
	}
	if err := executeRolloutStateMachine(nil, &run, rolloutRunKeys{}, &controlclient.Client{}, &bytes.Buffer{}, true); err == nil {
		t.Fatal("nil rollout store accepted")
	}
}

func commandForKind(base controlclient.Command, prepared rolloutdriver.PreparedTargetV1, raw []byte, kind, terminal string) controlclient.Command {
	base.CommandID = preparedCommandID(prepared, kind)
	base.CommandKind = kind
	base.CommandDigest = dsse.Digest(raw)
	base.TerminalStatus = terminal
	return base
}

func rolloutResponseClient(t *testing.T, status int, value any) *controlclient.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if status != 0 && status != http.StatusOK {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(`{"error":"test_error","message":"injected response"}`))
			return
		}
		writeRolloutRunJSON(t, writer, value)
	}))
	t.Cleanup(server.Close)
	client, err := controlclient.New(server.URL, "test-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func loadRolloutExecutionTestFixture(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
) verifiedRolloutRun {
	t.Helper()
	run := loadRolloutRunTestFixture(t, fixture)
	run.targets[0].admissionRaw = offlineRead(
		t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetAdmissionKind),
	)
	run.targets[0].captureRaw = offlineRead(
		t, rolloutRunTargetPath(t, fixture.workspace, rolloutstore.TargetCaptureExportKind),
	)
	return run
}

func rolloutTestCaptureProjection(
	t *testing.T,
	run verifiedRolloutRun,
	state controlstore.EvidenceCaptureState,
) controlstore.EvidenceCapture {
	t.Helper()
	export, err := controlprotocol.DecodeControllerEvidenceCaptureV1(run.targets[0].captureRaw)
	if err != nil {
		t.Fatal(err)
	}
	statement := export.Statement
	ttl, err := rolloutEvidenceCaptureTTL(run.targets[0].timeouts)
	if err != nil {
		t.Fatal(err)
	}
	armedAt, err := time.Parse(time.RFC3339Nano, statement.ArmedAt)
	if err != nil {
		t.Fatal(err)
	}
	view := controlstore.EvidenceCapture{
		CaptureID: statement.CaptureID, RequestID: rolloutCaptureRequestID(run.plan, 0),
		NodeID: statement.NodeID, TenantID: statement.TenantID,
		RuntimeRef: statement.RuntimeRef, Generation: statement.Generation,
		ActivationID: statement.ActivationID, ActivationBeginDigest: statement.ActivationBeginDigest,
		State: state, BaselineHead: statement.BaselineHead, FinalHead: statement.FinalHead,
		FrameCount: int(statement.FrameCount), CapturedBytes: int(statement.FrameCount),
		ActivationBeginSequence: statement.ActivationBeginSequence,
		CapsuleDigest:           statement.CapsuleDigest, PolicyDigest: statement.PolicyDigest,
		ActivationCheckpointDigest: statement.ActivationCheckpointDigest,
		ArmedAt:                    statement.ArmedAt, ExpiresAt: armedAt.Add(ttl).Format(time.RFC3339Nano),
		ObservedAt: statement.ObservedAt,
	}
	switch state {
	case controlstore.EvidenceCaptureSealed:
		view.SealedAt = statement.SealedAt
		view.CanaryCommandID = statement.CanaryCommandID
	case controlstore.EvidenceCaptureArmed, controlstore.EvidenceCaptureExpired, controlstore.EvidenceCaptureFailed:
		view.FinalHead = view.BaselineHead
		view.FrameCount = 0
		view.CapturedBytes = 0
		view.ActivationBeginSequence = 0
		view.CapsuleDigest = ""
		view.PolicyDigest = ""
		view.ActivationCheckpointDigest = ""
		view.ObservedAt = ""
		if state == controlstore.EvidenceCaptureExpired {
			view.ExpiredAt = view.ExpiresAt
		}
		if state == controlstore.EvidenceCaptureFailed {
			view.FailedAt = view.ArmedAt
			view.Failure = controlstore.EvidenceCaptureFailureCoordinate
		}
	}
	if err := view.Validate(); err != nil {
		t.Fatalf("test capture projection: %v", err)
	}
	return view
}
