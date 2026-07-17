package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutstore"
)

type rolloutStatusFixture struct {
	directory string
	store     *rolloutstore.Store
	plan      rollout.PlanV1
	planRaw   []byte
}

func newRolloutStatusFixture(t *testing.T, targets int) *rolloutStatusFixture {
	t.Helper()
	plan := rolloutStatusTestPlan(targets)
	planRaw, err := rollout.MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "rollout")
	store, err := rolloutstore.Create(directory)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &rolloutStatusFixture{
		directory: directory,
		store:     store,
		plan:      plan,
		planRaw:   planRaw,
	}
	t.Cleanup(func() {
		if fixture.store != nil {
			if err := fixture.store.Close(); err != nil {
				t.Errorf("close rollout fixture: %v", err)
			}
		}
	})
	if err := store.WriteOnce(rolloutstore.PlanFileName, planRaw); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *rolloutStatusFixture) close(t *testing.T) {
	t.Helper()
	if fixture.store == nil {
		return
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.store = nil
}

func (fixture *rolloutStatusFixture) appendInitial(t *testing.T, target int) rollout.TargetStateV1 {
	t.Helper()
	state := rolloutStatusInitialState(t, fixture.planRaw, fixture.plan, target)
	fixture.appendState(t, target, 0, state)
	return state
}

func (fixture *rolloutStatusFixture) appendPassed(t *testing.T, target int) rollout.TargetStateV1 {
	t.Helper()
	state := fixture.appendInitial(t, target)
	phases := []string{
		rollout.PhasePreflightPassed,
		rollout.PhaseEvidenceCaptureArmed,
		rollout.PhaseAdmitSubmitted,
		rollout.PhaseAdmitted,
		rollout.PhaseStartSubmitted,
		rollout.PhaseRunning,
		rollout.PhaseCanaryAuthorized,
		rollout.PhaseCanarySubmitted,
		rollout.PhaseAgentReportedTerminal,
		rollout.PhaseEvidenceCollected,
		rollout.PhasePassed,
	}
	for index, phase := range phases {
		state.Phase = phase
		state.UpdatedAt = rolloutStatusTestTime(time.Duration(index+1) * time.Second)
		if phase == rollout.PhaseAdmitted {
			state.RuntimeRef = "executor-" + strings.Repeat(string(rune('a'+target)), 64)
			state.AdmissionDigest = rolloutStatusTestDigest(100 + target)
		}
		if phase == rollout.PhaseAgentReportedTerminal {
			state.CanaryResultDigest = rolloutStatusTestDigest(200 + target)
			state.CanaryResultBytes = 32
		}
		fixture.appendState(t, target, uint64(index+1), state)
	}
	return state
}

func (fixture *rolloutStatusFixture) appendState(
	t *testing.T,
	target int,
	sequence uint64,
	state rollout.TargetStateV1,
) {
	t.Helper()
	raw, err := rollout.MarshalTargetStateV1(state)
	if err != nil {
		t.Fatalf("marshal target %d state %d: %v", target, sequence, err)
	}
	if _, err := fixture.store.AppendTargetState(uint16(target), sequence, raw); err != nil {
		t.Fatalf("append target %d state %d: %v", target, sequence, err)
	}
}

func TestRolloutStatusHumanShowsJourneyAndUnverifiedProgress(t *testing.T) {
	fixture := newRolloutStatusFixture(t, 3)
	fixture.appendPassed(t, 0)
	fixture.appendInitial(t, 1)
	fixture.appendInitial(t, 2)
	fixture.close(t)

	var output bytes.Buffer
	if err := run(
		[]string{"rollout", "status", "-dir", fixture.directory},
		&output,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	want := "rollout: rollout-1\n" +
		"status: running (unverified workspace)\n" +
		"journey: plan -> preflight -> canary -> batch -> proof\n" +
		"progress: 1/3 targets passed\n" +
		"current: batch=1 target=1 node=node-1 phase=planned\n"
	if output.String() != want {
		t.Fatalf("status output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestRolloutStatusJSONSurfacesExactActionRequiredReason(t *testing.T) {
	fixture := newRolloutStatusFixture(t, 2)
	state := fixture.appendInitial(t, 0)
	state.Phase = rollout.PhaseActionRequired
	state.ActionRequiredReason = "evidence_capture_overflow"
	state.UpdatedAt = rolloutStatusTestTime(time.Second)
	fixture.appendState(t, 0, 1, state)
	fixture.appendInitial(t, 1)
	fixture.close(t)

	var output bytes.Buffer
	if err := run(
		[]string{"rollout", "status", "-dir", fixture.directory, "-json"},
		&output,
		&bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"steward.rollout-status.v1","rollout_id":"rollout-1","journey":"plan -> preflight -> canary -> batch -> proof","phase":"action_required","current_phase":"action_required","passed_targets":0,"total_targets":2,"current_batch":0,"current_target":0,"current_node_id":"node-0","action_required_reason":"evidence_capture_overflow","verified":false,"verification":"unverified_workspace"}` + "\n"
	if output.String() != want {
		t.Fatalf("JSON status=%q, want %q", output.String(), want)
	}

	output.Reset()
	if err := statusRollout([]string{"-dir", fixture.directory}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "status: action_required (unverified workspace)\n") ||
		!strings.HasSuffix(output.String(), "action required: evidence_capture_overflow\n") {
		t.Fatalf("human action-required status did not retain the exact reason: %q", output.String())
	}
}

func TestRolloutStatusPassedHasNoActiveBatchOrNode(t *testing.T) {
	fixture := newRolloutStatusFixture(t, 2)
	fixture.appendPassed(t, 0)
	fixture.appendPassed(t, 1)
	fixture.close(t)

	var output bytes.Buffer
	if err := statusRollout([]string{"-dir", fixture.directory, "-json"}, &output); err != nil {
		t.Fatal(err)
	}
	var status rolloutStatusOutput
	if err := json.Unmarshal(output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Phase != rollout.FleetPhasePassed ||
		status.CurrentPhase != rollout.FleetPhasePassed ||
		status.PassedTargets != 2 ||
		status.TotalTargets != 2 ||
		status.CurrentBatch != nil ||
		status.CurrentTarget != nil ||
		status.CurrentNodeID != "" ||
		status.Verified ||
		status.Verification != rolloutStatusVerificationV1 {
		t.Fatalf("passed status=%#v", status)
	}
	if output.Len() > 1024 {
		t.Fatalf("bounded status output grew to %d bytes", output.Len())
	}
	output.Reset()
	if err := statusRollout([]string{"-dir", fixture.directory}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "progress: 2/2 targets passed\n") ||
		!strings.HasSuffix(output.String(), "current: phase=passed\n") ||
		strings.Contains(output.String(), "node=") {
		t.Fatalf("human passed status=%q", output.String())
	}
}

func TestRolloutStatusRejectsMissingCorruptAndAmbiguousState(t *testing.T) {
	t.Run("missing target state", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "target 0 has no state checkpoint") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("corrupt state", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		if _, err := fixture.store.AppendTargetState(0, 0, []byte(`{"schema_version":`)); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "parse rollout state") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("ambiguous duplicate field", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		state := rolloutStatusInitialState(t, fixture.planRaw, fixture.plan, 0)
		raw, err := rollout.MarshalTargetStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		ambiguous := bytes.Replace(
			raw,
			[]byte(`"phase":"planned"`),
			[]byte(`"phase":"planned","phase":"planned"`),
			1,
		)
		if _, err := fixture.store.AppendTargetState(0, 0, ambiguous); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		if err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{}); err == nil {
			t.Fatal("ambiguous state was accepted")
		}
	})

	t.Run("skipped checkpoint transition", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		state := fixture.appendInitial(t, 0)
		state.Phase = rollout.PhaseEvidenceCaptureArmed
		state.UpdatedAt = rolloutStatusTestTime(time.Second)
		fixture.appendState(t, 0, 1, state)
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "phase must advance exactly one step") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("state binding mismatch", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		state := rolloutStatusInitialState(t, fixture.planRaw, fixture.plan, 0)
		state.Binding.NodeID = "node-other"
		fixture.appendState(t, 0, 0, state)
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "state does not match its plan target") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("terminal state without history", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		state := rolloutStatusInitialState(t, fixture.planRaw, fixture.plan, 0)
		state.Phase = rollout.PhaseActionRequired
		state.ActionRequiredReason = "operator_review"
		raw, err := rollout.MarshalTargetStateV1(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.store.AppendTargetState(0, 0, raw); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		err = statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "initial state must be planned") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("state outside plan", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.appendInitial(t, 0)
		if _, err := fixture.store.AppendTargetState(1, 0, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "target 1 outside the plan") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("later target advanced before predecessor passed", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 2)
		fixture.appendInitial(t, 0)
		state := fixture.appendInitial(t, 1)
		state.Phase = rollout.PhasePreflightPassed
		state.UpdatedAt = rolloutStatusTestTime(time.Second)
		fixture.appendState(t, 1, 1, state)
		fixture.close(t)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "advanced before target 0 passed") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestRolloutStatusRejectsInvalidPlanFlagsAndCommands(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "rollout")
	store, err := rolloutstore.Create(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteOnce(rolloutstore.PlanFileName, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := statusRollout([]string{"-dir", directory}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "parse rollout plan") {
		t.Fatalf("invalid plan error=%v", err)
	}

	for _, arguments := range [][]string{
		{"rollout"},
		{"rollout", "create"},
		{"rollout", "status"},
		{"rollout", "status", "-dir", directory, "extra"},
		{"rollout", "status", "-dir", directory, "-unknown"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid rollout arguments accepted: %#v", arguments)
		}
	}
}

func TestRolloutStatusHonorsWorkspaceLockAndSecurity(t *testing.T) {
	t.Run("lifetime lock", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.appendInitial(t, 0)
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if !errors.Is(err, rolloutstore.ErrLocked) {
			t.Fatalf("locked status error=%v, want ErrLocked", err)
		}
	})

	t.Run("workspace permissions", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.appendInitial(t, 0)
		fixture.close(t)
		if err := os.Chmod(fixture.directory, 0o755); err != nil {
			t.Fatal(err)
		}
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if !errors.Is(err, rolloutstore.ErrUnsafeWorkspace) {
			t.Fatalf("unsafe workspace error=%v", err)
		}
	})

	t.Run("artifact permissions", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.appendInitial(t, 0)
		fixture.close(t)
		if err := os.Chmod(filepath.Join(fixture.directory, rolloutstore.PlanFileName), 0o644); err != nil {
			t.Fatal(err)
		}
		err := statusRollout([]string{"-dir", fixture.directory}, &bytes.Buffer{})
		if !errors.Is(err, rolloutstore.ErrUnsafeWorkspace) {
			t.Fatalf("unsafe artifact error=%v", err)
		}
	})

	t.Run("workspace symlink", func(t *testing.T) {
		fixture := newRolloutStatusFixture(t, 1)
		fixture.appendInitial(t, 0)
		fixture.close(t)
		link := filepath.Join(t.TempDir(), "rollout-link")
		if err := os.Symlink(fixture.directory, link); err != nil {
			t.Fatal(err)
		}
		err := statusRollout([]string{"-dir", link}, &bytes.Buffer{})
		if !errors.Is(err, rolloutstore.ErrUnsafeWorkspace) {
			t.Fatalf("symlink workspace error=%v", err)
		}
	})
}

func rolloutStatusTestPlan(targets int) rollout.PlanV1 {
	plan := rollout.PlanV1{
		SchemaVersion: rollout.PlanSchemaV1,
		RolloutID:     "rollout-1",
		TenantID:      "tenant-a",
		ReleaseDigest: rolloutStatusTestDigest(1),
		PolicyDigest:  rolloutStatusTestDigest(2),
		Archive: ocibundle.ArchiveIdentity{
			Digest: rolloutStatusTestDigest(3),
			Bytes:  4096,
		},
		Canary:    activation.CanaryV1{Kind: activation.CanaryHermesWorkspaceAuditV1},
		BatchSize: 2,
		CreatedAt: rolloutStatusTestTime(0),
		Deadline:  rolloutStatusTestTime(time.Hour),
		Targets:   make([]rollout.TargetV1, targets),
	}
	for index := range plan.Targets {
		plan.Targets[index] = rollout.TargetV1{
			NodeID:               fmt.Sprintf("node-%d", index),
			InstanceID:           fmt.Sprintf("agent-%d", index),
			ActivationID:         fmt.Sprintf("activation-%d", index),
			IntentDigest:         rolloutStatusTestDigest(10 + index),
			ActivationPlanDigest: rolloutStatusTestDigest(80 + index),
			GatewayReceiptEpoch:  1,
			GatewayReceiptPublicKeySHA256: rolloutStatusTestDigest(
				120 + index,
			),
			OperationPolicyDigest: rolloutStatusTestDigest(160 + index),
			ClaimGeneration:       uint64(index + 1),
			InstanceGeneration:    uint64(index + 2),
			AdmitCommandID:        fmt.Sprintf("command-%d-admit", index),
			StartCommandID:        fmt.Sprintf("command-%d-start", index),
			CanaryCommandID:       fmt.Sprintf("command-%d-canary", index),
		}
	}
	return plan
}

func rolloutStatusInitialState(
	t *testing.T,
	planRaw []byte,
	plan rollout.PlanV1,
	target int,
) rollout.TargetStateV1 {
	t.Helper()
	planDigest, err := rollout.PlanDigestV1(planRaw)
	if err != nil {
		t.Fatal(err)
	}
	planned := plan.Targets[target]
	return rollout.TargetStateV1{
		SchemaVersion: rollout.TargetStateSchemaV1,
		Binding: rollout.TargetBindingV1{
			PlanDigest:         planDigest,
			RolloutID:          plan.RolloutID,
			TargetIndex:        uint16(target),
			TenantID:           plan.TenantID,
			NodeID:             planned.NodeID,
			InstanceID:         planned.InstanceID,
			ActivationID:       planned.ActivationID,
			ClaimGeneration:    planned.ClaimGeneration,
			InstanceGeneration: planned.InstanceGeneration,
		},
		Phase:     rollout.PhasePlanned,
		UpdatedAt: rolloutStatusTestTime(0),
	}
}

func rolloutStatusTestDigest(value int) string {
	return fmt.Sprintf("sha256:%064x", value)
}

func rolloutStatusTestTime(offset time.Duration) string {
	return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC).
		Add(offset).
		Format(time.RFC3339Nano)
}
