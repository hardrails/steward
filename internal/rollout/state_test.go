package rollout

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestTargetStateV1AcceptsExactOrderedProgress(t *testing.T) {
	plan := rolloutPlanFixture(1)
	planRaw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	state := initialTargetState(planRaw, plan, 0)
	if err := CorrelateTargetStateV1(planRaw, state); err != nil {
		t.Fatal(err)
	}
	for _, phase := range targetPhaseSequence[1:] {
		next := state
		next.Phase = phase
		next.UpdatedAt = nextStateTime(state.UpdatedAt)
		if phase == PhaseAdmitted {
			next.RuntimeRef = runtimeRefFixture()
			next.AdmissionDigest = digest("e")
		}
		if phase == PhaseAgentReportedTerminal {
			next.CanaryResultDigest = digest("f")
			next.CanaryResultBytes = 512
		}
		if err := ValidateTargetTransitionV1(state, next); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
		state = next
	}
	if state.Phase != PhasePassed {
		t.Fatalf("final state=%#v", state)
	}
	raw, err := MarshalTargetStateV1(state)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTargetStateV1(raw)
	if err != nil || parsed != state {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestTargetStateV1RejectsSkippedChangedAndRecoveredProgress(t *testing.T) {
	plan := rolloutPlanFixture(1)
	planRaw, _ := MarshalPlanV1(plan)
	initial := initialTargetState(planRaw, plan, 0)

	skipped := initial
	skipped.Phase = PhaseEvidenceCaptureArmed
	skipped.UpdatedAt = nextStateTime(initial.UpdatedAt)
	if err := ValidateTargetTransitionV1(initial, skipped); err == nil {
		t.Fatal("skipped phase accepted")
	}

	admitted := initial
	for _, phase := range []string{
		PhasePreflightPassed,
		PhaseEvidenceCaptureArmed,
		PhaseAdmitSubmitted,
		PhaseAdmitted,
	} {
		next := admitted
		next.Phase = phase
		next.UpdatedAt = nextStateTime(admitted.UpdatedAt)
		if phase == PhaseAdmitted {
			next.RuntimeRef = runtimeRefFixture()
			next.AdmissionDigest = digest("e")
		}
		if err := ValidateTargetTransitionV1(admitted, next); err != nil {
			t.Fatal(err)
		}
		admitted = next
	}
	changed := admitted
	changed.Phase = PhaseStartSubmitted
	changed.UpdatedAt = nextStateTime(admitted.UpdatedAt)
	changed.RuntimeRef = "executor-" + strings.Repeat("b", 64)
	if err := ValidateTargetTransitionV1(admitted, changed); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("runtime substitution err=%v", err)
	}

	action := admitted
	action.Phase = PhaseActionRequired
	action.ActionRequiredReason = "outcome_unknown"
	action.UpdatedAt = nextStateTime(admitted.UpdatedAt)
	if err := ValidateTargetTransitionV1(admitted, action); err != nil {
		t.Fatal(err)
	}
	recovered := action
	recovered.Phase = PhaseStartSubmitted
	recovered.ActionRequiredReason = ""
	recovered.UpdatedAt = nextStateTime(action.UpdatedAt)
	if err := ValidateTargetTransitionV1(action, recovered); err == nil {
		t.Fatal("sticky action_required recovered")
	}
}

func TestTargetStateV1RejectsInvalidIndependentShapes(t *testing.T) {
	plan := rolloutPlanFixture(1)
	planRaw, _ := MarshalPlanV1(plan)
	valid := initialTargetState(planRaw, plan, 0)
	for name, mutate := range map[string]func(*TargetStateV1){
		"schema":        func(value *TargetStateV1) { value.SchemaVersion = "other" },
		"plan digest":   func(value *TargetStateV1) { value.Binding.PlanDigest = "" },
		"phase":         func(value *TargetStateV1) { value.Phase = "rollback" },
		"time":          func(value *TargetStateV1) { value.UpdatedAt = "bad" },
		"early runtime": func(value *TargetStateV1) { value.RuntimeRef = runtimeRefFixture() },
		"early result": func(value *TargetStateV1) {
			value.CanaryResultDigest = digest("f")
			value.CanaryResultBytes = 1
		},
		"reason": func(value *TargetStateV1) {
			value.ActionRequiredReason = "unexpected"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid state accepted: %#v", candidate)
			}
		})
	}
	action := valid
	action.Phase = PhaseActionRequired
	action.ActionRequiredReason = "outcome_unknown"
	action.RuntimeRef = runtimeRefFixture()
	if err := action.Validate(); err == nil {
		t.Fatal("partial action-required runtime binding accepted")
	}

	raw, _ := json.Marshal(valid)
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := ParseTargetStateV1(unknown); err == nil {
		t.Fatal("unknown state field accepted")
	}
}

func TestValidateFleetProgressV1EnforcesCanaryFirstSequentialOrder(t *testing.T) {
	plan := rolloutPlanFixture(3)
	planRaw, _ := MarshalPlanV1(plan)
	states := []TargetStateV1{
		initialTargetState(planRaw, plan, 0),
		initialTargetState(planRaw, plan, 1),
		initialTargetState(planRaw, plan, 2),
	}
	if err := ValidateFleetProgressV1(planRaw, states); err != nil {
		t.Fatal(err)
	}
	states[1].Phase = PhasePreflightPassed
	states[1].UpdatedAt = planTime(time.Second)
	if err := ValidateFleetProgressV1(planRaw, states); err == nil {
		t.Fatal("later target advanced before canary")
	}
	states[1] = initialTargetState(planRaw, plan, 1)
	states[0] = passedTargetState(states[0])
	states[1].Phase = PhasePreflightPassed
	states[1].UpdatedAt = planTime(20 * time.Second)
	if err := ValidateFleetProgressV1(planRaw, states); err != nil {
		t.Fatal(err)
	}
	states[2].Phase = PhasePreflightPassed
	states[2].UpdatedAt = planTime(21 * time.Second)
	if err := ValidateFleetProgressV1(planRaw, states); err == nil {
		t.Fatal("third target advanced before second passed")
	}
}

func initialTargetState(planRaw []byte, plan PlanV1, index int) TargetStateV1 {
	target := plan.Targets[index]
	return TargetStateV1{
		SchemaVersion: TargetStateSchemaV1,
		Binding: TargetBindingV1{
			PlanDigest:         dsse.Digest(planRaw),
			RolloutID:          plan.RolloutID,
			TargetIndex:        uint16(index),
			TenantID:           plan.TenantID,
			NodeID:             target.NodeID,
			InstanceID:         target.InstanceID,
			ActivationID:       target.ActivationID,
			ClaimGeneration:    target.ClaimGeneration,
			InstanceGeneration: target.InstanceGeneration,
		},
		Phase:     PhasePlanned,
		UpdatedAt: plan.CreatedAt,
	}
}

func passedTargetState(state TargetStateV1) TargetStateV1 {
	state.Phase = PhasePassed
	state.RuntimeRef = runtimeRefFixture()
	state.AdmissionDigest = digest("e")
	state.CanaryResultDigest = digest("f")
	state.CanaryResultBytes = 512
	state.UpdatedAt = planTime(10 * time.Second)
	return state
}

func runtimeRefFixture() string {
	return "executor-" + strings.Repeat("a", 64)
}

func nextStateTime(value string) string {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed.Add(time.Second).Format(time.RFC3339Nano)
}
