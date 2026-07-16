package activation

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func validBinding(t *testing.T, planRaw []byte) BindingV1 {
	t.Helper()
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		t.Fatalf("ParsePlanV1() error = %v", err)
	}
	planDigest, err := PlanDigestV1(planRaw)
	if err != nil {
		t.Fatalf("PlanDigestV1() error = %v", err)
	}
	return BindingV1{
		ActivationID:  plan.ActivationID,
		PlanDigest:    planDigest,
		ReleaseDigest: plan.ReleaseDigest,
		PolicyDigest:  plan.PolicyDigest,
		IntentDigest:  plan.IntentDigest,
		Archive:       plan.Archive,
		TenantID:      "tenant-a",
		NodeID:        "node-a",
		InstanceID:    "hermes-a",
		Generation:    7,
	}
}

func initialState(t *testing.T) StateV1 {
	t.Helper()
	planRaw := mustMarshalPlan(t, validPlan())
	return StateV1{
		SchemaVersion: StateSchemaV1,
		Binding:       validBinding(t, planRaw),
		Phase:         PhaseNew,
		UpdatedAt:     "2026-07-16T10:00:00Z",
	}
}

func mustMarshalState(t *testing.T, state StateV1) []byte {
	t.Helper()
	raw, err := MarshalStateV1(state)
	if err != nil {
		t.Fatalf("MarshalStateV1() error = %v", err)
	}
	return raw
}

func stateAtPhase(t *testing.T, phase string) StateV1 {
	t.Helper()
	state := initialState(t)
	start, _ := canonicalTimestamp(state.UpdatedAt)
	for index := 1; index < len(phaseSequence); index++ {
		next := state
		next.Phase = phaseSequence[index]
		next.UpdatedAt = start.Add(time.Duration(index) * time.Nanosecond).UTC().Format(time.RFC3339Nano)
		if next.Phase == PhaseAdmitted {
			next.RuntimeRef = testRuntimeRef('a')
		}
		var err error
		state, err = AdvanceStateV1(state, next)
		if err != nil {
			t.Fatalf("AdvanceStateV1(%q -> %q) error = %v", phaseSequence[index-1], next.Phase, err)
		}
		if state.Phase == phase {
			return state
		}
	}
	if phase == PhaseNew {
		return initialState(t)
	}
	t.Fatalf("unknown requested test phase %q", phase)
	return StateV1{}
}

func TestStateRoundTripDigestAndCompleteMonotonicSequence(t *testing.T) {
	state := initialState(t)
	raw := mustMarshalState(t, state)
	parsed, err := ParseStateV1(raw)
	if err != nil {
		t.Fatalf("ParseStateV1() error = %v", err)
	}
	if parsed != state {
		t.Fatalf("ParseStateV1() = %#v, want %#v", parsed, state)
	}
	digest, err := StateDigestV1(raw)
	if err != nil {
		t.Fatalf("StateDigestV1() error = %v", err)
	}
	if !sha256Digest(digest) {
		t.Fatalf("StateDigestV1() = %q, want canonical SHA-256", digest)
	}

	start, _ := canonicalTimestamp(state.UpdatedAt)
	for index := 1; index < len(phaseSequence); index++ {
		next := state
		next.Phase = phaseSequence[index]
		next.UpdatedAt = start.Add(time.Duration(index) * time.Nanosecond).UTC().Format(time.RFC3339Nano)
		if next.Phase == PhaseAdmitted {
			next.RuntimeRef = testRuntimeRef('a')
		}
		state, err = AdvanceStateV1(state, next)
		if err != nil {
			t.Fatalf("AdvanceStateV1(%q -> %q) error = %v", phaseSequence[index-1], next.Phase, err)
		}
	}
	if state.Phase != PhasePassed {
		t.Fatalf("final phase = %q, want %q", state.Phase, PhasePassed)
	}
}

func TestStateExactReplayIsIdempotent(t *testing.T) {
	current := stateAtPhase(t, PhaseCanaryDispatched)
	got, err := AdvanceStateV1(current, current)
	if err != nil {
		t.Fatalf("AdvanceStateV1(exact replay) error = %v", err)
	}
	if got != current {
		t.Fatalf("AdvanceStateV1(exact replay) = %#v, want %#v", got, current)
	}

	changed := current
	changed.UpdatedAt = "2026-07-16T10:01:00Z"
	if err := ValidateStateTransitionV1(current, changed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("same-phase changed replay error = %v, want ErrInvalidTransition", err)
	}
}

func TestStateRejectsNonMonotonicTransitions(t *testing.T) {
	current := stateAtPhase(t, PhaseRunning)
	tests := map[string]func(*StateV1){
		"skip phase": func(next *StateV1) {
			next.Phase = PhaseCanaryAuthorized
		},
		"move backward": func(next *StateV1) {
			next.Phase = PhaseAdmitted
		},
		"same phase changed document": func(next *StateV1) {
			next.Phase = PhaseRunning
		},
		"timestamp unchanged": func(next *StateV1) {
			next.Phase = PhaseCanaryChallengeReady
			next.UpdatedAt = current.UpdatedAt
		},
		"timestamp moved backward": func(next *StateV1) {
			next.Phase = PhaseCanaryChallengeReady
			next.UpdatedAt = "2026-07-16T09:59:59Z"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			next := current
			next.UpdatedAt = "2026-07-16T10:01:00Z"
			mutate(&next)
			if err := ValidateStateTransitionV1(current, next); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("ValidateStateTransitionV1() error = %v, want ErrInvalidTransition", err)
			}
		})
	}
}

func TestStateRejectsBindingAndRuntimeIdentityChanges(t *testing.T) {
	current := stateAtPhase(t, PhaseRunning)
	tests := map[string]func(*StateV1){
		"plan digest": func(next *StateV1) {
			next.Binding.PlanDigest = testSHA256('b')
		},
		"release digest": func(next *StateV1) {
			next.Binding.ReleaseDigest = testSHA256('b')
		},
		"archive digest": func(next *StateV1) {
			next.Binding.Archive.Digest = testSHA256('b')
		},
		"tenant": func(next *StateV1) {
			next.Binding.TenantID = "tenant-b"
		},
		"cross-node substitution": func(next *StateV1) {
			next.Binding.NodeID = "node-b"
		},
		"instance": func(next *StateV1) {
			next.Binding.InstanceID = "hermes-b"
		},
		"generation substitution": func(next *StateV1) {
			next.Binding.Generation++
		},
		"runtime reference": func(next *StateV1) {
			next.RuntimeRef = testRuntimeRef('b')
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			next := current
			next.Phase = PhaseCanaryChallengeReady
			next.UpdatedAt = "2026-07-16T10:01:00Z"
			mutate(&next)
			err := ValidateStateTransitionV1(current, next)
			if !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("ValidateStateTransitionV1() error = %v, want ErrInvalidTransition and ErrBindingMismatch", err)
			}
		})
	}
}

func TestStateRuntimeReferenceAppearsOnlyAtAdmission(t *testing.T) {
	beforeAdmission := stateAtPhase(t, PhaseImageImported)

	premature := beforeAdmission
	premature.Phase = PhaseActionRequired
	premature.RuntimeRef = testRuntimeRef('a')
	premature.UpdatedAt = "2026-07-16T10:01:00Z"
	premature.ActionRequiredReason = "admission_failed"
	err := ValidateStateTransitionV1(beforeAdmission, premature)
	if !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("premature runtime_ref error = %v, want transition binding mismatch", err)
	}

	admitted := beforeAdmission
	admitted.Phase = PhaseAdmitted
	admitted.RuntimeRef = testRuntimeRef('a')
	admitted.UpdatedAt = "2026-07-16T10:01:00Z"
	if err := ValidateStateTransitionV1(beforeAdmission, admitted); err != nil {
		t.Fatalf("runtime_ref at admission error = %v", err)
	}

	missing := beforeAdmission
	missing.Phase = PhaseAdmitted
	missing.UpdatedAt = "2026-07-16T10:01:00Z"
	if err := ValidateStateTransitionV1(beforeAdmission, missing); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("missing runtime_ref error = %v, want ErrInvalidTransition", err)
	}
}

func TestActionRequiredIsStickyWithStableReason(t *testing.T) {
	current := stateAtPhase(t, PhaseCanaryDispatched)
	actionRequired := current
	actionRequired.Phase = PhaseActionRequired
	actionRequired.UpdatedAt = "2026-07-16T10:01:00Z"
	actionRequired.ActionRequiredReason = "canary_timeout"

	if err := ValidateStateTransitionV1(current, actionRequired); err != nil {
		t.Fatalf("transition to action_required error = %v", err)
	}
	if err := ValidateStateTransitionV1(actionRequired, actionRequired); err != nil {
		t.Fatalf("exact action_required replay error = %v", err)
	}

	changedReason := actionRequired
	changedReason.UpdatedAt = "2026-07-16T10:02:00Z"
	changedReason.ActionRequiredReason = "operator_override"
	if err := ValidateStateTransitionV1(actionRequired, changedReason); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("changed action_required reason error = %v, want ErrInvalidTransition", err)
	}

	resumed := actionRequired
	resumed.Phase = PhaseEvidenceCollected
	resumed.UpdatedAt = "2026-07-16T10:02:00Z"
	resumed.ActionRequiredReason = ""
	if err := ValidateStateTransitionV1(actionRequired, resumed); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("resumed action_required error = %v, want ErrInvalidTransition", err)
	}
}

func TestPassedIsTerminal(t *testing.T) {
	passed := stateAtPhase(t, PhasePassed)
	next := passed
	next.Phase = PhaseActionRequired
	next.UpdatedAt = "2026-07-16T10:02:00Z"
	next.ActionRequiredReason = "late_failure"
	if err := ValidateStateTransitionV1(passed, next); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("passed transition error = %v, want ErrInvalidTransition", err)
	}
}

func TestStateValidationRejectsOutOfContractSnapshots(t *testing.T) {
	tests := map[string]func(*StateV1){
		"wrong schema": func(state *StateV1) {
			state.SchemaVersion = "steward.activation-state.v2"
		},
		"unknown phase": func(state *StateV1) {
			state.Phase = "failed"
		},
		"runtime before admission": func(state *StateV1) {
			state.RuntimeRef = testRuntimeRef('a')
		},
		"noncanonical zero fraction timestamp": func(state *StateV1) {
			state.UpdatedAt = "2026-07-16T10:00:00.000Z"
		},
		"offset timestamp": func(state *StateV1) {
			state.UpdatedAt = "2026-07-16T03:00:00-07:00"
		},
		"zero generation": func(state *StateV1) {
			state.Binding.Generation = 0
		},
		"whitespace node id": func(state *StateV1) {
			state.Binding.NodeID = " node-a"
		},
		"control character identity": func(state *StateV1) {
			state.Binding.InstanceID = "hermes\nother"
		},
		"action reason in normal state": func(state *StateV1) {
			state.ActionRequiredReason = "unexpected"
		},
		"action required without reason": func(state *StateV1) {
			state.Phase = PhaseActionRequired
		},
		"action required arbitrary reason": func(state *StateV1) {
			state.Phase = PhaseActionRequired
			state.ActionRequiredReason = "run this command"
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state := initialState(t)
			mutate(&state)
			if err := state.Validate(); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("Validate() error = %v, want ErrInvalidState", err)
			}
		})
	}
}

func TestStateAcceptsCanonicalNanosecondTransitions(t *testing.T) {
	current := initialState(t)
	current.UpdatedAt = "2026-07-16T10:00:00.000000001Z"
	next := current
	next.Phase = PhaseReleaseVerified
	next.UpdatedAt = "2026-07-16T10:00:00.000000002Z"
	if err := ValidateStateTransitionV1(current, next); err != nil {
		t.Fatalf("nanosecond transition error = %v", err)
	}
}

func TestParseStateV1RejectsNonExactOrOversizeJSON(t *testing.T) {
	raw := string(mustMarshalState(t, initialState(t)))
	tests := map[string][]byte{
		"unknown top-level path": []byte(strings.TrimSuffix(raw, "}") + `,"path":"/tmp/state"}`),
		"duplicate phase": []byte(strings.Replace(raw,
			`"phase":"new"`, `"phase":"new","phase":"new"`, 1)),
		"unknown nested binding field": []byte(strings.Replace(raw,
			`"generation":7`, `"generation":7,"url":"https://invalid"`, 1)),
		"oversize": bytes.Repeat([]byte{' '}, MaxStateBytes+1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseStateV1(candidate)
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("ParseStateV1() error = %v, want ErrInvalidState", err)
			}
		})
	}
}
