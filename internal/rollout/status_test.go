package rollout

import (
	"testing"
	"time"
)

func TestSummarizeFleetV1DerivesRunningBatchAndPass(t *testing.T) {
	plan := rolloutPlanFixture(5)
	planRaw, _ := MarshalPlanV1(plan)
	states := make([]TargetStateV1, len(plan.Targets))
	for index := range states {
		states[index] = initialTargetState(planRaw, plan, index)
	}
	summary, err := SummarizeFleetV1(planRaw, states)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Phase != FleetPhaseRunning ||
		summary.CurrentTarget != 0 ||
		summary.CurrentBatch != 0 ||
		summary.CurrentTargetPhase != PhasePlanned {
		t.Fatalf("initial summary=%#v", summary)
	}
	if err := summary.Validate(); err != nil {
		t.Fatal(err)
	}

	states[0] = passedTargetState(states[0])
	states[1] = passedTargetState(states[1])
	states[1].UpdatedAt = planTime(11 * time.Second)
	summary, err = SummarizeFleetV1(planRaw, states)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PassedTargets != 2 ||
		summary.CurrentTarget != 2 ||
		summary.CurrentBatch != 1 {
		t.Fatalf("batch summary=%#v", summary)
	}

	for index := 2; index < len(states); index++ {
		states[index] = passedTargetState(states[index])
		states[index].UpdatedAt = planTime(time.Duration(index+10) * time.Second)
	}
	summary, err = SummarizeFleetV1(planRaw, states)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Phase != FleetPhasePassed ||
		summary.PassedTargets != len(states) ||
		summary.CurrentNodeID != "" {
		t.Fatalf("passed summary=%#v", summary)
	}
	if err := summary.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSummarizeFleetV1SurfacesStickyActionReason(t *testing.T) {
	plan := rolloutPlanFixture(2)
	planRaw, _ := MarshalPlanV1(plan)
	states := []TargetStateV1{
		initialTargetState(planRaw, plan, 0),
		initialTargetState(planRaw, plan, 1),
	}
	states[0].Phase = PhaseActionRequired
	states[0].ActionRequiredReason = "evidence_capture_overflow"
	states[0].UpdatedAt = planTime(time.Second)
	summary, err := SummarizeFleetV1(planRaw, states)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Phase != FleetPhaseActionRequired ||
		summary.ActionRequiredReason != "evidence_capture_overflow" ||
		summary.CurrentNodeID != "node-a" {
		t.Fatalf("action summary=%#v", summary)
	}
	if err := summary.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFleetSummaryV1RejectsContradictoryView(t *testing.T) {
	summary := FleetSummaryV1{
		RolloutID:          "rollout-1",
		Phase:              FleetPhasePassed,
		PassedTargets:      1,
		TotalTargets:       1,
		CurrentNodeID:      "node-a",
		CurrentTargetPhase: PhaseRunning,
	}
	if err := summary.Validate(); err == nil {
		t.Fatal("contradictory passed summary accepted")
	}
	summary = FleetSummaryV1{
		RolloutID:            "rollout-1",
		Phase:                FleetPhaseActionRequired,
		PassedTargets:        0,
		TotalTargets:         1,
		CurrentNodeID:        "node-a",
		CurrentTargetPhase:   PhaseActionRequired,
		ActionRequiredReason: "",
	}
	if err := summary.Validate(); err == nil {
		t.Fatal("action-required summary without reason accepted")
	}
}
