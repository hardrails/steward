package rollout

import "fmt"

const (
	FleetPhaseRunning        = "running"
	FleetPhasePassed         = "passed"
	FleetPhaseActionRequired = "action_required"
)

// FleetSummaryV1 is a derived view, not persisted rollout authority. The
// latest per-target checkpoints remain the only mutable local state.
type FleetSummaryV1 struct {
	RolloutID            string `json:"rollout_id"`
	Phase                string `json:"phase"`
	PassedTargets        int    `json:"passed_targets"`
	TotalTargets         int    `json:"total_targets"`
	CurrentBatch         uint16 `json:"current_batch"`
	CurrentTarget        uint16 `json:"current_target"`
	CurrentNodeID        string `json:"current_node_id,omitempty"`
	CurrentTargetPhase   string `json:"current_target_phase,omitempty"`
	ActionRequiredReason string `json:"action_required_reason,omitempty"`
}

// SummarizeFleetV1 derives one operator-facing status from the exact plan and
// ordered latest target states. It performs the same canary-first ordering and
// binding validation as offline proof correlation.
func SummarizeFleetV1(planRaw []byte, states []TargetStateV1) (FleetSummaryV1, error) {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return FleetSummaryV1{}, err
	}
	if err := ValidateFleetProgressV1(planRaw, states); err != nil {
		return FleetSummaryV1{}, err
	}
	summary := FleetSummaryV1{
		RolloutID:     plan.RolloutID,
		Phase:         FleetPhaseRunning,
		TotalTargets:  len(states),
		PassedTargets: 0,
	}
	for index, state := range states {
		if state.Phase == PhasePassed {
			summary.PassedTargets++
			continue
		}
		summary.CurrentTarget = uint16(index)
		summary.CurrentNodeID = plan.Targets[index].NodeID
		summary.CurrentTargetPhase = state.Phase
		summary.CurrentBatch = targetBatch(plan, index)
		if state.Phase == PhaseActionRequired {
			summary.Phase = FleetPhaseActionRequired
			summary.ActionRequiredReason = state.ActionRequiredReason
		}
		return summary, nil
	}
	summary.Phase = FleetPhasePassed
	return summary, nil
}

func targetBatch(plan PlanV1, target int) uint16 {
	if target == 0 {
		return 0
	}
	return uint16(1 + (target-1)/int(plan.BatchSize))
}

func (summary FleetSummaryV1) Validate() error {
	if !identifier(summary.RolloutID) ||
		summary.TotalTargets < 1 ||
		summary.TotalTargets > MaxTargets ||
		summary.PassedTargets < 0 ||
		summary.PassedTargets > summary.TotalTargets {
		return fmt.Errorf("rollout fleet summary counts or identity are invalid")
	}
	switch summary.Phase {
	case FleetPhasePassed:
		if summary.PassedTargets != summary.TotalTargets ||
			summary.CurrentBatch != 0 ||
			summary.CurrentTarget != 0 ||
			summary.CurrentNodeID != "" ||
			summary.CurrentTargetPhase != "" ||
			summary.ActionRequiredReason != "" {
			return fmt.Errorf("passed rollout fleet summary contains active target state")
		}
	case FleetPhaseRunning:
		_, normal := targetPhaseRank(summary.CurrentTargetPhase)
		if summary.PassedTargets >= summary.TotalTargets ||
			!publicIdentity(summary.CurrentNodeID, 128) ||
			!normal ||
			summary.CurrentTargetPhase == PhaseActionRequired ||
			summary.ActionRequiredReason != "" {
			return fmt.Errorf("running rollout fleet summary is invalid")
		}
	case FleetPhaseActionRequired:
		if summary.PassedTargets >= summary.TotalTargets ||
			!publicIdentity(summary.CurrentNodeID, 128) ||
			summary.CurrentTargetPhase != PhaseActionRequired ||
			!identifier(summary.ActionRequiredReason) {
			return fmt.Errorf("action-required rollout fleet summary is invalid")
		}
	default:
		return fmt.Errorf("rollout fleet summary phase is invalid")
	}
	return nil
}
