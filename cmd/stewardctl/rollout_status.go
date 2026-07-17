package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutstore"
)

const (
	rolloutStatusSchemaV1       = "steward.rollout-status.v1"
	rolloutStatusJourneyV1      = "plan -> preflight -> canary -> batch -> proof"
	rolloutStatusVerificationV1 = "unverified_workspace"
)

type rolloutStatusOutput struct {
	SchemaVersion        string  `json:"schema_version"`
	RolloutID            string  `json:"rollout_id"`
	Journey              string  `json:"journey"`
	Phase                string  `json:"phase"`
	CurrentPhase         string  `json:"current_phase"`
	PassedTargets        int     `json:"passed_targets"`
	TotalTargets         int     `json:"total_targets"`
	CurrentBatch         *uint16 `json:"current_batch,omitempty"`
	CurrentTarget        *uint16 `json:"current_target,omitempty"`
	CurrentNodeID        string  `json:"current_node_id,omitempty"`
	ActionRequiredReason string  `json:"action_required_reason,omitempty"`
	Verified             bool    `json:"verified"`
	Verification         string  `json:"verification"`
}

func rolloutCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("rollout command requires create, run, status, or verify")
	}
	switch arguments[0] {
	case "create":
		return createRollout(arguments[1:], stdout)
	case "run":
		return runRollout(arguments[1:], stdout)
	case "status":
		return statusRollout(arguments[1:], stdout)
	case "verify":
		return verifyRollout(arguments[1:], stdout)
	default:
		return errors.New("rollout command requires create, run, status, or verify")
	}
}

func statusRollout(arguments []string, stdout io.Writer) (resultErr error) {
	flags := flag.NewFlagSet("rollout status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only rollout workspace")
	jsonOutput := flags.Bool("json", false, "emit stable machine-readable status")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || flags.NArg() != 0 {
		return errors.New("rollout status requires -dir and no positional arguments")
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve rollout workspace path: %w", err)
	}
	store, err := rolloutstore.Open(directory)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
	}()

	planRaw, states, err := loadUnverifiedRolloutStates(store)
	if err != nil {
		return err
	}
	summary, err := rollout.SummarizeFleetV1(planRaw, states)
	if err != nil {
		return fmt.Errorf("summarize rollout workspace: %w", err)
	}
	if err := summary.Validate(); err != nil {
		return fmt.Errorf("validate rollout workspace summary: %w", err)
	}
	output := newRolloutStatusOutput(summary)
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	return writeHumanRolloutStatus(stdout, output)
}

// loadUnverifiedRolloutStates checks only the integrity and correlation of
// unsigned local workspace bytes. It validates every retained checkpoint so a
// malformed or skipped predecessor cannot be hidden behind a valid latest
// state. This does not authenticate the plan, states, commands, or evidence.
func loadUnverifiedRolloutStates(
	store *rolloutstore.Store,
) ([]byte, []rollout.TargetStateV1, error) {
	planRaw, err := store.Read(rolloutstore.PlanFileName, rollout.MaxPlanBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("read rollout plan: %w", err)
	}
	plan, err := rollout.ParsePlanV1(planRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse rollout plan: %w", err)
	}

	latest := make([]rollout.TargetStateV1, len(plan.Targets))
	for target := uint16(0); target < rolloutstore.MaxTargets; target++ {
		names, err := store.ListTargetStates(target)
		if err != nil {
			return nil, nil, fmt.Errorf("list rollout target %d states: %w", target, err)
		}
		if int(target) >= len(plan.Targets) {
			if len(names) != 0 {
				return nil, nil, fmt.Errorf("rollout workspace has state for target %d outside the plan", target)
			}
			continue
		}
		if len(names) == 0 {
			return nil, nil, fmt.Errorf("rollout target %d has no state checkpoint", target)
		}

		var previous rollout.TargetStateV1
		for sequence, name := range names {
			expected, nameErr := rolloutstore.TargetStateName(target, uint64(sequence))
			if nameErr != nil || name != expected {
				return nil, nil, errors.Join(
					fmt.Errorf("rollout target %d state checkpoints are not contiguous from zero", target),
					nameErr,
				)
			}
			raw, readErr := store.Read(name, rollout.MaxTargetStateBytes)
			if readErr != nil {
				return nil, nil, fmt.Errorf("read rollout state %q: %w", name, readErr)
			}
			state, parseErr := rollout.ParseTargetStateV1(raw)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("parse rollout state %q: %w", name, parseErr)
			}
			canonical, marshalErr := rollout.MarshalTargetStateV1(state)
			if marshalErr != nil || !bytes.Equal(canonical, raw) {
				return nil, nil, fmt.Errorf("rollout state %q is not canonical JSON", name)
			}
			if correlateErr := rollout.CorrelateTargetStateV1(planRaw, state); correlateErr != nil {
				return nil, nil, fmt.Errorf("correlate rollout state %q: %w", name, correlateErr)
			}
			if sequence == 0 {
				if state.Phase != rollout.PhasePlanned {
					return nil, nil, fmt.Errorf("rollout target %d initial state must be planned", target)
				}
			} else if transitionErr := rollout.ValidateTargetTransitionV1(previous, state); transitionErr != nil {
				return nil, nil, fmt.Errorf("validate rollout state %q: %w", name, transitionErr)
			}
			previous = state
		}
		latest[target] = previous
	}
	if err := rollout.ValidateFleetProgressV1(planRaw, latest); err != nil {
		return nil, nil, fmt.Errorf("validate rollout fleet progress: %w", err)
	}
	return planRaw, latest, nil
}

func newRolloutStatusOutput(summary rollout.FleetSummaryV1) rolloutStatusOutput {
	currentPhase := summary.CurrentTargetPhase
	if currentPhase == "" {
		currentPhase = summary.Phase
	}
	output := rolloutStatusOutput{
		SchemaVersion:        rolloutStatusSchemaV1,
		RolloutID:            summary.RolloutID,
		Journey:              rolloutStatusJourneyV1,
		Phase:                summary.Phase,
		CurrentPhase:         currentPhase,
		PassedTargets:        summary.PassedTargets,
		TotalTargets:         summary.TotalTargets,
		CurrentNodeID:        summary.CurrentNodeID,
		ActionRequiredReason: summary.ActionRequiredReason,
		Verified:             false,
		Verification:         rolloutStatusVerificationV1,
	}
	if summary.Phase != rollout.FleetPhasePassed {
		batch := summary.CurrentBatch
		target := summary.CurrentTarget
		output.CurrentBatch = &batch
		output.CurrentTarget = &target
	}
	return output
}

func writeHumanRolloutStatus(stdout io.Writer, output rolloutStatusOutput) error {
	if _, err := fmt.Fprintf(stdout, "rollout: %s\n", output.RolloutID); err != nil {
		return err
	}
	verification := "unverified workspace"
	if output.Verified {
		switch output.Verification {
		case "authenticated_retained_progress":
			verification = "authenticated retained progress"
		default:
			verification = "verified: " + output.Verification
		}
	}
	if _, err := fmt.Fprintf(stdout, "status: %s (%s)\n", output.Phase, verification); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "journey: %s\n", output.Journey); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		stdout,
		"progress: %d/%d targets passed\n",
		output.PassedTargets,
		output.TotalTargets,
	); err != nil {
		return err
	}
	if output.CurrentBatch == nil || output.CurrentTarget == nil {
		_, err := fmt.Fprintf(stdout, "current: phase=%s\n", output.CurrentPhase)
		return err
	}
	if _, err := fmt.Fprintf(
		stdout,
		"current: batch=%d target=%d node=%s phase=%s\n",
		*output.CurrentBatch,
		*output.CurrentTarget,
		output.CurrentNodeID,
		output.CurrentPhase,
	); err != nil {
		return err
	}
	if output.ActionRequiredReason != "" {
		_, err := fmt.Fprintf(stdout, "action required: %s\n", output.ActionRequiredReason)
		return err
	}
	return nil
}
