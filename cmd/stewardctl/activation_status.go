package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/controlprotocol"
)

const (
	activationWaitingRun          = "activation_run"
	activationWaitingCanaryTask   = "canary_task"
	activationWaitingCheckpoint   = "activation_checkpoint"
	activationWaitingFinalWitness = "final_witness"

	activationAttachCanaryTaskCommand = "stewardctl activation attach -dir DIR -kind canary-task -in FILE"
	activationResumeRunCommand        = "stewardctl activation run -dir DIR ..."
	activationAttachWitnessCommand    = "stewardctl activation attach -dir DIR -kind final-witness -in FILE"
)

func activationReplaceFailedCommand(generation uint64) string {
	return fmt.Sprintf(
		"correct the failure, stop and destroy the failed workload, then create a new activation ID with an instance generation greater than %d",
		generation,
	)
}

func statusActivation(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("activation status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directoryFlag := flags.String("dir", "", "owner-only activation workspace")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directoryFlag == "" || flags.NArg() != 0 {
		return errors.New("activation status requires -dir and no positional arguments")
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return fmt.Errorf("resolve activation workspace path: %w", err)
	}
	store, err := activationstore.Open(directory)
	if err != nil {
		return err
	}
	defer store.Close()

	inputs, chain, err := loadUnverifiedActivationStateChain(store)
	if err != nil {
		return err
	}
	return writeUnverifiedActivationStatus(stdout, store, inputs, chain)
}

// loadUnverifiedActivationStateChain validates only local, unsigned workspace
// consistency. It deliberately does not authenticate the plan, state, or any
// companion artifact; callers must keep Verified false in user-facing output.
func loadUnverifiedActivationStateChain(
	store *activationstore.Store,
) (verifiedActivationInputs, activationStateChain, error) {
	planRaw, err := store.Read(activationstore.PlanFileName, activation.MaxPlanBytes)
	if err != nil {
		return verifiedActivationInputs{}, activationStateChain{}, fmt.Errorf("read activation plan: %w", err)
	}
	plan, err := activation.ParsePlanV1(planRaw)
	if err != nil {
		return verifiedActivationInputs{}, activationStateChain{}, fmt.Errorf("parse activation plan: %w", err)
	}
	names, err := store.ListStateCheckpoints()
	if err != nil {
		return verifiedActivationInputs{}, activationStateChain{}, err
	}
	if len(names) == 0 {
		return verifiedActivationInputs{}, activationStateChain{}, errors.New("activation workspace has no state checkpoint")
	}
	chain := activationStateChain{names: names}
	for index, name := range names {
		expected, nameErr := activationstore.StateCheckpointName(uint64(index))
		if nameErr != nil || name != expected {
			return verifiedActivationInputs{}, activationStateChain{},
				errors.New("activation state checkpoints are not contiguous from zero")
		}
		raw, readErr := store.Read(name, activation.MaxStateBytes)
		if readErr != nil {
			return verifiedActivationInputs{}, activationStateChain{},
				fmt.Errorf("read activation state %q: %w", name, readErr)
		}
		state, parseErr := activation.ParseStateV1(raw)
		if parseErr != nil {
			return verifiedActivationInputs{}, activationStateChain{},
				fmt.Errorf("parse activation state %q: %w", name, parseErr)
		}
		if index > 0 {
			if transitionErr := activation.ValidateStateTransitionV1(chain.states[index-1], state); transitionErr != nil {
				return verifiedActivationInputs{}, activationStateChain{},
					fmt.Errorf("validate activation state %q: %w", name, transitionErr)
			}
		}
		chain.raw = append(chain.raw, raw)
		chain.states = append(chain.states, state)
	}

	initial := chain.states[0]
	planDigest, err := activation.PlanDigestV1(planRaw)
	if err != nil {
		return verifiedActivationInputs{}, activationStateChain{},
			fmt.Errorf("identify activation plan: %w", err)
	}
	if initial.Phase != activation.PhaseNew ||
		initial.Binding.ActivationID != plan.ActivationID ||
		initial.Binding.PlanDigest != planDigest ||
		initial.Binding.ReleaseDigest != plan.ReleaseDigest ||
		initial.Binding.PolicyDigest != plan.PolicyDigest ||
		initial.Binding.IntentDigest != plan.IntentDigest ||
		initial.Binding.Archive != plan.Archive {
		return verifiedActivationInputs{}, activationStateChain{},
			errors.New("initial activation state does not match the unsigned activation plan")
	}
	return verifiedActivationInputs{planRaw: planRaw, plan: plan}, chain, nil
}

func writeUnverifiedActivationStatus(
	stdout io.Writer,
	store *activationstore.Store,
	inputs verifiedActivationInputs,
	chain activationStateChain,
) error {
	var waitingFor, nextCommand, proofDigest string
	switch chain.latest().Phase {
	case activation.PhaseNew,
		activation.PhaseReleaseVerified,
		activation.PhasePreflightPassed,
		activation.PhaseImageImported,
		activation.PhaseAdmitted,
		activation.PhaseRunning,
		activation.PhaseCanaryAuthorized,
		activation.PhaseCanaryDispatched,
		activation.PhaseEvidenceCollected:
		waitingFor = activationWaitingRun
		nextCommand = activationResumeRunCommand
	case activation.PhaseCanaryChallengeReady:
		if _, present, err := readOptionalActivationArtifact(
			store, activationstore.CanaryTaskFileName, maxTaskBundleBytes,
		); err != nil {
			return fmt.Errorf("inspect attached canary task: %w", err)
		} else if !present {
			waitingFor = activationWaitingCanaryTask
			nextCommand = activationAttachCanaryTaskCommand
		} else {
			waitingFor = activationWaitingRun
			nextCommand = activationResumeRunCommand
		}
	case activation.PhaseAgentReportedTerminal:
		checkpointRaw, checkpointPresent, err := readOptionalActivationArtifact(
			store,
			activationstore.ExecutorCheckpointFileName,
			activation.MaxExecutorCheckpointBytes,
		)
		if err != nil {
			return fmt.Errorf("inspect activation checkpoint: %w", err)
		}
		if !checkpointPresent {
			waitingFor = activationWaitingCheckpoint
			nextCommand = activationResumeRunCommand
			break
		}
		if _, err := activation.ParseExecutorCheckpointV1(checkpointRaw); err != nil {
			return fmt.Errorf("validate retained activation checkpoint: %w", err)
		}
		if _, present, err := readOptionalActivationArtifact(
			store,
			activationstore.ExecutorFinalWitnessFileName,
			controlprotocol.MaxExecutorEvidenceJSONBytes,
		); err != nil {
			return fmt.Errorf("inspect attached final witness: %w", err)
		} else if !present {
			waitingFor = activationWaitingFinalWitness
			nextCommand = activationAttachWitnessCommand
		} else {
			waitingFor = activationWaitingRun
			nextCommand = activationResumeRunCommand
		}
	case activation.PhasePassed:
		proofRaw, err := store.Read(activationstore.ProofFileName, activation.MaxProofBytes)
		if err != nil {
			return fmt.Errorf("read activation proof: %w", err)
		}
		if _, err := activation.CorrelateProofV1(inputs.planRaw, chain.latestRaw(), proofRaw); err != nil {
			return fmt.Errorf("correlate activation proof: %w", err)
		}
		proofDigest, err = activation.ProofDigestV1(proofRaw)
		if err != nil {
			return fmt.Errorf("identify activation proof: %w", err)
		}
	case activation.PhaseActionRequired:
		waitingFor = "operator"
		nextCommand = activationReplaceFailedCommand(
			chain.latest().Binding.Generation,
		)
	}
	return writeActivationStatus(stdout, inputs, chain, false, waitingFor, nextCommand, proofDigest)
}
