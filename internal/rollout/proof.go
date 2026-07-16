package rollout

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	ProofManifestSchemaV1 = "steward.rollout-proof-manifest.v1"
	MaxProofManifestBytes = 128 << 10
)

var ErrInvalidProofManifest = errors.New("invalid rollout proof manifest")

// TargetProofV1 binds one ordered target to its exact local target state and
// existing activation proof. The signed companions remain authoritative.
type TargetProofV1 struct {
	TargetIndex           uint16 `json:"target_index"`
	NodeID                string `json:"node_id"`
	ActivationID          string `json:"activation_id"`
	ActivationPlanDigest  string `json:"activation_plan_digest"`
	TargetStateDigest     string `json:"target_state_digest"`
	ActivationProofDigest string `json:"activation_proof_digest"`
}

// ProofManifestV1 is an unsigned aggregate correlation record. It does not
// replace any publisher, command, task, Executor, Gateway, or witness
// signature authenticated by each target's activation proof.
type ProofManifestV1 struct {
	SchemaVersion string          `json:"schema_version"`
	RolloutID     string          `json:"rollout_id"`
	PlanDigest    string          `json:"plan_digest"`
	Targets       []TargetProofV1 `json:"targets"`
	CompletedAt   string          `json:"completed_at"`
}

// ParseProofManifestV1 strictly decodes one bounded aggregate manifest.
func ParseProofManifestV1(raw []byte) (ProofManifestV1, error) {
	var manifest ProofManifestV1
	if err := dsse.DecodeStrictInto(raw, MaxProofManifestBytes, &manifest); err != nil {
		return ProofManifestV1{}, invalidProofManifest("decode: %v", err)
	}
	if err := manifest.Validate(); err != nil {
		return ProofManifestV1{}, err
	}
	return manifest, nil
}

// MarshalProofManifestV1 emits deterministic JSON after validation.
func MarshalProofManifestV1(manifest ProofManifestV1) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, invalidProofManifest("marshal: %v", err)
	}
	if len(raw) > MaxProofManifestBytes {
		return nil, invalidProofManifest(
			"encoded proof manifest exceeds %d bytes",
			MaxProofManifestBytes,
		)
	}
	return raw, nil
}

// ProofManifestDigestV1 validates and identifies exact manifest bytes.
func ProofManifestDigestV1(raw []byte) (string, error) {
	if _, err := ParseProofManifestV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks only the aggregate manifest's finite internal shape.
func (manifest ProofManifestV1) Validate() error {
	if manifest.SchemaVersion != ProofManifestSchemaV1 {
		return invalidProofManifest("unsupported schema version")
	}
	if !identifier(manifest.RolloutID) ||
		!controlprotocol.ValidSHA256Digest(manifest.PlanDigest) {
		return invalidProofManifest("rollout identity or plan digest is invalid")
	}
	if len(manifest.Targets) == 0 || len(manifest.Targets) > MaxTargets {
		return invalidProofManifest(
			"targets must contain between 1 and %d entries",
			MaxTargets,
		)
	}
	for index, target := range manifest.Targets {
		if int(target.TargetIndex) != index ||
			!publicIdentity(target.NodeID, 128) ||
			!identifier(target.ActivationID) ||
			!controlprotocol.ValidSHA256Digest(target.ActivationPlanDigest) ||
			!controlprotocol.ValidSHA256Digest(target.TargetStateDigest) ||
			!controlprotocol.ValidSHA256Digest(target.ActivationProofDigest) {
			return invalidProofManifest("target %d is invalid or out of order", index)
		}
	}
	if _, ok := canonicalTimestamp(manifest.CompletedAt); !ok {
		return invalidProofManifest("completed_at must be canonical UTC RFC3339Nano")
	}
	return nil
}

// CorrelateProofManifestV1 checks the exact rollout plan, latest target states,
// per-target activation plans, final activation states, activation proofs, and
// aggregate manifest. It correlates bytes and identities but does not itself
// verify the signatures and receipt chains inside the activation companions.
func CorrelateProofManifestV1(
	planRaw []byte,
	targetStateRaws [][]byte,
	activationPlanRaws [][]byte,
	activationStateRaws [][]byte,
	activationProofRaws [][]byte,
	manifestRaw []byte,
) (ProofManifestV1, error) {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return ProofManifestV1{}, invalidProofManifest("plan companion: %v", err)
	}
	manifest, err := ParseProofManifestV1(manifestRaw)
	if err != nil {
		return ProofManifestV1{}, err
	}
	count := len(plan.Targets)
	if len(targetStateRaws) != count ||
		len(activationPlanRaws) != count ||
		len(activationStateRaws) != count ||
		len(activationProofRaws) != count ||
		len(manifest.Targets) != count {
		return ProofManifestV1{}, invalidProofManifest(
			"every target requires one state, activation plan, activation state, and activation proof",
		)
	}
	if manifest.RolloutID != plan.RolloutID ||
		manifest.PlanDigest != dsse.Digest(planRaw) {
		return ProofManifestV1{}, proofManifestBindingMismatch(
			"manifest does not match the rollout plan",
		)
	}
	completed, _ := canonicalTimestamp(manifest.CompletedAt)
	targetStates := make([]TargetStateV1, count)
	for index, target := range plan.Targets {
		state, err := ParseTargetStateV1(targetStateRaws[index])
		if err != nil {
			return ProofManifestV1{}, invalidProofManifest(
				"target %d state: %v",
				index,
				err,
			)
		}
		if err := CorrelateTargetStateV1(planRaw, state); err != nil {
			return ProofManifestV1{}, invalidProofManifest(
				"target %d state correlation: %v",
				index,
				err,
			)
		}
		if state.Phase != PhasePassed {
			return ProofManifestV1{}, invalidProofManifest(
				"target %d has not passed",
				index,
			)
		}
		targetStates[index] = state

		activationPlan, err := activation.ParsePlanV1(activationPlanRaws[index])
		if err != nil {
			return ProofManifestV1{}, invalidProofManifest(
				"target %d activation plan: %v",
				index,
				err,
			)
		}
		if activationPlan.Transport != activation.TransportControlUplink ||
			activationPlan.ActivationID != target.ActivationID ||
			activationPlan.ReleaseDigest != plan.ReleaseDigest ||
			activationPlan.PolicyDigest != plan.PolicyDigest ||
			activationPlan.IntentDigest != target.IntentDigest ||
			activationPlan.Archive != plan.Archive ||
			activationPlan.Canary != plan.Canary ||
			dsse.Digest(activationPlanRaws[index]) != target.ActivationPlanDigest {
			return ProofManifestV1{}, proofManifestBindingMismatch(
				"target %d activation plan does not match the rollout target",
				index,
			)
		}
		activationProof, err := activation.CorrelateProofV1(
			activationPlanRaws[index],
			activationStateRaws[index],
			activationProofRaws[index],
		)
		if err != nil {
			return ProofManifestV1{}, invalidProofManifest(
				"target %d activation proof: %v",
				index,
				err,
			)
		}
		if activationProof.Binding.TenantID != plan.TenantID ||
			activationProof.Binding.NodeID != target.NodeID ||
			activationProof.Binding.InstanceID != target.InstanceID ||
			activationProof.Binding.Generation != target.InstanceGeneration ||
			activationProof.RuntimeRef != state.RuntimeRef ||
			activationProof.Canary.ResultDigest != state.CanaryResultDigest ||
			activationProof.Canary.ResultBytes != state.CanaryResultBytes {
			return ProofManifestV1{}, proofManifestBindingMismatch(
				"target %d activation proof does not match rollout state",
				index,
			)
		}
		entry := manifest.Targets[index]
		if entry.TargetIndex != uint16(index) ||
			entry.NodeID != target.NodeID ||
			entry.ActivationID != target.ActivationID ||
			entry.ActivationPlanDigest != target.ActivationPlanDigest ||
			entry.TargetStateDigest != dsse.Digest(targetStateRaws[index]) ||
			entry.ActivationProofDigest != dsse.Digest(activationProofRaws[index]) {
			return ProofManifestV1{}, proofManifestBindingMismatch(
				"target %d aggregate proof entry is inconsistent",
				index,
			)
		}
		stateTime, _ := canonicalTimestamp(state.UpdatedAt)
		proofTime, _ := canonicalTimestamp(activationProof.CompletedAt)
		if completed.Before(stateTime) || completed.Before(proofTime) {
			return ProofManifestV1{}, invalidProofManifest(
				"completed_at precedes target %d completion",
				index,
			)
		}
	}
	if err := ValidateFleetProgressV1(planRaw, targetStates); err != nil {
		return ProofManifestV1{}, invalidProofManifest(
			"fleet progress: %v",
			err,
		)
	}
	return manifest, nil
}

func invalidProofManifest(format string, arguments ...any) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidProofManifest,
		fmt.Sprintf(format, arguments...),
	)
}

func proofManifestBindingMismatch(format string, arguments ...any) error {
	return fmt.Errorf(
		"%w: %w: %s",
		ErrInvalidProofManifest,
		ErrBindingMismatch,
		fmt.Sprintf(format, arguments...),
	)
}
