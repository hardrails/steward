package activation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	ProofSchemaV1 = "steward.activation-proof.v1"
	MaxProofBytes = 128 << 10

	MaxCanaryResultBytes int64 = 1 << 20
)

var ErrInvalidProof = errors.New("invalid activation proof")

// CanaryProofV1 correlates the fixed canary contract with one signed task permit
// and one bounded result. It retains no prompt, request, result body, or run log.
type CanaryProofV1 struct {
	Kind         string `json:"kind"`
	TaskDigest   string `json:"task_digest"`
	PermitDigest string `json:"permit_digest"`
	ResultDigest string `json:"result_digest"`
	ResultBytes  int64  `json:"result_bytes"`
}

// ReceiptCoordinateV1 identifies a verified signed receipt-chain head. The
// coordinate is not self-authenticating; callers must verify the companion chain
// and pin its public key separately.
type ReceiptCoordinateV1 struct {
	ReceiptNodeID   string `json:"receipt_node_id"`
	ReceiptEpoch    uint64 `json:"receipt_epoch"`
	Sequence        uint64 `json:"sequence"`
	ChainHash       string `json:"chain_hash"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// WitnessCoordinateV1 identifies the separately signed controller export that
// anchors the Executor receipt coordinate. The witness key and export must be
// authenticated outside this unsigned manifest.
type WitnessCoordinateV1 struct {
	ControllerInstanceID   string `json:"controller_instance_id"`
	ControlNodeID          string `json:"control_node_id"`
	ReceiptNodeID          string `json:"receipt_node_id"`
	ReceiptEpoch           uint64 `json:"receipt_epoch"`
	Sequence               uint64 `json:"sequence"`
	ChainHash              string `json:"chain_hash"`
	ReceiptPublicKeySHA256 string `json:"receipt_public_key_sha256"`
	WitnessPublicKeySHA256 string `json:"witness_public_key_sha256"`
	WitnessExportDigest    string `json:"witness_export_digest"`
	WitnessedAt            string `json:"witnessed_at"`
}

// ProofV1 is an unsigned correlation manifest containing only identities,
// digests, sizes, timestamps, and receipt coordinates. Authenticity derives from
// separately verified signed companions and externally pinned receipt and witness
// keys; parsing or correlating this file alone proves no execution or authority.
type ProofV1 struct {
	SchemaVersion            string              `json:"schema_version"`
	Binding                  BindingV1           `json:"binding"`
	StateDigest              string              `json:"state_digest"`
	RuntimeRef               string              `json:"runtime_ref"`
	Canary                   CanaryProofV1       `json:"canary"`
	ExecutorBeginDigest      string              `json:"executor_begin_digest"`
	ExecutorCheckpointDigest string              `json:"executor_checkpoint_digest"`
	ExecutorEvidence         ReceiptCoordinateV1 `json:"executor_evidence"`
	GatewayEvidence          ReceiptCoordinateV1 `json:"gateway_evidence"`
	Witness                  WitnessCoordinateV1 `json:"witness"`
	CompletedAt              string              `json:"completed_at"`
}

// ParseProofV1 strictly decodes one bounded proof manifest.
func ParseProofV1(raw []byte) (ProofV1, error) {
	var proof ProofV1
	if err := dsse.DecodeStrictInto(raw, MaxProofBytes, &proof); err != nil {
		return ProofV1{}, invalidProof("decode: %v", err)
	}
	if err := proof.Validate(); err != nil {
		return ProofV1{}, err
	}
	return proof, nil
}

// MarshalProofV1 emits the deterministic encoding/json representation after
// validation.
func MarshalProofV1(proof ProofV1) ([]byte, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, invalidProof("marshal: %v", err)
	}
	if len(raw) > MaxProofBytes {
		return nil, invalidProof("encoded proof exceeds %d bytes", MaxProofBytes)
	}
	return raw, nil
}

// ProofDigestV1 validates a proof and identifies its exact serialized bytes.
// It does not authenticate the proof.
func ProofDigestV1(raw []byte) (string, error) {
	if _, err := ParseProofV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks the proof's internal bindings and finite coordinates.
func (proof ProofV1) Validate() error {
	if proof.SchemaVersion != ProofSchemaV1 {
		return invalidProof("unsupported schema version")
	}
	if err := proof.Binding.validate(); err != nil {
		return invalidProof("binding: %v", err)
	}
	if !sha256Digest(proof.StateDigest) {
		return invalidProof("state_digest must be canonical SHA-256")
	}
	if !runtimeRef(proof.RuntimeRef) {
		return invalidProof("runtime_ref is invalid")
	}
	if err := proof.Canary.validate(); err != nil {
		return invalidProof("canary: %v", err)
	}
	if !sha256Digest(proof.ExecutorBeginDigest) ||
		!sha256Digest(proof.ExecutorCheckpointDigest) {
		return invalidProof("executor begin and checkpoint digests must be canonical SHA-256")
	}
	if err := proof.ExecutorEvidence.validate(); err != nil {
		return invalidProof("executor_evidence: %v", err)
	}
	if proof.ExecutorEvidence.ReceiptNodeID != proof.Binding.NodeID {
		return invalidProof("executor evidence belongs to another node")
	}
	if err := proof.GatewayEvidence.validate(); err != nil {
		return invalidProof("gateway_evidence: %v", err)
	}
	if proof.GatewayEvidence.ReceiptNodeID != proof.Binding.NodeID+"/gateway" {
		return invalidProof("gateway evidence belongs to another node")
	}
	if err := proof.Witness.validate(); err != nil {
		return invalidProof("witness: %v", err)
	}
	if !proof.Witness.matches(proof.ExecutorEvidence) {
		return invalidProof("witness coordinate does not match executor evidence")
	}
	completed, ok := canonicalTimestamp(proof.CompletedAt)
	if !ok {
		return invalidProof("completed_at must be canonical UTC RFC3339Nano")
	}
	witnessed, _ := canonicalTimestamp(proof.Witness.WitnessedAt)
	if witnessed.After(completed) {
		return invalidProof("witnessed_at is after completed_at")
	}
	return nil
}

// CorrelateProofV1 strictly parses a plan, final state, and proof and checks all
// repeated bindings and exact-file digests. It does not verify signatures,
// receipt chains, witness exports, image contents, or canary semantics.
func CorrelateProofV1(planRaw, stateRaw, proofRaw []byte) (ProofV1, error) {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return ProofV1{}, invalidProof("plan companion: %v", err)
	}
	state, err := ParseStateV1(stateRaw)
	if err != nil {
		return ProofV1{}, invalidProof("state companion: %v", err)
	}
	proof, err := ParseProofV1(proofRaw)
	if err != nil {
		return ProofV1{}, err
	}
	planDigest := dsse.Digest(planRaw)
	stateDigest := dsse.Digest(stateRaw)
	if state.Phase != PhasePassed {
		return ProofV1{}, invalidProof("state companion is not passed")
	}
	if state.Binding.PlanDigest != planDigest ||
		state.Binding.ActivationID != plan.ActivationID ||
		state.Binding.ReleaseDigest != plan.ReleaseDigest ||
		state.Binding.PolicyDigest != plan.PolicyDigest ||
		state.Binding.IntentDigest != plan.IntentDigest ||
		state.Binding.Archive != plan.Archive {
		return ProofV1{}, proofBindingMismatch("state does not match plan")
	}
	if proof.Binding != state.Binding || proof.StateDigest != stateDigest ||
		proof.RuntimeRef != state.RuntimeRef || proof.Canary.Kind != plan.Canary.Kind {
		return ProofV1{}, proofBindingMismatch("proof does not match plan and final state")
	}
	stateTime, _ := canonicalTimestamp(state.UpdatedAt)
	completed, _ := canonicalTimestamp(proof.CompletedAt)
	if completed.Before(stateTime) {
		return ProofV1{}, invalidProof("completed_at precedes the final state")
	}
	return proof, nil
}

func (canary CanaryProofV1) validate() error {
	if _, ok := agentrelease.CanaryContractForKind(canary.Kind); !ok {
		return errors.New("kind is not a supported built-in canary contract")
	}
	if !sha256Digest(canary.TaskDigest) || !sha256Digest(canary.PermitDigest) ||
		!sha256Digest(canary.ResultDigest) {
		return errors.New("task, permit, and result digests must be canonical SHA-256 values")
	}
	if canary.ResultBytes <= 0 || canary.ResultBytes > MaxCanaryResultBytes {
		return fmt.Errorf("result_bytes must be between 1 and %d", MaxCanaryResultBytes)
	}
	return nil
}

func (coordinate ReceiptCoordinateV1) validate() error {
	if !publicIdentity(coordinate.ReceiptNodeID, 256) || coordinate.ReceiptEpoch == 0 ||
		coordinate.Sequence == 0 || !sha256Digest(coordinate.ChainHash) ||
		!sha256Digest(coordinate.PublicKeySHA256) {
		return errors.New("receipt coordinate is invalid")
	}
	return nil
}

func (witness WitnessCoordinateV1) validate() error {
	if !publicIdentity(witness.ControllerInstanceID, 128) ||
		!publicIdentity(witness.ControlNodeID, 128) ||
		!publicIdentity(witness.ReceiptNodeID, 256) ||
		witness.ReceiptEpoch == 0 || witness.Sequence == 0 ||
		!sha256Digest(witness.ChainHash) ||
		!sha256Digest(witness.ReceiptPublicKeySHA256) ||
		!sha256Digest(witness.WitnessPublicKeySHA256) ||
		!sha256Digest(witness.WitnessExportDigest) {
		return errors.New("witness coordinate is invalid")
	}
	if _, ok := canonicalTimestamp(witness.WitnessedAt); !ok {
		return errors.New("witnessed_at must be canonical UTC RFC3339Nano")
	}
	return nil
}

func (witness WitnessCoordinateV1) matches(receipt ReceiptCoordinateV1) bool {
	return witness.ReceiptNodeID == receipt.ReceiptNodeID &&
		witness.ReceiptEpoch == receipt.ReceiptEpoch &&
		witness.Sequence == receipt.Sequence &&
		witness.ChainHash == receipt.ChainHash &&
		witness.ReceiptPublicKeySHA256 == receipt.PublicKeySHA256
}

func invalidProof(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProof, fmt.Sprintf(format, arguments...))
}

func proofBindingMismatch(message string) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalidProof, ErrBindingMismatch, message)
}
