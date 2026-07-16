package activation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	StateSchemaV1 = "steward.activation-state.v1"
	MaxStateBytes = 128 << 10

	PhaseNew                   = "new"
	PhaseReleaseVerified       = "release_verified"
	PhasePreflightPassed       = "preflight_passed"
	PhaseImageImported         = "image_imported"
	PhaseAdmitted              = "admitted"
	PhaseRunning               = "running"
	PhaseCanaryChallengeReady  = "canary_challenge_ready"
	PhaseCanaryAuthorized      = "canary_authorized"
	PhaseCanaryDispatched      = "canary_dispatched"
	PhaseAgentReportedTerminal = "agent_reported_terminal"
	PhaseEvidenceCollected     = "evidence_collected"
	PhasePassed                = "passed"
	PhaseActionRequired        = "action_required"
)

var (
	ErrInvalidState      = errors.New("invalid activation state")
	ErrInvalidTransition = errors.New("invalid activation state transition")
	ErrBindingMismatch   = errors.New("activation binding mismatch")
)

var phaseSequence = [...]string{
	PhaseNew,
	PhaseReleaseVerified,
	PhasePreflightPassed,
	PhaseImageImported,
	PhaseAdmitted,
	PhaseRunning,
	PhaseCanaryChallengeReady,
	PhaseCanaryAuthorized,
	PhaseCanaryDispatched,
	PhaseAgentReportedTerminal,
	PhaseEvidenceCollected,
	PhasePassed,
}

// BindingV1 is the immutable activation and runtime identity. RuntimeRef is
// stored separately because it does not exist until admission succeeds.
type BindingV1 struct {
	ActivationID  string    `json:"activation_id"`
	PlanDigest    string    `json:"plan_digest"`
	ReleaseDigest string    `json:"release_digest"`
	PolicyDigest  string    `json:"policy_digest"`
	IntentDigest  string    `json:"intent_digest"`
	Archive       ArchiveV1 `json:"archive"`
	TenantID      string    `json:"tenant_id"`
	NodeID        string    `json:"node_id"`
	InstanceID    string    `json:"instance_id"`
	Generation    uint64    `json:"generation"`
}

// StateV1 is a bounded activation checkpoint. It contains no commands, logs,
// paths, URLs, credentials, or arbitrary error text. ActionRequiredReason is a
// stable machine-readable code, not an instruction to clear the condition.
type StateV1 struct {
	SchemaVersion        string    `json:"schema_version"`
	Binding              BindingV1 `json:"binding"`
	Phase                string    `json:"phase"`
	RuntimeRef           string    `json:"runtime_ref,omitempty"`
	UpdatedAt            string    `json:"updated_at"`
	ActionRequiredReason string    `json:"action_required_reason,omitempty"`
}

// ParseStateV1 strictly decodes one bounded state checkpoint.
func ParseStateV1(raw []byte) (StateV1, error) {
	var state StateV1
	if err := dsse.DecodeStrictInto(raw, MaxStateBytes, &state); err != nil {
		return StateV1{}, invalidState("decode: %v", err)
	}
	if err := state.Validate(); err != nil {
		return StateV1{}, err
	}
	return state, nil
}

// MarshalStateV1 emits the deterministic encoding/json representation after
// validation.
func MarshalStateV1(state StateV1) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, invalidState("marshal: %v", err)
	}
	if len(raw) > MaxStateBytes {
		return nil, invalidState("encoded state exceeds %d bytes", MaxStateBytes)
	}
	return raw, nil
}

// StateDigestV1 validates a checkpoint and identifies its exact serialized
// bytes. It does not authenticate the state.
func StateDigestV1(raw []byte) (string, error) {
	if _, err := ParseStateV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks one state snapshot independently of its predecessor.
func (state StateV1) Validate() error {
	if state.SchemaVersion != StateSchemaV1 {
		return invalidState("unsupported schema version")
	}
	if err := state.Binding.validate(); err != nil {
		return invalidState("binding: %v", err)
	}
	rank, normal := phaseRank(state.Phase)
	if !normal && state.Phase != PhaseActionRequired {
		return invalidState("unknown phase %q", state.Phase)
	}
	if _, ok := canonicalTimestamp(state.UpdatedAt); !ok {
		return invalidState("updated_at must be canonical UTC RFC3339Nano")
	}
	if state.Phase == PhaseActionRequired {
		if !identifier(state.ActionRequiredReason) {
			return invalidState("action_required needs one bounded reason code")
		}
		if state.RuntimeRef != "" && !runtimeRef(state.RuntimeRef) {
			return invalidState("runtime_ref is invalid")
		}
		return nil
	}
	if state.ActionRequiredReason != "" {
		return invalidState("action_required_reason is valid only in action_required")
	}
	admittedRank, _ := phaseRank(PhaseAdmitted)
	if rank < admittedRank {
		if state.RuntimeRef != "" {
			return invalidState("runtime_ref must be absent before admission")
		}
	} else if !runtimeRef(state.RuntimeRef) {
		return invalidState("runtime_ref is required from admitted onward")
	}
	return nil
}

// ValidateStateTransitionV1 accepts only the next normal phase or a transition
// to action_required. Exact replay of the complete current state is idempotent.
// passed and action_required are terminal; action_required is deliberately sticky.
func ValidateStateTransitionV1(current, next StateV1) error {
	if err := current.Validate(); err != nil {
		return fmt.Errorf("%w: current: %v", ErrInvalidTransition, err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("%w: next: %v", ErrInvalidTransition, err)
	}
	if current == next {
		return nil
	}
	if current.Binding != next.Binding {
		return fmt.Errorf("%w: %w", ErrInvalidTransition, ErrBindingMismatch)
	}
	if current.Phase == PhasePassed {
		return invalidTransition("passed is terminal")
	}
	if current.Phase == PhaseActionRequired {
		return invalidTransition("action_required is sticky")
	}

	currentTime, _ := canonicalTimestamp(current.UpdatedAt)
	nextTime, _ := canonicalTimestamp(next.UpdatedAt)
	if !nextTime.After(currentTime) {
		return invalidTransition("updated_at must advance")
	}
	if current.RuntimeRef != "" {
		if next.RuntimeRef != current.RuntimeRef {
			return fmt.Errorf("%w: %w: runtime_ref changed", ErrInvalidTransition, ErrBindingMismatch)
		}
	} else if next.RuntimeRef != "" && next.Phase != PhaseAdmitted {
		return fmt.Errorf("%w: %w: runtime_ref appeared outside admission", ErrInvalidTransition, ErrBindingMismatch)
	}

	if next.Phase == PhaseActionRequired {
		return nil
	}
	currentRank, _ := phaseRank(current.Phase)
	nextRank, _ := phaseRank(next.Phase)
	if nextRank != currentRank+1 {
		return invalidTransition("phase must advance exactly one step")
	}
	return nil
}

// AdvanceStateV1 returns next after validating the transition. It performs no
// persistence or external action.
func AdvanceStateV1(current, next StateV1) (StateV1, error) {
	if err := ValidateStateTransitionV1(current, next); err != nil {
		return StateV1{}, err
	}
	if current == next {
		return current, nil
	}
	return next, nil
}

func (binding BindingV1) validate() error {
	if !identifier(binding.ActivationID) {
		return errors.New("activation_id is not a bounded identifier")
	}
	if !sha256Digest(binding.PlanDigest) || !sha256Digest(binding.ReleaseDigest) ||
		!sha256Digest(binding.PolicyDigest) || !sha256Digest(binding.IntentDigest) {
		return errors.New("binding digests must be canonical SHA-256 values")
	}
	if err := validateArchive(binding.Archive); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if !publicIdentity(binding.TenantID, 128) || !publicIdentity(binding.NodeID, 128) ||
		!publicIdentity(binding.InstanceID, 256) {
		return errors.New("tenant, node, or instance identity is invalid")
	}
	if binding.Generation == 0 {
		return errors.New("generation must be positive")
	}
	return nil
}

func phaseRank(phase string) (int, bool) {
	for rank, candidate := range phaseSequence {
		if phase == candidate {
			return rank, true
		}
	}
	return 0, false
}

func invalidState(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidState, fmt.Sprintf(format, arguments...))
}

func invalidTransition(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTransition, fmt.Sprintf(format, arguments...))
}
