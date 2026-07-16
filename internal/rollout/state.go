package rollout

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	TargetStateSchemaV1 = "steward.rollout-target-state.v1"
	MaxTargetStateBytes = 64 << 10

	PhasePlanned               = "planned"
	PhasePreflightPassed       = "preflight_passed"
	PhaseEvidenceCaptureArmed  = "evidence_capture_armed"
	PhaseAdmitSubmitted        = "admit_submitted"
	PhaseAdmitted              = "admitted"
	PhaseStartSubmitted        = "start_submitted"
	PhaseRunning               = "running"
	PhaseCanaryAuthorized      = "canary_authorized"
	PhaseCanarySubmitted       = "canary_submitted"
	PhaseAgentReportedTerminal = "agent_reported_terminal"
	PhaseEvidenceCollected     = "evidence_collected"
	PhasePassed                = "passed"
	PhaseActionRequired        = "action_required"
)

var (
	ErrInvalidState      = errors.New("invalid rollout target state")
	ErrInvalidTransition = errors.New("invalid rollout target state transition")
	ErrBindingMismatch   = errors.New("rollout binding mismatch")
)

var targetPhaseSequence = [...]string{
	PhasePlanned,
	PhasePreflightPassed,
	PhaseEvidenceCaptureArmed,
	PhaseAdmitSubmitted,
	PhaseAdmitted,
	PhaseStartSubmitted,
	PhaseRunning,
	PhaseCanaryAuthorized,
	PhaseCanarySubmitted,
	PhaseAgentReportedTerminal,
	PhaseEvidenceCollected,
	PhasePassed,
}

// TargetBindingV1 is the immutable identity copied from one ordered plan
// target. TargetIndex is zero-based and therefore also proves rollout order.
type TargetBindingV1 struct {
	PlanDigest         string `json:"plan_digest"`
	RolloutID          string `json:"rollout_id"`
	TargetIndex        uint16 `json:"target_index"`
	TenantID           string `json:"tenant_id"`
	NodeID             string `json:"node_id"`
	InstanceID         string `json:"instance_id"`
	ActivationID       string `json:"activation_id"`
	ClaimGeneration    uint64 `json:"claim_generation"`
	InstanceGeneration uint64 `json:"instance_generation"`
}

// TargetStateV1 is one bounded append-only checkpoint. It contains no command
// bytes, credentials, paths, URLs, arbitrary error text, prompt, or result
// body. Companion artifacts carry those exact bytes separately.
type TargetStateV1 struct {
	SchemaVersion        string          `json:"schema_version"`
	Binding              TargetBindingV1 `json:"binding"`
	Phase                string          `json:"phase"`
	RuntimeRef           string          `json:"runtime_ref,omitempty"`
	AdmissionDigest      string          `json:"admission_digest,omitempty"`
	CanaryResultDigest   string          `json:"canary_result_digest,omitempty"`
	CanaryResultBytes    int64           `json:"canary_result_bytes,omitempty"`
	UpdatedAt            string          `json:"updated_at"`
	ActionRequiredReason string          `json:"action_required_reason,omitempty"`
}

// ParseTargetStateV1 strictly decodes one bounded state checkpoint.
func ParseTargetStateV1(raw []byte) (TargetStateV1, error) {
	var state TargetStateV1
	if err := dsse.DecodeStrictInto(raw, MaxTargetStateBytes, &state); err != nil {
		return TargetStateV1{}, invalidState("decode: %v", err)
	}
	if err := state.Validate(); err != nil {
		return TargetStateV1{}, err
	}
	return state, nil
}

// MarshalTargetStateV1 emits deterministic JSON after validation.
func MarshalTargetStateV1(state TargetStateV1) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, invalidState("marshal: %v", err)
	}
	if len(raw) > MaxTargetStateBytes {
		return nil, invalidState("encoded state exceeds %d bytes", MaxTargetStateBytes)
	}
	return raw, nil
}

// TargetStateDigestV1 validates and identifies exact checkpoint bytes.
func TargetStateDigestV1(raw []byte) (string, error) {
	if _, err := ParseTargetStateV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks one state independently of its predecessor and plan.
func (state TargetStateV1) Validate() error {
	if state.SchemaVersion != TargetStateSchemaV1 {
		return invalidState("unsupported schema version")
	}
	if err := state.Binding.validate(); err != nil {
		return invalidState("binding: %v", err)
	}
	rank, normal := targetPhaseRank(state.Phase)
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
		if err := validateOptionalRuntimeBinding(state); err != nil {
			return invalidState("%v", err)
		}
		if err := validateOptionalCanaryResult(state); err != nil {
			return invalidState("%v", err)
		}
		return nil
	}
	if state.ActionRequiredReason != "" {
		return invalidState("action_required_reason is valid only in action_required")
	}

	admittedRank, _ := targetPhaseRank(PhaseAdmitted)
	if rank < admittedRank {
		if state.RuntimeRef != "" || state.AdmissionDigest != "" {
			return invalidState("runtime and admission identity must be absent before admission")
		}
	} else if !runtimeRef(state.RuntimeRef) ||
		!controlprotocol.ValidSHA256Digest(state.AdmissionDigest) {
		return invalidState("runtime and admission identity are required from admitted onward")
	}

	terminalRank, _ := targetPhaseRank(PhaseAgentReportedTerminal)
	if rank < terminalRank {
		if state.CanaryResultDigest != "" || state.CanaryResultBytes != 0 {
			return invalidState("canary result identity must be absent before terminal observation")
		}
	} else if !controlprotocol.ValidSHA256Digest(state.CanaryResultDigest) ||
		state.CanaryResultBytes <= 0 ||
		state.CanaryResultBytes > activation.MaxCanaryResultBytes {
		return invalidState("bounded canary result identity is required from terminal observation onward")
	}
	return nil
}

// ValidateTargetTransitionV1 permits exact replay, the next normal phase, or a
// sticky transition to action_required. It never permits rollback or skipping.
func ValidateTargetTransitionV1(current, next TargetStateV1) error {
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
	if err := preserveOrIntroduceRuntime(current, next); err != nil {
		return err
	}
	if err := preserveOrIntroduceCanary(current, next); err != nil {
		return err
	}
	if next.Phase == PhaseActionRequired {
		return nil
	}
	currentRank, _ := targetPhaseRank(current.Phase)
	nextRank, _ := targetPhaseRank(next.Phase)
	if nextRank != currentRank+1 {
		return invalidTransition("phase must advance exactly one step")
	}
	return nil
}

// CorrelateTargetStateV1 validates that one state belongs to the exact indexed
// target in the serialized rollout plan.
func CorrelateTargetStateV1(planRaw []byte, state TargetStateV1) error {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return invalidState("plan companion: %v", err)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	planDigest := dsse.Digest(planRaw)
	index := int(state.Binding.TargetIndex)
	if index >= len(plan.Targets) {
		return fmt.Errorf("%w: %w: target index is outside the plan", ErrInvalidState, ErrBindingMismatch)
	}
	target := plan.Targets[index]
	expected := TargetBindingV1{
		PlanDigest:         planDigest,
		RolloutID:          plan.RolloutID,
		TargetIndex:        state.Binding.TargetIndex,
		TenantID:           plan.TenantID,
		NodeID:             target.NodeID,
		InstanceID:         target.InstanceID,
		ActivationID:       target.ActivationID,
		ClaimGeneration:    target.ClaimGeneration,
		InstanceGeneration: target.InstanceGeneration,
	}
	if state.Binding != expected {
		return fmt.Errorf("%w: %w: state does not match its plan target", ErrInvalidState, ErrBindingMismatch)
	}
	updated, _ := canonicalTimestamp(state.UpdatedAt)
	deadline, _ := canonicalTimestamp(plan.Deadline)
	if state.Phase != PhaseActionRequired && updated.After(deadline) {
		return invalidState("normal target progress is after the rollout deadline")
	}
	return nil
}

// ValidateFleetProgressV1 derives fleet validity from one latest state per
// target. A target cannot leave planned until every earlier target has passed;
// this enforces canary-first, sequential execution without a second mutable
// aggregate state machine.
func ValidateFleetProgressV1(planRaw []byte, states []TargetStateV1) error {
	plan, err := ParsePlanV1(planRaw)
	if err != nil {
		return err
	}
	if len(states) != len(plan.Targets) {
		return invalidState("fleet progress must contain exactly one state per target")
	}
	for index, state := range states {
		if int(state.Binding.TargetIndex) != index {
			return invalidState("fleet progress states are not in target order")
		}
		if err := CorrelateTargetStateV1(planRaw, state); err != nil {
			return err
		}
		if index > 0 && state.Phase != PhasePlanned && states[index-1].Phase != PhasePassed {
			return invalidState("target %d advanced before target %d passed", index, index-1)
		}
	}
	return nil
}

func (binding TargetBindingV1) validate() error {
	if !controlprotocol.ValidSHA256Digest(binding.PlanDigest) ||
		!identifier(binding.RolloutID) ||
		!publicIdentity(binding.TenantID, 128) ||
		!publicIdentity(binding.NodeID, 128) ||
		!publicIdentity(binding.InstanceID, 256) ||
		!identifier(binding.ActivationID) ||
		binding.ClaimGeneration == 0 ||
		binding.InstanceGeneration == 0 {
		return errors.New("target binding is invalid")
	}
	return nil
}

func validateOptionalRuntimeBinding(state TargetStateV1) error {
	present := state.RuntimeRef != "" || state.AdmissionDigest != ""
	if !present {
		return nil
	}
	if !runtimeRef(state.RuntimeRef) ||
		!controlprotocol.ValidSHA256Digest(state.AdmissionDigest) {
		return errors.New("partial or invalid runtime admission identity")
	}
	return nil
}

func validateOptionalCanaryResult(state TargetStateV1) error {
	present := state.CanaryResultDigest != "" || state.CanaryResultBytes != 0
	if !present {
		return nil
	}
	if !controlprotocol.ValidSHA256Digest(state.CanaryResultDigest) ||
		state.CanaryResultBytes <= 0 ||
		state.CanaryResultBytes > activation.MaxCanaryResultBytes {
		return errors.New("partial or invalid canary result identity")
	}
	return nil
}

func preserveOrIntroduceRuntime(current, next TargetStateV1) error {
	if current.RuntimeRef != "" || current.AdmissionDigest != "" {
		if next.RuntimeRef != current.RuntimeRef ||
			next.AdmissionDigest != current.AdmissionDigest {
			return fmt.Errorf("%w: %w: runtime admission identity changed", ErrInvalidTransition, ErrBindingMismatch)
		}
		return nil
	}
	if next.RuntimeRef != "" || next.AdmissionDigest != "" {
		if next.Phase != PhaseAdmitted {
			return fmt.Errorf("%w: %w: runtime admission identity appeared outside admission", ErrInvalidTransition, ErrBindingMismatch)
		}
	}
	return nil
}

func preserveOrIntroduceCanary(current, next TargetStateV1) error {
	if current.CanaryResultDigest != "" || current.CanaryResultBytes != 0 {
		if next.CanaryResultDigest != current.CanaryResultDigest ||
			next.CanaryResultBytes != current.CanaryResultBytes {
			return fmt.Errorf("%w: %w: canary result identity changed", ErrInvalidTransition, ErrBindingMismatch)
		}
		return nil
	}
	if next.CanaryResultDigest != "" || next.CanaryResultBytes != 0 {
		if next.Phase != PhaseAgentReportedTerminal {
			return fmt.Errorf("%w: %w: canary result identity appeared outside terminal observation", ErrInvalidTransition, ErrBindingMismatch)
		}
	}
	return nil
}

func targetPhaseRank(phase string) (int, bool) {
	for rank, candidate := range targetPhaseSequence {
		if phase == candidate {
			return rank, true
		}
	}
	return 0, false
}

func runtimeRef(value string) bool {
	const prefix = "executor-"
	return strings.HasPrefix(value, prefix) &&
		len(value) == len(prefix)+64 &&
		lowerHex(strings.TrimPrefix(value, prefix))
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func invalidState(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidState, fmt.Sprintf(format, arguments...))
}

func invalidTransition(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTransition, fmt.Sprintf(format, arguments...))
}
