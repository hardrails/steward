// Package rollout defines strict, side-effect-free manifests for one ordered
// fleet rollout. These records coordinate existing signed authorities; they do
// not authorize admission, choose nodes, sign commands, or prove execution.
package rollout

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
)

const (
	PlanSchemaV1 = "steward.rollout-plan.v1"
	MaxPlanBytes = 256 << 10
	MaxTargets   = 64
	MaxBatchSize = 16

	maxRolloutDuration = 24 * time.Hour
)

var (
	ErrInvalidPlan = errors.New("invalid rollout plan")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// TargetV1 binds one ordered node activation and the exact command identities
// that the trusted coordinator will sign. Array order is rollout order; no
// selector, label, or controller-side placement rule is implied.
type TargetV1 struct {
	NodeID               string `json:"node_id"`
	InstanceID           string `json:"instance_id"`
	ActivationID         string `json:"activation_id"`
	IntentDigest         string `json:"intent_digest"`
	ActivationPlanDigest string `json:"activation_plan_digest"`
	ClaimGeneration      uint64 `json:"claim_generation"`
	InstanceGeneration   uint64 `json:"instance_generation"`
	AdmitCommandID       string `json:"admit_command_id"`
	StartCommandID       string `json:"start_command_id"`
	CanaryCommandID      string `json:"canary_command_id"`
}

// PlanV1 is an unsigned, non-authoritative rollout manifest. The first target
// is always the canary. Later targets are grouped into fixed-size batches, but
// the initial runner processes targets sequentially within each batch.
type PlanV1 struct {
	SchemaVersion string                    `json:"schema_version"`
	RolloutID     string                    `json:"rollout_id"`
	TenantID      string                    `json:"tenant_id"`
	ReleaseDigest string                    `json:"release_digest"`
	PolicyDigest  string                    `json:"policy_digest"`
	Archive       ocibundle.ArchiveIdentity `json:"archive"`
	Canary        activation.CanaryV1       `json:"canary"`
	BatchSize     uint16                    `json:"batch_size"`
	CreatedAt     string                    `json:"created_at"`
	Deadline      string                    `json:"deadline"`
	Targets       []TargetV1                `json:"targets"`
}

// BatchV1 identifies one deterministic half-open target range. Batch zero is
// always the single canary target.
type BatchV1 struct {
	Number uint16
	Start  int
	End    int
}

// ParsePlanV1 strictly decodes one bounded plan.
func ParsePlanV1(raw []byte) (PlanV1, error) {
	var plan PlanV1
	if err := dsse.DecodeStrictInto(raw, MaxPlanBytes, &plan); err != nil {
		return PlanV1{}, invalidPlan("decode: %v", err)
	}
	if err := plan.Validate(); err != nil {
		return PlanV1{}, err
	}
	return plan, nil
}

// MarshalPlanV1 emits the deterministic encoding/json representation after
// validation.
func MarshalPlanV1(plan PlanV1) ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, invalidPlan("marshal: %v", err)
	}
	if len(raw) > MaxPlanBytes {
		return nil, invalidPlan("encoded plan exceeds %d bytes", MaxPlanBytes)
	}
	return raw, nil
}

// PlanDigestV1 validates and identifies the exact serialized plan bytes. It is
// a correlation digest, not a signature.
func PlanDigestV1(raw []byte) (string, error) {
	if _, err := ParsePlanV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks the finite plan schema, ordering identities, and bounds.
func (plan PlanV1) Validate() error {
	if plan.SchemaVersion != PlanSchemaV1 {
		return invalidPlan("unsupported schema version")
	}
	if !identifier(plan.RolloutID) || !publicIdentity(plan.TenantID, 128) {
		return invalidPlan("rollout or tenant identity is invalid")
	}
	if !controlprotocol.ValidSHA256Digest(plan.ReleaseDigest) ||
		!controlprotocol.ValidSHA256Digest(plan.PolicyDigest) {
		return invalidPlan("release and policy digests must be canonical SHA-256 values")
	}
	if !controlprotocol.ValidSHA256Digest(plan.Archive.Digest) ||
		plan.Archive.Bytes <= 0 ||
		plan.Archive.Bytes > activation.MaxActivationArchiveBytes {
		return invalidPlan("archive identity is invalid")
	}
	if plan.Canary.Kind != activation.CanaryHermesWorkspaceAuditV1 {
		return invalidPlan("canary kind must be %q", activation.CanaryHermesWorkspaceAuditV1)
	}
	if plan.BatchSize == 0 || plan.BatchSize > MaxBatchSize {
		return invalidPlan("batch_size must be between 1 and %d", MaxBatchSize)
	}
	created, ok := canonicalTimestamp(plan.CreatedAt)
	if !ok {
		return invalidPlan("created_at must be canonical UTC RFC3339Nano")
	}
	deadline, ok := canonicalTimestamp(plan.Deadline)
	if !ok || !deadline.After(created) || deadline.Sub(created) > maxRolloutDuration {
		return invalidPlan("deadline must be after created_at and at most 24 hours later")
	}
	if len(plan.Targets) == 0 || len(plan.Targets) > MaxTargets {
		return invalidPlan("targets must contain between 1 and %d entries", MaxTargets)
	}

	nodes := make(map[string]struct{}, len(plan.Targets))
	activations := make(map[string]struct{}, len(plan.Targets))
	commands := make(map[string]struct{}, len(plan.Targets)*3)
	for index, target := range plan.Targets {
		if err := target.validate(); err != nil {
			return invalidPlan("target %d: %v", index, err)
		}
		if _, duplicate := nodes[target.NodeID]; duplicate {
			return invalidPlan("target %d repeats node_id", index)
		}
		nodes[target.NodeID] = struct{}{}
		if _, duplicate := activations[target.ActivationID]; duplicate {
			return invalidPlan("target %d repeats activation_id", index)
		}
		activations[target.ActivationID] = struct{}{}
		for _, commandID := range []string{
			target.AdmitCommandID,
			target.StartCommandID,
			target.CanaryCommandID,
		} {
			if _, duplicate := commands[commandID]; duplicate {
				return invalidPlan("target %d repeats a command identity", index)
			}
			commands[commandID] = struct{}{}
		}
	}
	return nil
}

func (target TargetV1) validate() error {
	if !publicIdentity(target.NodeID, 128) ||
		!publicIdentity(target.InstanceID, 256) ||
		!identifier(target.ActivationID) {
		return errors.New("node, instance, or activation identity is invalid")
	}
	if !controlprotocol.ValidSHA256Digest(target.IntentDigest) ||
		!controlprotocol.ValidSHA256Digest(target.ActivationPlanDigest) {
		return errors.New("intent and activation plan digests must be canonical SHA-256 values")
	}
	if target.ClaimGeneration == 0 || target.InstanceGeneration == 0 {
		return errors.New("claim and instance generations must be positive")
	}
	if !identifier(target.AdmitCommandID) ||
		!identifier(target.StartCommandID) ||
		!identifier(target.CanaryCommandID) {
		return errors.New("command identities are invalid")
	}
	if target.AdmitCommandID == target.StartCommandID ||
		target.AdmitCommandID == target.CanaryCommandID ||
		target.StartCommandID == target.CanaryCommandID {
		return errors.New("command identities must be distinct")
	}
	return nil
}

// Batches returns deterministic rollout ranges. The first range contains only
// the canary; subsequent ranges contain at most BatchSize targets.
func (plan PlanV1) Batches() ([]BatchV1, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	batches := []BatchV1{{Number: 0, Start: 0, End: 1}}
	for start, number := 1, uint16(1); start < len(plan.Targets); number++ {
		end := start + int(plan.BatchSize)
		if end > len(plan.Targets) {
			end = len(plan.Targets)
		}
		batches = append(batches, BatchV1{Number: number, Start: start, End: end})
		start = end
	}
	return batches, nil
}

func identifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func publicIdentity(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func canonicalTimestamp(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func invalidPlan(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPlan, fmt.Sprintf(format, arguments...))
}
