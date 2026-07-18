// Package activation defines strict, side-effect-free activation manifests.
//
// The manifests in this package do not authorize admission, execute a canary,
// import an image, or authenticate any referenced artifact. They are bounded
// correlation records for a later runner and offline verifier. Authority remains
// in the separately signed release, site policy, instance intent, task permit,
// receipt chains, and controller witness export identified by their digests.
package activation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
)

const (
	PlanSchemaV1 = "steward.activation-plan.v1"

	TransportNodeLocal                    = "node_local"
	TransportControlUplink                = "control_uplink"
	CanaryHermesWorkspaceAuditV1          = agentrelease.CanaryKindHermesWorkspaceAuditV1
	CanaryOpenClawWorkspaceAuditV1        = agentrelease.CanaryKindOpenClawWorkspaceAuditV1
	MaxPlanBytes                          = 64 << 10
	MaxActivationArchiveBytes      int64  = ocibundle.DefaultMaxArchiveBytes
	MinStepTimeoutSeconds          uint32 = 1
	MaxStepTimeoutSeconds          uint32 = 24 * 60 * 60
)

var (
	ErrInvalidPlan = errors.New("invalid activation plan")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// ArchiveV1 is the same comparable digest-and-size identity accepted by the OCI
// importer. It identifies bytes without naming a path, registry, URL, or tag.
type ArchiveV1 = ocibundle.ArchiveIdentity

// CanaryV1 selects one finite canary contract. It contains no command, hook,
// prompt, environment value, or authority material.
type CanaryV1 struct {
	Kind string `json:"kind"`
}

// TimeoutsV1 bounds each phase that a future activation runner may perform.
// These are execution ceilings, not retries or authorization.
type TimeoutsV1 struct {
	PreflightSeconds   uint32 `json:"preflight_seconds"`
	ImageImportSeconds uint32 `json:"image_import_seconds"`
	AdmissionSeconds   uint32 `json:"admission_seconds"`
	StartupSeconds     uint32 `json:"startup_seconds"`
	CanarySeconds      uint32 `json:"canary_seconds"`
	EvidenceSeconds    uint32 `json:"evidence_seconds"`
}

// PlanV1 is an unsigned, non-authoritative activation manifest. Its digests bind
// exact companion artifacts, but validation does not authenticate those artifacts.
type PlanV1 struct {
	SchemaVersion string     `json:"schema_version"`
	ActivationID  string     `json:"activation_id"`
	ReleaseDigest string     `json:"release_digest"`
	PolicyDigest  string     `json:"policy_digest"`
	IntentDigest  string     `json:"intent_digest"`
	Archive       ArchiveV1  `json:"archive"`
	Transport     string     `json:"transport"`
	Canary        CanaryV1   `json:"canary"`
	Timeouts      TimeoutsV1 `json:"timeouts"`
}

// ParsePlanV1 strictly decodes one bounded plan. Unknown fields, duplicate
// fields at any depth, trailing values, and invalid bounds are rejected.
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
// validation. ParsePlanV1 also accepts semantically equivalent JSON whitespace
// and member ordering; PlanDigestV1 intentionally identifies the exact input bytes.
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

// PlanDigestV1 validates a plan and returns the SHA-256 digest of its exact
// serialized bytes. The digest correlates a file; it is not a signature.
func PlanDigestV1(raw []byte) (string, error) {
	if _, err := ParsePlanV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

// Validate checks the finite plan schema and all local bounds.
func (plan PlanV1) Validate() error {
	if plan.SchemaVersion != PlanSchemaV1 {
		return invalidPlan("unsupported schema version")
	}
	if !identifier(plan.ActivationID) {
		return invalidPlan("activation_id is not a bounded identifier")
	}
	if !sha256Digest(plan.ReleaseDigest) || !sha256Digest(plan.PolicyDigest) ||
		!sha256Digest(plan.IntentDigest) {
		return invalidPlan("release, policy, and intent digests must be canonical SHA-256 values")
	}
	if err := validateArchive(plan.Archive); err != nil {
		return invalidPlan("archive: %v", err)
	}
	if plan.Transport != TransportNodeLocal && plan.Transport != TransportControlUplink {
		return invalidPlan(
			"transport must be %q or %q",
			TransportNodeLocal,
			TransportControlUplink,
		)
	}
	if _, ok := agentrelease.CanaryContractForKind(plan.Canary.Kind); !ok {
		return invalidPlan("canary kind is not a supported built-in contract")
	}
	if err := plan.Timeouts.validate(); err != nil {
		return invalidPlan("timeouts: %v", err)
	}
	return nil
}

func validateArchive(archive ArchiveV1) error {
	if !sha256Digest(archive.Digest) {
		return errors.New("digest must be one canonical SHA-256 value")
	}
	if archive.Bytes <= 0 || archive.Bytes > MaxActivationArchiveBytes {
		return fmt.Errorf("bytes must be between 1 and %d", MaxActivationArchiveBytes)
	}
	return nil
}

func (timeouts TimeoutsV1) validate() error {
	values := []uint32{
		timeouts.PreflightSeconds,
		timeouts.ImageImportSeconds,
		timeouts.AdmissionSeconds,
		timeouts.StartupSeconds,
		timeouts.CanarySeconds,
		timeouts.EvidenceSeconds,
	}
	for _, value := range values {
		if value < MinStepTimeoutSeconds || value > MaxStepTimeoutSeconds {
			return fmt.Errorf("every timeout must be between %d and %d seconds",
				MinStepTimeoutSeconds, MaxStepTimeoutSeconds)
		}
	}
	return nil
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

func sha256Digest(value string) bool {
	return strings.HasPrefix(value, "sha256:") &&
		lowerHex(strings.TrimPrefix(value, "sha256:"), sha256.Size*2)
}

func lowerHex(value string, exactLength int) bool {
	if len(value) != exactLength {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func runtimeRef(value string) bool {
	const prefix = "executor-"
	return strings.HasPrefix(value, prefix) &&
		lowerHex(strings.TrimPrefix(value, prefix), sha256.Size*2)
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
