// Package agentrelease defines Steward's publisher-signed, portable agent
// release contract. A release describes one immutable agent artifact and one
// deterministic qualification canary. It grants no tenant, node, task, or
// runtime authority.
package agentrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType = "application/vnd.steward.agent-release.v1+json"
	SchemaV1    = "steward.agent-release.v1"

	MaxEnvelopeBytes      = 256 << 10
	MaxPayloadBytes       = 128 << 10
	MaxCanaryRequestBytes = 4 << 10
	MaxArchiveBytes       = int64(20 << 30)

	CanaryKindHermesWorkspaceAuditV1        = "hermes_workspace_audit_v1"
	CanaryKindOpenClawWorkspaceAuditV1      = "openclaw_workspace_audit_v1"
	HermesServiceID                         = "hermes-api"
	HermesOperationID                       = "hermes.run"
	HermesWorkspaceAuditInput               = "STEWARD_WORKSPACE_AUDIT"
	HermesSessionIDPrefix                   = "steward-activation"
	HermesWorkspaceAuditEmptyFixtureID      = "steward.workspace-audit.empty.v1"
	HermesWorkspaceAuditEmptyManifestDigest = "sha256:44bb67d3ad826643e50057a69657757316fd25dcd700a918a6db0a38924acec6"
	OpenClawServiceID                       = "openclaw-api"
	OpenClawOperationID                     = "openclaw.run"
	OpenClawWorkspaceAuditMessage           = "Run the Steward workspace audit."
	OpenClawSessionIDPrefix                 = "steward-activation"
	OpenClawWorkspaceAuditFixtureID         = "steward.workspace-audit.qualification.v1"
	OpenClawWorkspaceAuditManifestDigest    = "sha256:8a88036085cd27e3e0a85ab10f3fbfed492633fa76fd18a85bb478747c4d56d5"
	SkillManifestArtifactKind               = "skill-manifest"
)

var (
	ErrInvalid        = errors.New("invalid agent release")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	urlPattern        = regexp.MustCompile(`(?i)(?:[a-z][a-z0-9+.-]*://|www\.)`)
)

// Release is descriptive publisher metadata, not runtime authority. The
// embedded capsule remains the authoritative artifact profile, and activation
// still requires site policy, instance intent, and tenant-owned task permits.
type Release struct {
	SchemaVersion     string        `json:"schema_version"`
	ReleaseID         string        `json:"release_id"`
	PublisherKeyID    string        `json:"publisher_key_id"`
	Display           Display       `json:"display"`
	CapsuleDSSEBase64 string        `json:"capsule_dsse_base64"`
	Archive           Archive       `json:"archive"`
	Canary            Canary        `json:"canary"`
	Qualification     Qualification `json:"qualification"`
}

// Display contains outcome-led catalog text. It has no external link or
// executable extension fields.
type Display struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Outcome string `json:"outcome"`
}

// Archive binds the exact offline OCI archive bytes and the image tuple that
// those bytes must contain. Image must exactly equal the embedded capsule's
// image identity.
type Archive struct {
	SHA256Digest string                  `json:"sha256_digest"`
	SizeBytes    int64                   `json:"size_bytes"`
	Image        admission.ImageIdentity `json:"image"`
}

// Canary is the only supported release qualification recipe. Request is a
// closed recipe rather than concrete bytes because every activation needs a
// distinct agent session ID.
type Canary struct {
	Kind                            string        `json:"kind"`
	ServiceID                       string        `json:"service_id"`
	OperationID                     string        `json:"operation_id"`
	Request                         RequestRecipe `json:"request"`
	RequiredStateDisposition        string        `json:"required_state_disposition"`
	SkillManifestDigest             string        `json:"skill_manifest_digest"`
	ExpectedWorkspaceManifestDigest string        `json:"expected_workspace_manifest_digest"`
	FixtureID                       string        `json:"fixture_id"`
}

// RequestRecipe contains no prompt or executable extension point. Verification
// accepts only an exact compiled-in workspace-audit recipe.
type RequestRecipe struct {
	Input           string `json:"input"`
	SessionIDPrefix string `json:"session_id_prefix"`
}

// CanaryContract is one compiled-in agent recipe. It contains no executable
// extension point; callers can select only an exact contract returned here.
type CanaryContract struct {
	Kind                            string
	Profile                         admission.ProfileRef
	ServiceID                       string
	OperationID                     string
	Request                         RequestRecipe
	FixtureID                       string
	ExpectedWorkspaceManifestDigest string
}

// Qualification binds a completed gVisor qualification evidence artifact and
// makes known limitations explicit in the signed release.
type Qualification struct {
	EvidenceDigest string   `json:"evidence_digest"`
	CompletedAt    string   `json:"completed_at"`
	Runtime        string   `json:"runtime"`
	Limitations    []string `json:"limitations"`
}

// Verified is returned only after both DSSE signatures, every finite schema
// constraint, the embedded capsule, and all duplicated bindings have verified.
// Digests identify the exact serialized bytes, not re-encoded equivalents.
type Verified struct {
	Release               Release
	Capsule               admission.ProfileCapsule
	CapsuleEnvelope       []byte
	PublisherKeyID        string
	EnvelopeDigest        string
	PayloadDigest         string
	CapsuleEnvelopeDigest string
	CapsulePayloadDigest  string
}

type hermesCanaryRequest struct {
	Input     string `json:"input"`
	SessionID string `json:"session_id"`
}

type openClawCanaryRequest struct {
	Message   string `json:"message"`
	SessionID string `json:"session_id"`
}

type validatedParts struct {
	capsule         admission.ProfileCapsule
	capsuleEnvelope []byte
	capsulePayload  []byte
}

// Sign creates one canonical, single-signature release envelope. The same
// publisher key must already sign the embedded capsule. now is required so an
// expired capsule cannot be republished through this helper.
func Sign(release Release, keyID string, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if now.IsZero() {
		return nil, invalid("publisher time is unavailable")
	}
	if !identifier(keyID, 256) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, invalid("publisher signing key is invalid")
	}
	if release.PublisherKeyID != keyID {
		return nil, invalid("release publisher key ID does not match signing key")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, invalid("publisher public key is invalid")
	}
	payload, _, err := marshalAndValidate(release, now, publicKey)
	if err != nil {
		return nil, err
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, privateKey)
	if err != nil {
		return nil, invalid("sign release envelope: %v", err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return nil, invalid("marshal release envelope: %v", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, invalid("release envelope exceeds %d bytes", MaxEnvelopeBytes)
	}
	return raw, nil
}

// Verify authenticates a canonical release envelope with operator-supplied
// publisher keys. The exact same key ID and public key must authenticate the
// embedded capsule. now is required for capsule expiry validation.
func Verify(rawEnvelope []byte, trustedPublishers map[string]ed25519.PublicKey, now time.Time) (Verified, error) {
	if now.IsZero() {
		return Verified{}, invalid("verification time is unavailable")
	}
	envelope, parsedPayload, err := parseCanonicalEnvelope(rawEnvelope, MaxEnvelopeBytes, MaxPayloadBytes, PayloadType, "release")
	if err != nil {
		return Verified{}, err
	}
	payload, publisherKeyID, err := dsse.Verify(rawEnvelope, PayloadType, trustedPublishers)
	if err != nil {
		return Verified{}, invalid("verify release envelope: %v", err)
	}
	if !bytes.Equal(payload, parsedPayload) {
		return Verified{}, invalid("verified release payload differs from parsed envelope")
	}
	if envelope.Signatures[0].KeyID != publisherKeyID {
		return Verified{}, invalid("release signature key ID is ambiguous")
	}
	publicKey, ok := trustedPublishers[publisherKeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Verified{}, invalid("verified publisher key is unavailable")
	}
	if !utf8.Valid(payload) {
		return Verified{}, invalid("release payload is not valid UTF-8")
	}
	var release Release
	if err := dsse.DecodeStrictInto(payload, MaxPayloadBytes, &release); err != nil {
		return Verified{}, invalid("decode release payload: %v", err)
	}
	if release.PublisherKeyID != publisherKeyID {
		return Verified{}, invalid("release publisher key ID does not match verified signature")
	}
	_, parts, err := marshalAndValidate(release, now, publicKey)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Release: release, Capsule: parts.capsule,
		CapsuleEnvelope: append([]byte(nil), parts.capsuleEnvelope...),
		PublisherKeyID:  publisherKeyID,
		EnvelopeDigest:  digest(rawEnvelope), PayloadDigest: digest(payload),
		CapsuleEnvelopeDigest: digest(parts.capsuleEnvelope),
		CapsulePayloadDigest:  digest(parts.capsulePayload),
	}, nil
}

// BuildCanaryRequest returns the exact canonical JSON request bytes for one
// activation. The activation ID is data, not authority; a later task permit
// must sign the returned bytes before Gateway may dispatch them.
func BuildCanaryRequest(recipe RequestRecipe, activationID string) ([]byte, error) {
	contract, ok := CanaryContractForRequest(recipe)
	if !ok {
		return nil, invalid("request recipe is not a supported workspace audit")
	}
	if !identifier(activationID, 128) {
		return nil, invalid("activation ID is invalid")
	}
	sessionID := recipe.SessionIDPrefix + "-" + activationID
	if !identifier(sessionID, 128) {
		return nil, invalid("derived canary session ID exceeds its supported shape")
	}
	var request []byte
	var err error
	switch contract.Kind {
	case CanaryKindHermesWorkspaceAuditV1:
		request, err = json.Marshal(hermesCanaryRequest{Input: recipe.Input, SessionID: sessionID})
	case CanaryKindOpenClawWorkspaceAuditV1:
		request, err = json.Marshal(openClawCanaryRequest{Message: recipe.Input, SessionID: sessionID})
	default:
		return nil, invalid("request recipe contract is unavailable")
	}
	if err != nil || len(request) == 0 || len(request) > MaxCanaryRequestBytes {
		return nil, invalid("marshal bounded canary request")
	}
	return request, nil
}

// CanaryContractForKind returns one finite built-in canary contract.
func CanaryContractForKind(kind string) (CanaryContract, bool) {
	switch kind {
	case CanaryKindHermesWorkspaceAuditV1:
		return CanaryContract{
			Kind: kind, Profile: admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
			ServiceID: HermesServiceID, OperationID: HermesOperationID,
			Request:                         RequestRecipe{Input: HermesWorkspaceAuditInput, SessionIDPrefix: HermesSessionIDPrefix},
			FixtureID:                       HermesWorkspaceAuditEmptyFixtureID,
			ExpectedWorkspaceManifestDigest: HermesWorkspaceAuditEmptyManifestDigest,
		}, true
	case CanaryKindOpenClawWorkspaceAuditV1:
		return CanaryContract{
			Kind: kind, Profile: admission.ProfileRef{ID: "openclaw-v1", Version: "v1"},
			ServiceID: OpenClawServiceID, OperationID: OpenClawOperationID,
			Request:                         RequestRecipe{Input: OpenClawWorkspaceAuditMessage, SessionIDPrefix: OpenClawSessionIDPrefix},
			FixtureID:                       OpenClawWorkspaceAuditFixtureID,
			ExpectedWorkspaceManifestDigest: OpenClawWorkspaceAuditManifestDigest,
		}, true
	default:
		return CanaryContract{}, false
	}
}

// CanaryContractForRequest rejects every request recipe outside the compiled-in set.
func CanaryContractForRequest(request RequestRecipe) (CanaryContract, bool) {
	for _, kind := range []string{CanaryKindHermesWorkspaceAuditV1, CanaryKindOpenClawWorkspaceAuditV1} {
		contract, _ := CanaryContractForKind(kind)
		if contract.Request == request {
			return contract, true
		}
	}
	return CanaryContract{}, false
}

// CanaryContractForOperation rejects every service operation outside the compiled-in set.
func CanaryContractForOperation(serviceID, operationID string) (CanaryContract, bool) {
	for _, kind := range []string{CanaryKindHermesWorkspaceAuditV1, CanaryKindOpenClawWorkspaceAuditV1} {
		contract, _ := CanaryContractForKind(kind)
		if contract.ServiceID == serviceID && contract.OperationID == operationID {
			return contract, true
		}
	}
	return CanaryContract{}, false
}

// CanaryContractForService rejects every service outside the compiled-in set.
func CanaryContractForService(serviceID string) (CanaryContract, bool) {
	for _, kind := range []string{CanaryKindHermesWorkspaceAuditV1, CanaryKindOpenClawWorkspaceAuditV1} {
		contract, _ := CanaryContractForKind(kind)
		if contract.ServiceID == serviceID {
			return contract, true
		}
	}
	return CanaryContract{}, false
}

// CanarySessionID derives the only accepted activation-scoped session identity.
func CanarySessionID(kind, activationID string) (string, error) {
	contract, ok := CanaryContractForKind(kind)
	if !ok || !identifier(activationID, 128) {
		return "", invalid("canary contract or activation ID is invalid")
	}
	sessionID := contract.Request.SessionIDPrefix + "-" + activationID
	if !identifier(sessionID, 128) {
		return "", invalid("derived canary session ID exceeds its supported shape")
	}
	return sessionID, nil
}

func marshalAndValidate(release Release, now time.Time, publisherKey ed25519.PublicKey) ([]byte, validatedParts, error) {
	parts, err := validateRelease(release, now, publisherKey)
	if err != nil {
		return nil, validatedParts{}, err
	}
	payload, err := json.Marshal(release)
	if err != nil {
		return nil, validatedParts{}, invalid("marshal release payload: %v", err)
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, validatedParts{}, invalid("release payload exceeds %d bytes", MaxPayloadBytes)
	}
	return payload, parts, nil
}

func validateRelease(release Release, now time.Time, publisherKey ed25519.PublicKey) (validatedParts, error) {
	if release.SchemaVersion != SchemaV1 || !identifier(release.ReleaseID, 128) ||
		!identifier(release.PublisherKeyID, 256) {
		return validatedParts{}, invalid("release identity is invalid")
	}
	if !displayText(release.Display.Title, 128) || !displayText(release.Display.Summary, 512) ||
		!displayText(release.Display.Outcome, 512) {
		return validatedParts{}, invalid("release display metadata is invalid")
	}
	if !digestValue(release.Archive.SHA256Digest) ||
		release.Archive.SizeBytes < 1 || release.Archive.SizeBytes > MaxArchiveBytes {
		return validatedParts{}, invalid("archive metadata is invalid")
	}
	if err := release.Archive.Image.Validate(); err != nil {
		return validatedParts{}, invalid("archive image identity: %v", err)
	}
	if err := validateQualification(release.Qualification); err != nil {
		return validatedParts{}, err
	}

	capsuleEnvelope, err := decodeCanonicalBase64(release.CapsuleDSSEBase64, MaxPayloadBytes, "capsule DSSE")
	if err != nil {
		return validatedParts{}, err
	}
	capsuleDSSE, capsulePayload, err := parseCanonicalEnvelope(
		capsuleEnvelope, MaxPayloadBytes, MaxPayloadBytes, admission.CapsulePayloadType, "capsule",
	)
	if err != nil {
		return validatedParts{}, err
	}
	if capsuleDSSE.Signatures[0].KeyID != release.PublisherKeyID {
		return validatedParts{}, invalid("capsule signature key ID does not match release publisher")
	}
	if len(publisherKey) != 0 {
		verifiedPayload, keyID, err := dsse.Verify(
			capsuleEnvelope, admission.CapsulePayloadType,
			map[string]ed25519.PublicKey{release.PublisherKeyID: publisherKey},
		)
		if err != nil {
			return validatedParts{}, invalid("verify embedded capsule with release publisher: %v", err)
		}
		if keyID != release.PublisherKeyID || !bytes.Equal(verifiedPayload, capsulePayload) {
			return validatedParts{}, invalid("embedded capsule publisher binding is inconsistent")
		}
	}
	if !utf8.Valid(capsulePayload) {
		return validatedParts{}, invalid("capsule payload is not valid UTF-8")
	}
	var capsule admission.ProfileCapsule
	if err := dsse.DecodeStrictInto(capsulePayload, MaxPayloadBytes, &capsule); err != nil {
		return validatedParts{}, invalid("decode embedded capsule: %v", err)
	}
	if err := capsule.Validate(now); err != nil {
		return validatedParts{}, invalid("validate embedded capsule: %v", err)
	}
	if capsule.PublisherKeyID != release.PublisherKeyID {
		return validatedParts{}, invalid("capsule publisher key ID does not match release publisher")
	}
	if capsule.Image != release.Archive.Image {
		return validatedParts{}, invalid("archive image tuple does not match embedded capsule")
	}
	contract, ok := CanaryContractForKind(release.Canary.Kind)
	if !ok {
		return validatedParts{}, invalid("release canary contract is unavailable")
	}
	if capsule.Profile != contract.Profile ||
		!capsule.Capabilities.State || !capsule.Capabilities.Service ||
		capsule.Service.ID != contract.ServiceID {
		return validatedParts{}, invalid("workspace-audit canary requires its exact service profile")
	}
	profile, ok := admission.DefaultProfiles().Lookup(capsule.Profile)
	if !ok || capsule.State.Path != profile.StatePath || capsule.State.SchemaVersion != profile.StateSchemaVersion {
		return validatedParts{}, invalid("capsule state shape differs from its built-in agent profile")
	}
	if err := validateArtifacts(capsule.Artifacts, release.Canary.SkillManifestDigest); err != nil {
		return validatedParts{}, err
	}

	if err := validateCanary(release.Canary); err != nil {
		return validatedParts{}, err
	}
	return validatedParts{
		capsule: capsule, capsuleEnvelope: capsuleEnvelope,
		capsulePayload: capsulePayload,
	}, nil
}

func validateCanary(canary Canary) error {
	contract, ok := CanaryContractForKind(canary.Kind)
	if !ok || canary.ServiceID != contract.ServiceID || canary.OperationID != contract.OperationID {
		return invalid("release canary is not a supported workspace audit")
	}
	if !digestValue(canary.SkillManifestDigest) ||
		canary.ExpectedWorkspaceManifestDigest != contract.ExpectedWorkspaceManifestDigest ||
		canary.FixtureID != contract.FixtureID {
		return invalid("release canary artifact bindings are invalid")
	}
	if canary.Request != contract.Request ||
		canary.RequiredStateDisposition != "new" {
		return invalid("release canary recipe is outside the closed workspace-audit contract")
	}
	return nil
}

func validateQualification(qualification Qualification) error {
	if !digestValue(qualification.EvidenceDigest) || qualification.Runtime != "runsc" {
		return invalid("qualification evidence or runtime is invalid")
	}
	completed, err := time.Parse("2006-01-02T15:04:05Z", qualification.CompletedAt)
	if err != nil || completed.Format("2006-01-02T15:04:05Z") != qualification.CompletedAt {
		return invalid("qualification completion time is not canonical UTC RFC3339")
	}
	if len(qualification.Limitations) < 1 || len(qualification.Limitations) > 8 {
		return invalid("qualification must contain 1 to 8 limitations")
	}
	seen := make(map[string]struct{}, len(qualification.Limitations))
	for _, limitation := range qualification.Limitations {
		if !displayText(limitation, 512) {
			return invalid("qualification contains an invalid limitation")
		}
		if _, exists := seen[limitation]; exists {
			return invalid("qualification contains duplicate limitations")
		}
		seen[limitation] = struct{}{}
	}
	return nil
}

func validateArtifacts(artifacts []admission.ArtifactDigest, skillManifestDigest string) error {
	seen := make(map[string]struct{}, len(artifacts))
	matched := false
	for _, artifact := range artifacts {
		if _, exists := seen[artifact.Kind]; exists {
			return invalid("capsule contains duplicate artifact kind %q", artifact.Kind)
		}
		seen[artifact.Kind] = struct{}{}
		if artifact.Kind == SkillManifestArtifactKind {
			if artifact.Digest != skillManifestDigest {
				return invalid("capsule skill manifest artifact does not match release canary")
			}
			matched = true
		}
	}
	if !matched {
		return invalid("capsule omits the release canary skill manifest artifact")
	}
	return nil
}

func parseCanonicalEnvelope(raw []byte, maxEnvelope, maxPayload int, payloadType, label string) (dsse.Envelope, []byte, error) {
	if len(raw) == 0 || len(raw) > maxEnvelope {
		return dsse.Envelope{}, nil, invalid("%s envelope is empty or exceeds %d bytes", label, maxEnvelope)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return dsse.Envelope{}, nil, invalid("parse %s envelope: %v", label, err)
	}
	if envelope.PayloadType != payloadType {
		return dsse.Envelope{}, nil, invalid("%s envelope has the wrong payload type", label)
	}
	if len(envelope.Signatures) != 1 {
		return dsse.Envelope{}, nil, invalid("%s envelope must contain exactly one signature", label)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > maxPayload ||
		base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return dsse.Envelope{}, nil, invalid("%s payload is not bounded canonical base64", label)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != envelope.Signatures[0].Sig {
		return dsse.Envelope{}, nil, invalid("%s signature is not canonical base64", label)
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return dsse.Envelope{}, nil, invalid("%s envelope JSON is not canonical", label)
	}
	return envelope, payload, nil
}

func decodeCanonicalBase64(encoded string, maxBytes int, label string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, invalid("%s is empty or exceeds its encoded limit", label)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxBytes ||
		base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, invalid("%s is not canonical base64", label)
	}
	return raw, nil
}

func identifier(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && identifierPattern.MatchString(value)
}

func displayText(value string, max int) bool {
	if len(value) == 0 || len(value) > max || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || urlPattern.MatchString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func digestValue(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, arguments...)...)
}
