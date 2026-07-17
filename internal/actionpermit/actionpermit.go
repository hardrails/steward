// Package actionpermit verifies short-lived, authority-signed permission for
// one exact connector request or a bounded set of exact requests. It validates
// signed intent only; callers must still compare every returned binding with
// trusted runtime state and the exact request bytes before an external effect.
package actionpermit

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
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadTypeV1 = "application/vnd.steward.action-permit.v1+json"
	PayloadTypeV2 = "application/vnd.steward.action-permit.v2+json"
	PayloadTypeV3 = "application/vnd.steward.action-permit.v3+json"
	PayloadTypeV4 = "application/vnd.steward.action-permit.v4+json"
	SchemaV1      = "steward.action-permit.v1"
	SchemaV2      = "steward.action-permit.v2"
	SchemaV3      = "steward.action-permit.v3"
	SchemaV4      = "steward.action-permit.v4"

	// PayloadType remains the original format identifier for source
	// compatibility with callers that construct legacy permit fixtures.
	PayloadType = PayloadTypeV1

	// EffectModeAuthorized marks a permit as authority for one exact managed
	// external effect. The value is intentionally finite and exact: accepting
	// aliases would create downgrade ambiguity at the enforcement boundary.
	EffectModeAuthorized = "authorized"

	// MaxEnvelopeBytes is the decoded transport limit for one permit envelope.
	MaxEnvelopeBytes = 16 << 10
	// MaxRequestBytes matches Gateway's hard connector request-body ceiling,
	// independently of a connector's smaller configured limit.
	MaxRequestBytes int64 = 4 << 20
	// MaxBundleSteps bounds approval scope, parsing work, and envelope size.
	MaxBundleSteps = 8
	// MaxValidity is the hard ceiling even when a caller is misconfigured with
	// a more permissive lifetime.
	MaxValidity = 24 * time.Hour

	timestampLayout = "2006-01-02T15:04:05Z"
)

var (
	ErrInvalid     = errors.New("invalid action permit")
	routeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Statement is the complete signed authority for one exact connector request.
// It contains no credential, upstream address, method, or path: those remain
// fixed by trusted Gateway configuration selected by connector_id and
// operation_id.
type Statement struct {
	SchemaVersion     string `json:"schema_version"`
	EffectMode        string `json:"effect_mode,omitempty"`
	ApprovalThreshold int    `json:"approval_threshold,omitempty"`
	NodeID            string `json:"node_id"`
	TenantID          string `json:"tenant_id"`
	InstanceID        string `json:"instance_id"`
	Generation        uint64 `json:"generation"`
	CapsuleDigest     string `json:"capsule_digest"`
	PolicyDigest      string `json:"policy_digest"`
	RoutePolicyDigest string `json:"route_policy_digest"`
	ConnectorID       string `json:"connector_id"`
	OperationID       string `json:"operation_id"`
	OperationDigest   string `json:"operation_policy_digest"`
	TaskID            string `json:"task_id"`
	RequestDigest     string `json:"request_digest"`
	RequestBytes      int64  `json:"request_bytes"`
	ContentType       string `json:"content_type"`
	NotBefore         string `json:"not_before"`
	ExpiresAt         string `json:"expires_at"`
}

// BundleStep is one exact request authorized by a BundleStatement. StepID is
// the stable operator-facing name; TaskID is the runtime replay boundary.
type BundleStep struct {
	StepID          string `json:"step_id"`
	ConnectorID     string `json:"connector_id"`
	OperationID     string `json:"operation_id"`
	OperationDigest string `json:"operation_policy_digest"`
	TaskID          string `json:"task_id"`
	RequestDigest   string `json:"request_digest"`
	RequestBytes    int64  `json:"request_bytes"`
	ContentType     string `json:"content_type"`
}

// BundleStatement authorizes a bounded, unordered set of exact connector
// requests. It is not a session grant: a caller may select only a listed step,
// and Gateway independently spends that step's task ID before network access.
type BundleStatement struct {
	SchemaVersion     string       `json:"schema_version"`
	EffectMode        string       `json:"effect_mode"`
	ApprovalThreshold int          `json:"approval_threshold"`
	NodeID            string       `json:"node_id"`
	TenantID          string       `json:"tenant_id"`
	InstanceID        string       `json:"instance_id"`
	Generation        uint64       `json:"generation"`
	CapsuleDigest     string       `json:"capsule_digest"`
	PolicyDigest      string       `json:"policy_digest"`
	RoutePolicyDigest string       `json:"route_policy_digest"`
	BundleID          string       `json:"bundle_id"`
	Steps             []BundleStep `json:"steps"`
	NotBefore         string       `json:"not_before"`
	ExpiresAt         string       `json:"expires_at"`
}

// wireStatement uses pointers solely to distinguish an omitted member from a
// present zero value. Every v1 member is required, including request_bytes,
// whose valid value may be zero. EffectMode uses RawMessage because it must be
// absent in v1 and present as a non-null string in v2.
type wireStatement struct {
	SchemaVersion     *string         `json:"schema_version"`
	EffectMode        json.RawMessage `json:"effect_mode"`
	ApprovalThreshold json.RawMessage `json:"approval_threshold"`
	NodeID            *string         `json:"node_id"`
	TenantID          *string         `json:"tenant_id"`
	InstanceID        *string         `json:"instance_id"`
	Generation        *uint64         `json:"generation"`
	CapsuleDigest     *string         `json:"capsule_digest"`
	PolicyDigest      *string         `json:"policy_digest"`
	RoutePolicyDigest *string         `json:"route_policy_digest"`
	ConnectorID       *string         `json:"connector_id"`
	OperationID       *string         `json:"operation_id"`
	OperationDigest   *string         `json:"operation_policy_digest"`
	TaskID            *string         `json:"task_id"`
	RequestDigest     *string         `json:"request_digest"`
	RequestBytes      *int64          `json:"request_bytes"`
	ContentType       *string         `json:"content_type"`
	NotBefore         *string         `json:"not_before"`
	ExpiresAt         *string         `json:"expires_at"`
}

type wireBundleStatement struct {
	SchemaVersion     *string           `json:"schema_version"`
	EffectMode        *string           `json:"effect_mode"`
	ApprovalThreshold *int              `json:"approval_threshold"`
	NodeID            *string           `json:"node_id"`
	TenantID          *string           `json:"tenant_id"`
	InstanceID        *string           `json:"instance_id"`
	Generation        *uint64           `json:"generation"`
	CapsuleDigest     *string           `json:"capsule_digest"`
	PolicyDigest      *string           `json:"policy_digest"`
	RoutePolicyDigest *string           `json:"route_policy_digest"`
	BundleID          *string           `json:"bundle_id"`
	Steps             *[]wireBundleStep `json:"steps"`
	NotBefore         *string           `json:"not_before"`
	ExpiresAt         *string           `json:"expires_at"`
}

type wireBundleStep struct {
	StepID          *string `json:"step_id"`
	ConnectorID     *string `json:"connector_id"`
	OperationID     *string `json:"operation_id"`
	OperationDigest *string `json:"operation_policy_digest"`
	TaskID          *string `json:"task_id"`
	RequestDigest   *string `json:"request_digest"`
	RequestBytes    *int64  `json:"request_bytes"`
	ContentType     *string `json:"content_type"`
}

// Verified is returned only after signature, schema, bounds, and time checks
// succeed. EnvelopeDigest identifies the exact serialized DSSE envelope.
type Verified struct {
	Statement      Statement
	Bundle         *BundleStatement
	KeyID          string
	KeyIDs         []string
	Complete       bool
	EnvelopeDigest string
	PayloadType    string
}

// RequestDigest binds a permit to the exact request-body bytes. Callers must
// compute it after validating the body and without reserializing JSON.
func RequestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verify authenticates and validates one bounded DSSE permit. maxValidity is
// an explicit local-policy ceiling and must itself be within the 24-hour hard
// limit. now is required: a missing clock cannot safely establish validity.
func Verify(rawEnvelope []byte, trusted map[string]ed25519.PublicKey, now time.Time, maxValidity time.Duration) (Verified, error) {
	return verify(rawEnvelope, trusted, now, maxValidity, false)
}

// VerifyPartial authenticates a canonical multi-party approval artifact before
// it has reached its signed threshold. It is for offline approval handoff only;
// Gateway must always use Verify.
func VerifyPartial(rawEnvelope []byte, trusted map[string]ed25519.PublicKey, now time.Time, maxValidity time.Duration) (Verified, error) {
	return verify(rawEnvelope, trusted, now, maxValidity, true)
}

func verify(rawEnvelope []byte, trusted map[string]ed25519.PublicKey, now time.Time, maxValidity time.Duration, allowPartial bool) (Verified, error) {
	if len(rawEnvelope) == 0 || len(rawEnvelope) > MaxEnvelopeBytes {
		return Verified{}, invalid("envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	if now.IsZero() {
		return Verified{}, invalid("node time is unavailable")
	}
	if maxValidity <= 0 || maxValidity > MaxValidity {
		return Verified{}, invalid("maximum validity must be positive and at most %s", MaxValidity)
	}

	// Action permits intentionally have one canonical envelope spelling. DSSE
	// signatures cover the payload, not the surrounding JSON or other
	// signatures; canonical ordering makes the complete approval artifact and
	// its receipt digest unambiguous.
	envelope, err := dsse.Parse(rawEnvelope)
	if err != nil {
		return Verified{}, invalid("parse canonical permit envelope: %v", err)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payloadBytes) != envelope.Payload {
		return Verified{}, invalid("permit payload is not canonical base64")
	}
	for _, signature := range envelope.Signatures {
		signatureBytes, decodeErr := base64.StdEncoding.DecodeString(signature.Sig)
		if decodeErr != nil || len(signatureBytes) != ed25519.SignatureSize ||
			base64.StdEncoding.EncodeToString(signatureBytes) != signature.Sig {
			return Verified{}, invalid("permit signature is not canonical base64")
		}
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, rawEnvelope) {
		return Verified{}, invalid("permit envelope is not canonical")
	}
	if envelope.PayloadType != PayloadTypeV1 && envelope.PayloadType != PayloadTypeV2 &&
		envelope.PayloadType != PayloadTypeV3 && envelope.PayloadType != PayloadTypeV4 {
		return Verified{}, invalid("unsupported permit payload type")
	}
	payload := payloadBytes
	if !utf8.Valid(payload) {
		return Verified{}, invalid("signed statement is not valid UTF-8")
	}
	var statement Statement
	var bundle *BundleStatement
	approvalThreshold := 0
	if envelope.PayloadType == PayloadTypeV4 {
		parsed, err := decodeBundleStatement(payload)
		if err != nil {
			return Verified{}, err
		}
		if err := validateBundleStatement(parsed, now, maxValidity); err != nil {
			return Verified{}, err
		}
		bundle = &parsed
		approvalThreshold = parsed.ApprovalThreshold
	} else {
		var wire wireStatement
		if err := dsse.DecodeStrictInto(payload, MaxEnvelopeBytes, &wire); err != nil {
			return Verified{}, invalid("decode signed statement: %v", err)
		}
		var ok bool
		statement, ok = wire.statement(envelope.PayloadType)
		if !ok {
			return Verified{}, invalid("signed statement omits a required field")
		}
		if err := validateStatement(statement, envelope.PayloadType, now, maxValidity); err != nil {
			return Verified{}, err
		}
		approvalThreshold = statement.ApprovalThreshold
	}
	_, keyIDs, err := dsse.VerifyAll(rawEnvelope, envelope.PayloadType, trusted)
	if err != nil {
		return Verified{}, invalid("verify every DSSE signature: %v", err)
	}
	for _, keyID := range keyIDs {
		if !routeID(keyID) {
			return Verified{}, invalid("signature key ID is not a bounded identifier")
		}
	}
	complete := true
	switch envelope.PayloadType {
	case PayloadTypeV1, PayloadTypeV2:
		if len(keyIDs) != 1 {
			return Verified{}, invalid("version 1 and 2 permits require exactly one signature")
		}
	case PayloadTypeV3, PayloadTypeV4:
		if len(keyIDs) > approvalThreshold || !allowPartial && len(keyIDs) != approvalThreshold {
			return Verified{}, invalid("permit signature count does not match approval threshold")
		}
		complete = len(keyIDs) == approvalThreshold
	}
	keyID := ""
	if len(keyIDs) > 0 {
		keyID = keyIDs[0]
	}
	return Verified{
		Statement: statement, Bundle: bundle, KeyID: keyID, KeyIDs: append([]string(nil), keyIDs...), Complete: complete,
		EnvelopeDigest: dsse.Digest(rawEnvelope), PayloadType: envelope.PayloadType,
	}, nil
}

func (wire wireStatement) statement(payloadType string) (Statement, bool) {
	if wire.SchemaVersion == nil || wire.NodeID == nil || wire.TenantID == nil || wire.InstanceID == nil ||
		wire.Generation == nil || wire.CapsuleDigest == nil || wire.PolicyDigest == nil || wire.RoutePolicyDigest == nil ||
		wire.ConnectorID == nil || wire.OperationID == nil || wire.OperationDigest == nil || wire.TaskID == nil || wire.RequestDigest == nil ||
		wire.RequestBytes == nil || wire.ContentType == nil || wire.NotBefore == nil || wire.ExpiresAt == nil {
		return Statement{}, false
	}
	if payloadType == PayloadTypeV1 && (len(wire.EffectMode) != 0 || len(wire.ApprovalThreshold) != 0) ||
		payloadType == PayloadTypeV2 && (len(wire.EffectMode) == 0 || len(wire.ApprovalThreshold) != 0) ||
		payloadType == PayloadTypeV3 && (len(wire.EffectMode) == 0 || len(wire.ApprovalThreshold) == 0) {
		return Statement{}, false
	}
	effectMode := ""
	if len(wire.EffectMode) != 0 {
		if bytes.Equal(wire.EffectMode, []byte("null")) || json.Unmarshal(wire.EffectMode, &effectMode) != nil {
			return Statement{}, false
		}
	}
	approvalThreshold := 0
	if len(wire.ApprovalThreshold) != 0 {
		if bytes.Equal(wire.ApprovalThreshold, []byte("null")) || json.Unmarshal(wire.ApprovalThreshold, &approvalThreshold) != nil {
			return Statement{}, false
		}
	}
	return Statement{
		SchemaVersion: *wire.SchemaVersion, EffectMode: effectMode, ApprovalThreshold: approvalThreshold,
		NodeID: *wire.NodeID, TenantID: *wire.TenantID,
		InstanceID: *wire.InstanceID, Generation: *wire.Generation, CapsuleDigest: *wire.CapsuleDigest,
		PolicyDigest: *wire.PolicyDigest, RoutePolicyDigest: *wire.RoutePolicyDigest,
		ConnectorID: *wire.ConnectorID, OperationID: *wire.OperationID, OperationDigest: *wire.OperationDigest, TaskID: *wire.TaskID,
		RequestDigest: *wire.RequestDigest, RequestBytes: *wire.RequestBytes, ContentType: *wire.ContentType,
		NotBefore: *wire.NotBefore, ExpiresAt: *wire.ExpiresAt,
	}, true
}

func decodeBundleStatement(payload []byte) (BundleStatement, error) {
	var wire wireBundleStatement
	if err := dsse.DecodeStrictInto(payload, MaxEnvelopeBytes, &wire); err != nil {
		return BundleStatement{}, invalid("decode signed bundle statement: %v", err)
	}
	if wire.SchemaVersion == nil || wire.EffectMode == nil || wire.ApprovalThreshold == nil || wire.NodeID == nil ||
		wire.TenantID == nil || wire.InstanceID == nil || wire.Generation == nil || wire.CapsuleDigest == nil ||
		wire.PolicyDigest == nil || wire.RoutePolicyDigest == nil || wire.BundleID == nil || wire.Steps == nil ||
		wire.NotBefore == nil || wire.ExpiresAt == nil {
		return BundleStatement{}, invalid("signed bundle statement omits a required field")
	}
	steps := make([]BundleStep, 0, len(*wire.Steps))
	for _, wireStep := range *wire.Steps {
		step, ok := wireStep.step()
		if !ok {
			return BundleStatement{}, invalid("signed bundle step omits a required field")
		}
		steps = append(steps, step)
	}
	return BundleStatement{
		SchemaVersion: *wire.SchemaVersion, EffectMode: *wire.EffectMode, ApprovalThreshold: *wire.ApprovalThreshold,
		NodeID: *wire.NodeID, TenantID: *wire.TenantID, InstanceID: *wire.InstanceID, Generation: *wire.Generation,
		CapsuleDigest: *wire.CapsuleDigest, PolicyDigest: *wire.PolicyDigest, RoutePolicyDigest: *wire.RoutePolicyDigest,
		BundleID: *wire.BundleID, Steps: steps, NotBefore: *wire.NotBefore, ExpiresAt: *wire.ExpiresAt,
	}, nil
}

func (wire wireBundleStep) step() (BundleStep, bool) {
	if wire.StepID == nil || wire.ConnectorID == nil || wire.OperationID == nil || wire.OperationDigest == nil ||
		wire.TaskID == nil || wire.RequestDigest == nil || wire.RequestBytes == nil || wire.ContentType == nil {
		return BundleStep{}, false
	}
	return BundleStep{
		StepID: *wire.StepID, ConnectorID: *wire.ConnectorID, OperationID: *wire.OperationID,
		OperationDigest: *wire.OperationDigest, TaskID: *wire.TaskID, RequestDigest: *wire.RequestDigest,
		RequestBytes: *wire.RequestBytes, ContentType: *wire.ContentType,
	}, true
}

// EncodeHeader produces the only accepted HTTP-header representation. The
// unpadded URL-safe alphabet prevents delimiter ambiguity and copy/paste
// changes from acquiring a second accepted spelling.
func EncodeHeader(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return "", invalid("header envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeHeader opens one canonical HTTP-header value. Exact re-encoding rejects
// padding, ignored newlines, alternate trailing bits, surrounding whitespace,
// and comma-joined multiple values.
func DecodeHeader(value string) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(MaxEnvelopeBytes) {
		return nil, invalid("header is empty or exceeds the encoded limit")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > MaxEnvelopeBytes ||
		base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, invalid("header is not one canonical base64url value")
	}
	return raw, nil
}

func validateStatement(statement Statement, payloadType string, now time.Time, maxValidity time.Duration) error {
	switch payloadType {
	case PayloadTypeV1:
		if statement.SchemaVersion != SchemaV1 || statement.EffectMode != "" {
			return invalid("payload type, schema version, and effect mode do not form a supported permit version")
		}
	case PayloadTypeV2:
		if statement.SchemaVersion != SchemaV2 || statement.EffectMode != EffectModeAuthorized || statement.ApprovalThreshold != 0 {
			return invalid("payload type, schema version, effect mode, and approval threshold do not form a supported permit version")
		}
	case PayloadTypeV3:
		if statement.SchemaVersion != SchemaV3 || statement.EffectMode != EffectModeAuthorized ||
			statement.ApprovalThreshold < 2 || statement.ApprovalThreshold > 8 {
			return invalid("payload type, schema version, and effect mode do not form a supported permit version")
		}
	default:
		return invalid("unsupported permit payload type")
	}
	if err := validateRuntimeBinding(statement.NodeID, statement.TenantID, statement.InstanceID, statement.Generation,
		statement.CapsuleDigest, statement.PolicyDigest, statement.RoutePolicyDigest); err != nil {
		return err
	}
	if !routeID(statement.ConnectorID) || !routeID(statement.OperationID) || !routeID(statement.TaskID) {
		return invalid("statement contains an invalid identifier")
	}
	if err := validateRequestBinding(statement.OperationDigest, statement.RequestDigest, statement.RequestBytes, statement.ContentType); err != nil {
		return err
	}
	return validateValidity(statement.NotBefore, statement.ExpiresAt, now, maxValidity)
}

func validateBundleStatement(bundle BundleStatement, now time.Time, maxValidity time.Duration) error {
	if bundle.SchemaVersion != SchemaV4 || bundle.EffectMode != EffectModeAuthorized ||
		bundle.ApprovalThreshold < 1 || bundle.ApprovalThreshold > MaxBundleSteps {
		return invalid("payload type, schema version, effect mode, and approval threshold do not form a supported bundle version")
	}
	if err := validateRuntimeBinding(bundle.NodeID, bundle.TenantID, bundle.InstanceID, bundle.Generation,
		bundle.CapsuleDigest, bundle.PolicyDigest, bundle.RoutePolicyDigest); err != nil {
		return err
	}
	if !routeID(bundle.BundleID) {
		return invalid("bundle contains an invalid identifier")
	}
	if len(bundle.Steps) == 0 || len(bundle.Steps) > MaxBundleSteps {
		return invalid("bundle must contain between 1 and %d exact steps", MaxBundleSteps)
	}
	seenTasks := make(map[string]struct{}, len(bundle.Steps))
	previousStepID := ""
	for index, step := range bundle.Steps {
		if !routeID(step.StepID) || !routeID(step.ConnectorID) || !routeID(step.OperationID) || !routeID(step.TaskID) {
			return invalid("bundle step %d contains an invalid identifier", index)
		}
		if previousStepID != "" && step.StepID <= previousStepID {
			return invalid("bundle steps must have unique step IDs in ascending order")
		}
		previousStepID = step.StepID
		if _, exists := seenTasks[step.TaskID]; exists {
			return invalid("bundle steps must have unique task IDs")
		}
		seenTasks[step.TaskID] = struct{}{}
		if err := validateRequestBinding(step.OperationDigest, step.RequestDigest, step.RequestBytes, step.ContentType); err != nil {
			return invalid("bundle step %d: %v", index, err)
		}
	}
	return validateValidity(bundle.NotBefore, bundle.ExpiresAt, now, maxValidity)
}

func validateRuntimeBinding(nodeID, tenantID, instanceID string, generation uint64, capsuleDigest, policyDigest, routePolicyDigest string) error {
	if !publicIdentity(nodeID, 128) || !publicIdentity(tenantID, 128) || !publicIdentity(instanceID, 256) {
		return invalid("statement contains an invalid identity")
	}
	if generation == 0 {
		return invalid("generation must be positive")
	}
	if !digest(capsuleDigest) || !digest(policyDigest) || !digest(routePolicyDigest) {
		return invalid("statement contains an invalid SHA-256 digest")
	}
	return nil
}

func validateRequestBinding(operationDigest, requestDigest string, requestBytes int64, contentType string) error {
	if !digest(operationDigest) || !digest(requestDigest) {
		return invalid("request binding contains an invalid SHA-256 digest")
	}
	if requestBytes < 0 || requestBytes > MaxRequestBytes {
		return invalid("request size is outside the supported range")
	}
	if contentType != "" && contentType != "application/json" {
		return invalid("content type must be empty or application/json")
	}
	if contentType == "" && (requestBytes != 0 || requestDigest != RequestDigest(nil)) {
		return invalid("bodyless operation must bind the empty request")
	}
	if contentType == "application/json" && requestBytes == 0 {
		return invalid("JSON operation must bind a non-empty request")
	}
	return nil
}

func validateValidity(notBeforeValue, expiresAtValue string, now time.Time, maxValidity time.Duration) error {
	notBefore, err := canonicalTime(notBeforeValue)
	if err != nil {
		return invalid("not_before: %v", err)
	}
	expiresAt, err := canonicalTime(expiresAtValue)
	if err != nil {
		return invalid("expires_at: %v", err)
	}
	if !expiresAt.After(notBefore) || expiresAt.Sub(notBefore) > maxValidity {
		return invalid("validity interval is empty or exceeds the local maximum")
	}
	if now.Before(notBefore) {
		return invalid("permit is not yet valid according to node time")
	}
	if !now.Before(expiresAt) {
		return invalid("permit has expired according to node time")
	}
	return nil
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(timestampLayout) != value {
		return time.Time{}, errors.New("timestamp must be canonical UTC RFC3339 seconds")
	}
	return parsed, nil
}

func publicIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func routeID(value string) bool {
	return routeIDPattern.MatchString(value)
}

func digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
