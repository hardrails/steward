// Package taskpermit verifies short-lived, authority-signed permission to
// dispatch one exact task request to one managed agent service. It validates
// signed intent only: callers must still compare every returned binding with
// trusted runtime state and the exact request bytes before dispatch.
package taskpermit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType = "application/vnd.steward.task-permit.v1+json"
	SchemaV1    = "steward.task-permit.v1"

	// MaxEnvelopeBytes is the decoded transport limit for one task permit.
	MaxEnvelopeBytes = 16 << 10
	// MaxRequestBytes is the hard ceiling for the exact service request body.
	MaxRequestBytes int64 = 64 << 10
	// MaxValidity is the hard ceiling even when local policy is misconfigured
	// with a more permissive lifetime.
	MaxValidity = 15 * time.Minute

	timestampLayout  = "2006-01-02T15:04:05Z"
	taskDigestDomain = "steward-task-permit-spend-v1\x00"
)

var (
	ErrInvalid        = errors.New("invalid task permit")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Statement is the complete signed authority for one exact service request.
// It contains no bearer token, service address, response, or request body.
// Callers bind the latter by comparing its exact length and RequestDigest.
type Statement struct {
	SchemaVersion         string `json:"schema_version"`
	NodeID                string `json:"node_id"`
	TenantID              string `json:"tenant_id"`
	InstanceID            string `json:"instance_id"`
	RuntimeRef            string `json:"runtime_ref"`
	GrantID               string `json:"grant_id"`
	Generation            uint64 `json:"generation"`
	CapsuleDigest         string `json:"capsule_digest"`
	PolicyDigest          string `json:"policy_digest"`
	RoutePolicyDigest     string `json:"route_policy_digest"`
	ServiceID             string `json:"service_id"`
	OperationID           string `json:"operation_id"`
	OperationPolicyDigest string `json:"operation_policy_digest"`
	TaskID                string `json:"task_id"`
	RequestDigest         string `json:"request_digest"`
	RequestBytes          int64  `json:"request_bytes"`
	ContentType           string `json:"content_type"`
	NotBefore             string `json:"not_before"`
	ExpiresAt             string `json:"expires_at"`
}

// wireStatement uses pointers only to distinguish an omitted member from a
// present zero value. Every member of a signed Statement is required.
type wireStatement struct {
	SchemaVersion         *string `json:"schema_version"`
	NodeID                *string `json:"node_id"`
	TenantID              *string `json:"tenant_id"`
	InstanceID            *string `json:"instance_id"`
	RuntimeRef            *string `json:"runtime_ref"`
	GrantID               *string `json:"grant_id"`
	Generation            *uint64 `json:"generation"`
	CapsuleDigest         *string `json:"capsule_digest"`
	PolicyDigest          *string `json:"policy_digest"`
	RoutePolicyDigest     *string `json:"route_policy_digest"`
	ServiceID             *string `json:"service_id"`
	OperationID           *string `json:"operation_id"`
	OperationPolicyDigest *string `json:"operation_policy_digest"`
	TaskID                *string `json:"task_id"`
	RequestDigest         *string `json:"request_digest"`
	RequestBytes          *int64  `json:"request_bytes"`
	ContentType           *string `json:"content_type"`
	NotBefore             *string `json:"not_before"`
	ExpiresAt             *string `json:"expires_at"`
}

// Verified is returned only after signature, schema, bounds, and time checks
// succeed. EnvelopeDigest identifies the exact serialized DSSE envelope.
type Verified struct {
	Statement      Statement
	KeyID          string
	EnvelopeDigest string
}

// RequestDigest binds a permit to the exact request-body bytes. Callers must
// compute it without parsing or reserializing the request.
func RequestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TaskDigest returns the durable replay identity for one logical workload
// task. Generation and grant are deliberately absent so replacing a workload
// cannot make the same tenant task spendable again. Length framing makes the
// tuple unambiguous even if this helper is called before input validation.
func TaskDigest(tenantID, instanceID, taskID string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(taskDigestDomain))
	var length [8]byte
	for _, value := range []string{tenantID, instanceID, taskID} {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// Verify authenticates and validates one bounded DSSE permit. maxValidity is
// an explicit local-policy ceiling and must itself be within the hard limit.
// now is required because a missing clock cannot safely establish validity.
func Verify(rawEnvelope []byte, trusted map[string]ed25519.PublicKey, now time.Time, maxValidity time.Duration) (Verified, error) {
	if len(rawEnvelope) == 0 || len(rawEnvelope) > MaxEnvelopeBytes {
		return Verified{}, invalid("envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	if now.IsZero() {
		return Verified{}, invalid("node time is unavailable")
	}
	if maxValidity <= 0 || maxValidity > MaxValidity {
		return Verified{}, invalid("maximum validity must be positive and at most %s", MaxValidity)
	}

	// DSSE signs the payload, not the surrounding JSON. A single canonical
	// envelope spelling prevents an intermediary from changing the permit
	// digest without changing its authority.
	envelope, err := dsse.Parse(rawEnvelope)
	if err != nil {
		return Verified{}, invalid("parse canonical single-signature envelope: %v", err)
	}
	if len(envelope.Signatures) != 1 {
		return Verified{}, invalid("permit envelope must contain exactly one signature")
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payloadBytes) != envelope.Payload {
		return Verified{}, invalid("permit payload is not canonical base64")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signatureBytes) != envelope.Signatures[0].Sig {
		return Verified{}, invalid("permit signature is not canonical base64")
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, rawEnvelope) {
		return Verified{}, invalid("permit envelope is not canonical")
	}
	payload, keyID, err := dsse.Verify(rawEnvelope, PayloadType, trusted)
	if err != nil {
		return Verified{}, invalid("verify DSSE envelope: %v", err)
	}
	if !utf8.Valid(payload) {
		return Verified{}, invalid("signed statement is not valid UTF-8")
	}
	if !identifier(keyID) {
		return Verified{}, invalid("signature key ID is not a bounded identifier")
	}
	var wire wireStatement
	if err := dsse.DecodeStrictInto(payload, MaxEnvelopeBytes, &wire); err != nil {
		return Verified{}, invalid("decode signed statement: %v", err)
	}
	statement, ok := wire.statement()
	if !ok {
		return Verified{}, invalid("signed statement omits a required field")
	}
	if err := validateStatement(statement, now, maxValidity); err != nil {
		return Verified{}, err
	}
	return Verified{
		Statement: statement, KeyID: keyID, EnvelopeDigest: dsse.Digest(rawEnvelope),
	}, nil
}

func (wire wireStatement) statement() (Statement, bool) {
	if wire.SchemaVersion == nil || wire.NodeID == nil || wire.TenantID == nil || wire.InstanceID == nil ||
		wire.RuntimeRef == nil || wire.GrantID == nil || wire.Generation == nil || wire.CapsuleDigest == nil ||
		wire.PolicyDigest == nil || wire.RoutePolicyDigest == nil || wire.ServiceID == nil || wire.OperationID == nil ||
		wire.OperationPolicyDigest == nil || wire.TaskID == nil || wire.RequestDigest == nil || wire.RequestBytes == nil ||
		wire.ContentType == nil || wire.NotBefore == nil || wire.ExpiresAt == nil {
		return Statement{}, false
	}
	return Statement{
		SchemaVersion: *wire.SchemaVersion, NodeID: *wire.NodeID, TenantID: *wire.TenantID,
		InstanceID: *wire.InstanceID, RuntimeRef: *wire.RuntimeRef, GrantID: *wire.GrantID,
		Generation: *wire.Generation, CapsuleDigest: *wire.CapsuleDigest, PolicyDigest: *wire.PolicyDigest,
		RoutePolicyDigest: *wire.RoutePolicyDigest, ServiceID: *wire.ServiceID, OperationID: *wire.OperationID,
		OperationPolicyDigest: *wire.OperationPolicyDigest, TaskID: *wire.TaskID, RequestDigest: *wire.RequestDigest,
		RequestBytes: *wire.RequestBytes, ContentType: *wire.ContentType, NotBefore: *wire.NotBefore,
		ExpiresAt: *wire.ExpiresAt,
	}, true
}

// EncodeHeader produces the only accepted HTTP-header representation. The
// unpadded URL-safe alphabet prevents delimiter ambiguity.
func EncodeHeader(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return "", invalid("header envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeHeader opens one canonical HTTP-header value. Exact re-encoding rejects
// padding, ignored whitespace, alternate trailing bits, and joined values.
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

func validateStatement(statement Statement, now time.Time, maxValidity time.Duration) error {
	if statement.SchemaVersion != SchemaV1 {
		return invalid("unsupported schema version")
	}
	if !publicIdentity(statement.NodeID, 128) || !publicIdentity(statement.TenantID, 128) ||
		!publicIdentity(statement.InstanceID, 256) || !runtimeRef(statement.RuntimeRef) || !grantID(statement.GrantID) ||
		!identifier(statement.ServiceID) || !identifier(statement.OperationID) || !identifier(statement.TaskID) {
		return invalid("statement contains an invalid identifier")
	}
	if statement.Generation == 0 {
		return invalid("generation must be positive")
	}
	if !digest(statement.CapsuleDigest) || !digest(statement.PolicyDigest) || !digest(statement.RoutePolicyDigest) ||
		!digest(statement.OperationPolicyDigest) || !digest(statement.RequestDigest) {
		return invalid("statement contains an invalid SHA-256 digest")
	}
	if statement.RequestBytes <= 0 || statement.RequestBytes > MaxRequestBytes {
		return invalid("request size is outside the supported range")
	}
	if statement.ContentType != "application/json" {
		return invalid("content type must be application/json")
	}

	notBefore, err := canonicalTime(statement.NotBefore)
	if err != nil {
		return invalid("not_before: %v", err)
	}
	expiresAt, err := canonicalTime(statement.ExpiresAt)
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

func identifier(value string) bool { return identifierPattern.MatchString(value) }

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

func runtimeRef(value string) bool {
	return strings.HasPrefix(value, "executor-") && len(value) == len("executor-")+sha256.Size*2 &&
		lowerHex(value[len("executor-"):])
}

func grantID(value string) bool {
	return strings.HasPrefix(value, "grant-") && len(value) == len("grant-")+sha256.Size*2 &&
		lowerHex(value[len("grant-"):])
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return value != ""
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
