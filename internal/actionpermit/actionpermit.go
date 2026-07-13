// Package actionpermit verifies short-lived, authority-signed permission for
// one exact connector request. It deliberately validates signed intent only;
// callers must still compare every returned binding with trusted runtime state
// and the exact request bytes before producing an external effect.
package actionpermit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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
	PayloadType = "application/vnd.steward.action-permit.v1+json"
	SchemaV1    = "steward.action-permit.v1"

	// MaxEnvelopeBytes is the decoded transport limit for one permit envelope.
	MaxEnvelopeBytes = 16 << 10
	// MaxRequestBytes matches Gateway's hard connector request-body ceiling,
	// independently of a connector's smaller configured limit.
	MaxRequestBytes int64 = 4 << 20
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
	NodeID            string `json:"node_id"`
	TenantID          string `json:"tenant_id"`
	InstanceID        string `json:"instance_id"`
	Generation        uint64 `json:"generation"`
	CapsuleDigest     string `json:"capsule_digest"`
	PolicyDigest      string `json:"policy_digest"`
	RoutePolicyDigest string `json:"route_policy_digest"`
	ConnectorID       string `json:"connector_id"`
	OperationID       string `json:"operation_id"`
	TaskID            string `json:"task_id"`
	RequestDigest     string `json:"request_digest"`
	RequestBytes      int64  `json:"request_bytes"`
	ContentType       string `json:"content_type"`
	NotBefore         string `json:"not_before"`
	ExpiresAt         string `json:"expires_at"`
}

// wireStatement uses pointers solely to distinguish an omitted member from a
// present zero value. Every member of a signed Statement is required, including
// request_bytes, whose valid value may be zero.
type wireStatement struct {
	SchemaVersion     *string `json:"schema_version"`
	NodeID            *string `json:"node_id"`
	TenantID          *string `json:"tenant_id"`
	InstanceID        *string `json:"instance_id"`
	Generation        *uint64 `json:"generation"`
	CapsuleDigest     *string `json:"capsule_digest"`
	PolicyDigest      *string `json:"policy_digest"`
	RoutePolicyDigest *string `json:"route_policy_digest"`
	ConnectorID       *string `json:"connector_id"`
	OperationID       *string `json:"operation_id"`
	TaskID            *string `json:"task_id"`
	RequestDigest     *string `json:"request_digest"`
	RequestBytes      *int64  `json:"request_bytes"`
	ContentType       *string `json:"content_type"`
	NotBefore         *string `json:"not_before"`
	ExpiresAt         *string `json:"expires_at"`
}

// Verified is returned only after signature, schema, bounds, and time checks
// succeed. EnvelopeDigest identifies the exact serialized DSSE envelope.
type Verified struct {
	Statement      Statement
	KeyID          string
	EnvelopeDigest string
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
	if len(rawEnvelope) == 0 || len(rawEnvelope) > MaxEnvelopeBytes {
		return Verified{}, invalid("envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	if now.IsZero() {
		return Verified{}, invalid("node time is unavailable")
	}
	if maxValidity <= 0 || maxValidity > MaxValidity {
		return Verified{}, invalid("maximum validity must be positive and at most %s", MaxValidity)
	}

	// Action permits intentionally have one canonical envelope spelling and one
	// signature. DSSE signatures cover the payload, not the surrounding JSON or
	// other signatures; accepting alternate envelope spellings would let an
	// intermediary change the receipt's permit digest without changing authority.
	envelope, err := dsse.Parse(rawEnvelope)
	if err != nil || len(envelope.Signatures) != 1 {
		return Verified{}, invalid("parse canonical single-signature envelope: %v", err)
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
	if !routeID(keyID) {
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
		wire.Generation == nil || wire.CapsuleDigest == nil || wire.PolicyDigest == nil || wire.RoutePolicyDigest == nil ||
		wire.ConnectorID == nil || wire.OperationID == nil || wire.TaskID == nil || wire.RequestDigest == nil ||
		wire.RequestBytes == nil || wire.ContentType == nil || wire.NotBefore == nil || wire.ExpiresAt == nil {
		return Statement{}, false
	}
	return Statement{
		SchemaVersion: *wire.SchemaVersion, NodeID: *wire.NodeID, TenantID: *wire.TenantID,
		InstanceID: *wire.InstanceID, Generation: *wire.Generation, CapsuleDigest: *wire.CapsuleDigest,
		PolicyDigest: *wire.PolicyDigest, RoutePolicyDigest: *wire.RoutePolicyDigest,
		ConnectorID: *wire.ConnectorID, OperationID: *wire.OperationID, TaskID: *wire.TaskID,
		RequestDigest: *wire.RequestDigest, RequestBytes: *wire.RequestBytes, ContentType: *wire.ContentType,
		NotBefore: *wire.NotBefore, ExpiresAt: *wire.ExpiresAt,
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

func validateStatement(statement Statement, now time.Time, maxValidity time.Duration) error {
	if statement.SchemaVersion != SchemaV1 {
		return invalid("unsupported schema version")
	}
	if !publicIdentity(statement.NodeID, 128) || !publicIdentity(statement.TenantID, 128) ||
		!publicIdentity(statement.InstanceID, 256) || !routeID(statement.ConnectorID) ||
		!routeID(statement.OperationID) || !routeID(statement.TaskID) {
		return invalid("statement contains an invalid identifier")
	}
	if statement.Generation == 0 {
		return invalid("generation must be positive")
	}
	if !digest(statement.CapsuleDigest) || !digest(statement.PolicyDigest) ||
		!digest(statement.RoutePolicyDigest) || !digest(statement.RequestDigest) {
		return invalid("statement contains an invalid SHA-256 digest")
	}
	if statement.RequestBytes < 0 || statement.RequestBytes > MaxRequestBytes {
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
