// Package interactionpermit verifies tenant-signed responses to one exact
// agent-authored interaction request. Control is an untrusted courier: only the
// node Gateway may turn an inspected envelope into a response visible to the
// requesting workload.
package interactionpermit

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

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType          = "application/vnd.steward.interaction-response.v1+json"
	SchemaV1             = "steward.interaction-response.v1"
	ResponseBodySchemaV1 = "steward.interaction-response-body.v1"

	MaxEnvelopeBytes = 16 << 10
	MaxResponseBytes = 4 << 10
	MaxValidity      = 24 * time.Hour

	timestampLayout = "2006-01-02T15:04:05Z"
)

var (
	ErrInvalid        = errors.New("invalid interaction response permit")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Statement binds one exact response body to one exact interaction and
// admitted workload. The response body travels beside this envelope and is
// compared byte-for-byte by digest and length before it is exposed.
type Statement struct {
	SchemaVersion  string `json:"schema_version"`
	NodeID         string `json:"node_id"`
	TenantID       string `json:"tenant_id"`
	InstanceID     string `json:"instance_id"`
	RuntimeRef     string `json:"runtime_ref"`
	GrantID        string `json:"grant_id"`
	Generation     uint64 `json:"generation"`
	CapsuleDigest  string `json:"capsule_digest"`
	PolicyDigest   string `json:"policy_digest"`
	InteractionID  string `json:"interaction_id"`
	RequestDigest  string `json:"request_digest"`
	ResponseDigest string `json:"response_digest"`
	ResponseBytes  int64  `json:"response_bytes"`
	NotBefore      string `json:"not_before"`
	ExpiresAt      string `json:"expires_at"`
}

type wireStatement struct {
	SchemaVersion  *string `json:"schema_version"`
	NodeID         *string `json:"node_id"`
	TenantID       *string `json:"tenant_id"`
	InstanceID     *string `json:"instance_id"`
	RuntimeRef     *string `json:"runtime_ref"`
	GrantID        *string `json:"grant_id"`
	Generation     *uint64 `json:"generation"`
	CapsuleDigest  *string `json:"capsule_digest"`
	PolicyDigest   *string `json:"policy_digest"`
	InteractionID  *string `json:"interaction_id"`
	RequestDigest  *string `json:"request_digest"`
	ResponseDigest *string `json:"response_digest"`
	ResponseBytes  *int64  `json:"response_bytes"`
	NotBefore      *string `json:"not_before"`
	ExpiresAt      *string `json:"expires_at"`
}

type Inspected struct {
	Statement      Statement
	KeyID          string
	EnvelopeDigest string
}

type Verified struct {
	Statement      Statement
	KeyID          string
	EnvelopeDigest string
}

type ResponseBody struct {
	SchemaVersion string `json:"schema_version"`
	Choice        string `json:"choice,omitempty"`
	Text          string `json:"text,omitempty"`
}

func (body ResponseBody) Validate(options []string, allowText bool) error {
	if body.SchemaVersion != ResponseBodySchemaV1 ||
		body.Choice == "" && body.Text == "" ||
		body.Choice != "" && !responseText(body.Choice, 128) ||
		body.Text != "" && (!allowText || !responseText(body.Text, 2048)) {
		return invalid("interaction response body is invalid")
	}
	if body.Choice != "" {
		found := false
		for _, option := range options {
			if option == body.Choice {
				found = true
				break
			}
		}
		if !found {
			return invalid("interaction response choice was not offered")
		}
	}
	return nil
}

// Sign creates one canonical, single-signature response permit after applying
// the same structural bounds enforced by inspection and verification.
func Sign(statement Statement, keyID string, private ed25519.PrivateKey) ([]byte, error) {
	if !identifier(keyID) || len(private) != ed25519.PrivateKeySize {
		return nil, invalid("response signing key is invalid")
	}
	notBefore, err := canonicalTime(statement.NotBefore)
	if err != nil {
		return nil, invalid("not_before: %v", err)
	}
	if err := validateStatement(statement, notBefore, MaxValidity); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, invalid("marshal response statement")
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, private)
	if err != nil {
		return nil, invalid("sign response statement")
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil || len(raw) > MaxEnvelopeBytes {
		return nil, invalid("marshal response envelope")
	}
	return raw, nil
}

// ResponseDigest binds the exact JSON response bytes without parsing or
// reserializing them.
func ResponseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// InspectUnverified validates bounds, encoding, and statement shape without
// authenticating the signature. It is safe for routing, never authorization.
func InspectUnverified(raw []byte) (Inspected, error) {
	statement, keyID, envelopeDigest, err := inspect(raw)
	if err != nil {
		return Inspected{}, err
	}
	notBefore, err := canonicalTime(statement.NotBefore)
	if err != nil {
		return Inspected{}, invalid("not_before: %v", err)
	}
	if err := validateStatement(statement, notBefore, MaxValidity); err != nil {
		return Inspected{}, err
	}
	return Inspected{Statement: statement, KeyID: keyID, EnvelopeDigest: envelopeDigest}, nil
}

// Verify authenticates one canonical envelope against the admitted tenant task
// authorities and enforces the node's maximum response validity.
func Verify(raw []byte, trusted map[string]ed25519.PublicKey, now time.Time, maxValidity time.Duration) (Verified, error) {
	if now.IsZero() {
		return Verified{}, invalid("node time is unavailable")
	}
	if maxValidity <= 0 || maxValidity > MaxValidity {
		return Verified{}, invalid("maximum validity must be positive and at most %s", MaxValidity)
	}
	statement, keyID, envelopeDigest, err := inspect(raw)
	if err != nil {
		return Verified{}, err
	}
	payload, verifiedKeyID, err := dsse.Verify(raw, PayloadType, trusted)
	if err != nil || verifiedKeyID != keyID || !utf8.Valid(payload) {
		return Verified{}, invalid("verify DSSE envelope")
	}
	if err := validateStatement(statement, now, maxValidity); err != nil {
		return Verified{}, err
	}
	return Verified{Statement: statement, KeyID: keyID, EnvelopeDigest: envelopeDigest}, nil
}

func inspect(raw []byte) (Statement, string, string, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Statement{}, "", "", invalid("envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != PayloadType || len(envelope.Signatures) != 1 {
		return Statement{}, "", "", invalid("parse canonical single-signature envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload || !utf8.Valid(payload) {
		return Statement{}, "", "", invalid("response payload is not canonical UTF-8")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != envelope.Signatures[0].Sig ||
		!identifier(envelope.Signatures[0].KeyID) {
		return Statement{}, "", "", invalid("response signature encoding is invalid")
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Statement{}, "", "", invalid("response envelope is not canonical")
	}
	var wire wireStatement
	if err := dsse.DecodeStrictInto(payload, MaxEnvelopeBytes, &wire); err != nil {
		return Statement{}, "", "", invalid("decode signed statement: %v", err)
	}
	statement, ok := wire.statement()
	if !ok {
		return Statement{}, "", "", invalid("signed statement omits a required field")
	}
	return statement, envelope.Signatures[0].KeyID, dsse.Digest(raw), nil
}

func (wire wireStatement) statement() (Statement, bool) {
	if wire.SchemaVersion == nil || wire.NodeID == nil || wire.TenantID == nil ||
		wire.InstanceID == nil || wire.RuntimeRef == nil || wire.GrantID == nil ||
		wire.Generation == nil || wire.CapsuleDigest == nil || wire.PolicyDigest == nil ||
		wire.InteractionID == nil || wire.RequestDigest == nil || wire.ResponseDigest == nil ||
		wire.ResponseBytes == nil || wire.NotBefore == nil || wire.ExpiresAt == nil {
		return Statement{}, false
	}
	return Statement{
		SchemaVersion: *wire.SchemaVersion, NodeID: *wire.NodeID, TenantID: *wire.TenantID,
		InstanceID: *wire.InstanceID, RuntimeRef: *wire.RuntimeRef, GrantID: *wire.GrantID,
		Generation: *wire.Generation, CapsuleDigest: *wire.CapsuleDigest,
		PolicyDigest: *wire.PolicyDigest, InteractionID: *wire.InteractionID,
		RequestDigest: *wire.RequestDigest, ResponseDigest: *wire.ResponseDigest,
		ResponseBytes: *wire.ResponseBytes, NotBefore: *wire.NotBefore, ExpiresAt: *wire.ExpiresAt,
	}, true
}

func validateStatement(statement Statement, now time.Time, maxValidity time.Duration) error {
	if statement.SchemaVersion != SchemaV1 {
		return invalid("unsupported schema version")
	}
	if !publicIdentity(statement.NodeID, 128) || !publicIdentity(statement.TenantID, 128) ||
		!publicIdentity(statement.InstanceID, 256) || !runtimeRef(statement.RuntimeRef) ||
		!grantID(statement.GrantID) || !interactionID(statement.InteractionID) {
		return invalid("statement contains an invalid identity")
	}
	if statement.Generation == 0 {
		return invalid("generation must be positive")
	}
	if !digest(statement.CapsuleDigest) || !digest(statement.PolicyDigest) ||
		!digest(statement.RequestDigest) || !digest(statement.ResponseDigest) {
		return invalid("statement contains an invalid SHA-256 digest")
	}
	if statement.ResponseBytes <= 0 || statement.ResponseBytes > MaxResponseBytes {
		return invalid("response size is outside the supported range")
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

func responseText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func identifier(value string) bool { return identifierPattern.MatchString(value) }

func digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	return lowerHex(value[len("sha256:"):])
}

func runtimeRef(value string) bool {
	return strings.HasPrefix(value, "executor-") &&
		len(value) == len("executor-")+sha256.Size*2 && lowerHex(value[len("executor-"):])
}

func grantID(value string) bool {
	return strings.HasPrefix(value, "grant-") &&
		len(value) == len("grant-")+sha256.Size*2 && lowerHex(value[len("grant-"):])
}

func interactionID(value string) bool {
	return strings.HasPrefix(value, "interaction-") &&
		len(value) == len("interaction-")+sha256.Size*2 && lowerHex(value[len("interaction-"):])
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
