// Package controlauth provides the small credential vocabulary used by the
// bundled Steward control plane. Bearer secrets are never persisted: durable
// records retain only a keyed digest made with a separately protected auth key.
package controlauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	KeyBytes                     = 32
	operatorPrefix               = "steward_cp_v1"
	nodePrefix                   = "steward_node_v1"
	enrollmentPrefix             = "steward_enroll_v1"
	evidenceChallengePrefix      = "steward_evidence_challenge_v1_"
	credentialVersion            = 1
	enrollmentVersion            = 1
	maxTokenBytes                = 512
	maxTenantBindings            = 128
	evidenceChallengeNonceBytes  = 16
	evidenceChallengeMACBytes    = sha256.Size
	maxEvidenceChallengeLifetime = 10 * time.Minute

	// BootstrapRequestID is reserved for the recoverable first-site-admin
	// handoff. Normal operator issuance must reject this request identity.
	BootstrapRequestID = "steward-bootstrap-v1"
)

var (
	ErrUnauthorized       = errors.New("control credential is invalid")
	ErrForbidden          = errors.New("control credential is outside the requested tenant scope")
	ErrEnrollmentConsumed = errors.New("enrollment was already consumed by another request")
	ErrEnrollmentExpired  = errors.New("enrollment is expired")
)

type Role string

const (
	RoleSiteAdmin      Role = "site_admin"
	RoleTenantOperator Role = "tenant_operator"
)

type CredentialKind string

const (
	KindOperator CredentialKind = "operator"
	KindNode     CredentialKind = "node"
)

// Credential is the durable, non-secret half of one bearer credential.
type Credential struct {
	Version   int            `json:"version"`
	ID        string         `json:"id"`
	Kind      CredentialKind `json:"kind"`
	Role      Role           `json:"role,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	TenantIDs []string       `json:"tenant_ids,omitempty"`
	NodeID    string         `json:"node_id,omitempty"`
	Audience  string         `json:"audience,omitempty"`
	TokenMAC  []byte         `json:"token_mac"`
	RequestID string         `json:"request_id,omitempty"`
	CreatedAt string         `json:"created_at"`
	Revoked   bool           `json:"revoked"`
	RevokedAt string         `json:"revoked_at,omitempty"`
}

// Enrollment is a durable one-time capability. An exact retry of the first
// request_id reproduces the same node credential without storing its secret.
type Enrollment struct {
	Version            int      `json:"version"`
	ID                 string   `json:"id"`
	TenantIDs          []string `json:"tenant_ids"`
	NodeID             string   `json:"node_id"`
	Audience           string   `json:"audience"`
	TokenMAC           []byte   `json:"token_mac"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          string   `json:"expires_at"`
	IssueRequestID     string   `json:"issue_request_id,omitempty"`
	IssuerCredentialID string   `json:"issuer_credential_id,omitempty"`
	RequestID          string   `json:"request_id,omitempty"`
	CredentialID       string   `json:"credential_id,omitempty"`
	ConsumedAt         string   `json:"consumed_at,omitempty"`
	Revoked            bool     `json:"revoked"`
	RevokedAt          string   `json:"revoked_at,omitempty"`
}

type Identity struct {
	CredentialID string
	Role         Role
	TenantID     string
}

type NodeIdentity struct {
	CredentialID string
	TenantIDs    []string
	NodeID       string
	Audience     string
}

// NodeCredentialFile is the existing node-scoped Executor credential v2
// shape consumed by internal/uplink.LoadCredentialWithSecurity.
type NodeCredentialFile struct {
	Version    int    `json:"version"`
	Scope      string `json:"scope"`
	NodeID     string `json:"node_id"`
	Credential string `json:"credential"`
}

type Manager struct {
	key    [KeyBytes]byte
	random io.Reader
}

func New(key []byte) (*Manager, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("control auth key must contain exactly %d bytes", KeyBytes)
	}
	manager := &Manager{random: rand.Reader}
	copy(manager.key[:], key)
	return manager, nil
}

// InstanceID is the stable, non-secret identity of one control authority. It
// changes when the control authentication key changes and is safe to bind into
// node proof-of-possession statements.
func (m *Manager) InstanceID() string {
	if m == nil {
		return ""
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-control-instance-v1\x00"))
	_, _ = digest.Write(m.key[:])
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

// MintEvidenceChallenge returns a short-lived stateless challenge bound to one
// authenticated node credential. The opaque value contains no bearer secret.
func (m *Manager) MintEvidenceChallenge(credentialID, nodeID string, now, expiresAt time.Time) (string, error) {
	if m == nil || !validIdentity(credentialID, 128) || !validIdentity(nodeID, 128) || now.IsZero() ||
		!expiresAt.After(now) || expiresAt.Sub(now) > maxEvidenceChallengeLifetime {
		return "", errors.New("evidence challenge requires bounded identities and a short future lifetime")
	}
	nonce := make([]byte, evidenceChallengeNonceBytes)
	if _, err := io.ReadFull(m.random, nonce); err != nil {
		return "", fmt.Errorf("generate evidence challenge: %w", err)
	}
	payload := make([]byte, 1+8+2+2+len(credentialID)+len(nodeID)+len(nonce))
	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:9], uint64(expiresAt.UTC().Unix()))
	binary.BigEndian.PutUint16(payload[9:11], uint16(len(credentialID)))
	binary.BigEndian.PutUint16(payload[11:13], uint16(len(nodeID)))
	offset := 13
	copy(payload[offset:], credentialID)
	offset += len(credentialID)
	copy(payload[offset:], nodeID)
	offset += len(nodeID)
	copy(payload[offset:], nonce)
	mac := m.mac("evidence-challenge", string(payload))
	raw := append(payload, mac...)
	return evidenceChallengePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// VerifyEvidenceChallenge authenticates one challenge without retaining server
// memory. Credential rotation, node substitution, expiry, and byte tampering all
// invalidate the value.
func (m *Manager) VerifyEvidenceChallenge(raw, credentialID, nodeID string, now time.Time) error {
	if m == nil || !validIdentity(credentialID, 128) || !validIdentity(nodeID, 128) || now.IsZero() ||
		!strings.HasPrefix(raw, evidenceChallengePrefix) {
		return ErrUnauthorized
	}
	encoded := strings.TrimPrefix(raw, evidenceChallengePrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded ||
		len(decoded) < 13+evidenceChallengeNonceBytes+evidenceChallengeMACBytes {
		return ErrUnauthorized
	}
	payload := decoded[:len(decoded)-evidenceChallengeMACBytes]
	actualMAC := decoded[len(decoded)-evidenceChallengeMACBytes:]
	if payload[0] != 1 || !m.matches(m.mac("evidence-challenge", string(payload)), actualMAC) {
		return ErrUnauthorized
	}
	credentialLength := int(binary.BigEndian.Uint16(payload[9:11]))
	nodeLength := int(binary.BigEndian.Uint16(payload[11:13]))
	expectedLength := 13 + credentialLength + nodeLength + evidenceChallengeNonceBytes
	if credentialLength == 0 || nodeLength == 0 || expectedLength != len(payload) {
		return ErrUnauthorized
	}
	offset := 13
	challengedCredential := string(payload[offset : offset+credentialLength])
	offset += credentialLength
	challengedNode := string(payload[offset : offset+nodeLength])
	if challengedCredential != credentialID || challengedNode != nodeID {
		return ErrUnauthorized
	}
	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(payload[1:9])), 0).UTC()
	if !expiresAt.After(now.UTC()) || expiresAt.Sub(now.UTC()) > maxEvidenceChallengeLifetime {
		return ErrUnauthorized
	}
	return nil
}

// InitializeKey exclusively creates and fsyncs one owner-only raw auth key.
func InitializeKey(path string) (*Manager, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("control auth key path must be clean and absolute")
	}
	var key [KeyBytes]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("generate control auth key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create control auth key %q: %w", path, err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := writeAll(file, key[:]); err != nil {
		return nil, fmt.Errorf("write control auth key: %w", err)
	}
	if err := file.Sync(); err != nil {
		return nil, fmt.Errorf("sync control auth key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close control auth key: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	complete = true
	return New(key[:])
}

func LoadKey(path string) (*Manager, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("control auth key path must be clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat control auth key: %w", err)
	}
	if err := validateSecretInfo(before); err != nil {
		return nil, fmt.Errorf("control auth key %q: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open control auth key: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("control auth key changed while opening")
	}
	if err := validateSecretInfo(opened); err != nil {
		return nil, err
	}
	var key [KeyBytes]byte
	if _, err := io.ReadFull(file, key[:]); err != nil {
		return nil, fmt.Errorf("read control auth key: %w", err)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("control auth key has trailing bytes")
	}
	after, err := file.Stat()
	if err != nil || !sameSnapshot(opened, after) {
		return nil, errors.New("control auth key changed while reading")
	}
	return New(key[:])
}

func (m *Manager) MintOperator(role Role, tenantID string, now time.Time) (string, Credential, error) {
	if !validRoleScope(role, tenantID) || now.IsZero() {
		return "", Credential{}, errors.New("operator credential requires a valid role, scope, and creation time")
	}
	raw, id, err := m.randomToken(operatorPrefix, "cred")
	if err != nil {
		return "", Credential{}, err
	}
	credential := Credential{
		Version: credentialVersion, ID: id, Kind: KindOperator, Role: role, TenantID: tenantID,
		CreatedAt: canonicalTime(now),
	}
	credential.TokenMAC = m.operatorMAC(raw, credential)
	return raw, credential, nil
}

// MintOperatorForRequest deterministically derives a recoverable operator
// bearer from one bounded request identity. Only the bearer MAC is persisted.
func (m *Manager) MintOperatorForRequest(requestID string, role Role, tenantID string, createdAt time.Time) (string, Credential, error) {
	if !validIdentity(requestID, 128) || requestID == BootstrapRequestID ||
		!validRoleScope(role, tenantID) || createdAt.IsZero() {
		return "", Credential{}, errors.New("operator request requires a non-reserved identity, valid scope, and creation time")
	}
	return m.deterministicOperator("operator-request", "cred", requestID, role, tenantID, createdAt)
}

// MintBootstrapOperator deterministically derives the reserved first
// site-administrator bearer in a domain isolated from normal requests.
func (m *Manager) MintBootstrapOperator(createdAt time.Time) (string, Credential, error) {
	if createdAt.IsZero() {
		return "", Credential{}, errors.New("bootstrap operator requires a creation time")
	}
	return m.deterministicOperator(
		"bootstrap-operator", "bootstrap-cred", BootstrapRequestID,
		RoleSiteAdmin, "", createdAt,
	)
}

func (m *Manager) MintEnrollment(tenantIDs []string, nodeID string, expiresAt, now time.Time) (string, Enrollment, error) {
	canonical, canonicalErr := CanonicalTenantIDs(tenantIDs)
	if canonicalErr != nil || !validIdentity(nodeID, 128) || now.IsZero() ||
		!expiresAt.After(now) || expiresAt.Sub(now) > 24*time.Hour {
		return "", Enrollment{}, errors.New("enrollment requires bounded identities and a future lifetime no greater than 24 hours")
	}
	raw, id, err := m.randomToken(enrollmentPrefix, "enroll")
	if err != nil {
		return "", Enrollment{}, err
	}
	enrollment := Enrollment{
		Version: enrollmentVersion, ID: id, TenantIDs: canonical, NodeID: nodeID, Audience: "executor",
		CreatedAt: canonicalTime(now), ExpiresAt: canonicalTime(expiresAt),
	}
	enrollment.TokenMAC = m.enrollmentMAC(raw, enrollment)
	return raw, enrollment, nil
}

// MintEnrollmentForRequest deterministically derives a recoverable enrollment
// bearer for one operator credential and request identity. The durable store
// retains only its keyed MAC and the fields needed to reproduce an exact retry.
func (m *Manager) MintEnrollmentForRequest(requestID, issuerCredentialID string, tenantIDs []string, nodeID string, expiresAt, createdAt time.Time) (string, Enrollment, error) {
	canonical, canonicalErr := CanonicalTenantIDs(tenantIDs)
	if m == nil || canonicalErr != nil || !validIdentity(requestID, 128) ||
		!validIdentity(issuerCredentialID, 128) || !validIdentity(nodeID, 128) || createdAt.IsZero() ||
		!expiresAt.After(createdAt) || expiresAt.Sub(createdAt) > 24*time.Hour {
		return "", Enrollment{}, errors.New("enrollment request requires bounded identities and a future lifetime no greater than 24 hours")
	}
	scopeFields := append([]string{issuerCredentialID, nodeID}, canonical...)
	scopeFields = append(scopeFields, canonicalTime(createdAt), canonicalTime(expiresAt))
	scope := strings.Join(scopeFields, "\x00")
	idDigest := m.derive("enrollment-request-id", requestID, scope)
	secret := m.derive("enrollment-request-secret", requestID, scope)
	id := "enroll-" + hex.EncodeToString(idDigest[:16])
	raw := enrollmentPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	enrollment := Enrollment{
		Version: enrollmentVersion, ID: id, TenantIDs: canonical, NodeID: nodeID, Audience: "executor",
		CreatedAt: canonicalTime(createdAt), ExpiresAt: canonicalTime(expiresAt),
		IssueRequestID: requestID, IssuerCredentialID: issuerCredentialID,
	}
	enrollment.TokenMAC = m.enrollmentMAC(raw, enrollment)
	return raw, enrollment, nil
}

// Exchange deterministically derives one node credential. The caller must
// persist returnedEnrollment and credential atomically before returning file.
func (m *Manager) Exchange(raw, requestID string, now time.Time, enrollment Enrollment) (NodeCredentialFile, Credential, Enrollment, error) {
	if !validIdentity(requestID, 128) || now.IsZero() || enrollment.Revoked || enrollment.Version != enrollmentVersion ||
		!validCanonicalTenantIDs(enrollment.TenantIDs) || !validIdentity(enrollment.NodeID, 128) || enrollment.Audience != "executor" {
		return NodeCredentialFile{}, Credential{}, Enrollment{}, ErrUnauthorized
	}
	id, err := parseToken(raw, enrollmentPrefix)
	if err != nil || id != enrollment.ID || !m.matches(enrollment.TokenMAC, m.enrollmentMAC(raw, enrollment)) {
		return NodeCredentialFile{}, Credential{}, Enrollment{}, ErrUnauthorized
	}
	expires, err := parseCanonicalTime(enrollment.ExpiresAt)
	if err != nil || !expires.After(now) {
		return NodeCredentialFile{}, Credential{}, Enrollment{}, ErrEnrollmentExpired
	}
	if enrollment.RequestID != "" && enrollment.RequestID != requestID {
		return NodeCredentialFile{}, Credential{}, Enrollment{}, ErrEnrollmentConsumed
	}
	credentialID := "node-cred-" + hex.EncodeToString(m.derive("node-id", raw, requestID)[:16])
	secret := base64.RawURLEncoding.EncodeToString(m.derive("node-secret", raw, requestID))
	nodeToken := nodePrefix + "_" + credentialID + "_" + secret
	credential := Credential{
		Version: credentialVersion, ID: credentialID, Kind: KindNode,
		TenantIDs: append([]string(nil), enrollment.TenantIDs...), NodeID: enrollment.NodeID, Audience: enrollment.Audience,
		CreatedAt: canonicalTime(now),
	}
	updated := enrollment
	if updated.RequestID == "" {
		updated.RequestID = requestID
		updated.CredentialID = credentialID
		updated.ConsumedAt = canonicalTime(now)
	} else {
		credential.CreatedAt = updated.ConsumedAt
	}
	credential.TokenMAC = m.nodeMAC(nodeToken, credential)
	return NodeCredentialFile{Version: 2, Scope: "node", NodeID: enrollment.NodeID, Credential: nodeToken}, credential, updated, nil
}

func (m *Manager) OperatorCredentialID(raw string) (string, error) {
	return parseToken(raw, operatorPrefix)
}

func (m *Manager) NodeCredentialID(raw string) (string, error) {
	return ParseNodeCredentialID(raw)
}

// ParseNodeCredentialID returns the non-secret identifier embedded in a node
// bearer. It validates the complete token encoding but does not authenticate
// the bearer; authentication still requires Manager and its retained MAC.
func ParseNodeCredentialID(raw string) (string, error) { return parseToken(raw, nodePrefix) }

func (m *Manager) EnrollmentID(raw string) (string, error) {
	return parseToken(raw, enrollmentPrefix)
}

func (m *Manager) AuthenticateOperator(raw string, credential Credential) (Identity, error) {
	id, err := parseToken(raw, operatorPrefix)
	if err != nil || credential.Version != credentialVersion || credential.Kind != KindOperator || credential.Revoked ||
		id != credential.ID || !validRoleScope(credential.Role, credential.TenantID) ||
		!m.matches(credential.TokenMAC, m.operatorMAC(raw, credential)) {
		return Identity{}, ErrUnauthorized
	}
	return Identity{CredentialID: credential.ID, Role: credential.Role, TenantID: credential.TenantID}, nil
}

func (m *Manager) AuthenticateNode(raw string, credential Credential) (NodeIdentity, error) {
	id, err := parseToken(raw, nodePrefix)
	if err != nil || credential.Version != credentialVersion || credential.Kind != KindNode || credential.Revoked ||
		id != credential.ID || !validCanonicalTenantIDs(credential.TenantIDs) || !validIdentity(credential.NodeID, 128) ||
		credential.Audience != "executor" || !m.matches(credential.TokenMAC, m.nodeMAC(raw, credential)) {
		return NodeIdentity{}, ErrUnauthorized
	}
	return NodeIdentity{
		CredentialID: credential.ID, TenantIDs: append([]string(nil), credential.TenantIDs...),
		NodeID: credential.NodeID, Audience: credential.Audience,
	}, nil
}

func AuthorizedTenant(identity Identity, tenantID string) bool {
	if !validIdentity(tenantID, 128) {
		return false
	}
	return identity.Role == RoleSiteAdmin && identity.TenantID == "" ||
		identity.Role == RoleTenantOperator && identity.TenantID == tenantID
}

func IsSiteAdmin(identity Identity) bool {
	return identity.Role == RoleSiteAdmin && identity.TenantID == ""
}

// NodeAuthorizedTenant reports membership in the immutable, canonical tenant
// set carried by an authenticated node credential.
func NodeAuthorizedTenant(identity NodeIdentity, tenantID string) bool {
	if !validIdentity(tenantID, 128) || !validCanonicalTenantIDs(identity.TenantIDs) {
		return false
	}
	index := sort.SearchStrings(identity.TenantIDs, tenantID)
	return index < len(identity.TenantIDs) && identity.TenantIDs[index] == tenantID
}

func ValidateCredential(credential Credential) error {
	if credential.Version != credentialVersion || !validIdentity(credential.ID, 128) || len(credential.TokenMAC) != sha256.Size ||
		credential.CreatedAt == "" {
		return errors.New("invalid durable credential")
	}
	if _, err := parseCanonicalTime(credential.CreatedAt); err != nil {
		return errors.New("invalid credential creation time")
	}
	if credential.Revoked != (credential.RevokedAt != "") {
		return errors.New("incomplete credential revocation")
	}
	if credential.Revoked {
		revoked, err := parseCanonicalTime(credential.RevokedAt)
		created, _ := parseCanonicalTime(credential.CreatedAt)
		if err != nil || revoked.Before(created) {
			return errors.New("invalid credential revocation time")
		}
	}
	switch credential.Kind {
	case KindOperator:
		if !validRoleScope(credential.Role, credential.TenantID) ||
			(credential.RequestID != "" && !validIdentity(credential.RequestID, 128)) ||
			(credential.RequestID == BootstrapRequestID &&
				(credential.Role != RoleSiteAdmin || credential.TenantID != "")) ||
			len(credential.TenantIDs) != 0 || credential.NodeID != "" || credential.Audience != "" {
			return errors.New("invalid operator credential")
		}
	case KindNode:
		if credential.Role != "" || credential.TenantID != "" || credential.RequestID != "" ||
			!validCanonicalTenantIDs(credential.TenantIDs) ||
			!validIdentity(credential.NodeID, 128) || credential.Audience != "executor" {
			return errors.New("invalid node credential")
		}
	default:
		return errors.New("invalid credential kind")
	}
	return nil
}

func ValidateEnrollment(enrollment Enrollment) error {
	if enrollment.Version != enrollmentVersion || !validIdentity(enrollment.ID, 128) ||
		!validCanonicalTenantIDs(enrollment.TenantIDs) || !validIdentity(enrollment.NodeID, 128) ||
		enrollment.Audience != "executor" || len(enrollment.TokenMAC) != sha256.Size {
		return errors.New("invalid durable enrollment")
	}
	created, createdErr := parseCanonicalTime(enrollment.CreatedAt)
	expires, expiresErr := parseCanonicalTime(enrollment.ExpiresAt)
	if createdErr != nil || expiresErr != nil || !expires.After(created) || expires.Sub(created) > 24*time.Hour {
		return errors.New("invalid enrollment lifetime")
	}
	if (enrollment.IssueRequestID == "") != (enrollment.IssuerCredentialID == "") ||
		enrollment.IssueRequestID != "" && (!validIdentity(enrollment.IssueRequestID, 128) || !validIdentity(enrollment.IssuerCredentialID, 128)) {
		return errors.New("incomplete enrollment issuance identity")
	}
	if (enrollment.RequestID == "") != (enrollment.CredentialID == "") ||
		(enrollment.RequestID == "") != (enrollment.ConsumedAt == "") {
		return errors.New("incomplete enrollment consumption")
	}
	if enrollment.RequestID != "" {
		if !validIdentity(enrollment.RequestID, 128) || !validIdentity(enrollment.CredentialID, 128) {
			return errors.New("invalid enrollment consumption identity")
		}
		consumed, err := parseCanonicalTime(enrollment.ConsumedAt)
		if err != nil || consumed.Before(created) || consumed.After(expires) {
			return errors.New("invalid enrollment consumption time")
		}
	}
	if enrollment.Revoked != (enrollment.RevokedAt != "") {
		return errors.New("incomplete enrollment revocation")
	}
	if enrollment.Revoked {
		revoked, err := parseCanonicalTime(enrollment.RevokedAt)
		if err != nil || revoked.Before(created) {
			return errors.New("invalid enrollment revocation time")
		}
	}
	return nil
}

func (m *Manager) deterministicOperator(domain, idPrefix, requestID string, role Role, tenantID string, createdAt time.Time) (string, Credential, error) {
	if m == nil {
		return "", Credential{}, errors.New("control auth manager is unavailable")
	}
	scope := string(role) + "\x00" + tenantID
	idDigest := m.derive(domain+"-id", requestID, scope)
	secret := m.derive(domain+"-secret", requestID, scope)
	id := idPrefix + "-" + hex.EncodeToString(idDigest[:16])
	raw := operatorPrefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	credential := Credential{
		Version: credentialVersion, ID: id, Kind: KindOperator, Role: role, TenantID: tenantID,
		RequestID: requestID, CreatedAt: canonicalTime(createdAt),
	}
	credential.TokenMAC = m.operatorMAC(raw, credential)
	return raw, credential, nil
}

// CanonicalTenantIDs validates, copies, and sorts a node's explicit tenant
// bindings. Duplicate bindings are rejected instead of silently changing the
// meaning of a caller-supplied capability.
func CanonicalTenantIDs(tenantIDs []string) ([]string, error) {
	if len(tenantIDs) == 0 || len(tenantIDs) > maxTenantBindings {
		return nil, errors.New("tenant bindings must contain between 1 and 128 tenants")
	}
	canonical := append([]string(nil), tenantIDs...)
	for _, tenantID := range canonical {
		if !validIdentity(tenantID, 128) {
			return nil, errors.New("tenant binding contains an invalid identity")
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, errors.New("tenant bindings contain a duplicate identity")
		}
	}
	return canonical, nil
}

func (m *Manager) randomToken(prefix, idPrefix string) (string, string, error) {
	if m == nil || m.random == nil {
		return "", "", errors.New("control auth manager is unavailable")
	}
	var idRaw [16]byte
	var secret [32]byte
	if _, err := io.ReadFull(m.random, idRaw[:]); err != nil {
		return "", "", fmt.Errorf("generate credential id: %w", err)
	}
	if _, err := io.ReadFull(m.random, secret[:]); err != nil {
		return "", "", fmt.Errorf("generate credential secret: %w", err)
	}
	id := idPrefix + "-" + hex.EncodeToString(idRaw[:])
	return prefix + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret[:]), id, nil
}

func parseToken(raw, prefix string) (string, error) {
	if len(raw) == 0 || len(raw) > maxTokenBytes || strings.ContainsAny(raw, "\r\n\x00") {
		return "", ErrUnauthorized
	}
	rest, ok := strings.CutPrefix(raw, prefix+"_")
	if !ok {
		return "", ErrUnauthorized
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok || !validIdentity(id, 128) {
		return "", ErrUnauthorized
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return "", ErrUnauthorized
	}
	return id, nil
}

func (m *Manager) mac(domain, raw string, fields ...string) []byte {
	hash := hmac.New(sha256.New, m.key[:])
	_, _ = hash.Write([]byte("steward-control-auth-v2\x00" + domain + "\x00" + raw))
	for _, field := range fields {
		_, _ = hash.Write([]byte{'\x00'})
		_, _ = hash.Write([]byte(field))
	}
	return hash.Sum(nil)
}

func (m *Manager) operatorMAC(raw string, credential Credential) []byte {
	fields := []string{credential.ID, string(credential.Role), credential.TenantID, credential.CreatedAt}
	// Omitting the new request field for legacy/random credentials preserves
	// the pre-request-id MAC contract and keeps existing durable records valid.
	if credential.RequestID != "" {
		fields = append(fields, credential.RequestID)
	}
	return m.mac("operator", raw, fields...)
}

func (m *Manager) enrollmentMAC(raw string, enrollment Enrollment) []byte {
	fields := []string{enrollment.ID, enrollment.NodeID, enrollment.Audience, enrollment.CreatedAt, enrollment.ExpiresAt}
	fields = append(fields, enrollment.TenantIDs...)
	// Omitting issuance fields for random legacy enrollments preserves their
	// existing MAC contract while binding every deterministic issuance retry to
	// both its request identity and the operator credential that created it.
	if enrollment.IssueRequestID != "" {
		fields = append(fields, enrollment.IssueRequestID, enrollment.IssuerCredentialID)
	}
	return m.mac("enrollment", raw, fields...)
}

func (m *Manager) nodeMAC(raw string, credential Credential) []byte {
	fields := []string{credential.ID, credential.NodeID, credential.Audience, credential.CreatedAt}
	fields = append(fields, credential.TenantIDs...)
	return m.mac("node", raw, fields...)
}

func (m *Manager) matches(expected, actual []byte) bool {
	return len(expected) == len(actual) && subtle.ConstantTimeCompare(actual, expected) == 1
}

func (m *Manager) derive(domain, raw, requestID string) []byte {
	hash := hmac.New(sha256.New, m.key[:])
	_, _ = hash.Write([]byte("steward-control-derive-v1\x00" + domain + "\x00" + raw + "\x00" + requestID))
	return hash.Sum(nil)
}

func validRoleScope(role Role, tenantID string) bool {
	return role == RoleSiteAdmin && tenantID == "" || role == RoleTenantOperator && validIdentity(tenantID, 128)
}

func validCanonicalTenantIDs(tenantIDs []string) bool {
	if len(tenantIDs) == 0 || len(tenantIDs) > maxTenantBindings {
		return false
	}
	for index, tenantID := range tenantIDs {
		if !validIdentity(tenantID, 128) || index > 0 && tenantIDs[index-1] >= tenantID {
			return false
		}
	}
	return true
}

func validIdentity(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, errors.New("time is not canonical UTC RFC3339Nano")
	}
	return parsed, nil
}

func validateSecretInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != KeyBytes {
		return fmt.Errorf("must be a %d-byte owner-only regular file", KeyBytes)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Nlink) != 1 || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be owned by the service user and have exactly one link")
	}
	return nil
}

func sameSnapshot(left, right os.FileInfo) bool {
	return os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsRune(path, '\x00')
}

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open control auth key directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync control auth key directory: %w", err)
	}
	return nil
}
