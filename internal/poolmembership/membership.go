// Package poolmembership defines the provider-neutral, independently signed
// statement that makes one node eligible for one elastic Steward node pool.
package poolmembership

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType = "application/vnd.steward.node-pool-membership.v1+json"
	MaxLifetime = 24 * time.Hour
)

// Statement binds a short-lived node identity to one exact pool membership
// generation. The boot and scheduling-policy digests prevent a valid statement
// from being replayed by a differently configured machine.
type Statement struct {
	SchemaVersion            int      `json:"schema_version"`
	ControllerInstanceID     string   `json:"controller_instance_id"`
	PoolID                   string   `json:"pool_id"`
	PoolMembershipGeneration uint64   `json:"pool_membership_generation"`
	PoolCreatedAt            string   `json:"pool_created_at"`
	NodeID                   string   `json:"node_id"`
	TenantIDs                []string `json:"tenant_ids"`
	Architecture             string   `json:"architecture,omitempty"`
	BootIdentitySHA256       string   `json:"boot_identity_sha256"`
	SchedulingPolicySHA256   string   `json:"scheduling_policy_sha256"`
	IssuedAt                 string   `json:"issued_at"`
	NotAfter                 string   `json:"not_after"`
}

type Verified struct {
	Statement Statement
	Envelope  []byte
	Digest    string
	KeyID     string
}

func Sign(statement Statement, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if err := Validate(statement); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, privateKey)
	if err != nil {
		return nil, err
	}
	return dsse.Marshal(envelope)
}

func Verify(raw []byte, keyID string, publicKey ed25519.PublicKey, now time.Time) (Verified, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !validIdentity(keyID, 256) || len(publicKey) != ed25519.PublicKeySize || now.IsZero() {
		return Verified{}, errors.New("node-pool membership verification input is invalid")
	}
	payload, verifiedKeyID, err := dsse.Verify(raw, PayloadType, map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		return Verified{}, err
	}
	var statement Statement
	if err := dsse.DecodeStrictInto(payload, 32<<10, &statement); err != nil {
		return Verified{}, errors.New("node-pool membership payload is invalid")
	}
	if err := Validate(statement); err != nil {
		return Verified{}, err
	}
	issued, _ := time.Parse(time.RFC3339Nano, statement.IssuedAt)
	notAfter, _ := time.Parse(time.RFC3339Nano, statement.NotAfter)
	now = now.UTC()
	if now.Before(issued) || !now.Before(notAfter) {
		return Verified{}, errors.New("node-pool membership is not currently valid")
	}
	return Verified{Statement: statement, Envelope: slices.Clone(raw), Digest: dsse.Digest(raw), KeyID: verifiedKeyID}, nil
}

// Inspect returns the validated payload without trusting its signature. It is
// only for selecting the public pool configuration needed by Verify.
func Inspect(raw []byte) (Statement, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return Statement{}, errors.New("node-pool membership envelope is invalid")
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != PayloadType {
		return Statement{}, errors.New("node-pool membership envelope is invalid")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return Statement{}, errors.New("node-pool membership payload encoding is invalid")
	}
	var statement Statement
	if err := dsse.DecodeStrictInto(payload, 32<<10, &statement); err != nil || Validate(statement) != nil {
		return Statement{}, errors.New("node-pool membership payload is invalid")
	}
	return statement, nil
}

func Validate(statement Statement) error {
	if statement.SchemaVersion != 1 || !validIdentity(statement.ControllerInstanceID, 160) ||
		!validIdentity(statement.PoolID, 128) || statement.PoolMembershipGeneration == 0 ||
		!validIdentity(statement.NodeID, 128) || len(statement.TenantIDs) == 0 || len(statement.TenantIDs) > 64 ||
		statement.Architecture != "" && !validIdentity(statement.Architecture, 64) ||
		!validDigest(statement.BootIdentitySHA256) || !validDigest(statement.SchedulingPolicySHA256) {
		return errors.New("node-pool membership statement is invalid")
	}
	for index, tenantID := range statement.TenantIDs {
		if !validIdentity(tenantID, 128) || index > 0 && statement.TenantIDs[index-1] >= tenantID {
			return errors.New("node-pool membership tenant set is not canonical")
		}
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, statement.IssuedAt)
	notAfter, notAfterErr := time.Parse(time.RFC3339Nano, statement.NotAfter)
	created, createdErr := time.Parse(time.RFC3339Nano, statement.PoolCreatedAt)
	if issuedErr != nil || notAfterErr != nil || createdErr != nil || statement.PoolCreatedAt != created.UTC().Format(time.RFC3339Nano) ||
		statement.IssuedAt != issued.UTC().Format(time.RFC3339Nano) || issued.Before(created) ||
		statement.NotAfter != notAfter.UTC().Format(time.RFC3339Nano) || !notAfter.After(issued) || notAfter.Sub(issued) > MaxLifetime {
		return errors.New("node-pool membership validity window is invalid")
	}
	return nil
}

func validIdentity(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
