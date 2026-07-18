// Package influence derives a bounded per-grant history commitment from the
// signed receipts for responses that Steward Gateway released to an agent.
// The commitment carries no response content. It is safe to sign into an exact
// effect permit and can be reconstructed offline from the receipt ledger.
package influence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

const SchemaV1 = "steward.effect-context.v1"

var ErrInvalid = errors.New("invalid effect context")

// Head identifies the exact Gateway-mediated response history visible to one
// admitted grant. Sequence zero is the grant-specific genesis commitment.
type Head struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	GrantID       string `json:"grant_id"`
	Generation    uint64 `json:"generation"`
	Sequence      uint64 `json:"sequence"`
	ChainHash     string `json:"chain_hash"`
}

// Genesis returns the deterministic empty response history for one grant.
func Genesis(tenantID, grantID string, generation uint64) (Head, error) {
	if !publicIdentity(tenantID, 128) || !grantIdentity(grantID) || generation == 0 {
		return Head{}, ErrInvalid
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("steward-effect-context-genesis-v1\x00"))
	for _, value := range []string{tenantID, grantID, strconv.FormatUint(generation, 10)} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return Head{
		SchemaVersion: SchemaV1, TenantID: tenantID, GrantID: grantID,
		Generation: generation, ChainHash: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// Advance commits one exact signed terminal receipt hash. The signed receipt
// carries the response digest and grant identity; callers must validate that
// receipt before advancing this projection.
func Advance(current Head, receiptHash string) (Head, error) {
	if err := current.Validate(); err != nil || !digest(receiptHash) || current.Sequence == ^uint64(0) {
		return Head{}, ErrInvalid
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("steward-effect-context-advance-v1\x00"))
	_, _ = hash.Write([]byte(current.ChainHash))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(receiptHash))
	return Head{
		SchemaVersion: current.SchemaVersion, TenantID: current.TenantID,
		GrantID: current.GrantID, Generation: current.Generation,
		Sequence: current.Sequence + 1, ChainHash: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// Validate rejects alternate or incomplete context-head representations.
func (head Head) Validate() error {
	if head.SchemaVersion != SchemaV1 || !publicIdentity(head.TenantID, 128) ||
		!grantIdentity(head.GrantID) || head.Generation == 0 || !digest(head.ChainHash) {
		return ErrInvalid
	}
	return nil
}

func publicIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func grantIdentity(value string) bool {
	if len(value) != len("grant-")+64 || !strings.HasPrefix(value, "grant-") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "grant-"))
	return err == nil
}

func digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
