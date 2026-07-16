// Package agentcatalog defines a curator-signed, offline catalog of verified
// agent releases. A catalog is descriptive inventory: it grants no tenant,
// node, task, admission, or deployment authority.
package agentcatalog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	PayloadType = "application/vnd.steward.agent-catalog.v1+json"
	SchemaV1    = "steward.agent-catalog.v1"

	AuthorityDescriptiveOnly = "descriptive-only"

	StatusCandidate = "candidate"
	StatusApproved  = "approved"
	StatusRetired   = "retired"

	MaxEnvelopeBytes = dsse.DefaultMaxEnvelopeBytes
	MaxPayloadBytes  = dsse.MaxPayloadBytes
	MaxEntries       = 64

	MaxSkillManifestBytes         = int64(1 << 20)
	MaxQualificationEvidenceBytes = int64(4 << 20)
)

var (
	ErrInvalid        = errors.New("invalid agent catalog")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Catalog is one immutable, monotonically identified catalog revision.
// Revision ordering is an operator convention enforced by the distribution
// workflow; a detached catalog cannot know which other revisions exist.
type Catalog struct {
	SchemaVersion string  `json:"schema_version"`
	CatalogID     string  `json:"catalog_id"`
	Revision      uint64  `json:"revision"`
	IssuedAt      string  `json:"issued_at"`
	CuratorKeyID  string  `json:"curator_key_id"`
	Authority     string  `json:"authority"`
	Entries       []Entry `json:"entries"`
}

// Entry embeds the exact signed release and the publisher identity needed to
// verify it without a network. Status is descriptive curation, not admission
// policy.
type Entry struct {
	EntryID               string            `json:"entry_id"`
	Status                string            `json:"status"`
	Publisher             PublisherIdentity `json:"publisher"`
	ReleaseDSSEBase64     string            `json:"release_dsse_base64"`
	ReleaseEnvelopeDigest string            `json:"release_envelope_digest"`
	Bindings              ArtifactBindings  `json:"bindings"`
}

// PublisherIdentity pins the exact Ed25519 public key used by the embedded
// release and capsule signatures.
type PublisherIdentity struct {
	KeyID                  string `json:"key_id"`
	Ed25519PublicKeyBase64 string `json:"ed25519_public_key_base64"`
	PublicKeyDigest        string `json:"public_key_digest"`
}

// ArtifactBindings identify the exact external files checked when a curator
// issued the catalog. The files are not loaded or executed by this package.
type ArtifactBindings struct {
	Archive               FileBinding `json:"archive"`
	SkillManifest         FileBinding `json:"skill_manifest"`
	QualificationEvidence FileBinding `json:"qualification_evidence"`
}

// FileBinding identifies exact bytes and their bounded size.
type FileBinding struct {
	SHA256Digest string `json:"sha256_digest"`
	SizeBytes    int64  `json:"size_bytes"`
}

// Verified contains the authenticated catalog plus independently reverified
// embedded agent releases.
type Verified struct {
	Catalog        Catalog
	CuratorKeyID   string
	EnvelopeDigest string
	PayloadDigest  string
	Entries        []VerifiedEntry
}

// VerifiedEntry pairs catalog curation metadata with the reverified release.
type VerifiedEntry struct {
	Entry   Entry
	Release agentrelease.Verified
}

// Sign creates one canonical, single-signature catalog envelope. Every
// embedded release is verified with its pinned publisher key before signing.
func Sign(catalog Catalog, keyID string, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if now.IsZero() {
		return nil, invalid("verification time is unavailable")
	}
	if !identifier(keyID, 256) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, invalid("curator signing key is invalid")
	}
	if catalog.CuratorKeyID != keyID {
		return nil, invalid("catalog curator key ID does not match signing key")
	}
	if catalog.IssuedAt != now.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") {
		return nil, invalid("catalog issue time does not match signing time")
	}
	if _, err := validateCatalog(catalog); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(catalog)
	if err != nil {
		return nil, invalid("marshal catalog payload: %v", err)
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, invalid("catalog payload exceeds %d bytes", MaxPayloadBytes)
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, privateKey)
	if err != nil {
		return nil, invalid("sign catalog envelope: %v", err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		return nil, invalid("marshal catalog envelope: %v", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, invalid("catalog envelope exceeds %d bytes", MaxEnvelopeBytes)
	}
	return raw, nil
}

// Verify authenticates one canonical catalog envelope with operator-supplied
// curator keys, then reverifies every embedded release with its pinned
// publisher identity at the signed catalog issue time. Verification therefore
// remains deterministic after a release capsule expires; the catalog records
// curation history and does not assert current deployment readiness.
func Verify(rawEnvelope []byte, trustedCurators map[string]ed25519.PublicKey) (Verified, error) {
	envelope, parsedPayload, err := parseCanonicalEnvelope(rawEnvelope)
	if err != nil {
		return Verified{}, err
	}
	payload, curatorKeyID, err := dsse.Verify(rawEnvelope, PayloadType, trustedCurators)
	if err != nil {
		return Verified{}, invalid("verify catalog envelope: %v", err)
	}
	if !bytes.Equal(payload, parsedPayload) || envelope.Signatures[0].KeyID != curatorKeyID {
		return Verified{}, invalid("catalog signature binding is inconsistent")
	}
	var catalog Catalog
	if err := dsse.DecodeStrictInto(payload, MaxPayloadBytes, &catalog); err != nil {
		return Verified{}, invalid("decode catalog payload: %v", err)
	}
	if catalog.CuratorKeyID != curatorKeyID {
		return Verified{}, invalid("catalog curator key ID does not match verified signature")
	}
	entries, err := validateCatalog(catalog)
	if err != nil {
		return Verified{}, err
	}
	return Verified{
		Catalog: catalog, CuratorKeyID: curatorKeyID,
		EnvelopeDigest: dsse.Digest(rawEnvelope),
		PayloadDigest:  dsse.Digest(payload),
		Entries:        entries,
	}, nil
}

func validateCatalog(catalog Catalog) ([]VerifiedEntry, error) {
	if catalog.SchemaVersion != SchemaV1 || !identifier(catalog.CatalogID, 128) ||
		catalog.Revision == 0 || !identifier(catalog.CuratorKeyID, 256) ||
		catalog.Authority != AuthorityDescriptiveOnly {
		return nil, invalid("catalog identity is invalid")
	}
	issuedAt, err := time.Parse("2006-01-02T15:04:05Z", catalog.IssuedAt)
	if err != nil || issuedAt.Format("2006-01-02T15:04:05Z") != catalog.IssuedAt {
		return nil, invalid("catalog issue time is not canonical UTC RFC3339")
	}
	if len(catalog.Entries) == 0 || len(catalog.Entries) > MaxEntries {
		return nil, invalid("catalog must contain 1 to %d entries", MaxEntries)
	}

	verified := make([]VerifiedEntry, 0, len(catalog.Entries))
	seenReleaseIDs := make(map[string]struct{}, len(catalog.Entries))
	seenReleaseDigests := make(map[string]struct{}, len(catalog.Entries))
	publisherDigests := make(map[string]string, len(catalog.Entries))
	previousEntryID := ""
	for _, entry := range catalog.Entries {
		if previousEntryID != "" && entry.EntryID <= previousEntryID {
			return nil, invalid("catalog entries must be strictly sorted by entry_id")
		}
		previousEntryID = entry.EntryID
		release, err := validateEntry(entry, issuedAt)
		if err != nil {
			return nil, err
		}
		releaseIdentity := release.PublisherKeyID + "\x00" + release.Release.ReleaseID
		if _, exists := seenReleaseIDs[releaseIdentity]; exists {
			return nil, invalid(
				"catalog contains duplicate publisher/release identity %q/%q",
				release.PublisherKeyID,
				release.Release.ReleaseID,
			)
		}
		seenReleaseIDs[releaseIdentity] = struct{}{}
		if _, exists := seenReleaseDigests[release.EnvelopeDigest]; exists {
			return nil, invalid("catalog contains duplicate release envelope")
		}
		seenReleaseDigests[release.EnvelopeDigest] = struct{}{}
		if digest, exists := publisherDigests[entry.Publisher.KeyID]; exists &&
			digest != entry.Publisher.PublicKeyDigest {
			return nil, invalid(
				"catalog publisher key ID %q resolves to multiple public keys",
				entry.Publisher.KeyID,
			)
		}
		publisherDigests[entry.Publisher.KeyID] = entry.Publisher.PublicKeyDigest
		verified = append(verified, VerifiedEntry{Entry: entry, Release: release})
	}
	return verified, nil
}

func validateEntry(entry Entry, now time.Time) (agentrelease.Verified, error) {
	if !identifier(entry.EntryID, 128) || !validStatus(entry.Status) {
		return agentrelease.Verified{}, invalid("catalog entry %q has an invalid identity or status", entry.EntryID)
	}
	if !identifier(entry.Publisher.KeyID, 256) {
		return agentrelease.Verified{}, invalid("catalog entry %q has an invalid publisher key ID", entry.EntryID)
	}
	publicKey, err := decodeCanonicalBase64(
		entry.Publisher.Ed25519PublicKeyBase64, ed25519.PublicKeySize, "publisher public key",
	)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return agentrelease.Verified{}, invalid("catalog entry %q has an invalid publisher public key", entry.EntryID)
	}
	if entry.Publisher.PublicKeyDigest != dsse.Digest(publicKey) {
		return agentrelease.Verified{}, invalid("catalog entry %q publisher key digest does not match", entry.EntryID)
	}
	releaseRaw, err := decodeCanonicalBase64(
		entry.ReleaseDSSEBase64, agentrelease.MaxEnvelopeBytes, "release DSSE",
	)
	if err != nil {
		return agentrelease.Verified{}, invalid("catalog entry %q: %v", entry.EntryID, err)
	}
	if entry.ReleaseEnvelopeDigest != dsse.Digest(releaseRaw) {
		return agentrelease.Verified{}, invalid("catalog entry %q release envelope digest does not match", entry.EntryID)
	}
	release, err := agentrelease.Verify(
		releaseRaw,
		map[string]ed25519.PublicKey{entry.Publisher.KeyID: ed25519.PublicKey(publicKey)},
		now,
	)
	if err != nil {
		return agentrelease.Verified{}, invalid("catalog entry %q embedded release: %v", entry.EntryID, err)
	}
	if release.PublisherKeyID != entry.Publisher.KeyID {
		return agentrelease.Verified{}, invalid("catalog entry %q publisher identity does not match release", entry.EntryID)
	}
	qualificationCompletedAt, err := time.Parse(
		"2006-01-02T15:04:05Z",
		release.Release.Qualification.CompletedAt,
	)
	if err != nil || qualificationCompletedAt.After(now) {
		return agentrelease.Verified{}, invalid(
			"catalog entry %q qualification was not complete at catalog issue time",
			entry.EntryID,
		)
	}
	if entry.Bindings.Archive != (FileBinding{
		SHA256Digest: release.Release.Archive.SHA256Digest,
		SizeBytes:    release.Release.Archive.SizeBytes,
	}) {
		return agentrelease.Verified{}, invalid("catalog entry %q archive binding does not match release", entry.EntryID)
	}
	if err := validateFileBinding(
		entry.Bindings.SkillManifest, MaxSkillManifestBytes,
		release.Release.Canary.SkillManifestDigest, "skill manifest",
	); err != nil {
		return agentrelease.Verified{}, invalid("catalog entry %q: %v", entry.EntryID, err)
	}
	if err := validateFileBinding(
		entry.Bindings.QualificationEvidence, MaxQualificationEvidenceBytes,
		release.Release.Qualification.EvidenceDigest, "qualification evidence",
	); err != nil {
		return agentrelease.Verified{}, invalid("catalog entry %q: %v", entry.EntryID, err)
	}
	return release, nil
}

func validateFileBinding(binding FileBinding, maxBytes int64, expectedDigest, label string) error {
	if binding.SHA256Digest != expectedDigest {
		return fmt.Errorf("%s digest does not match release", label)
	}
	if binding.SizeBytes < 1 || binding.SizeBytes > maxBytes {
		return fmt.Errorf("%s size must be between 1 and %d bytes", label, maxBytes)
	}
	return nil
}

func parseCanonicalEnvelope(raw []byte) (dsse.Envelope, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return dsse.Envelope{}, nil, invalid("catalog envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return dsse.Envelope{}, nil, invalid("parse catalog envelope: %v", err)
	}
	if envelope.PayloadType != PayloadType || len(envelope.Signatures) != 1 {
		return dsse.Envelope{}, nil, invalid("catalog envelope has the wrong type or signature count")
	}
	payload, err := decodeCanonicalBase64(envelope.Payload, MaxPayloadBytes, "catalog payload")
	if err != nil {
		return dsse.Envelope{}, nil, err
	}
	signature, err := decodeCanonicalBase64(
		envelope.Signatures[0].Sig, ed25519.SignatureSize, "catalog signature",
	)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return dsse.Envelope{}, nil, invalid("catalog signature is invalid")
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return dsse.Envelope{}, nil, invalid("catalog envelope JSON is not canonical")
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
		return nil, invalid("%s is not bounded canonical base64", label)
	}
	return raw, nil
}

func validStatus(status string) bool {
	return status == StatusCandidate || status == StatusApproved || status == StatusRetired
}

func identifier(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && identifierPattern.MatchString(value) &&
		strings.TrimSpace(value) == value
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, arguments...)...)
}
