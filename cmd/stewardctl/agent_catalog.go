package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentcatalog"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	agentCatalogSourceSchemaV1 = "steward.agent-catalog-source.v1"
	agentCatalogResultSchemaV1 = "steward.agent-catalog-result.v1"
	maxAgentCatalogSourceBytes = int64(256 << 10)
	maxAgentCatalogPathBytes   = 4096
	maxAgentCatalogQueryBytes  = 128
	// One catalog issuance may inspect at most 64 GiB of signed archive bytes.
	// This still permits all 64 entries when each archive is at most 1 GiB, or
	// three maximum-size 20 GiB archives with 4 GiB of headroom, while bounding
	// the source snapshot and hashing work caused by one untrusted manifest.
	maxAgentCatalogAggregateArchiveBytes = int64(64 << 30)
	// Valid archives may consume at most 128 GiB of first-pass tar payload
	// bytes across one issuance. Each archive also retains the lower existing
	// 40 GiB per-archive ceiling.
	maxAgentCatalogAggregateUncompressedBytes = int64(128 << 30)
)

type agentCatalogSource struct {
	SchemaVersion string                    `json:"schema_version"`
	CatalogID     string                    `json:"catalog_id"`
	Revision      uint64                    `json:"revision"`
	Entries       []agentCatalogSourceEntry `json:"entries"`
}

type agentCatalogSourceEntry struct {
	EntryID               string `json:"entry_id"`
	Status                string `json:"status"`
	Release               string `json:"release"`
	PublisherKeyID        string `json:"publisher_key_id"`
	PublisherPublicKey    string `json:"publisher_public_key"`
	Archive               string `json:"archive"`
	SkillManifest         string `json:"skill_manifest"`
	QualificationEvidence string `json:"qualification_evidence"`
}

type agentCatalogPreflightEntry struct {
	source          agentCatalogSourceEntry
	releaseRaw      []byte
	publisherPublic ed25519.PublicKey
	release         agentrelease.Verified
	bindings        agentcatalog.ArtifactBindings
}

type agentCatalogEntryOutput struct {
	EntryID               string                        `json:"entry_id"`
	Status                string                        `json:"status"`
	ReleaseID             string                        `json:"release_id"`
	CapsuleID             string                        `json:"capsule_id"`
	PublisherKeyID        string                        `json:"publisher_key_id"`
	PublisherKeyDigest    string                        `json:"publisher_key_digest"`
	ReleaseEnvelopeDigest string                        `json:"release_envelope_digest"`
	ReleasePayloadDigest  string                        `json:"release_payload_digest"`
	CapsuleEnvelopeDigest string                        `json:"capsule_envelope_digest"`
	CapsulePayloadDigest  string                        `json:"capsule_payload_digest"`
	CapsuleIssuedAt       string                        `json:"capsule_issued_at"`
	CapsuleExpiresAt      string                        `json:"capsule_expires_at"`
	Profile               admission.ProfileRef          `json:"profile"`
	Resources             admission.ResourceLimits      `json:"resources"`
	Capabilities          admission.Capabilities        `json:"capabilities"`
	State                 admission.StateShape          `json:"state"`
	Service               admission.ServiceShape        `json:"service"`
	Command               []string                      `json:"command"`
	Artifacts             []admission.ArtifactDigest    `json:"artifacts"`
	Display               agentrelease.Display          `json:"display"`
	Image                 admission.ImageIdentity       `json:"image"`
	Bindings              agentcatalog.ArtifactBindings `json:"bindings"`
	Canary                agentrelease.Canary           `json:"canary"`
	Qualification         agentrelease.Qualification    `json:"qualification"`
}

type agentCatalogDifference struct {
	Field string `json:"field"`
	Left  string `json:"left"`
	Right string `json:"right"`
}

type agentCatalogComparison struct {
	Equivalent  bool                     `json:"equivalent"`
	Left        agentCatalogEntryOutput  `json:"left"`
	Right       agentCatalogEntryOutput  `json:"right"`
	Differences []agentCatalogDifference `json:"differences"`
}

type agentCatalogResult struct {
	SchemaVersion  string                    `json:"schema_version"`
	Operation      string                    `json:"operation"`
	Valid          bool                      `json:"valid"`
	CatalogID      string                    `json:"catalog_id"`
	Revision       uint64                    `json:"revision"`
	IssuedAt       string                    `json:"issued_at"`
	CuratorKeyID   string                    `json:"curator_key_id"`
	Authority      string                    `json:"authority"`
	EnvelopeDigest string                    `json:"envelope_digest"`
	PayloadDigest  string                    `json:"payload_digest"`
	Count          int                       `json:"count"`
	Entries        []agentCatalogEntryOutput `json:"entries,omitempty"`
	Entry          *agentCatalogEntryOutput  `json:"entry,omitempty"`
	Comparison     *agentCatalogComparison   `json:"comparison,omitempty"`
}

type agentCatalogReadOptions struct {
	inputPath     string
	publicKeyPath string
	keyID         string
}

func agentCatalogCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("agent-catalog command requires issue, verify, list, search, show, or compare")
	}
	switch arguments[0] {
	case "issue":
		return issueAgentCatalog(arguments[1:], stdout)
	case "verify":
		return readAgentCatalogCommand("verify", arguments[1:], stdout)
	case "list":
		return readAgentCatalogCommand("list", arguments[1:], stdout)
	case "search":
		return readAgentCatalogCommand("search", arguments[1:], stdout)
	case "show":
		return readAgentCatalogCommand("show", arguments[1:], stdout)
	case "compare":
		return readAgentCatalogCommand("compare", arguments[1:], stdout)
	default:
		return errors.New("agent-catalog command requires issue, verify, list, search, show, or compare")
	}
}

func issueAgentCatalog(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent-catalog issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "strict catalog source manifest")
	privateKeyPath := flags.String("key", "", "owner-only curator Ed25519 private key")
	keyID := flags.String("key-id", "", "curator key ID")
	outputPath := flags.String("out", "", "new owner-only signed catalog revision")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *manifestPath == "" || *privateKeyPath == "" || *keyID == "" ||
		*outputPath == "" || flags.NArg() != 0 {
		return errors.New("agent-catalog issue requires -manifest, -key, -key-id, -out, and no positional arguments")
	}
	if !agentCatalogBoundedIdentifier(*keyID, 256) {
		return errors.New("agent catalog curator key ID is invalid")
	}
	inputRoot, manifestName, err := openAgentCatalogInputRoot(*manifestPath)
	if err != nil {
		return fmt.Errorf("open agent catalog input root: %w", err)
	}
	defer inputRoot.Close()
	sourceRaw, err := securefile.ReadRoot(
		inputRoot, manifestName, maxAgentCatalogSourceBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read agent catalog source: %w", err)
	}
	var source agentCatalogSource
	if err := dsse.DecodeStrictInto(sourceRaw, int(maxAgentCatalogSourceBytes), &source); err != nil {
		return fmt.Errorf("decode agent catalog source: %w", err)
	}
	if err := validateAgentCatalogSource(source); err != nil {
		return err
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read curator private key: %w", err)
	}
	curatorPublic, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(curatorPublic) != ed25519.PublicKeySize {
		return errors.New("curator private key does not contain an Ed25519 public key")
	}
	now := timeNow().UTC()
	preflightEntries, err := preflightAgentCatalogEntries(inputRoot, source.Entries, now)
	if err != nil {
		return err
	}
	entries := make([]agentcatalog.Entry, 0, len(preflightEntries))
	remainingUncompressed := maxAgentCatalogAggregateUncompressedBytes
	for _, preflightEntry := range preflightEntries {
		entry, uncompressedBytes, err := buildAgentCatalogEntry(
			inputRoot,
			preflightEntry,
			remainingUncompressed,
		)
		if err != nil {
			return err
		}
		if uncompressedBytes < 1 || uncompressedBytes > remainingUncompressed {
			return errors.New("agent catalog archive inspection returned invalid uncompressed usage")
		}
		remainingUncompressed -= uncompressedBytes
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].EntryID < entries[right].EntryID
	})
	catalog := agentcatalog.Catalog{
		SchemaVersion: agentcatalog.SchemaV1,
		CatalogID:     source.CatalogID,
		Revision:      source.Revision,
		IssuedAt:      now.Truncate(time.Second).Format("2006-01-02T15:04:05Z"),
		CuratorKeyID:  *keyID,
		Authority:     agentcatalog.AuthorityDescriptiveOnly,
		Entries:       entries,
	}
	rawEnvelope, err := agentcatalog.Sign(catalog, *keyID, privateKey, now)
	if err != nil {
		return fmt.Errorf("sign agent catalog: %w", err)
	}
	verified, err := agentcatalog.Verify(
		rawEnvelope, map[string]ed25519.PublicKey{*keyID: curatorPublic},
	)
	if err != nil {
		return fmt.Errorf("self-verify agent catalog: %w", err)
	}
	if err := writeNewFile(*outputPath, rawEnvelope, 0o600); err != nil {
		return fmt.Errorf("write agent catalog: %w", err)
	}
	return writeAgentCatalogResult(stdout, catalogResult(verified, "issued", verified.Entries))
}

func validateAgentCatalogSource(source agentCatalogSource) error {
	if source.SchemaVersion != agentCatalogSourceSchemaV1 || !agentCatalogIdentifier(source.CatalogID) ||
		source.Revision == 0 || len(source.Entries) == 0 ||
		len(source.Entries) > agentcatalog.MaxEntries {
		return errors.New("agent catalog source identity or entry count is invalid")
	}
	seenEntryIDs := make(map[string]struct{}, len(source.Entries))
	for _, sourceEntry := range source.Entries {
		if !agentCatalogIdentifier(sourceEntry.EntryID) ||
			!agentCatalogStatus(sourceEntry.Status) ||
			!agentCatalogBoundedIdentifier(sourceEntry.PublisherKeyID, 256) {
			return errors.New("agent catalog source entry identity or status is invalid")
		}
		if _, exists := seenEntryIDs[sourceEntry.EntryID]; exists {
			return fmt.Errorf("agent catalog source contains duplicate entry ID %q", sourceEntry.EntryID)
		}
		seenEntryIDs[sourceEntry.EntryID] = struct{}{}
		paths := []struct {
			label string
			value string
		}{
			{label: "release", value: sourceEntry.Release},
			{label: "publisher public key", value: sourceEntry.PublisherPublicKey},
			{label: "archive", value: sourceEntry.Archive},
			{label: "skill manifest", value: sourceEntry.SkillManifest},
			{label: "qualification evidence", value: sourceEntry.QualificationEvidence},
		}
		for _, path := range paths {
			if err := validateAgentCatalogRelativePath(path.value); err != nil {
				return fmt.Errorf("entry %q %s path: %w", sourceEntry.EntryID, path.label, err)
			}
		}
	}
	return nil
}

func preflightAgentCatalogEntries(
	inputRoot *os.Root,
	sourceEntries []agentCatalogSourceEntry,
	now time.Time,
) ([]agentCatalogPreflightEntry, error) {
	preflight := make([]agentCatalogPreflightEntry, 0, len(sourceEntries))
	seenReleaseIDs := make(map[string]struct{}, len(sourceEntries))
	seenReleaseDigests := make(map[string]struct{}, len(sourceEntries))
	publisherDigests := make(map[string]string, len(sourceEntries))
	for _, source := range sourceEntries {
		releaseRaw, err := securefile.ReadRoot(
			inputRoot, source.Release, agentrelease.MaxEnvelopeBytes, securefile.TrustFile,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q read agent release: %w", source.EntryID, err)
		}
		publisherPublic, err := readAgentCatalogPublicKey(
			inputRoot,
			source.PublisherPublicKey,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q read publisher public key: %w", source.EntryID, err)
		}
		publicKeyDigest := dsse.Digest(publisherPublic)
		if digest, exists := publisherDigests[source.PublisherKeyID]; exists &&
			digest != publicKeyDigest {
			return nil, fmt.Errorf(
				"agent catalog publisher key ID %q resolves to multiple public keys",
				source.PublisherKeyID,
			)
		}
		publisherDigests[source.PublisherKeyID] = publicKeyDigest
		release, err := agentrelease.Verify(
			releaseRaw,
			map[string]ed25519.PublicKey{source.PublisherKeyID: publisherPublic},
			now,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q verify agent release: %w", source.EntryID, err)
		}
		if release.PublisherKeyID != source.PublisherKeyID {
			return nil, fmt.Errorf("entry %q publisher key ID does not match release", source.EntryID)
		}
		releaseIdentity := release.PublisherKeyID + "\x00" + release.Release.ReleaseID
		if _, exists := seenReleaseIDs[releaseIdentity]; exists {
			return nil, fmt.Errorf(
				"agent catalog source contains duplicate publisher/release identity %q/%q",
				release.PublisherKeyID,
				release.Release.ReleaseID,
			)
		}
		seenReleaseIDs[releaseIdentity] = struct{}{}
		if _, exists := seenReleaseDigests[release.EnvelopeDigest]; exists {
			return nil, errors.New("agent catalog source contains duplicate release envelope")
		}
		seenReleaseDigests[release.EnvelopeDigest] = struct{}{}
		skillManifest, err := securefile.ReadRoot(
			inputRoot,
			source.SkillManifest,
			agentcatalog.MaxSkillManifestBytes,
			securefile.TrustFile,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q read skill manifest: %w", source.EntryID, err)
		}
		if dsse.Digest(skillManifest) != release.Release.Canary.SkillManifestDigest {
			return nil, fmt.Errorf("entry %q skill manifest bytes do not match release", source.EntryID)
		}
		qualificationEvidence, err := securefile.ReadRoot(
			inputRoot,
			source.QualificationEvidence,
			agentcatalog.MaxQualificationEvidenceBytes,
			securefile.TrustFile,
		)
		if err != nil {
			return nil, fmt.Errorf("entry %q read qualification evidence: %w", source.EntryID, err)
		}
		if dsse.Digest(qualificationEvidence) != release.Release.Qualification.EvidenceDigest {
			return nil, fmt.Errorf("entry %q qualification evidence bytes do not match release", source.EntryID)
		}
		preflight = append(preflight, agentCatalogPreflightEntry{
			source:          source,
			releaseRaw:      releaseRaw,
			publisherPublic: publisherPublic,
			release:         release,
			bindings: agentcatalog.ArtifactBindings{
				Archive: agentcatalog.FileBinding{
					SHA256Digest: release.Release.Archive.SHA256Digest,
					SizeBytes:    release.Release.Archive.SizeBytes,
				},
				SkillManifest: agentcatalog.FileBinding{
					SHA256Digest: dsse.Digest(skillManifest),
					SizeBytes:    int64(len(skillManifest)),
				},
				QualificationEvidence: agentcatalog.FileBinding{
					SHA256Digest: dsse.Digest(qualificationEvidence),
					SizeBytes:    int64(len(qualificationEvidence)),
				},
			},
		})
	}
	if err := validateAgentCatalogArchiveBudget(preflight); err != nil {
		return nil, err
	}
	return preflight, nil
}

func validateAgentCatalogArchiveBudget(entries []agentCatalogPreflightEntry) error {
	remaining := maxAgentCatalogAggregateArchiveBytes
	for _, entry := range entries {
		size := entry.release.Release.Archive.SizeBytes
		if size < 1 || size > remaining {
			return fmt.Errorf(
				"agent catalog aggregate archive inspection budget exceeds %d bytes",
				maxAgentCatalogAggregateArchiveBytes,
			)
		}
		remaining -= size
	}
	return nil
}

func buildAgentCatalogEntry(
	inputRoot *os.Root,
	preflight agentCatalogPreflightEntry,
	remainingUncompressed int64,
) (agentcatalog.Entry, int64, error) {
	source := preflight.source
	release := preflight.release
	if remainingUncompressed < release.Release.Archive.SizeBytes {
		return agentcatalog.Entry{}, 0, fmt.Errorf(
			"agent catalog aggregate uncompressed archive budget exceeds %d bytes",
			maxAgentCatalogAggregateUncompressedBytes,
		)
	}
	limits := ocibundle.DefaultLimits()
	// The signed byte length is an inspection ceiling, not only a comparison
	// after parsing. A publisher cannot understate a large untrusted archive to
	// bypass the aggregate source-byte budget and force the larger snapshot.
	limits.MaxArchiveBytes = release.Release.Archive.SizeBytes
	if remainingUncompressed < limits.MaxUncompressedBytes {
		limits.MaxUncompressedBytes = remainingUncompressed
	}
	inspection, err := ocibundle.InspectRootSource(inputRoot, source.Archive, limits)
	if err != nil {
		return agentcatalog.Entry{}, 0, fmt.Errorf("entry %q inspect archive: %w", source.EntryID, err)
	}
	if inspection.Archive.Digest != release.Release.Archive.SHA256Digest ||
		inspection.Archive.Bytes != release.Release.Archive.SizeBytes ||
		inspection.Image.ManifestDigest != release.Release.Archive.Image.ManifestDigest ||
		inspection.Image.ConfigDigest != release.Release.Archive.Image.ConfigDigest ||
		inspection.Image.Platform != (ocibundle.Platform{
			OS:           release.Release.Archive.Image.Platform.OS,
			Architecture: release.Release.Archive.Image.Platform.Architecture,
			Variant:      release.Release.Archive.Image.Platform.Variant,
		}) {
		return agentcatalog.Entry{}, 0, fmt.Errorf("entry %q archive bytes or image identity do not match release", source.EntryID)
	}
	return agentcatalog.Entry{
		EntryID: source.EntryID,
		Status:  source.Status,
		Publisher: agentcatalog.PublisherIdentity{
			KeyID:                  source.PublisherKeyID,
			Ed25519PublicKeyBase64: base64.StdEncoding.EncodeToString(preflight.publisherPublic),
			PublicKeyDigest:        dsse.Digest(preflight.publisherPublic),
		},
		ReleaseDSSEBase64:     base64.StdEncoding.EncodeToString(preflight.releaseRaw),
		ReleaseEnvelopeDigest: dsse.Digest(preflight.releaseRaw),
		Bindings:              preflight.bindings,
	}, inspection.UncompressedBytes, nil
}

func readAgentCatalogCommand(operation string, arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent-catalog "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := agentCatalogReadOptions{}
	flags.StringVar(&options.inputPath, "in", "", "signed agent catalog DSSE envelope")
	flags.StringVar(&options.publicKeyPath, "public-key", "", "external curator Ed25519 public key")
	flags.StringVar(&options.keyID, "key-id", "", "external curator key ID")
	status := flags.String("status", "", "optional exact candidate, approved, or retired filter")
	query := flags.String("query", "", "bounded case-insensitive search query")
	entryID := flags.String("entry-id", "", "exact entry ID")
	leftEntryID := flags.String("left-entry-id", "", "left exact entry ID")
	rightEntryID := flags.String("right-entry-id", "", "right exact entry ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if options.inputPath == "" || options.publicKeyPath == "" || options.keyID == "" ||
		flags.NArg() != 0 {
		return fmt.Errorf("agent-catalog %s requires -in, -public-key, -key-id, and no positional arguments", operation)
	}
	if !agentCatalogBoundedIdentifier(options.keyID, 256) {
		return errors.New("agent catalog curator key ID is invalid")
	}
	if *status != "" && !agentCatalogStatus(*status) {
		return errors.New("agent catalog status filter must be candidate, approved, or retired")
	}
	switch operation {
	case "verify":
		if *status != "" || *query != "" || *entryID != "" || *leftEntryID != "" || *rightEntryID != "" {
			return errors.New("agent-catalog verify does not accept selection flags")
		}
	case "list":
		if *query != "" || *entryID != "" || *leftEntryID != "" || *rightEntryID != "" {
			return errors.New("agent-catalog list accepts only the optional -status selection flag")
		}
	case "search":
		if !agentCatalogQuery(*query) || *entryID != "" || *leftEntryID != "" || *rightEntryID != "" {
			return errors.New("agent-catalog search requires one bounded -query and accepts optional -status")
		}
	case "show":
		if !agentCatalogIdentifier(*entryID) || *status != "" || *query != "" ||
			*leftEntryID != "" || *rightEntryID != "" {
			return errors.New("agent-catalog show requires one exact -entry-id and no other selection flags")
		}
	case "compare":
		if !agentCatalogIdentifier(*leftEntryID) || !agentCatalogIdentifier(*rightEntryID) ||
			*leftEntryID == *rightEntryID || *status != "" || *query != "" || *entryID != "" {
			return errors.New("agent-catalog compare requires distinct -left-entry-id and -right-entry-id values")
		}
	default:
		return errors.New("unsupported agent-catalog read operation")
	}

	verified, err := loadVerifiedAgentCatalog(options)
	if err != nil {
		return err
	}
	switch operation {
	case "verify":
		return writeAgentCatalogResult(stdout, catalogResult(verified, operation, nil))
	case "list":
		filtered := filterAgentCatalogEntries(verified.Entries, *status, "")
		return writeAgentCatalogResult(stdout, catalogResult(verified, operation, filtered))
	case "search":
		filtered := filterAgentCatalogEntries(verified.Entries, *status, *query)
		return writeAgentCatalogResult(stdout, catalogResult(verified, operation, filtered))
	case "show":
		found, ok := findAgentCatalogEntry(verified.Entries, *entryID)
		if !ok {
			return fmt.Errorf("agent catalog entry %q was not found", *entryID)
		}
		output := catalogResult(verified, operation, nil)
		entry := agentCatalogEntryResult(found)
		output.Entry = &entry
		output.Count = 1
		return writeAgentCatalogResult(stdout, output)
	case "compare":
		left, leftOK := findAgentCatalogEntry(verified.Entries, *leftEntryID)
		right, rightOK := findAgentCatalogEntry(verified.Entries, *rightEntryID)
		if !leftOK || !rightOK {
			return errors.New("both agent catalog comparison entries must exist")
		}
		output := catalogResult(verified, operation, nil)
		comparison := compareAgentCatalogEntries(left, right)
		output.Comparison = &comparison
		output.Count = 2
		return writeAgentCatalogResult(stdout, output)
	}
	return errors.New("unsupported agent-catalog read operation")
}

func loadVerifiedAgentCatalog(options agentCatalogReadOptions) (agentcatalog.Verified, error) {
	rawEnvelope, err := securefile.Read(
		options.inputPath, agentcatalog.MaxEnvelopeBytes, securefile.TrustFile,
	)
	if err != nil {
		return agentcatalog.Verified{}, fmt.Errorf("read agent catalog: %w", err)
	}
	publicKey, err := readPublicKey(options.publicKeyPath)
	if err != nil {
		return agentcatalog.Verified{}, fmt.Errorf("read curator public key: %w", err)
	}
	verified, err := agentcatalog.Verify(
		rawEnvelope,
		map[string]ed25519.PublicKey{options.keyID: publicKey},
	)
	if err != nil {
		return agentcatalog.Verified{}, err
	}
	return verified, nil
}

func catalogResult(
	verified agentcatalog.Verified,
	operation string,
	entries []agentcatalog.VerifiedEntry,
) agentCatalogResult {
	output := agentCatalogResult{
		SchemaVersion:  agentCatalogResultSchemaV1,
		Operation:      operation,
		Valid:          true,
		CatalogID:      verified.Catalog.CatalogID,
		Revision:       verified.Catalog.Revision,
		IssuedAt:       verified.Catalog.IssuedAt,
		CuratorKeyID:   verified.CuratorKeyID,
		Authority:      verified.Catalog.Authority,
		EnvelopeDigest: verified.EnvelopeDigest,
		PayloadDigest:  verified.PayloadDigest,
		Count:          len(verified.Entries),
	}
	if entries != nil {
		output.Count = len(entries)
		output.Entries = make([]agentCatalogEntryOutput, 0, len(entries))
		for _, entry := range entries {
			output.Entries = append(output.Entries, agentCatalogEntryResult(entry))
		}
	}
	return output
}

func agentCatalogEntryResult(entry agentcatalog.VerifiedEntry) agentCatalogEntryOutput {
	return agentCatalogEntryOutput{
		EntryID:               entry.Entry.EntryID,
		Status:                entry.Entry.Status,
		ReleaseID:             entry.Release.Release.ReleaseID,
		CapsuleID:             entry.Release.Capsule.CapsuleID,
		PublisherKeyID:        entry.Release.PublisherKeyID,
		PublisherKeyDigest:    entry.Entry.Publisher.PublicKeyDigest,
		ReleaseEnvelopeDigest: entry.Release.EnvelopeDigest,
		ReleasePayloadDigest:  entry.Release.PayloadDigest,
		CapsuleEnvelopeDigest: entry.Release.CapsuleEnvelopeDigest,
		CapsulePayloadDigest:  entry.Release.CapsulePayloadDigest,
		CapsuleIssuedAt:       entry.Release.Capsule.IssuedAt,
		CapsuleExpiresAt:      entry.Release.Capsule.ExpiresAt,
		Profile:               entry.Release.Capsule.Profile,
		Resources:             entry.Release.Capsule.Resources,
		Capabilities:          entry.Release.Capsule.Capabilities,
		State:                 entry.Release.Capsule.State,
		Service:               entry.Release.Capsule.Service,
		Command:               append([]string(nil), entry.Release.Capsule.Command...),
		Artifacts:             append([]admission.ArtifactDigest(nil), entry.Release.Capsule.Artifacts...),
		Display:               entry.Release.Release.Display,
		Image:                 entry.Release.Release.Archive.Image,
		Bindings:              entry.Entry.Bindings,
		Canary:                entry.Release.Release.Canary,
		Qualification:         entry.Release.Release.Qualification,
	}
}

func filterAgentCatalogEntries(
	entries []agentcatalog.VerifiedEntry,
	status string,
	query string,
) []agentcatalog.VerifiedEntry {
	needle := strings.ToLower(query)
	filtered := make([]agentcatalog.VerifiedEntry, 0, len(entries))
	for _, entry := range entries {
		if status != "" && entry.Entry.Status != status {
			continue
		}
		if needle != "" && !agentCatalogMatchesQuery(entry, needle) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func agentCatalogMatchesQuery(entry agentcatalog.VerifiedEntry, needle string) bool {
	capabilities := entry.Release.Capsule.Capabilities
	switch needle {
	case "capability:state":
		return capabilities.State
	case "capability:inference":
		return capabilities.Inference
	case "capability:service":
		return capabilities.Service
	case "capability:egress":
		return capabilities.Egress
	case "capability:connector":
		return capabilities.Connector
	default:
		return strings.Contains(strings.ToLower(agentCatalogSearchText(entry)), needle)
	}
}

func agentCatalogSearchText(entry agentcatalog.VerifiedEntry) string {
	release := entry.Release.Release
	values := []string{
		entry.Entry.EntryID,
		entry.Entry.Status,
		release.ReleaseID,
		entry.Release.Capsule.CapsuleID,
		entry.Release.PublisherKeyID,
		release.Display.Title,
		release.Display.Summary,
		release.Display.Outcome,
		release.Archive.Image.Repository,
		release.Archive.Image.ManifestDigest,
		release.Archive.Image.ConfigDigest,
		release.Archive.Image.Platform.OS,
		release.Archive.Image.Platform.Architecture,
		entry.Release.Capsule.IssuedAt,
		entry.Release.Capsule.ExpiresAt,
		entry.Release.Capsule.Profile.ID,
		entry.Release.Capsule.Profile.Version,
		strconv.FormatInt(entry.Release.Capsule.Resources.MemoryBytes, 10),
		strconv.FormatInt(entry.Release.Capsule.Resources.CPUMillis, 10),
		strconv.FormatInt(entry.Release.Capsule.Resources.PIDs, 10),
		entry.Release.Capsule.State.SchemaVersion,
		entry.Release.Capsule.State.Path,
		entry.Release.Capsule.Service.ID,
		strconv.Itoa(entry.Release.Capsule.Service.Port),
		release.Qualification.Runtime,
	}
	values = append(values, entry.Release.Capsule.Command...)
	for _, artifact := range entry.Release.Capsule.Artifacts {
		values = append(values, artifact.Kind, artifact.Digest)
	}
	values = append(values, release.Qualification.Limitations...)
	return strings.Join(values, "\n")
}

func findAgentCatalogEntry(
	entries []agentcatalog.VerifiedEntry,
	entryID string,
) (agentcatalog.VerifiedEntry, bool) {
	index := sort.Search(len(entries), func(index int) bool {
		return entries[index].Entry.EntryID >= entryID
	})
	if index >= len(entries) || entries[index].Entry.EntryID != entryID {
		return agentcatalog.VerifiedEntry{}, false
	}
	return entries[index], true
}

func compareAgentCatalogEntries(
	left agentcatalog.VerifiedEntry,
	right agentcatalog.VerifiedEntry,
) agentCatalogComparison {
	leftOutput := agentCatalogEntryResult(left)
	rightOutput := agentCatalogEntryResult(right)
	differences := make([]agentCatalogDifference, 0)
	add := func(field, leftValue, rightValue string) {
		if leftValue != rightValue {
			differences = append(differences, agentCatalogDifference{
				Field: field, Left: leftValue, Right: rightValue,
			})
		}
	}
	add("status", leftOutput.Status, rightOutput.Status)
	add("release_id", leftOutput.ReleaseID, rightOutput.ReleaseID)
	add("capsule.id", leftOutput.CapsuleID, rightOutput.CapsuleID)
	add("publisher_key_id", leftOutput.PublisherKeyID, rightOutput.PublisherKeyID)
	add("publisher_key_digest", leftOutput.PublisherKeyDigest, rightOutput.PublisherKeyDigest)
	add("release_envelope_digest", leftOutput.ReleaseEnvelopeDigest, rightOutput.ReleaseEnvelopeDigest)
	add("release_payload_digest", leftOutput.ReleasePayloadDigest, rightOutput.ReleasePayloadDigest)
	add("capsule_envelope_digest", leftOutput.CapsuleEnvelopeDigest, rightOutput.CapsuleEnvelopeDigest)
	add("capsule_payload_digest", leftOutput.CapsulePayloadDigest, rightOutput.CapsulePayloadDigest)
	add("capsule.issued_at", leftOutput.CapsuleIssuedAt, rightOutput.CapsuleIssuedAt)
	add("capsule.expires_at", leftOutput.CapsuleExpiresAt, rightOutput.CapsuleExpiresAt)
	add("profile.id", leftOutput.Profile.ID, rightOutput.Profile.ID)
	add("profile.version", leftOutput.Profile.Version, rightOutput.Profile.Version)
	add("resources.memory_bytes", strconv.FormatInt(leftOutput.Resources.MemoryBytes, 10), strconv.FormatInt(rightOutput.Resources.MemoryBytes, 10))
	add("resources.cpu_millis", strconv.FormatInt(leftOutput.Resources.CPUMillis, 10), strconv.FormatInt(rightOutput.Resources.CPUMillis, 10))
	add("resources.pids", strconv.FormatInt(leftOutput.Resources.PIDs, 10), strconv.FormatInt(rightOutput.Resources.PIDs, 10))
	add("capabilities.state", strconv.FormatBool(leftOutput.Capabilities.State), strconv.FormatBool(rightOutput.Capabilities.State))
	add("capabilities.inference", strconv.FormatBool(leftOutput.Capabilities.Inference), strconv.FormatBool(rightOutput.Capabilities.Inference))
	add("capabilities.service", strconv.FormatBool(leftOutput.Capabilities.Service), strconv.FormatBool(rightOutput.Capabilities.Service))
	add("capabilities.egress", strconv.FormatBool(leftOutput.Capabilities.Egress), strconv.FormatBool(rightOutput.Capabilities.Egress))
	add("capabilities.connector", strconv.FormatBool(leftOutput.Capabilities.Connector), strconv.FormatBool(rightOutput.Capabilities.Connector))
	add("state.schema_version", leftOutput.State.SchemaVersion, rightOutput.State.SchemaVersion)
	add("state.path", leftOutput.State.Path, rightOutput.State.Path)
	add("service.id", leftOutput.Service.ID, rightOutput.Service.ID)
	add("service.port", strconv.Itoa(leftOutput.Service.Port), strconv.Itoa(rightOutput.Service.Port))
	add("command", agentCatalogCommandText(leftOutput.Command), agentCatalogCommandText(rightOutput.Command))
	add("artifacts", agentCatalogArtifactsText(leftOutput.Artifacts), agentCatalogArtifactsText(rightOutput.Artifacts))
	add("archive.sha256_digest", leftOutput.Bindings.Archive.SHA256Digest, rightOutput.Bindings.Archive.SHA256Digest)
	add("archive.size_bytes", strconv.FormatInt(leftOutput.Bindings.Archive.SizeBytes, 10), strconv.FormatInt(rightOutput.Bindings.Archive.SizeBytes, 10))
	add("skill_manifest.sha256_digest", leftOutput.Bindings.SkillManifest.SHA256Digest, rightOutput.Bindings.SkillManifest.SHA256Digest)
	add("skill_manifest.size_bytes", strconv.FormatInt(leftOutput.Bindings.SkillManifest.SizeBytes, 10), strconv.FormatInt(rightOutput.Bindings.SkillManifest.SizeBytes, 10))
	add("qualification_evidence.sha256_digest", leftOutput.Bindings.QualificationEvidence.SHA256Digest, rightOutput.Bindings.QualificationEvidence.SHA256Digest)
	add("qualification_evidence.size_bytes", strconv.FormatInt(leftOutput.Bindings.QualificationEvidence.SizeBytes, 10), strconv.FormatInt(rightOutput.Bindings.QualificationEvidence.SizeBytes, 10))
	add("image.repository", leftOutput.Image.Repository, rightOutput.Image.Repository)
	add("image.manifest_digest", leftOutput.Image.ManifestDigest, rightOutput.Image.ManifestDigest)
	add("image.config_digest", leftOutput.Image.ConfigDigest, rightOutput.Image.ConfigDigest)
	add(
		"image.platform",
		leftOutput.Image.Platform.OS+"/"+leftOutput.Image.Platform.Architecture+"/"+leftOutput.Image.Platform.Variant,
		rightOutput.Image.Platform.OS+"/"+rightOutput.Image.Platform.Architecture+"/"+rightOutput.Image.Platform.Variant,
	)
	add("display.title", leftOutput.Display.Title, rightOutput.Display.Title)
	add("display.summary", leftOutput.Display.Summary, rightOutput.Display.Summary)
	add("display.outcome", leftOutput.Display.Outcome, rightOutput.Display.Outcome)
	add("canary.kind", leftOutput.Canary.Kind, rightOutput.Canary.Kind)
	add("canary.service_id", leftOutput.Canary.ServiceID, rightOutput.Canary.ServiceID)
	add("canary.operation_id", leftOutput.Canary.OperationID, rightOutput.Canary.OperationID)
	add("canary.request.input", leftOutput.Canary.Request.Input, rightOutput.Canary.Request.Input)
	add(
		"canary.request.session_id_prefix",
		leftOutput.Canary.Request.SessionIDPrefix,
		rightOutput.Canary.Request.SessionIDPrefix,
	)
	add("canary.required_state_disposition", leftOutput.Canary.RequiredStateDisposition, rightOutput.Canary.RequiredStateDisposition)
	add("canary.expected_workspace_manifest_digest", leftOutput.Canary.ExpectedWorkspaceManifestDigest, rightOutput.Canary.ExpectedWorkspaceManifestDigest)
	add("canary.fixture_id", leftOutput.Canary.FixtureID, rightOutput.Canary.FixtureID)
	add("qualification.runtime", leftOutput.Qualification.Runtime, rightOutput.Qualification.Runtime)
	add("qualification.completed_at", leftOutput.Qualification.CompletedAt, rightOutput.Qualification.CompletedAt)
	add(
		"qualification.limitations",
		strings.Join(leftOutput.Qualification.Limitations, "\n"),
		strings.Join(rightOutput.Qualification.Limitations, "\n"),
	)
	return agentCatalogComparison{
		Equivalent: len(differences) == 0,
		Left:       leftOutput, Right: rightOutput, Differences: differences,
	}
}

func agentCatalogCommandText(command []string) string {
	// A slice of strings has no unsupported JSON values, so Marshal cannot
	// fail. JSON preserves argument boundaries and escapes embedded controls.
	raw, _ := json.Marshal(command)
	return string(raw)
}

func agentCatalogArtifactsText(artifacts []admission.ArtifactDigest) string {
	sorted := append([]admission.ArtifactDigest(nil), artifacts...)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].Kind != sorted[right].Kind {
			return sorted[left].Kind < sorted[right].Kind
		}
		return sorted[left].Digest < sorted[right].Digest
	})
	values := make([]string, 0, len(sorted))
	for _, artifact := range sorted {
		values = append(values, artifact.Kind+"="+artifact.Digest)
	}
	return strings.Join(values, "\n")
}

func openAgentCatalogInputRoot(manifestPath string) (*os.Root, string, error) {
	absoluteManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return nil, "", err
	}
	canonicalDirectory, err := filepath.EvalSymlinks(filepath.Dir(absoluteManifest))
	if err != nil {
		return nil, "", err
	}
	before, err := os.Lstat(canonicalDirectory)
	if err != nil {
		return nil, "", err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("manifest parent is not a stable directory")
	}
	root, err := os.OpenRoot(canonicalDirectory)
	if err != nil {
		return nil, "", err
	}
	anchored, anchoredErr := root.Stat(".")
	current, currentErr := os.Lstat(canonicalDirectory)
	if anchoredErr != nil || currentErr != nil ||
		!os.SameFile(before, anchored) || !os.SameFile(before, current) {
		_ = root.Close()
		return nil, "", errors.Join(
			errors.New("manifest parent changed while opening its confined root"),
			anchoredErr,
			currentErr,
		)
	}
	manifestName := filepath.Base(filepath.Clean(absoluteManifest))
	if manifestName == "." || manifestName == string(filepath.Separator) ||
		strings.ContainsRune(manifestName, '\x00') {
		_ = root.Close()
		return nil, "", errors.New("agent catalog manifest name is invalid")
	}
	return root, manifestName, nil
}

func readAgentCatalogPublicKey(root *os.Root, name string) (ed25519.PublicKey, error) {
	raw, err := securefile.ReadRoot(root, name, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not base64 Ed25519")
	}
	return ed25519.PublicKey(decoded), nil
}

func validateAgentCatalogRelativePath(value string) error {
	if value == "" || len(value) > maxAgentCatalogPathBytes ||
		strings.ContainsRune(value, '\x00') || !utf8.ValidString(value) {
		return errors.New("path is empty or exceeds its bound")
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return errors.New("path must be relative to the manifest directory")
	}
	for _, component := range strings.FieldsFunc(value, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if component == ".." {
			return errors.New("path must not contain a '..' component")
		}
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == "" || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return errors.New("path must name a file beneath the manifest directory")
	}
	return nil
}

func agentCatalogStatus(value string) bool {
	return value == agentcatalog.StatusCandidate ||
		value == agentcatalog.StatusApproved ||
		value == agentcatalog.StatusRetired
}

func agentCatalogQuery(value string) bool {
	if value == "" || len(value) > maxAgentCatalogQueryBytes || !utf8.ValidString(value) ||
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

func agentCatalogIdentifier(value string) bool {
	return agentCatalogBoundedIdentifier(value, 128)
}

func agentCatalogBoundedIdentifier(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	if !agentCatalogAlphaNumeric(value[0]) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(agentCatalogAlphaNumeric(character) ||
			character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func agentCatalogAlphaNumeric(character byte) bool {
	return (character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9')
}

func writeAgentCatalogResult(stdout io.Writer, output agentCatalogResult) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(output)
}
