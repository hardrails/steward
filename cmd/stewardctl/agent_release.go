package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	agentReleaseVerificationSchemaV1          = "steward.agent-release-verification.v1"
	maxAgentReleaseSkillManifestBytes         = int64(1 << 20)
	maxAgentReleaseQualificationEvidenceBytes = int64(4 << 20)
)

type agentReleaseLimitations []string

func (values *agentReleaseLimitations) String() string { return strings.Join(*values, ",") }
func (values *agentReleaseLimitations) Set(value string) error {
	if len(*values) >= 8 {
		return errors.New("at most eight release limitations are allowed")
	}
	if strings.TrimSpace(value) == "" || len(value) > 512 {
		return errors.New("release limitation must be 1 to 512 non-whitespace bytes")
	}
	*values = append(*values, value)
	return nil
}

type agentReleaseArchiveOutput struct {
	SHA256Digest string `json:"sha256_digest"`
	SizeBytes    int64  `json:"size_bytes"`
	Status       string `json:"status"`
}

type agentReleaseOutput struct {
	SchemaVersion         string                     `json:"schema_version"`
	Operation             string                     `json:"operation"`
	Valid                 bool                       `json:"valid"`
	ReleaseID             string                     `json:"release_id"`
	PublisherKeyID        string                     `json:"publisher_key_id"`
	EnvelopeDigest        string                     `json:"envelope_digest"`
	PayloadDigest         string                     `json:"payload_digest"`
	CapsuleEnvelopeDigest string                     `json:"capsule_envelope_digest"`
	CapsulePayloadDigest  string                     `json:"capsule_payload_digest"`
	Display               agentrelease.Display       `json:"display"`
	Archive               agentReleaseArchiveOutput  `json:"archive"`
	Image                 admission.ImageIdentity    `json:"image"`
	Canary                agentrelease.Canary        `json:"canary"`
	Qualification         agentrelease.Qualification `json:"qualification"`
}

func agentReleaseCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("agent-release command requires issue or verify")
	}
	switch arguments[0] {
	case "issue":
		return issueAgentRelease(arguments[1:], stdout)
	case "verify":
		return verifyAgentRelease(arguments[1:], stdout)
	default:
		return errors.New("agent-release command requires issue or verify")
	}
}

func issueAgentRelease(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent-release issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	capsulePath := flags.String("capsule", "", "publisher-signed capsule DSSE envelope")
	archivePath := flags.String("archive", "", "bounded offline Docker/OCI archive")
	skillManifestPath := flags.String("skill-manifest", "", "exact qualified skill manifest")
	qualificationEvidencePath := flags.String("qualification-evidence", "", "exact qualification evidence")
	releaseID := flags.String("release-id", "", "stable publisher release identity")
	title := flags.String("title", "", "short outcome-led release title")
	summary := flags.String("summary", "", "concrete release summary")
	outcome := flags.String("outcome", "", "observable release outcome")
	completedAt := flags.String("completed-at", "", "qualification completion time in canonical UTC RFC3339")
	privateKeyPath := flags.String("key", "", "owner-only publisher Ed25519 private key")
	keyID := flags.String("key-id", "", "publisher key ID shared with the capsule")
	outputPath := flags.String("out", "", "new owner-only signed agent release")
	var limitations agentReleaseLimitations
	flags.Var(&limitations, "limitation", "known qualification limitation; repeat 1 to 8 times")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *capsulePath == "" || *archivePath == "" || *skillManifestPath == "" ||
		*qualificationEvidencePath == "" || *releaseID == "" || *title == "" ||
		*summary == "" || *outcome == "" || *completedAt == "" ||
		*privateKeyPath == "" || *keyID == "" || *outputPath == "" ||
		len(limitations) == 0 || flags.NArg() != 0 {
		return errors.New("agent-release issue requires capsule, archive, skill manifest, qualification evidence, release metadata, limitation, publisher key, key ID, and output")
	}
	completed, err := time.Parse("2006-01-02T15:04:05Z", *completedAt)
	if err != nil || completed.Format("2006-01-02T15:04:05Z") != *completedAt {
		return errors.New("agent-release completion time must be canonical UTC RFC3339")
	}

	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return fmt.Errorf("read publisher private key: %w", err)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("publisher private key does not contain an Ed25519 public key")
	}
	capsuleEnvelope, err := securefile.Read(
		*capsulePath, agentrelease.MaxEnvelopeBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read capsule envelope: %w", err)
	}
	now := timeNow().UTC()
	capsule, err := openReleaseCapsule(capsuleEnvelope, *keyID, publicKey, now)
	if err != nil {
		return err
	}
	skillManifest, err := securefile.Read(
		*skillManifestPath, maxAgentReleaseSkillManifestBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read skill manifest: %w", err)
	}
	qualificationEvidence, err := securefile.Read(
		*qualificationEvidencePath, maxAgentReleaseQualificationEvidenceBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read qualification evidence: %w", err)
	}
	inspection, err := ocibundle.InspectSource(*archivePath, ocibundle.DefaultLimits())
	if err != nil {
		return fmt.Errorf("inspect release archive: %w", err)
	}
	image := admission.ImageIdentity{
		Repository:     capsule.Image.Repository,
		ManifestDigest: inspection.Image.ManifestDigest,
		ConfigDigest:   inspection.Image.ConfigDigest,
		Platform: admission.Platform{
			OS:           inspection.Image.Platform.OS,
			Architecture: inspection.Image.Platform.Architecture,
			Variant:      inspection.Image.Platform.Variant,
		},
	}
	release := agentrelease.Release{
		SchemaVersion: agentrelease.SchemaV1,
		ReleaseID:     *releaseID, PublisherKeyID: *keyID,
		Display:           agentrelease.Display{Title: *title, Summary: *summary, Outcome: *outcome},
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsuleEnvelope),
		Archive: agentrelease.Archive{
			SHA256Digest: inspection.Archive.Digest,
			SizeBytes:    inspection.Archive.Bytes,
			Image:        image,
		},
		Canary: agentrelease.Canary{
			Kind:      agentrelease.CanaryKindHermesWorkspaceAuditV1,
			ServiceID: agentrelease.HermesServiceID, OperationID: agentrelease.HermesOperationID,
			Request: agentrelease.RequestRecipe{
				Input:           agentrelease.HermesWorkspaceAuditInput,
				SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
			},
			RequiredStateDisposition:        "new",
			SkillManifestDigest:             dsse.Digest(skillManifest),
			ExpectedWorkspaceManifestDigest: agentrelease.HermesWorkspaceAuditEmptyManifestDigest,
			FixtureID:                       agentrelease.HermesWorkspaceAuditEmptyFixtureID,
		},
		Qualification: agentrelease.Qualification{
			EvidenceDigest: dsse.Digest(qualificationEvidence),
			CompletedAt:    *completedAt,
			Runtime:        "runsc",
			Limitations:    append([]string(nil), limitations...),
		},
	}
	rawEnvelope, err := agentrelease.Sign(release, *keyID, privateKey, now)
	if err != nil {
		return fmt.Errorf("sign agent release: %w", err)
	}
	verified, err := agentrelease.Verify(
		rawEnvelope, map[string]ed25519.PublicKey{*keyID: publicKey}, now,
	)
	if err != nil {
		return fmt.Errorf("self-verify agent release: %w", err)
	}
	if err := writeNewFile(*outputPath, rawEnvelope, 0o600); err != nil {
		return fmt.Errorf("write agent release: %w", err)
	}
	return writeAgentReleaseOutput(stdout, "issued", "verified", verified)
}

func verifyAgentRelease(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent-release verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("in", "", "signed agent release DSSE envelope")
	publicKeyPath := flags.String("public-key", "", "external publisher Ed25519 public key")
	keyID := flags.String("key-id", "", "external publisher key ID")
	archivePath := flags.String("archive", "", "optional offline archive to verify and prepare")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *inputPath == "" || *publicKeyPath == "" || *keyID == "" || flags.NArg() != 0 {
		return errors.New("agent-release verify requires -in, -public-key, -key-id, and no positional arguments")
	}
	rawEnvelope, err := securefile.Read(
		*inputPath, agentrelease.MaxEnvelopeBytes, securefile.TrustFile,
	)
	if err != nil {
		return fmt.Errorf("read agent release: %w", err)
	}
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return fmt.Errorf("read publisher public key: %w", err)
	}
	verified, err := agentrelease.Verify(
		rawEnvelope, map[string]ed25519.PublicKey{*keyID: publicKey}, timeNow().UTC(),
	)
	if err != nil {
		return err
	}
	archiveStatus := "not_requested"
	if *archivePath != "" {
		expected := ocibundle.Identity{
			ManifestDigest: verified.Release.Archive.Image.ManifestDigest,
			ConfigDigest:   verified.Release.Archive.Image.ConfigDigest,
			Platform: ocibundle.Platform{
				OS:           verified.Release.Archive.Image.Platform.OS,
				Architecture: verified.Release.Archive.Image.Platform.Architecture,
				Variant:      verified.Release.Archive.Image.Platform.Variant,
			},
		}
		prepared, err := ocibundle.PrepareBound(
			*archivePath,
			expected,
			ocibundle.ArchiveIdentity{
				Digest: verified.Release.Archive.SHA256Digest,
				Bytes:  verified.Release.Archive.SizeBytes,
			},
			ocibundle.DefaultLimits(),
		)
		if err != nil {
			return fmt.Errorf("verify release archive: %w", err)
		}
		if err := prepared.Close(); err != nil {
			return fmt.Errorf("close verified release archive: %w", err)
		}
		archiveStatus = "verified"
	}
	return writeAgentReleaseOutput(stdout, "verified", archiveStatus, verified)
}

func openReleaseCapsule(raw []byte, keyID string, publicKey ed25519.PublicKey, now time.Time) (admission.ProfileCapsule, error) {
	payload, verifiedKeyID, err := dsse.Verify(
		raw, admission.CapsulePayloadType,
		map[string]ed25519.PublicKey{keyID: publicKey},
	)
	if err != nil {
		return admission.ProfileCapsule{}, fmt.Errorf("verify capsule publisher: %w", err)
	}
	var capsule admission.ProfileCapsule
	if err := dsse.DecodeStrictInto(payload, agentrelease.MaxPayloadBytes, &capsule); err != nil {
		return admission.ProfileCapsule{}, fmt.Errorf("decode capsule: %w", err)
	}
	if err := capsule.Validate(now); err != nil {
		return admission.ProfileCapsule{}, fmt.Errorf("validate capsule: %w", err)
	}
	if verifiedKeyID != keyID || capsule.PublisherKeyID != keyID {
		return admission.ProfileCapsule{}, errors.New("capsule publisher key ID does not match release publisher")
	}
	return capsule, nil
}

func writeAgentReleaseOutput(stdout io.Writer, operation, archiveStatus string, verified agentrelease.Verified) error {
	release := verified.Release
	output := agentReleaseOutput{
		SchemaVersion: agentReleaseVerificationSchemaV1,
		Operation:     operation, Valid: true,
		ReleaseID: release.ReleaseID, PublisherKeyID: verified.PublisherKeyID,
		EnvelopeDigest: verified.EnvelopeDigest, PayloadDigest: verified.PayloadDigest,
		CapsuleEnvelopeDigest: verified.CapsuleEnvelopeDigest,
		CapsulePayloadDigest:  verified.CapsulePayloadDigest,
		Display:               release.Display,
		Archive: agentReleaseArchiveOutput{
			SHA256Digest: release.Archive.SHA256Digest,
			SizeBytes:    release.Archive.SizeBytes,
			Status:       archiveStatus,
		},
		Image: release.Archive.Image, Canary: release.Canary,
		Qualification: release.Qualification,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(output)
}
