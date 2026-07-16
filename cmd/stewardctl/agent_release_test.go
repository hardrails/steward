package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

type agentReleaseCLIFixture struct {
	now                       time.Time
	directory                 string
	archivePath               string
	capsulePath               string
	skillManifestPath         string
	qualificationEvidencePath string
	privateKeyPath            string
	publicKeyPath             string
	outputPath                string
	manifestDigest            string
	configDigest              string
	skillManifest             []byte
	qualificationEvidence     []byte
}

func TestAgentReleaseIssueAndVerify(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	var issued bytes.Buffer
	if err := run(fixture.issueArguments(), &issued, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue agent release: %v", err)
	}
	info, err := os.Stat(fixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("release mode = %o, want 0600", info.Mode().Perm())
	}
	issuedOutput := decodeAgentReleaseOutput(t, issued.Bytes())
	if !issuedOutput.Valid || issuedOutput.Operation != "issued" ||
		issuedOutput.Archive.Status != "verified" ||
		issuedOutput.ReleaseID != "hermes-workspace-audit" ||
		issuedOutput.PublisherKeyID != "publisher-a" {
		t.Fatalf("issued output = %#v", issuedOutput)
	}

	raw, err := os.ReadFile(fixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := readPublicKey(fixture.publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := agentrelease.Verify(
		raw, map[string]ed25519.PublicKey{"publisher-a": publicKey}, fixture.now,
	)
	if err != nil {
		t.Fatalf("verify issued envelope: %v", err)
	}
	archiveRaw, err := os.ReadFile(fixture.archivePath)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, err := os.ReadFile(fixture.capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Release.Archive.SHA256Digest != dsse.Digest(archiveRaw) ||
		verified.Release.Archive.SizeBytes != int64(len(archiveRaw)) ||
		verified.Release.Archive.Image.ManifestDigest != fixture.manifestDigest ||
		verified.Release.Archive.Image.ConfigDigest != fixture.configDigest ||
		verified.CapsuleEnvelopeDigest != dsse.Digest(capsuleRaw) ||
		verified.Release.Canary.SkillManifestDigest != dsse.Digest(fixture.skillManifest) ||
		verified.Release.Qualification.EvidenceDigest != dsse.Digest(fixture.qualificationEvidence) ||
		issuedOutput.CapsuleEnvelopeDigest != dsse.Digest(capsuleRaw) {
		t.Fatalf("issued release does not bind exact inputs: %#v", verified.Release)
	}

	var withoutArchive bytes.Buffer
	if err := run([]string{
		"agent-release", "verify",
		"-in", fixture.outputPath,
		"-public-key", fixture.publicKeyPath,
		"-key-id", "publisher-a",
	}, &withoutArchive, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify release without archive: %v", err)
	}
	withoutArchiveOutput := decodeAgentReleaseOutput(t, withoutArchive.Bytes())
	if !withoutArchiveOutput.Valid || withoutArchiveOutput.Operation != "verified" ||
		withoutArchiveOutput.Archive.Status != "not_requested" ||
		withoutArchiveOutput.EnvelopeDigest != issuedOutput.EnvelopeDigest {
		t.Fatalf("verification output = %#v", withoutArchiveOutput)
	}

	var withArchive bytes.Buffer
	if err := run([]string{
		"agent-release", "verify",
		"-in", fixture.outputPath,
		"-public-key", fixture.publicKeyPath,
		"-key-id", "publisher-a",
		"-archive", fixture.archivePath,
	}, &withArchive, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify release archive: %v", err)
	}
	withArchiveOutput := decodeAgentReleaseOutput(t, withArchive.Bytes())
	if withArchiveOutput.Archive.Status != "verified" ||
		withArchiveOutput.Archive.SHA256Digest != verified.Release.Archive.SHA256Digest ||
		withArchiveOutput.Image != verified.Release.Archive.Image ||
		withArchiveOutput.Canary.RequiredStateDisposition != "new" ||
		withArchiveOutput.Canary.FixtureID != agentrelease.HermesWorkspaceAuditEmptyFixtureID {
		t.Fatalf("archive verification output = %#v", withArchiveOutput)
	}
}

func TestAgentReleaseVerifyRejectsWrongPublisherAndChangedArchive(t *testing.T) {
	fixture := newAgentReleaseCLIFixture(t)
	if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	otherPrivate := filepath.Join(fixture.directory, "other.private.pem")
	otherPublic := filepath.Join(fixture.directory, "other.public")
	if err := run([]string{
		"keygen", "-private-out", otherPrivate, "-public-out", otherPublic, "-key-id", "publisher-a",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"agent-release", "verify",
		"-in", fixture.outputPath, "-public-key", otherPublic, "-key-id", "publisher-a",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("release verified with a different publisher key")
	}

	file, err := os.OpenFile(fixture.archivePath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("changed archive bytes")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"agent-release", "verify",
		"-in", fixture.outputPath,
		"-public-key", fixture.publicKeyPath,
		"-key-id", "publisher-a",
		"-archive", fixture.archivePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "signed archive digest and size") {
		t.Fatalf("changed archive err = %v", err)
	}
}

func TestAgentReleaseIssueRejectsInputDriftAndUnsafeMetadata(t *testing.T) {
	t.Run("skill manifest differs from capsule", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		if err := os.WriteFile(fixture.skillManifestPath, []byte("changed skill manifest"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "skill manifest artifact") {
			t.Fatalf("mismatched skill manifest err = %v", err)
		}
		if _, err := os.Stat(fixture.outputPath); !os.IsNotExist(err) {
			t.Fatalf("invalid release output exists: %v", err)
		}
	})

	t.Run("archive differs from capsule", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		privateKey, err := readPrivateKey(fixture.privateKeyPath)
		if err != nil {
			t.Fatal(err)
		}
		capsule := fixture.capsule(t)
		capsule.Image.ManifestDigest = "sha256:" + strings.Repeat("f", 64)
		writeSignedJSON(
			t, fixture.capsulePath, admission.CapsulePayloadType,
			capsule, "publisher-a", privateKey,
		)
		if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "archive image tuple") {
			t.Fatalf("mismatched archive err = %v", err)
		}
	})

	t.Run("unsafe display URL", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		arguments := fixture.issueArguments()
		arguments[argumentValueIndex(t, arguments, "-summary")] = "See https://publisher.invalid"
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "display metadata") {
			t.Fatalf("URL metadata err = %v", err)
		}
	})

	t.Run("noncanonical completion time", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		arguments := fixture.issueArguments()
		arguments[argumentValueIndex(t, arguments, "-completed-at")] = "2026-07-16T11:30:00-07:00"
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "completion time") {
			t.Fatalf("completion time err = %v", err)
		}
	})

	t.Run("too many limitations", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		arguments := fixture.issueArguments()
		for index := 0; index < 8; index++ {
			arguments = append(arguments, "-limitation", "Additional bounded limitation.")
		}
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), "at most eight") {
			t.Fatalf("limitation cap err = %v", err)
		}
	})

	t.Run("existing output", func(t *testing.T) {
		fixture := newAgentReleaseCLIFixture(t)
		if err := os.WriteFile(fixture.outputPath, []byte("do not replace"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("existing release output was accepted")
		}
		raw, err := os.ReadFile(fixture.outputPath)
		if err != nil || string(raw) != "do not replace" {
			t.Fatalf("existing output changed: %q, %v", raw, err)
		}
	})
}

func TestAgentReleaseIssueBoundsHashedInputs(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		size  int
	}{
		{"skill manifest", "skill", int(maxAgentReleaseSkillManifestBytes) + 1},
		{"qualification evidence", "evidence", int(maxAgentReleaseQualificationEvidenceBytes) + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentReleaseCLIFixture(t)
			path := fixture.skillManifestPath
			if test.field == "evidence" {
				path = fixture.qualificationEvidencePath
			}
			if err := os.WriteFile(path, bytes.Repeat([]byte("x"), test.size), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
				!strings.Contains(err.Error(), "bounded") {
				t.Fatalf("oversized %s err = %v", test.name, err)
			}
		})
	}
}

func TestAgentReleaseCommandsRejectIncompleteArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{"agent-release"},
		{"agent-release", "unknown"},
		{"agent-release", "issue"},
		{"agent-release", "verify"},
		{"agent-release", "verify", "-in", "missing", "-public-key", "missing", "-key-id", "publisher", "extra"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("incomplete command accepted: %#v", arguments)
		}
	}
}

func newAgentReleaseCLIFixture(t *testing.T) agentReleaseCLIFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	previousNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousNow })

	directory := t.TempDir()
	archivePath, manifestDigest, configDigest, _ := writeImageImportArchive(t, directory)
	privateKeyPath := filepath.Join(directory, "publisher.private.pem")
	publicKeyPath := filepath.Join(directory, "publisher.public")
	if err := run([]string{
		"keygen",
		"-private-out", privateKeyPath,
		"-public-out", publicKeyPath,
		"-key-id", "publisher-a",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	skillManifest := []byte(`{"name":"steward.workspace-audit","schema_version":"steward.fixture-skill-manifest.v1","version":"1"}`)
	qualificationEvidence := []byte(`{"overall":"passed","runtime":"runsc","schema_version":"steward.agent-feasibility.v1"}`)
	skillManifestPath := filepath.Join(directory, "skill-manifest.json")
	qualificationEvidencePath := filepath.Join(directory, "qualification-evidence.json")
	if err := os.WriteFile(skillManifestPath, skillManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qualificationEvidencePath, qualificationEvidence, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := agentReleaseCLIFixture{
		now: now, directory: directory,
		archivePath: archivePath, capsulePath: filepath.Join(directory, "capsule.dsse.json"),
		skillManifestPath: skillManifestPath, qualificationEvidencePath: qualificationEvidencePath,
		privateKeyPath: privateKeyPath, publicKeyPath: publicKeyPath,
		outputPath:     filepath.Join(directory, "agent-release.dsse.json"),
		manifestDigest: manifestDigest, configDigest: configDigest,
		skillManifest: skillManifest, qualificationEvidence: qualificationEvidence,
	}
	privateKey, err := readPrivateKey(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	writeSignedJSON(
		t, fixture.capsulePath, admission.CapsulePayloadType,
		fixture.capsule(t), "publisher-a", privateKey,
	)
	return fixture
}

func (fixture agentReleaseCLIFixture) capsule(t *testing.T) admission.ProfileCapsule {
	t.Helper()
	return admission.ProfileCapsule{
		SchemaVersion:  admission.SchemaV1,
		CapsuleID:      "hermes-workspace-audit",
		PublisherKeyID: "publisher-a",
		Profile:        admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository:     "registry.example/agent",
			ManifestDigest: fixture.manifestDigest,
			ConfigDigest:   fixture.configDigest,
			Platform: admission.Platform{
				OS: "linux", Architecture: "amd64", Variant: "v1",
			},
		},
		Command: []string{"serve"},
		Resources: admission.ResourceLimits{
			MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128,
		},
		Capabilities: admission.Capabilities{State: true, Service: true},
		IssuedAt:     fixture.now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:    fixture.now.Add(10 * time.Minute).Format(time.RFC3339),
		Artifacts: []admission.ArtifactDigest{{
			Kind: agentrelease.SkillManifestArtifactKind, Digest: dsse.Digest(fixture.skillManifest),
		}},
		State:   admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service: admission.ServiceShape{ID: agentrelease.HermesServiceID, Port: 8766},
	}
}

func (fixture agentReleaseCLIFixture) issueArguments() []string {
	return []string{
		"agent-release", "issue",
		"-capsule", fixture.capsulePath,
		"-archive", fixture.archivePath,
		"-skill-manifest", fixture.skillManifestPath,
		"-qualification-evidence", fixture.qualificationEvidencePath,
		"-release-id", "hermes-workspace-audit",
		"-title", "Hermes workspace audit",
		"-summary", "Inspect a bounded workspace with an immutable custom skill.",
		"-outcome", "Produce the deterministic empty-workspace manifest.",
		"-completed-at", "2026-07-16T18:30:00Z",
		"-limitation", "Qualified only on linux amd64.",
		"-key", fixture.privateKeyPath,
		"-key-id", "publisher-a",
		"-out", fixture.outputPath,
	}
}

func decodeAgentReleaseOutput(t *testing.T, raw []byte) agentReleaseOutput {
	t.Helper()
	var output agentReleaseOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatalf("decode agent release output: %v\n%s", err, raw)
	}
	if output.SchemaVersion != agentReleaseVerificationSchemaV1 {
		t.Fatalf("output schema = %q", output.SchemaVersion)
	}
	return output
}

func argumentValueIndex(t *testing.T, arguments []string, name string) int {
	t.Helper()
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return index + 1
		}
	}
	t.Fatalf("argument %q not found in %#v", name, arguments)
	return 0
}
