package agentcatalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

type catalogFixture struct {
	now            time.Time
	curatorPrivate ed25519.PrivateKey
	curatorPublic  ed25519.PublicKey
	catalog        Catalog
}

func TestSignAndVerifyReverifyEmbeddedRelease(t *testing.T) {
	fixture := newCatalogFixture(t)
	raw, err := Sign(fixture.catalog, "curator-a", fixture.curatorPrivate, fixture.now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verified, err := Verify(
		raw,
		map[string]ed25519.PublicKey{"curator-a": fixture.curatorPublic},
	)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Catalog.CatalogID != "sovereign-agents" ||
		verified.Catalog.Revision != 7 ||
		verified.Catalog.Authority != AuthorityDescriptiveOnly ||
		verified.CuratorKeyID != "curator-a" ||
		verified.EnvelopeDigest != dsse.Digest(raw) ||
		len(verified.Entries) != 1 ||
		verified.Entries[0].Release.Release.ReleaseID != "hermes-a" {
		t.Fatalf("verified = %#v", verified)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := fixture.catalog
	tampered.Entries = append([]Entry(nil), fixture.catalog.Entries...)
	tampered.Entries[0].Publisher.Ed25519PublicKeyBase64 =
		base64.StdEncoding.EncodeToString(otherPublic)
	tampered.Entries[0].Publisher.PublicKeyDigest = dsse.Digest(otherPublic)
	tamperedRaw := signCatalogWithoutValidation(t, tampered, fixture.curatorPrivate)
	if _, err := Verify(
		tamperedRaw,
		map[string]ed25519.PublicKey{"curator-a": fixture.curatorPublic},
	); err == nil || !strings.Contains(err.Error(), "embedded release") {
		t.Fatalf("publisher substitution err = %v", err)
	}
}

func TestCatalogRejectsBindingStatusOrderingAndDuplicateRelease(t *testing.T) {
	fixture := newCatalogFixture(t)

	t.Run("archive binding", func(t *testing.T) {
		catalog := fixture.catalog
		catalog.Entries = append([]Entry(nil), fixture.catalog.Entries...)
		catalog.Entries[0].Bindings.Archive.SHA256Digest = "sha256:" + strings.Repeat("f", 64)
		raw := signCatalogWithoutValidation(t, catalog, fixture.curatorPrivate)
		if _, err := Verify(
			raw,
			map[string]ed25519.PublicKey{"curator-a": fixture.curatorPublic},
		); err == nil || !strings.Contains(err.Error(), "archive binding") {
			t.Fatalf("archive binding err = %v", err)
		}
	})

	t.Run("status", func(t *testing.T) {
		catalog := fixture.catalog
		catalog.Entries = append([]Entry(nil), fixture.catalog.Entries...)
		catalog.Entries[0].Status = "deploy"
		if _, err := Sign(catalog, "curator-a", fixture.curatorPrivate, fixture.now); err == nil ||
			!strings.Contains(err.Error(), "status") {
			t.Fatalf("status err = %v", err)
		}
	})

	t.Run("authority", func(t *testing.T) {
		catalog := fixture.catalog
		catalog.Authority = "deployment"
		if _, err := Sign(catalog, "curator-a", fixture.curatorPrivate, fixture.now); err == nil ||
			!strings.Contains(err.Error(), "identity") {
			t.Fatalf("authority err = %v", err)
		}
	})

	t.Run("issue time", func(t *testing.T) {
		catalog := fixture.catalog
		catalog.IssuedAt = fixture.now.Add(-time.Second).Format("2006-01-02T15:04:05Z")
		if _, err := Sign(catalog, "curator-a", fixture.curatorPrivate, fixture.now); err == nil ||
			!strings.Contains(err.Error(), "signing time") {
			t.Fatalf("issue time err = %v", err)
		}
	})

	t.Run("ordering", func(t *testing.T) {
		catalog := fixture.catalog
		second := fixture.catalog.Entries[0]
		second.EntryID = "agent-a"
		catalog.Entries = []Entry{fixture.catalog.Entries[0], second}
		if _, err := Sign(catalog, "curator-a", fixture.curatorPrivate, fixture.now); err == nil ||
			!strings.Contains(err.Error(), "strictly sorted") {
			t.Fatalf("ordering err = %v", err)
		}
	})

	t.Run("duplicate release", func(t *testing.T) {
		catalog := fixture.catalog
		second := fixture.catalog.Entries[0]
		second.EntryID = "hermes-b"
		catalog.Entries = []Entry{fixture.catalog.Entries[0], second}
		if _, err := Sign(catalog, "curator-a", fixture.curatorPrivate, fixture.now); err == nil ||
			!strings.Contains(err.Error(), "duplicate publisher/release") {
			t.Fatalf("duplicate release err = %v", err)
		}
	})
}

func TestCatalogRejectsWrongCuratorAndNonCanonicalEnvelope(t *testing.T) {
	fixture := newCatalogFixture(t)
	raw, err := Sign(fixture.catalog, "curator-a", fixture.curatorPrivate, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(
		raw,
		map[string]ed25519.PublicKey{"curator-a": otherPublic},
	); err == nil {
		t.Fatal("catalog verified with the wrong curator key")
	}
	nonCanonical := append([]byte(" "), raw...)
	if _, err := Verify(
		nonCanonical,
		map[string]ed25519.PublicKey{"curator-a": fixture.curatorPublic},
	); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical envelope err = %v", err)
	}
}

func newCatalogFixture(t *testing.T) catalogFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	curatorPublic, curatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skillManifest := []byte(`{"name":"workspace-audit","version":"1"}`)
	qualificationEvidence := []byte(`{"overall":"passed","runtime":"runsc"}`)
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	archiveDigest := "sha256:" + strings.Repeat("c", 64)
	capsule := admission.ProfileCapsule{
		SchemaVersion:  admission.SchemaV1,
		CapsuleID:      "hermes-a",
		PublisherKeyID: "publisher-a",
		Profile:        admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository:     "registry.example/hermes",
			ManifestDigest: manifestDigest,
			ConfigDigest:   configDigest,
			Platform:       admission.Platform{OS: "linux", Architecture: "amd64", Variant: "v1"},
		},
		Command:      []string{"serve"},
		Resources:    admission.ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128},
		Capabilities: admission.Capabilities{State: true, Service: true},
		IssuedAt:     now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:    now.Add(time.Hour).Format(time.RFC3339),
		Artifacts: []admission.ArtifactDigest{{
			Kind: agentrelease.SkillManifestArtifactKind, Digest: dsse.Digest(skillManifest),
		}},
		State:   admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service: admission.ServiceShape{ID: agentrelease.HermesServiceID, Port: 8766},
	}
	capsulePayload, err := json.Marshal(capsule)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Sign(
		admission.CapsulePayloadType, capsulePayload, "publisher-a", publisherPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, err := dsse.Marshal(capsuleEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	release := agentrelease.Release{
		SchemaVersion:     agentrelease.SchemaV1,
		ReleaseID:         "hermes-a",
		PublisherKeyID:    "publisher-a",
		Display:           agentrelease.Display{Title: "Hermes audit", Summary: "Audit one workspace.", Outcome: "Produce one bounded manifest."},
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsuleRaw),
		Archive: agentrelease.Archive{
			SHA256Digest: archiveDigest,
			SizeBytes:    4096,
			Image:        capsule.Image,
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
			CompletedAt:    now.Add(-30 * time.Minute).Format("2006-01-02T15:04:05Z"),
			Runtime:        "runsc",
			Limitations:    []string{"Qualified on linux amd64."},
		},
	}
	releaseRaw, err := agentrelease.Sign(release, "publisher-a", publisherPrivate, now)
	if err != nil {
		t.Fatalf("sign release fixture: %v", err)
	}
	entry := Entry{
		EntryID: "hermes-a",
		Status:  StatusApproved,
		Publisher: PublisherIdentity{
			KeyID:                  "publisher-a",
			Ed25519PublicKeyBase64: base64.StdEncoding.EncodeToString(publisherPublic),
			PublicKeyDigest:        dsse.Digest(publisherPublic),
		},
		ReleaseDSSEBase64:     base64.StdEncoding.EncodeToString(releaseRaw),
		ReleaseEnvelopeDigest: dsse.Digest(releaseRaw),
		Bindings: ArtifactBindings{
			Archive: FileBinding{SHA256Digest: archiveDigest, SizeBytes: 4096},
			SkillManifest: FileBinding{
				SHA256Digest: dsse.Digest(skillManifest), SizeBytes: int64(len(skillManifest)),
			},
			QualificationEvidence: FileBinding{
				SHA256Digest: dsse.Digest(qualificationEvidence), SizeBytes: int64(len(qualificationEvidence)),
			},
		},
	}
	return catalogFixture{
		now: now, curatorPrivate: curatorPrivate, curatorPublic: curatorPublic,
		catalog: Catalog{
			SchemaVersion: SchemaV1,
			CatalogID:     "sovereign-agents",
			Revision:      7,
			IssuedAt:      now.Format("2006-01-02T15:04:05Z"),
			CuratorKeyID:  "curator-a",
			Authority:     AuthorityDescriptiveOnly,
			Entries:       []Entry{entry},
		},
	}
}

func signCatalogWithoutValidation(t *testing.T, catalog Catalog, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(PayloadType, payload, "curator-a", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
