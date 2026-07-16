package agentrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

var testNow = time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)

type releaseFixture struct {
	public     ed25519.PublicKey
	private    ed25519.PrivateKey
	release    Release
	capsule    admission.ProfileCapsule
	capsuleRaw []byte
}

func TestSignAndVerify(t *testing.T) {
	fixture := newReleaseFixture(t)
	raw, err := Sign(fixture.release, "publisher-a", fixture.private, testNow)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		t.Fatalf("release envelope size = %d", len(raw))
	}

	verified, err := Verify(raw, map[string]ed25519.PublicKey{"publisher-a": fixture.public}, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reflect.DeepEqual(verified.Release, fixture.release) {
		t.Fatal("verified release differs from signed release")
	}
	if verified.Capsule.CapsuleID != fixture.capsule.CapsuleID ||
		verified.PublisherKeyID != "publisher-a" {
		t.Fatalf("verified binding = %#v / %q", verified.Capsule, verified.PublisherKeyID)
	}
	if !bytes.Equal(verified.CapsuleEnvelope, fixture.capsuleRaw) {
		t.Fatal("verified exact bytes differ from signed release")
	}

	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Parse(fixture.capsuleRaw)
	if err != nil {
		t.Fatal(err)
	}
	capsulePayload, err := base64.StdEncoding.DecodeString(capsuleEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if verified.EnvelopeDigest != digest(raw) ||
		verified.PayloadDigest != digest(payload) ||
		verified.CapsuleEnvelopeDigest != digest(fixture.capsuleRaw) ||
		verified.CapsulePayloadDigest != digest(capsulePayload) {
		t.Fatalf("verified digests are not exact: %#v", verified)
	}

	verified.CapsuleEnvelope[0] ^= 0xff
	again, err := Verify(raw, map[string]ed25519.PublicKey{"publisher-a": fixture.public}, testNow)
	if err != nil || !bytes.Equal(again.CapsuleEnvelope, fixture.capsuleRaw) {
		t.Fatal("returned byte slices alias verifier state")
	}
}

func TestVerifyRejectsReleaseIdentityDisplayAndArchiveMutations(t *testing.T) {
	fixture := newReleaseFixture(t)
	tests := []struct {
		name   string
		mutate func(*Release)
	}{
		{"schema", func(r *Release) { r.SchemaVersion = "steward.agent-release.v2" }},
		{"empty release ID", func(r *Release) { r.ReleaseID = "" }},
		{"invalid release ID", func(r *Release) { r.ReleaseID = "release/id" }},
		{"wrong publisher field", func(r *Release) { r.PublisherKeyID = "publisher-b" }},
		{"empty capsule base64", func(r *Release) { r.CapsuleDSSEBase64 = "" }},
		{"invalid capsule base64", func(r *Release) { r.CapsuleDSSEBase64 = "%%%" }},
		{"noncanonical capsule base64", func(r *Release) {
			r.CapsuleDSSEBase64 = r.CapsuleDSSEBase64[:4] + "\n" + r.CapsuleDSSEBase64[4:]
		}},
		{"empty title", func(r *Release) { r.Display.Title = "" }},
		{"surrounding display whitespace", func(r *Release) { r.Display.Summary = " padded" }},
		{"display control character", func(r *Release) { r.Display.Outcome = "works\nsilently" }},
		{"display URL", func(r *Release) { r.Display.Summary = "See https://publisher.invalid" }},
		{"bad archive digest", func(r *Release) { r.Archive.SHA256Digest = "sha256:not-a-digest" }},
		{"uppercase archive digest", func(r *Release) {
			r.Archive.SHA256Digest = "sha256:" + strings.Repeat("A", 64)
		}},
		{"zero archive size", func(r *Release) { r.Archive.SizeBytes = 0 }},
		{"excessive archive size", func(r *Release) { r.Archive.SizeBytes = MaxArchiveBytes + 1 }},
		{"invalid archive image", func(r *Release) { r.Archive.Image.Repository = "https://registry.invalid/image" }},
		{"repository mismatch", func(r *Release) { r.Archive.Image.Repository = "registry.example/other" }},
		{"manifest mismatch", func(r *Release) { r.Archive.Image.ManifestDigest = testDigest('1') }},
		{"config mismatch", func(r *Release) { r.Archive.Image.ConfigDigest = testDigest('2') }},
		{"platform OS mismatch", func(r *Release) { r.Archive.Image.Platform.OS = "freebsd" }},
		{"platform architecture mismatch", func(r *Release) { r.Archive.Image.Platform.Architecture = "arm64" }},
		{"platform variant mismatch", func(r *Release) { r.Archive.Image.Platform.Variant = "v8" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := fixture.release
			test.mutate(&release)
			raw := signReleasePayload(t, release, "publisher-a", fixture.private)
			assertInvalid(t, raw, fixture.public)
		})
	}
}

func TestVerifyRequiresTheSamePublisherForReleaseAndCapsule(t *testing.T) {
	fixture := newReleaseFixture(t)
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(
		signReleasePayload(t, fixture.release, "publisher-a", fixture.private),
		map[string]ed25519.PublicKey{"publisher-a": otherPublic}, testNow,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("untrusted outer publisher err = %v", err)
	}

	capsule := fixture.capsule
	capsule.PublisherKeyID = "publisher-b"
	release := fixture.release
	release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(
		signCapsule(t, capsule, "publisher-b", otherPrivate),
	)
	raw := signReleasePayload(t, release, "publisher-a", fixture.private)
	assertInvalid(t, raw, fixture.public)

	capsule.PublisherKeyID = "publisher-a"
	release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(
		signCapsule(t, capsule, "publisher-a", otherPrivate),
	)
	raw = signReleasePayload(t, release, "publisher-a", fixture.private)
	assertInvalid(t, raw, fixture.public)
}

func TestVerifyRejectsInvalidCapsulesAndArtifactBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*admission.ProfileCapsule)
	}{
		{"capsule publisher", func(c *admission.ProfileCapsule) { c.PublisherKeyID = "publisher-b" }},
		{"invalid capsule", func(c *admission.ProfileCapsule) { c.Resources.MemoryBytes = 0 }},
		{"expired capsule", func(c *admission.ProfileCapsule) {
			c.ExpiresAt = testNow.Add(-time.Second).Format(time.RFC3339)
		}},
		{"wrong profile", func(c *admission.ProfileCapsule) {
			c.Profile = admission.ProfileRef{ID: "openclaw-v1", Version: "v1"}
			c.State = admission.StateShape{SchemaVersion: "v1", Path: "/home/node/.openclaw"}
		}},
		{"wrong service", func(c *admission.ProfileCapsule) { c.Service.ID = "other-api" }},
		{"no state capability", func(c *admission.ProfileCapsule) { c.Capabilities.State = false }},
		{"no service capability", func(c *admission.ProfileCapsule) {
			c.Capabilities.Service = false
			c.Service = admission.ServiceShape{}
		}},
		{"wrong Hermes state", func(c *admission.ProfileCapsule) { c.State.Path = "/state" }},
		{"missing skill artifact", func(c *admission.ProfileCapsule) {
			c.Artifacts = []admission.ArtifactDigest{{Kind: "sbom", Digest: testDigest('b')}}
		}},
		{"mismatched skill artifact", func(c *admission.ProfileCapsule) {
			c.Artifacts[0].Digest = testDigest('c')
		}},
		{"duplicate skill artifact kind", func(c *admission.ProfileCapsule) {
			c.Artifacts = append(c.Artifacts, admission.ArtifactDigest{
				Kind: SkillManifestArtifactKind, Digest: c.Artifacts[0].Digest,
			})
		}},
		{"duplicate other artifact kind", func(c *admission.ProfileCapsule) {
			c.Artifacts = append(c.Artifacts, admission.ArtifactDigest{
				Kind: "sbom", Digest: testDigest('d'),
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReleaseFixture(t)
			capsule := fixture.capsule
			capsule.Command = append([]string(nil), capsule.Command...)
			capsule.Artifacts = append([]admission.ArtifactDigest(nil), capsule.Artifacts...)
			test.mutate(&capsule)
			release := fixture.release
			release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(
				signCapsule(t, capsule, "publisher-a", fixture.private),
			)
			assertInvalid(t, signReleasePayload(t, release, "publisher-a", fixture.private), fixture.public)
		})
	}
}

func TestVerifyRejectsCanaryMutations(t *testing.T) {
	fixture := newReleaseFixture(t)
	tests := []struct {
		name   string
		mutate func(*Release)
	}{
		{"kind", func(r *Release) { r.Canary.Kind = "shell_v1" }},
		{"service", func(r *Release) { r.Canary.ServiceID = "other-api" }},
		{"operation", func(r *Release) { r.Canary.OperationID = "hermes.exec" }},
		{"skill digest", func(r *Release) { r.Canary.SkillManifestDigest = "bad" }},
		{"workspace digest", func(r *Release) { r.Canary.ExpectedWorkspaceManifestDigest = testDigest('b') }},
		{"fixture ID", func(r *Release) { r.Canary.FixtureID = "steward.workspace-audit.small.v1" }},
		{"request input", func(r *Release) { r.Canary.Request.Input = "run a shell script" }},
		{"session prefix", func(r *Release) { r.Canary.Request.SessionIDPrefix = "publisher-session" }},
		{"state disposition", func(r *Release) { r.Canary.RequiredStateDisposition = "resume" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := fixture.release
			test.mutate(&release)
			assertInvalid(t, signReleasePayload(t, release, "publisher-a", fixture.private), fixture.public)
		})
	}
}

func TestBuildCanaryRequestUsesOneActivationScopedSession(t *testing.T) {
	recipe := RequestRecipe{
		Input: HermesWorkspaceAuditInput, SessionIDPrefix: HermesSessionIDPrefix,
	}
	request, err := BuildCanaryRequest(recipe, "activation-001")
	if err != nil {
		t.Fatalf("BuildCanaryRequest: %v", err)
	}
	want := []byte(`{"input":"STEWARD_WORKSPACE_AUDIT","session_id":"steward-activation-activation-001"}`)
	if !bytes.Equal(request, want) {
		t.Fatalf("request = %s, want %s", request, want)
	}
	again, err := BuildCanaryRequest(recipe, "activation-002")
	if err != nil || bytes.Equal(request, again) {
		t.Fatalf("second request = %s, err = %v", again, err)
	}
	maxActivationID := strings.Repeat("a", 128-len(HermesSessionIDPrefix)-1)
	if _, err := BuildCanaryRequest(recipe, maxActivationID); err != nil {
		t.Fatalf("maximum activation ID: %v", err)
	}
	for _, test := range []struct {
		name         string
		recipe       RequestRecipe
		activationID string
	}{
		{"wrong input", RequestRecipe{Input: "OTHER", SessionIDPrefix: HermesSessionIDPrefix}, "activation-1"},
		{"wrong prefix", RequestRecipe{Input: HermesWorkspaceAuditInput, SessionIDPrefix: "other"}, "activation-1"},
		{"empty activation", recipe, ""},
		{"invalid activation", recipe, "tenant/activation"},
		{"session too long", recipe, maxActivationID + "a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildCanaryRequest(test.recipe, test.activationID); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifyRejectsQualificationMutations(t *testing.T) {
	fixture := newReleaseFixture(t)
	tests := []struct {
		name   string
		mutate func(*Release)
	}{
		{"evidence digest", func(r *Release) { r.Qualification.EvidenceDigest = "bad" }},
		{"uppercase evidence digest", func(r *Release) {
			r.Qualification.EvidenceDigest = "sha256:" + strings.Repeat("F", 64)
		}},
		{"completion offset", func(r *Release) { r.Qualification.CompletedAt = "2026-07-16T12:00:00-07:00" }},
		{"completion fractional", func(r *Release) { r.Qualification.CompletedAt = "2026-07-16T19:00:00.000Z" }},
		{"runtime", func(r *Release) { r.Qualification.Runtime = "runc" }},
		{"no limitations", func(r *Release) { r.Qualification.Limitations = nil }},
		{"too many limitations", func(r *Release) {
			r.Qualification.Limitations = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}
		}},
		{"duplicate limitations", func(r *Release) {
			r.Qualification.Limitations = []string{"No external inference.", "No external inference."}
		}},
		{"limitation URL", func(r *Release) {
			r.Qualification.Limitations = []string{"Details at ssh://publisher.invalid."}
		}},
		{"limitation whitespace", func(r *Release) {
			r.Qualification.Limitations = []string{" padded"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := fixture.release
			release.Qualification.Limitations = append([]string(nil), release.Qualification.Limitations...)
			test.mutate(&release)
			assertInvalid(t, signReleasePayload(t, release, "publisher-a", fixture.private), fixture.public)
		})
	}
}

func TestVerifyRejectsEnvelopeAndJSONAmbiguity(t *testing.T) {
	fixture := newReleaseFixture(t)
	valid := signReleasePayload(t, fixture.release, "publisher-a", fixture.private)
	envelope, err := dsse.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}

	wrongTypeEnvelope, err := dsse.Sign("application/example", mustJSON(t, fixture.release), "publisher-a", fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	wrongType := mustEnvelope(t, wrongTypeEnvelope)

	multipleSignatures := envelope
	multipleSignatures.Signatures = append(
		append([]dsse.Signature(nil), envelope.Signatures...),
		dsse.Signature{KeyID: "publisher-b", Sig: envelope.Signatures[0].Sig},
	)

	noncanonicalPayload := envelope
	noncanonicalPayload.Payload = alternateBase64(t, envelope.Payload)

	noncanonicalSignature := envelope
	noncanonicalSignature.Signatures = append([]dsse.Signature(nil), envelope.Signatures...)
	noncanonicalSignature.Signatures[0].Sig = alternateBase64(t, envelope.Signatures[0].Sig)

	var reordered map[string]json.RawMessage
	if err := json.Unmarshal(valid, &reordered); err != nil {
		t.Fatal(err)
	}
	reorderedRaw, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reorderedRaw, valid) {
		t.Fatal("test setup did not reorder envelope JSON")
	}

	releasePayload := mustJSON(t, fixture.release)
	unknownPayload := appendObjectMember(releasePayload, `,"url":"https://invalid"}`)
	duplicatePayload := appendObjectMember(releasePayload, `,"release_id":"other"}`)
	requestRecipe := []byte(`"request":{"input":"STEWARD_WORKSPACE_AUDIT","session_id_prefix":"steward-activation"}`)
	unknownRequestRecipe := bytes.Replace(
		releasePayload, requestRecipe,
		[]byte(`"request":{"input":"STEWARD_WORKSPACE_AUDIT","session_id_prefix":"steward-activation","script":"id"}`), 1,
	)
	duplicateRequestRecipe := bytes.Replace(
		releasePayload, requestRecipe,
		[]byte(`"request":{"input":"STEWARD_WORKSPACE_AUDIT","input":"OTHER","session_id_prefix":"steward-activation"}`), 1,
	)
	missingDisposition := bytes.Replace(
		releasePayload, []byte(`,"required_state_disposition":"new"`), nil, 1,
	)
	if bytes.Equal(unknownRequestRecipe, releasePayload) ||
		bytes.Equal(duplicateRequestRecipe, releasePayload) ||
		bytes.Equal(missingDisposition, releasePayload) {
		t.Fatal("test setup did not mutate nested canary payload")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(releasePayload, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "qualification")
	missingPayload, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"wrong payload type", wrongType},
		{"unknown envelope field", appendObjectMember(valid, `,"extra":true`)},
		{"duplicate envelope field", appendObjectMember(valid, `,"payloadType":"`+PayloadType+`"`)},
		{"noncanonical envelope whitespace", append(append([]byte(nil), valid...), '\n')},
		{"noncanonical envelope member order", reorderedRaw},
		{"multiple signatures", mustEnvelope(t, multipleSignatures)},
		{"noncanonical payload base64", mustJSON(t, noncanonicalPayload)},
		{"noncanonical signature base64", mustJSON(t, noncanonicalSignature)},
		{"unknown release field", signRawPayload(t, unknownPayload, "publisher-a", fixture.private)},
		{"duplicate release field", signRawPayload(t, duplicatePayload, "publisher-a", fixture.private)},
		{"unknown request recipe field", signRawPayload(t, unknownRequestRecipe, "publisher-a", fixture.private)},
		{"duplicate request recipe field", signRawPayload(t, duplicateRequestRecipe, "publisher-a", fixture.private)},
		{"missing state disposition", signRawPayload(t, missingDisposition, "publisher-a", fixture.private)},
		{"missing release field", signRawPayload(t, missingPayload, "publisher-a", fixture.private)},
		{"invalid UTF-8 payload", signRawPayload(t, []byte{0xff, 0xfe}, "publisher-a", fixture.private)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertInvalid(t, test.raw, fixture.public)
		})
	}
}

func TestVerifyRejectsAmbiguousEmbeddedCapsules(t *testing.T) {
	fixture := newReleaseFixture(t)
	capsuleEnvelope, err := dsse.Parse(fixture.capsuleRaw)
	if err != nil {
		t.Fatal(err)
	}
	multipleSignatures := capsuleEnvelope
	multipleSignatures.Signatures = append(
		append([]dsse.Signature(nil), capsuleEnvelope.Signatures...),
		dsse.Signature{KeyID: "publisher-b", Sig: capsuleEnvelope.Signatures[0].Sig},
	)
	noncanonicalPayload := capsuleEnvelope
	noncanonicalPayload.Payload = alternateBase64(t, capsuleEnvelope.Payload)
	noncanonicalSignature := capsuleEnvelope
	noncanonicalSignature.Signatures = append([]dsse.Signature(nil), capsuleEnvelope.Signatures...)
	noncanonicalSignature.Signatures[0].Sig = alternateBase64(t, capsuleEnvelope.Signatures[0].Sig)

	capsulePayload := mustJSON(t, fixture.capsule)
	unknownCapsulePayload := appendObjectMember(capsulePayload, `,"hook":"id"}`)
	duplicateCapsulePayload := appendObjectMember(capsulePayload, `,"capsule_id":"other"}`)

	tests := []struct {
		name       string
		capsuleRaw []byte
	}{
		{"unknown envelope field", appendObjectMember(fixture.capsuleRaw, `,"extra":true`)},
		{"duplicate envelope field", appendObjectMember(fixture.capsuleRaw, `,"payloadType":"`+admission.CapsulePayloadType+`"`)},
		{"noncanonical envelope whitespace", append(append([]byte(nil), fixture.capsuleRaw...), '\n')},
		{"multiple signatures", mustEnvelope(t, multipleSignatures)},
		{"noncanonical payload base64", mustJSON(t, noncanonicalPayload)},
		{"noncanonical signature base64", mustJSON(t, noncanonicalSignature)},
		{"unknown capsule field", signRawCapsulePayload(t, unknownCapsulePayload, "publisher-a", fixture.private)},
		{"duplicate capsule field", signRawCapsulePayload(t, duplicateCapsulePayload, "publisher-a", fixture.private)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := fixture.release
			release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(test.capsuleRaw)
			assertInvalid(t, signReleasePayload(t, release, "publisher-a", fixture.private), fixture.public)
		})
	}
}

func TestReleaseSizeLimits(t *testing.T) {
	fixture := newReleaseFixture(t)
	assertInvalid(t, bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1), fixture.public)

	oversizedPayload := bytes.Repeat([]byte("x"), MaxPayloadBytes+1)
	raw := signRawPayload(t, oversizedPayload, "publisher-a", fixture.private)
	if len(raw) > MaxEnvelopeBytes {
		t.Fatalf("test release envelope unexpectedly exceeds outer limit: %d", len(raw))
	}
	assertInvalid(t, raw, fixture.public)

	release := fixture.release
	release.Display.Outcome = strings.Repeat("x", 513)
	assertInvalid(t, signReleasePayload(t, release, "publisher-a", fixture.private), fixture.public)
}

func TestSignRejectsInvalidInputs(t *testing.T) {
	fixture := newReleaseFixture(t)
	if _, err := Sign(fixture.release, "publisher-a", fixture.private, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero time err = %v", err)
	}
	if _, err := Sign(fixture.release, "publisher-b", fixture.private, testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong key ID err = %v", err)
	}
	if _, err := Sign(fixture.release, "publisher-a", ed25519.PrivateKey("short"), testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short key err = %v", err)
	}
	if _, err := Verify(
		signReleasePayload(t, fixture.release, "publisher-a", fixture.private),
		map[string]ed25519.PublicKey{"publisher-a": fixture.public}, time.Time{},
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero verify time err = %v", err)
	}

	release := fixture.release
	release.Archive.Image.ConfigDigest = testDigest('9')
	if _, err := Sign(release, "publisher-a", fixture.private, testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("inconsistent release err = %v", err)
	}
}

func newReleaseFixture(t testing.TB) releaseFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skillDigest := testDigest('a')
	image := admission.ImageIdentity{
		Repository:     "registry.example/steward/hermes",
		ManifestDigest: testDigest('c'),
		ConfigDigest:   testDigest('d'),
		Platform:       admission.Platform{OS: "linux", Architecture: "amd64"},
	}
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: "hermes-workspace-audit",
		PublisherKeyID: "publisher-a",
		IssuedAt:       testNow.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:      testNow.Add(24 * time.Hour).Format(time.RFC3339),
		Profile:        admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
		Image:          image, Command: []string{"serve"},
		Resources: admission.ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128},
		Capabilities: admission.Capabilities{
			State: true, Inference: true, Service: true, Connector: true,
		},
		Artifacts: []admission.ArtifactDigest{
			{Kind: SkillManifestArtifactKind, Digest: skillDigest},
			{Kind: "sbom", Digest: testDigest('e')},
		},
		State:   admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service: admission.ServiceShape{ID: HermesServiceID, Port: 8766},
	}
	capsuleRaw := signCapsule(t, capsule, "publisher-a", private)
	release := Release{
		SchemaVersion: SchemaV1, ReleaseID: "hermes-workspace-audit",
		PublisherKeyID: "publisher-a",
		Display: Display{
			Title:   "Hermes workspace audit",
			Summary: "Inspect a bounded workspace with an immutable custom skill.",
			Outcome: "Produce a deterministic manifest of the qualified workspace fixture.",
		},
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsuleRaw),
		Archive: Archive{
			SHA256Digest: testDigest('f'), SizeBytes: 64 << 20, Image: image,
		},
		Canary: Canary{
			Kind:      CanaryKindHermesWorkspaceAuditV1,
			ServiceID: HermesServiceID, OperationID: HermesOperationID,
			Request: RequestRecipe{
				Input: HermesWorkspaceAuditInput, SessionIDPrefix: HermesSessionIDPrefix,
			},
			RequiredStateDisposition:        "new",
			SkillManifestDigest:             skillDigest,
			ExpectedWorkspaceManifestDigest: HermesWorkspaceAuditEmptyManifestDigest,
			FixtureID:                       HermesWorkspaceAuditEmptyFixtureID,
		},
		Qualification: Qualification{
			EvidenceDigest: testDigest('1'), CompletedAt: "2026-07-16T18:30:00Z",
			Runtime: "runsc",
			Limitations: []string{
				"Qualified only on linux amd64.",
				"Local inference is controlled separately.",
			},
		},
	}
	return releaseFixture{
		public: public, private: private, release: release, capsule: capsule,
		capsuleRaw: capsuleRaw,
	}
}

func signCapsule(t testing.TB, capsule admission.ProfileCapsule, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signRawCapsulePayload(t, mustJSON(t, capsule), keyID, private)
}

func signRawCapsulePayload(t testing.TB, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := dsse.Sign(admission.CapsulePayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	return mustEnvelope(t, envelope)
}

func signReleasePayload(t testing.TB, release Release, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signRawPayload(t, mustJSON(t, release), keyID, private)
}

func signRawPayload(t testing.TB, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := dsse.Sign(PayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	return mustEnvelope(t, envelope)
}

func mustEnvelope(t testing.TB, envelope dsse.Envelope) []byte {
	t.Helper()
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func appendObjectMember(raw []byte, member string) []byte {
	result := append([]byte(nil), raw[:len(raw)-1]...)
	return append(result, member...)
}

func alternateBase64(t testing.TB, canonical string) string {
	t.Helper()
	padding := 0
	if strings.HasSuffix(canonical, "==") {
		padding = 2
	} else if strings.HasSuffix(canonical, "=") {
		padding = 1
	}
	if padding == 0 {
		t.Fatalf("base64 value has no unused trailing bits: %q", canonical)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := len(canonical) - padding - 1
	value := strings.IndexByte(alphabet, canonical[index])
	if value < 0 {
		t.Fatalf("base64 value has unexpected trailing character: %q", canonical)
	}
	mutated := []byte(canonical)
	mutated[index] = alphabet[value^1]
	canonicalBytes, canonicalErr := base64.StdEncoding.DecodeString(canonical)
	mutatedBytes, mutatedErr := base64.StdEncoding.DecodeString(string(mutated))
	if canonicalErr != nil || mutatedErr != nil || !bytes.Equal(canonicalBytes, mutatedBytes) {
		t.Fatal("test setup did not produce equivalent noncanonical base64")
	}
	return string(mutated)
}

func assertInvalid(t testing.TB, raw []byte, public ed25519.PublicKey) {
	t.Helper()
	if _, err := Verify(
		raw, map[string]ed25519.PublicKey{"publisher-a": public}, testNow,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify err = %v, want ErrInvalid", err)
	}
}

func testDigest(char byte) string {
	return "sha256:" + strings.Repeat(string(char), 64)
}
