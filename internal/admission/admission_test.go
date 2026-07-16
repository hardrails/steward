package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestVerifyAndAdmitIntersectsSignedArtifacts(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := testCapsule()
	policy := testPolicy(publisherPublic)
	capsuleRaw := signJSON(t, CapsulePayloadType, capsule, "publisher-1", publisherPrivate)
	policyRaw := signJSON(t, PolicyPayloadType, policy, "site-root", rootPrivate)
	intent := testIntent(dsse.Digest(capsuleRaw))
	admitted, err := VerifyAndAdmit(capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic}, intent, AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC), DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if admitted.PublisherKeyID != "publisher-1" || admitted.Profile.UID != 65532 || admitted.PolicyDigest != dsse.Digest(policyRaw) {
		t.Fatalf("unexpected admission: %#v", admitted)
	}
}

func TestVerifyAndAdmitRejectsOutOfEnvelopeResourceAndDuplicatePayload(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw := signJSON(t, PolicyPayloadType, testPolicy(publisherPublic), "site-root", rootPrivate)
	capsule := testCapsule()
	capsuleRaw := signJSON(t, CapsulePayloadType, capsule, "publisher-1", publisherPrivate)
	intent := testIntent(dsse.Digest(capsuleRaw))
	intent.Resources.MemoryBytes = 1024 << 20
	_, err = VerifyAndAdmit(capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic}, intent, AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, time.Now(), DefaultProfiles())
	if err == nil || !strings.Contains(err.Error(), "resource request") {
		t.Fatalf("expected resource denial, got %v", err)
	}

	payload, err := json.Marshal(capsule)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(payload), `"capsule_id":"capsule-a"`, `"capsule_id":"capsule-a","capsule_id":"capsule-b"`, 1)
	malformedRaw := signBytes(t, CapsulePayloadType, []byte(duplicate), "publisher-1", publisherPrivate)
	intent = testIntent(dsse.Digest(malformedRaw))
	_, err = VerifyAndAdmit(malformedRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic}, intent, AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, time.Now(), DefaultProfiles())
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("expected duplicate payload denial, got %v", err)
	}
}

func TestInferenceModelAliasRequiresExplicitSiteAuthorization(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule, policy := testCapsule(), testPolicy(public)
	intent := testIntent(testDigest('d'))
	intent.ModelAlias = "privileged-expensive-model"
	_, err = Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent,
		AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles())
	if err == nil || !strings.Contains(err.Error(), "model alias") {
		t.Fatalf("unlisted inference model alias err=%v", err)
	}
}

func testCapsule() ProfileCapsule {
	return ProfileCapsule{
		SchemaVersion: SchemaV1, CapsuleID: "capsule-a", PublisherKeyID: "publisher-1",
		Profile: ProfileRef{ID: "generic-v1", Version: "v1"},
		Image:   ImageIdentity{Repository: "registry.example/agent", ManifestDigest: testDigest('a'), ConfigDigest: testDigest('b'), Platform: Platform{OS: "linux", Architecture: "amd64"}},
		Command: []string{"/agent", "serve"}, Resources: ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128},
		Capabilities: Capabilities{State: true, Inference: true, Service: true}, State: StateShape{SchemaVersion: "v1", Path: "/state"}, Service: ServiceShape{ID: "api", Port: 8080},
		Artifacts: []ArtifactDigest{{Kind: "sbom", Digest: testDigest('c')}},
	}
}

func testPolicy(publisher ed25519.PublicKey) SitePolicy {
	return SitePolicy{SchemaVersion: SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []PublisherRule{{KeyID: "publisher-1", PublicKey: base64.StdEncoding.EncodeToString(publisher), AllowedProfiles: []ProfileRef{{ID: "generic-v1", Version: "v1"}}, AllowedRepositories: []string{"registry.example/agent"}, AllowedArtifacts: []ArtifactDigest{{Kind: "sbom", Digest: testDigest('c')}}, ResourceCeiling: ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128}}},
		Tenants: []TenantRule{{TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-1"}, ResourceCeiling: ResourceLimits{MemoryBytes: 256 << 20, CPUMillis: 500, PIDs: 64},
			AllowedArtifacts: []ArtifactDigest{{Kind: "sbom", Digest: testDigest('c')}}, InferenceRouteIDs: []string{"local-model"}, InferenceModelAliases: []string{"model-a"}, ServiceIDs: []string{"api"}}},
	}
}

func testIntent(capsuleDigest string) InstanceIntent {
	return InstanceIntent{TenantID: "tenant-a", NodeID: "node-a", InstanceID: "instance-a", LineageID: "lineage-a", Generation: 1, CapsuleDigest: capsuleDigest, Resources: ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32}, Capabilities: Capabilities{State: true, Inference: true, Service: true}, StateDisposition: "new", InferenceRouteID: "local-model", ModelAlias: "model-a", ServiceID: "api"}
}

func signJSON(t *testing.T, payloadType string, value any, keyID string, key ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return signBytes(t, payloadType, payload, keyID, key)
}
func signBytes(t *testing.T, payloadType string, payload []byte, keyID string, key ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := dsse.Sign(payloadType, payload, keyID, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func testDigest(char rune) string { return "sha256:" + strings.Repeat(string(char), 64) }
