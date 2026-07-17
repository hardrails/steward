package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTenantCommandKeysAreOperationScoped(t *testing.T) {
	commandPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
	policy.Tenants[0].CommandKeys = []CommandKey{{
		KeyID:     "tenant-a-lifecycle",
		PublicKey: base64.StdEncoding.EncodeToString(commandPublic),
		Operations: []string{
			"admit", "start", "stop", "destroy", "read", "purge",
			"activation-canary",
		},
	}}
	policy.SiteCleanupCommandKeys = []CommandKey{{
		KeyID:      "site-cleanup",
		PublicKey:  base64.StdEncoding.EncodeToString(cleanupPublic),
		Operations: []string{"stop", "destroy", "purge"},
	}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	keys, err := policy.TrustedCommandKeys("tenant-a", "start")
	if err != nil || !commandPublic.Equal(keys["tenant-a-lifecycle"]) {
		t.Fatalf("keys=%#v err=%v", keys, err)
	}
	for _, operation := range []string{"admit", "start", "read", "activation-canary"} {
		keys, err := policy.TrustedCommandKeys("tenant-a", operation)
		if err != nil {
			t.Fatalf("trusted %s keys: %v", operation, err)
		}
		if _, exists := keys["site-cleanup"]; exists {
			t.Fatalf("site cleanup key gained %s authority", operation)
		}
		if _, err := policy.TrustedCommandKeys("removed-tenant", operation); err == nil {
			t.Fatalf("site cleanup key authorized %s for a removed tenant", operation)
		}
	}
	if _, err := policy.TrustedCommandKeys("tenant-a", "provision"); err == nil {
		t.Fatal("unsigned-admission provision operation entered signed command scope")
	}
	if _, err := policy.TrustedCommandKeys("tenant-b", "start"); err == nil {
		t.Fatal("cross-tenant command key lookup succeeded")
	}
	keys, err = policy.TrustedCommandKeys("removed-tenant", "destroy")
	if err != nil || len(keys) != 1 || !cleanupPublic.Equal(keys["site-cleanup"]) {
		t.Fatalf("site cleanup keys=%#v err=%v", keys, err)
	}
}

func TestSitePolicyRejectsMalformedCommandKeyScopes(t *testing.T) {
	commandPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := CommandKey{KeyID: "commands", PublicKey: base64.StdEncoding.EncodeToString(commandPublic), Operations: []string{"start"}}
	for _, test := range []struct {
		name string
		keys []CommandKey
	}{
		{name: "unknown operation", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{"shell"}}}},
		{name: "duplicate operation", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{"start", "start"}}}},
		{name: "invalid public key", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: "not-base64", Operations: valid.Operations}}},
		{name: "duplicate key id", keys: []CommandKey{valid, valid}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
			policy.Tenants[0].CommandKeys = test.keys
			if err := policy.Validate(); err == nil {
				t.Fatal("malformed command authority was accepted")
			}
		})
	}
}

func TestSitePolicyRejectsMalformedCleanupKeysAndAuthorityCollisions(t *testing.T) {
	cleanupPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := CommandKey{
		KeyID: "site-cleanup", PublicKey: base64.StdEncoding.EncodeToString(cleanupPublic),
		Operations: []string{"stop", "destroy", "purge"},
	}
	for _, test := range []struct {
		name string
		keys []CommandKey
	}{
		{name: "non-cleanup operation", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{"start"}}}},
		{name: "duplicate operation", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{"stop", "stop"}}}},
		{name: "invalid public key", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: "not-base64", Operations: []string{"stop"}}}},
		{name: "duplicate key id", keys: []CommandKey{valid, valid}},
		{name: "empty scope", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey}}},
		{name: "oversized key id", keys: []CommandKey{{KeyID: strings.Repeat("k", 257), PublicKey: valid.PublicKey, Operations: []string{"stop"}}}},
		{name: "oversized operation", keys: []CommandKey{{KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{strings.Repeat("x", 33)}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
			policy.SiteCleanupCommandKeys = test.keys
			if err := policy.Validate(); err == nil {
				t.Fatal("malformed site cleanup authority was accepted")
			}
		})
	}
	tooMany := make([]CommandKey, 33)
	for index := range tooMany {
		tooMany[index] = valid
	}
	policy := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
	policy.SiteCleanupCommandKeys = tooMany
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("site cleanup key count bound err=%v", err)
	}

	policy = testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
	policy.SiteCleanupCommandKeys = []CommandKey{valid}
	policy.Tenants[0].CommandKeys = []CommandKey{{
		KeyID: valid.KeyID, PublicKey: valid.PublicKey, Operations: []string{"stop"},
	}}
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("tenant/site command key collision err=%v", err)
	}
	if _, err := policy.TrustedCommandKeys("tenant-a", "stop"); err == nil {
		t.Fatal("unvalidated tenant/site key-ID collision was resolved by overwrite")
	}

	lockdown := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
	lockdown.SiteCleanupCommandKeys = []CommandKey{valid}
	lockdown.Tenants = nil
	if err := lockdown.Validate(); err != nil {
		t.Fatalf("cleanup-only emergency lockdown policy was rejected: %v", err)
	}
	if _, err := lockdown.TrustedCommandKeys("removed-tenant", "stop"); err != nil {
		t.Fatalf("cleanup authority was lost with the final tenant rule: %v", err)
	}
}

func TestCommandStatementValidationBindsFiniteValidityWindow(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	valid := CommandStatement{
		SchemaVersion: CommandSchemaV2, CommandID: "command-1",
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a",
		RuntimeRef: "uplink:v2:8:tenant-a:6:node-a:agent-a", Kind: "start",
		AuthorizationContextDigest: testDigest('a'),
		ClaimGeneration:            1, InstanceGeneration: 2, CommandSequence: 3,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
	}
	if err := valid.Validate(now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CommandStatement){
		func(command *CommandStatement) { command.Kind = "exec" },
		func(command *CommandStatement) { command.Payload = json.RawMessage(`{"x":`) },
		func(command *CommandStatement) { command.CommandSequence = 0 },
		func(command *CommandStatement) { command.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano) },
		func(command *CommandStatement) {
			command.IssuedAt = now.Add(maxCommandClockSkew + time.Second).Format(time.RFC3339Nano)
		},
		func(command *CommandStatement) {
			command.ExpiresAt = now.Add(maxCommandLifetime + time.Minute).Format(time.RFC3339Nano)
		},
		func(command *CommandStatement) { command.RuntimeRef = strings.Repeat("x", 1025) },
		func(command *CommandStatement) { command.AuthorizationContextDigest = "sha256:invalid" },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(now); err == nil {
			t.Fatalf("invalid command was accepted: %#v", candidate)
		}
	}
}

func TestVerifyCapsuleForImportAuthenticatesArtifactWithoutTenantSelection(t *testing.T) {
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
	policy.Publishers[0].AllowedManifestDigests = []string{capsule.Image.ManifestDigest}
	capsuleRaw := signJSON(t, CapsulePayloadType, capsule, "publisher-1", publisherPrivate)
	policyRaw := signJSON(t, PolicyPayloadType, policy, "site-root", rootPrivate)
	verified, err := VerifyCapsuleForImport(
		capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic},
		time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC), DefaultProfiles(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Capsule.CapsuleID != capsule.CapsuleID || verified.SitePolicy.PolicyID != policy.PolicyID ||
		verified.CapsuleDigest == "" || verified.PolicyDigest == "" || verified.PublisherKeyID != "publisher-1" {
		t.Fatalf("verified import = %#v", verified)
	}
	policy.Publishers[0].Revoked = true
	policyRaw = signJSON(t, PolicyPayloadType, policy, "site-root", rootPrivate)
	if _, err := VerifyCapsuleForImport(capsuleRaw, policyRaw, map[string]ed25519.PublicKey{"site-root": rootPublic}, time.Now(), DefaultProfiles()); err == nil {
		t.Fatal("revoked publisher capsule was accepted for import")
	}
}
