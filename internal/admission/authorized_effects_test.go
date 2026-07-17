package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuthorizedEffectsPreservesLegacyAndRejectsDowngrades(t *testing.T) {
	publisher, _, _ := ed25519.GenerateKey(rand.Reader)
	capsule := testCapsule()
	capsule.Capabilities.Connector = true
	policy := testPolicy(publisher)
	policy.Tenants[0].ConnectorIDs = []string{"calendar.write", "vault.read"}
	intent := testIntent(testDigest('d'))
	intent.Capabilities.Connector = true
	intent.ConnectorIDs = []string{"calendar.write"}
	caller := AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}

	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err != nil {
		t.Fatalf("legacy intent without effect policy was rejected: %v", err)
	}
	intent.EffectMode = EffectModeStandard
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err == nil {
		t.Fatal("effect mode without tenant policy was accepted")
	}

	public, _, _ := ed25519.GenerateKey(rand.Reader)
	policy.Tenants[0].AuthorizedEffects = &AuthorizedEffectsPolicy{
		Mode: AuthorizedEffectsOptional,
		Keys: []ActionKey{{
			KeyID: "effects-approver", PublicKey: base64.StdEncoding.EncodeToString(public),
			ConnectorIDs: []string{"calendar.write"},
		}},
	}
	for _, invalidMode := range []string{"", "automatic"} {
		intent.EffectMode = invalidMode
		if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err == nil {
			t.Fatalf("optional policy accepted invalid effect mode %q", invalidMode)
		}
	}
	intent.EffectMode = EffectModeStandard
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err != nil {
		t.Fatalf("optional policy rejected explicit standard mode: %v", err)
	}
	capsule.Capabilities.Egress = true
	policy.Tenants[0].EgressRouteIDs = []string{"public-web"}
	intent.Capabilities.Egress = true
	intent.EgressRouteIDs = []string{"public-web"}
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err != nil {
		t.Fatalf("optional policy rejected legacy egress in explicit standard mode: %v", err)
	}
	intent.Capabilities.Egress = false
	intent.EgressRouteIDs = nil
	intent.EffectMode = EffectModeAuthorized
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err != nil {
		t.Fatalf("optional policy rejected covered authorized mode: %v", err)
	}

	policy.Tenants[0].AuthorizedEffects.Mode = AuthorizedEffectsRequired
	for _, downgrade := range []string{"", EffectModeStandard} {
		intent.EffectMode = downgrade
		if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err == nil || !strings.Contains(err.Error(), "downgrade") {
			t.Fatalf("required policy accepted effect mode %q: %v", downgrade, err)
		}
	}
	intent.EffectMode = EffectModeAuthorized
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err != nil {
		t.Fatalf("required policy rejected authorized mode: %v", err)
	}
}

func TestAuthorizedEffectsForbidsGenericEgressAndRequiresConnectorCoverage(t *testing.T) {
	capsule, policy, intent, caller := authorizedEffectsFixture(t)
	capsule.Capabilities.Egress = true
	policy.Tenants[0].EgressRouteIDs = []string{"public-web"}
	intent.Capabilities.Egress = true
	intent.EgressRouteIDs = []string{"public-web"}
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err == nil || !strings.Contains(err.Error(), "forbids generic egress") {
		t.Fatalf("authorized mode accepted generic egress: %v", err)
	}

	intent.Capabilities.Egress = false
	intent.EgressRouteIDs = nil
	policy.Tenants[0].AuthorizedEffects.Keys = policy.Tenants[0].AuthorizedEffects.Keys[1:]
	if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles()); err == nil || !strings.Contains(err.Error(), "lacks an authorized action key") {
		t.Fatalf("authorized mode accepted an uncovered connector: %v", err)
	}
}

func TestAuthorizedActionKeysAreNarrowedCanonicalAndDetached(t *testing.T) {
	capsule, policy, intent, caller := authorizedEffectsFixture(t)
	effective, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent, caller, PersistedFences{}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(effective.Intent.ConnectorIDs, ","); got != "calendar.write,vault.read" {
		t.Fatalf("admitted connector set is not canonical: %q", got)
	}
	keys, err := effective.AuthorizedActionKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KeyID != "a-vault" || keys[1].KeyID != "z-shared" {
		t.Fatalf("keys are not key-ID canonical: %#v", keys)
	}
	if got := strings.Join(keys[0].ConnectorIDs, ","); got != "vault.read" {
		t.Fatalf("narrowed key scope=%q", got)
	}
	if got := strings.Join(keys[1].ConnectorIDs, ","); got != "calendar.write,vault.read" {
		t.Fatalf("shared key scope=%q", got)
	}

	keys[0].KeyID = "substituted"
	keys[0].ConnectorIDs[0] = "substituted.connector"
	again, err := effective.AuthorizedActionKeys()
	if err != nil {
		t.Fatal(err)
	}
	if again[0].KeyID != "a-vault" || again[0].ConnectorIDs[0] != "vault.read" {
		t.Fatalf("returned authority aliases retained policy state: %#v", again)
	}

	narrowed, err := policy.AuthorizedActionKeys("tenant-a", []string{"vault.read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(narrowed) != 2 || len(narrowed[1].ConnectorIDs) != 1 || narrowed[1].ConnectorIDs[0] != "vault.read" {
		t.Fatalf("selection leaked an unselected connector: %#v", narrowed)
	}
	if _, err := policy.AuthorizedActionKeys("tenant-a", []string{"vault.read", "vault.read"}); err == nil {
		t.Fatal("duplicate selected connector was accepted")
	}
	if _, err := policy.AuthorizedActionKeys("tenant-a", []string{"other-tenant.connector"}); err == nil {
		t.Fatal("out-of-tenant connector substitution was accepted")
	}
}

func TestAuthorizedEffectsPolicyRejectsAmbiguousKeyIdentityAndScope(t *testing.T) {
	publisher, _, _ := ed25519.GenerateKey(rand.Reader)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := base64.StdEncoding.EncodeToString(public)
	valid := ActionKey{KeyID: "effects-approver", PublicKey: encoded, ConnectorIDs: []string{"calendar.write", "vault.read"}}

	tests := []struct {
		name   string
		mutate func(*AuthorizedEffectsPolicy)
	}{
		{"invalid mode", func(p *AuthorizedEffectsPolicy) { p.Mode = "best-effort" }},
		{"empty keys", func(p *AuthorizedEffectsPolicy) { p.Keys = nil }},
		{"invalid key ID", func(p *AuthorizedEffectsPolicy) { p.Keys[0].KeyID = "bad key" }},
		{"invalid public key", func(p *AuthorizedEffectsPolicy) { p.Keys[0].PublicKey = "not-base64" }},
		{"noncanonical public key", func(p *AuthorizedEffectsPolicy) { p.Keys[0].PublicKey = encoded + "\n" }},
		{"empty connector scope", func(p *AuthorizedEffectsPolicy) { p.Keys[0].ConnectorIDs = nil }},
		{"unknown connector", func(p *AuthorizedEffectsPolicy) { p.Keys[0].ConnectorIDs = []string{"other.write"} }},
		{"duplicate connector", func(p *AuthorizedEffectsPolicy) { p.Keys[0].ConnectorIDs = []string{"vault.read", "vault.read"} }},
		{"unsorted connectors", func(p *AuthorizedEffectsPolicy) { p.Keys[0].ConnectorIDs = []string{"vault.read", "calendar.write"} }},
		{"duplicate key ID", func(p *AuthorizedEffectsPolicy) { p.Keys = append(p.Keys, valid) }},
		{"duplicate key material", func(p *AuthorizedEffectsPolicy) {
			duplicate := valid
			duplicate.KeyID = "other-approver"
			p.Keys = append(p.Keys, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(publisher)
			policy.Tenants[0].ConnectorIDs = []string{"calendar.write", "vault.read"}
			policy.Tenants[0].AuthorizedEffects = &AuthorizedEffectsPolicy{Mode: AuthorizedEffectsRequired, Keys: []ActionKey{valid}}
			test.mutate(policy.Tenants[0].AuthorizedEffects)
			if err := policy.Validate(); err == nil {
				t.Fatal("ambiguous authorized effects authority was accepted")
			}
		})
	}

	policy := testPolicy(publisher)
	policy.Tenants[0].ConnectorIDs = []string{"calendar.write"}
	policy.Tenants[0].AuthorizedEffects = &AuthorizedEffectsPolicy{Mode: AuthorizedEffectsRequired}
	for index := 0; index < maxAuthorizedEffectKeys+1; index++ {
		key, _, _ := ed25519.GenerateKey(rand.Reader)
		policy.Tenants[0].AuthorizedEffects.Keys = append(policy.Tenants[0].AuthorizedEffects.Keys, ActionKey{
			KeyID: "effects-" + strings.Repeat("x", index+1), PublicKey: base64.StdEncoding.EncodeToString(key),
			ConnectorIDs: []string{"calendar.write"},
		})
	}
	if err := policy.Validate(); err == nil {
		t.Fatal("more than eight authorized effects keys were accepted")
	}

	policy = testPolicy(publisher)
	policy.Tenants[0].ConnectorIDs = []string{"calendar.write", "vault.read"}
	policy.Tenants[0].AuthorizedEffects = &AuthorizedEffectsPolicy{Mode: AuthorizedEffectsRequired, Keys: []ActionKey{valid}}
	tenantB := policy.Tenants[0]
	tenantB.TenantID = "tenant-b"
	tenantB.AuthorizedEffects = &AuthorizedEffectsPolicy{Mode: AuthorizedEffectsRequired, Keys: []ActionKey{{
		KeyID: "tenant-b-approver", PublicKey: encoded, ConnectorIDs: []string{"calendar.write"},
	}}}
	policy.Tenants = append(policy.Tenants, tenantB)
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "multiple tenants") {
		t.Fatalf("cross-tenant action-key substitution error=%v", err)
	}
}

func authorizedEffectsFixture(t *testing.T) (ProfileCapsule, SitePolicy, InstanceIntent, AuthenticatedIdentity) {
	t.Helper()
	publisher, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sharedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vaultPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := testCapsule()
	capsule.Capabilities.Connector = true
	policy := testPolicy(publisher)
	policy.Tenants[0].ConnectorIDs = []string{"calendar.write", "vault.read"}
	policy.Tenants[0].AuthorizedEffects = &AuthorizedEffectsPolicy{
		Mode: AuthorizedEffectsRequired,
		Keys: []ActionKey{
			{KeyID: "z-shared", PublicKey: base64.StdEncoding.EncodeToString(sharedPublic), ConnectorIDs: []string{"calendar.write", "vault.read"}},
			{KeyID: "a-vault", PublicKey: base64.StdEncoding.EncodeToString(vaultPublic), ConnectorIDs: []string{"vault.read"}},
		},
	}
	intent := testIntent(testDigest('d'))
	intent.Capabilities.Connector = true
	intent.ConnectorIDs = []string{"vault.read", "calendar.write"}
	intent.EffectMode = EffectModeAuthorized
	return capsule, policy, intent, AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}
}
