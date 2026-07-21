package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIntersectRejectsAuthorityAndCapabilityViolations(t *testing.T) {
	publisher, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProfileCapsule, *SitePolicy, *InstanceIntent, *AuthenticatedIdentity, *PersistedFences)
	}{
		{name: "caller tenant mismatch", mutate: func(_ *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent, caller *AuthenticatedIdentity, _ *PersistedFences) {
			caller.TenantID = "tenant-b"
		}},
		{name: "policy epoch rollback", mutate: func(_ *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, fences *PersistedFences) {
			fences.PolicyEpoch = 2
		}},
		{name: "generation rollback", mutate: func(_ *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, fences *PersistedFences) {
			fences.Generation = 2
		}},
		{name: "revoked publisher", mutate: func(_ *ProfileCapsule, policy *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			policy.Publishers[0].Revoked = true
		}},
		{name: "unapproved repository", mutate: func(capsule *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			capsule.Image.Repository = "registry.example/other"
		}},
		{name: "unknown profile", mutate: func(capsule *ProfileCapsule, policy *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			capsule.Profile = ProfileRef{ID: "other", Version: "v1"}
			policy.Publishers[0].AllowedProfiles = []ProfileRef{capsule.Profile}
		}},
		{name: "state shape differs", mutate: func(capsule *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			capsule.State.Path = "/other"
		}},
		{name: "inference route denied", mutate: func(_ *ProfileCapsule, _ *SitePolicy, intent *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			intent.InferenceRouteID = "other-route"
		}},
		{name: "service denied", mutate: func(_ *ProfileCapsule, _ *SitePolicy, intent *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			intent.ServiceID = "other-service"
		}},
		{name: "resource exceeds ceiling", mutate: func(_ *ProfileCapsule, _ *SitePolicy, intent *InstanceIntent, _ *AuthenticatedIdentity, _ *PersistedFences) {
			intent.Resources.PIDs = 129
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			capsule, policy := testCapsule(), testPolicy(publisher)
			intent := testIntent(testDigest('d'))
			identity := AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}
			fences := PersistedFences{}
			test.mutate(&capsule, &policy, &intent, &identity, &fences)
			if _, err := Intersect(capsule, intent.CapsuleDigest, policy, testDigest('e'), "publisher-1", "site-root", intent, identity, fences, DefaultProfiles()); err == nil {
				t.Fatal("unauthorized intersection accepted")
			}
		})
	}
}

func TestValidationRejectsCapsuleAndPolicyEdgeCases(t *testing.T) {
	publisher, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProfileCapsule)
	}{
		{name: "expired", mutate: func(c *ProfileCapsule) { c.ExpiresAt = "2020-01-01T00:00:00Z" }},
		{name: "malformed issue time", mutate: func(c *ProfileCapsule) { c.IssuedAt = "not-a-time" }},
		{name: "service shape without grant", mutate: func(c *ProfileCapsule) { c.Capabilities.Service = false }},
		{name: "unsafe state path", mutate: func(c *ProfileCapsule) { c.State.Path = "/state/../escape" }},
		{name: "bad image digest", mutate: func(c *ProfileCapsule) { c.Image.ConfigDigest = "sha256:not-hex" }},
		{name: "nul command", mutate: func(c *ProfileCapsule) { c.Command = []string{"agent\x00"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			capsule := testCapsule()
			test.mutate(&capsule)
			if err := capsule.Validate(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("invalid capsule accepted")
			}
		})
	}

	for _, test := range []struct {
		name   string
		mutate func(*SitePolicy)
	}{
		{name: "duplicate publisher", mutate: func(p *SitePolicy) { p.Publishers = append(p.Publishers, p.Publishers[0]) }},
		{name: "unknown tenant publisher", mutate: func(p *SitePolicy) { p.Tenants[0].PublisherKeyIDs = []string{"missing"} }},
		{name: "invalid repository", mutate: func(p *SitePolicy) { p.Publishers[0].AllowedRepositories = []string{"https://registry.example/agent"} }},
		{name: "invalid public key", mutate: func(p *SitePolicy) { p.Publishers[0].PublicKey = "not-base64" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(publisher)
			test.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestPublisherKeysReturnsIndependentDecodedKeys(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(public)
	keys, err := policy.PublisherKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !keys["publisher-1"].Equal(public) {
		t.Fatal("decoded publisher key differs")
	}
	policy.Publishers[0].PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := policy.PublisherKeys(); err == nil || !strings.Contains(err.Error(), "decode publisher key") {
		t.Fatalf("invalid publisher key did not fail predictably: %v", err)
	}
}

func TestCapsuleValidationRejectsEveryBoundedShape(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ProfileCapsule)
	}{
		{"identity", func(c *ProfileCapsule) { c.CapsuleID = "" }},
		{"profile", func(c *ProfileCapsule) { c.Profile.ID = "" }},
		{"repository", func(c *ProfileCapsule) { c.Image.Repository = "bad@repo" }},
		{"platform", func(c *ProfileCapsule) { c.Image.Platform.OS = "" }},
		{"resources", func(c *ProfileCapsule) { c.Resources.MemoryBytes = 0 }},
		{"empty command", func(c *ProfileCapsule) { c.Command = nil }},
		{"too many command args", func(c *ProfileCapsule) { c.Command = make([]string, 65) }},
		{"long command arg", func(c *ProfileCapsule) { c.Command = []string{strings.Repeat("x", 4097)} }},
		{"state schema", func(c *ProfileCapsule) { c.State.SchemaVersion = "" }},
		{"service id", func(c *ProfileCapsule) { c.Service.ID = "" }},
		{"service port", func(c *ProfileCapsule) { c.Service.Port = 70000 }},
		{"too many artifacts", func(c *ProfileCapsule) { c.Artifacts = make([]ArtifactDigest, 33) }},
		{"artifact kind", func(c *ProfileCapsule) { c.Artifacts[0].Kind = "" }},
		{"artifact digest", func(c *ProfileCapsule) { c.Artifacts[0].Digest = "bad" }},
		{"duplicate artifact kind", func(c *ProfileCapsule) {
			c.Artifacts = append(c.Artifacts, ArtifactDigest{Kind: c.Artifacts[0].Kind, Digest: testDigest('d')})
		}},
		{"malformed expiry", func(c *ProfileCapsule) { c.ExpiresAt = "tomorrow" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			capsule := testCapsule()
			test.mutate(&capsule)
			if err := capsule.Validate(time.Now()); err == nil {
				t.Fatal("invalid capsule accepted")
			}
		})
	}
}

func TestPolicyValidationRejectsEveryBoundedShape(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		name   string
		mutate func(*SitePolicy)
	}{
		{"identity", func(p *SitePolicy) { p.PolicyEpoch = 0 }},
		{"no publishers", func(p *SitePolicy) { p.Publishers = nil }},
		{"no tenants", func(p *SitePolicy) { p.Tenants = nil }},
		{"publisher key id", func(p *SitePolicy) { p.Publishers[0].KeyID = "" }},
		{"publisher ceiling", func(p *SitePolicy) { p.Publishers[0].ResourceCeiling.PIDs = 0 }},
		{"profiles empty", func(p *SitePolicy) { p.Publishers[0].AllowedProfiles = nil }},
		{"profile invalid", func(p *SitePolicy) { p.Publishers[0].AllowedProfiles[0].Version = "" }},
		{"repositories empty", func(p *SitePolicy) { p.Publishers[0].AllowedRepositories = nil }},
		{"manifest digest", func(p *SitePolicy) { p.Publishers[0].AllowedManifestDigests = []string{"bad"} }},
		{"duplicate tenant", func(p *SitePolicy) { p.Tenants = append(p.Tenants, p.Tenants[0]) }},
		{"tenant id", func(p *SitePolicy) { p.Tenants[0].TenantID = "" }},
		{"tenant publishers", func(p *SitePolicy) { p.Tenants[0].PublisherKeyIDs = nil }},
		{"tenant ceiling", func(p *SitePolicy) { p.Tenants[0].ResourceCeiling.CPUMillis = 0 }},
		{"route", func(p *SitePolicy) { p.Tenants[0].InferenceRouteIDs = []string{""} }},
		{"model alias missing", func(p *SitePolicy) { p.Tenants[0].InferenceModelAliases = nil }},
		{"model alias invalid", func(p *SitePolicy) { p.Tenants[0].InferenceModelAliases = []string{""} }},
		{"duplicate model alias", func(p *SitePolicy) { p.Tenants[0].InferenceModelAliases = []string{"model-a", "model-a"} }},
		{"service", func(p *SitePolicy) { p.Tenants[0].ServiceIDs = []string{""} }},
		{"egress route", func(p *SitePolicy) { p.Tenants[0].EgressRouteIDs = []string{"bad route"} }},
		{"duplicate egress route", func(p *SitePolicy) { p.Tenants[0].EgressRouteIDs = []string{"web", "web"} }},
		{"connector ID", func(p *SitePolicy) { p.Tenants[0].ConnectorIDs = []string{"bad connector"} }},
		{"duplicate connector ID", func(p *SitePolicy) { p.Tenants[0].ConnectorIDs = []string{"git.read", "git.read"} }},
		{"too many connector IDs", func(p *SitePolicy) { p.Tenants[0].ConnectorIDs = make([]string, 33) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy(public)
			test.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestEgressCapabilityIntersectionAndCanonicalRoutes(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	capsule, policy := testCapsule(), testPolicy(public)
	capsule.Capabilities.Egress = true
	policy.Tenants[0].EgressRouteIDs = []string{"package-mirrors", "public-web"}
	intent := testIntent(testDigest('d'))
	intent.Capabilities.Egress = true
	intent.EgressRouteIDs = []string{"public-web", "package-mirrors"}
	effective, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent,
		AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	canonical := CanonicalRouteIDs(effective.Intent.EgressRouteIDs)
	if len(canonical) != 2 || canonical[0] != "package-mirrors" || canonical[1] != "public-web" {
		t.Fatalf("canonical routes=%v", canonical)
	}
	for _, mutate := range []func(*InstanceIntent, *ProfileCapsule){
		func(intent *InstanceIntent, _ *ProfileCapsule) { intent.EgressRouteIDs = []string{"unknown"} },
		func(intent *InstanceIntent, _ *ProfileCapsule) {
			intent.EgressRouteIDs = []string{"public-web", "public-web"}
		},
		func(intent *InstanceIntent, _ *ProfileCapsule) { intent.Capabilities.Egress = false },
		func(_ *InstanceIntent, capsule *ProfileCapsule) { capsule.Capabilities.Egress = false },
	} {
		changedIntent, changedCapsule := intent, capsule
		mutate(&changedIntent, &changedCapsule)
		if _, err := Intersect(changedCapsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", changedIntent,
			AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles()); err == nil {
			t.Fatal("invalid egress authority accepted")
		}
	}
}

func TestConnectorCapabilityIntersectionAndCanonicalIDs(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	capsule, policy := testCapsule(), testPolicy(public)
	capsule.Capabilities.Connector = true
	policy.Tenants[0].ConnectorIDs = []string{"issues.create", "git.read"}
	intent := testIntent(testDigest('d'))
	intent.Capabilities.Connector = true
	intent.ConnectorIDs = []string{"issues.create", "git.read"}
	effective, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent,
		AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if got := effective.Intent.ConnectorIDs; len(got) != 2 || got[0] != "git.read" || got[1] != "issues.create" {
		t.Fatalf("effective connector IDs=%v", got)
	}
	canonical := CanonicalConnectorIDs([]string{"issues.create", "git.read", "issues.create"})
	if len(canonical) != 2 || canonical[0] != "git.read" || canonical[1] != "issues.create" {
		t.Fatalf("canonical connector IDs=%v", canonical)
	}

	for _, test := range []struct {
		name   string
		mutate func(*InstanceIntent, *ProfileCapsule)
	}{
		{name: "unknown", mutate: func(intent *InstanceIntent, _ *ProfileCapsule) { intent.ConnectorIDs = []string{"admin.delete"} }},
		{name: "duplicate", mutate: func(intent *InstanceIntent, _ *ProfileCapsule) {
			intent.ConnectorIDs = []string{"git.read", "git.read"}
		}},
		{name: "too many", mutate: func(intent *InstanceIntent, _ *ProfileCapsule) { intent.ConnectorIDs = make([]string, 33) }},
		{name: "empty", mutate: func(intent *InstanceIntent, _ *ProfileCapsule) { intent.ConnectorIDs = nil }},
		{name: "without capability", mutate: func(intent *InstanceIntent, _ *ProfileCapsule) { intent.Capabilities.Connector = false }},
		{name: "outside capsule ceiling", mutate: func(_ *InstanceIntent, capsule *ProfileCapsule) { capsule.Capabilities.Connector = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedIntent, changedCapsule := intent, capsule
			test.mutate(&changedIntent, &changedCapsule)
			if _, err := Intersect(changedCapsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", changedIntent,
				AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles()); err == nil {
				t.Fatal("invalid connector authority accepted")
			}
		})
	}
}

func TestIntersectRejectsRemainingAuthorityEdges(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		name   string
		mutate func(*ProfileCapsule, *SitePolicy, *InstanceIntent)
	}{
		{"capsule digest mismatch", func(_ *ProfileCapsule, _ *SitePolicy, i *InstanceIntent) { i.CapsuleDigest = testDigest('f') }},
		{"publisher not tenant authorized", func(_ *ProfileCapsule, p *SitePolicy, _ *InstanceIntent) {
			p.Tenants[0].PublisherKeyIDs = []string{"other"}
			p.Publishers = append(p.Publishers, PublisherRule{KeyID: "other", PublicKey: base64.StdEncoding.EncodeToString(public), AllowedProfiles: p.Publishers[0].AllowedProfiles, AllowedRepositories: p.Publishers[0].AllowedRepositories, ResourceCeiling: p.Publishers[0].ResourceCeiling})
		}},
		{"profile not authorized", func(c *ProfileCapsule, p *SitePolicy, _ *InstanceIntent) {
			p.Publishers[0].AllowedProfiles = []ProfileRef{{ID: c.Profile.ID, Version: "v2"}}
		}},
		{"manifest denied", func(_ *ProfileCapsule, p *SitePolicy, _ *InstanceIntent) {
			p.Publishers[0].AllowedManifestDigests = []string{testDigest('f')}
		}},
		{"capability exceeds capsule", func(c *ProfileCapsule, _ *SitePolicy, _ *InstanceIntent) { c.Capabilities.State = false }},
		{"state disposition", func(_ *ProfileCapsule, _ *SitePolicy, i *InstanceIntent) { i.StateDisposition = "none" }},
		{"inference fields without capability", func(_ *ProfileCapsule, _ *SitePolicy, i *InstanceIntent) { i.Capabilities.Inference = false }},
		{"service field without capability", func(_ *ProfileCapsule, _ *SitePolicy, i *InstanceIntent) { i.Capabilities.Service = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			capsule, policy := testCapsule(), testPolicy(public)
			intent := testIntent(testDigest('d'))
			test.mutate(&capsule, &policy, &intent)
			if _, err := Intersect(capsule, testDigest('d'), policy, testDigest('e'), "publisher-1", "site-root", intent,
				AuthenticatedIdentity{TenantID: "tenant-a", NodeID: "node-a"}, PersistedFences{}, DefaultProfiles()); err == nil {
				t.Fatal("invalid authority edge accepted")
			}
		})
	}
}

func TestDefaultProfilesIncludeFixedAgentStateLayouts(t *testing.T) {
	profiles := DefaultProfiles()
	for _, test := range []struct{ id, path string }{
		{"generic-v1", "/state"},
		{"hermes-v1", "/opt/data"},
	} {
		profile, ok := profiles.Lookup(ProfileRef{ID: test.id, Version: "v1"})
		if !ok || profile.StatePath != test.path || profile.UID != 65532 || profile.GID != 65532 {
			t.Fatalf("profile %s = %#v, %v", test.id, profile, ok)
		}
	}
}

func TestValidateProfileContractRejectsRuntimeSpecificDrift(t *testing.T) {
	capsule := ProfileCapsule{
		Profile: ProfileRef{ID: "hermes-v1", Version: "v1"}, Command: []string{"serve"},
		State:   StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service: ServiceShape{ID: "hermes-api", Port: 8766},
	}
	if _, err := ValidateProfileContract(capsule, DefaultProfiles()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ProfileCapsule){
		func(value *ProfileCapsule) { value.Command = []string{"worker"} },
		func(value *ProfileCapsule) { value.State.Path = "/state" },
		func(value *ProfileCapsule) { value.Service.Port = 9000 },
	} {
		changed := capsule
		changed.Command = append([]string(nil), capsule.Command...)
		mutate(&changed)
		if _, err := ValidateProfileContract(changed, DefaultProfiles()); err == nil {
			t.Fatalf("drifted capsule accepted: %#v", changed)
		}
	}
}

func TestRuntimeProfileReferenceMatchesBuiltInRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../docs/reference/runtime-profiles.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range DefaultProfiles() {
		command, service := "Publisher-defined", "Publisher-defined"
		if len(profile.Command) != 0 {
			command = "`" + strings.Join(profile.Command, " ") + "`"
		}
		if profile.ServiceID != "" {
			service = fmt.Sprintf("`%s` on `%d`", profile.ServiceID, profile.ServicePort)
		}
		row := fmt.Sprintf("| `%s@%s` | `%d:%d` | `%s` (`%s`) | %s | %s |",
			profile.Ref.ID, profile.Ref.Version, profile.UID, profile.GID, profile.StatePath,
			profile.StateSchemaVersion, command, service)
		if !strings.Contains(string(raw), row) {
			t.Fatalf("runtime profile reference is missing exact row: %s", row)
		}
	}
}

func TestSignedOperationReferenceMatchesEnforcementSets(t *testing.T) {
	raw, err := os.ReadFile("../../docs/reference/api.md")
	if err != nil {
		t.Fatal(err)
	}
	operationList := func(values map[string]struct{}) string {
		operations := make([]string, 0, len(values))
		for operation := range values {
			operations = append(operations, operation)
		}
		slices.Sort(operations)
		for index := range operations {
			operations[index] = "`" + operations[index] + "`"
		}
		return strings.Join(operations, ", ")
	}
	flattened := strings.ReplaceAll(string(raw), "\n  ", " ")
	for label, operations := range map[string]map[string]struct{}{
		"Tenant operations":       commandOperations,
		"Site cleanup operations": cleanupCommandOperations,
	} {
		contract := "- " + label + ": " + operationList(operations) + "."
		if !strings.Contains(flattened, contract) {
			t.Fatalf("signed-operation reference is missing exact contract: %s", contract)
		}
	}
}

func TestRepositoryNameAllowsAirGapRegistryPortButNotTags(t *testing.T) {
	for _, valid := range []string{"busybox", "registry.local/agents/hermes", "127.0.0.1:5000/steward/agent"} {
		if !repositoryName(valid) {
			t.Fatalf("valid repository rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"https://registry/agent", "registry/agent:latest", "user@registry/agent", "registry:0/agent", "registry:70000/agent", "registry//agent"} {
		if repositoryName(invalid) {
			t.Fatalf("invalid repository accepted: %q", invalid)
		}
	}
}
