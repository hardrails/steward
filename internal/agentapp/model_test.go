package agentapp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
)

func validDefinition() Definition {
	return Definition{
		Schema: DefinitionSchema, Name: "workspace-auditor",
		Runtime: Runtime{Engine: "hermes", Image: "example.invalid/hermes@sha256:" + strings.Repeat("a", 64), AdapterContract: "steward.hermes-agent.v1"},
		Model:   Model{Route: "local/default"}, Skills: []string{"workspace-audit"},
		Resources: Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256},
		Placement: Placement{Architectures: []string{"amd64"}, Isolation: "hardened", RequiredLabels: []Label{{Key: "zone", Value: "west"}}},
		State:     State{Persistent: true}, Lifetime: Lifetime{Mode: "service"},
	}
}

func TestBuildIsDeterministicAndTamperEvident(t *testing.T) {
	definition := validDefinition()
	first, err := Build(definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, _ := MarshalCanonical(first)
	secondRaw, _ := MarshalCanonical(second)
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("identical definitions produced different bundles")
	}
	first.Definition.Name = "changed"
	raw, _ := json.Marshal(first)
	if _, err := DecodeBundle(raw); err == nil || !strings.Contains(err.Error(), "source_digest") {
		t.Fatalf("tampered bundle error=%v", err)
	}
}

func TestToolProfilesRequireTheirExactPositiveCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		skills     []string
		connectors []string
		events     bool
		wantError  string
	}{
		{name: "workspace", profile: "workspace"},
		{name: "research", profile: "research", skills: []string{"steward-research"}, connectors: []string{"steward-research-search", "steward-research-extract"}, events: true},
		{name: "research missing events", profile: "research", skills: []string{"steward-research"}, connectors: []string{"steward-research-search", "steward-research-extract"}, wantError: "controller events"},
		{name: "developer codex", profile: "developer", skills: []string{"steward-coding-worker"}, connectors: []string{"steward-codex"}},
		{name: "developer claude", profile: "developer", skills: []string{"steward-coding-worker"}, connectors: []string{"steward-claude-code"}},
		{name: "developer missing worker", profile: "developer", skills: []string{"steward-coding-worker"}, wantError: "coding-worker connector"},
		{name: "unknown", profile: "browser", wantError: "tool_profile"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := validDefinition()
			definition.ToolProfile = test.profile
			definition.Skills = append(definition.Skills, test.skills...)
			definition.Capabilities.ConnectorIDs = append([]string(nil), test.connectors...)
			definition.Capabilities.ControllerEvents = test.events
			err := definition.Validate()
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error=%v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestBuildIntentJoinsPortableBundleToAuthenticatedAdmission(t *testing.T) {
	bundle, err := Build(validDefinition(), nil)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: "hermes-a", PublisherKeyID: "publisher-a",
		Profile: admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository: "example.invalid/hermes", ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			ConfigDigest: "sha256:" + strings.Repeat("b", 64), Platform: admission.Platform{OS: "linux", Architecture: "amd64"},
		},
		Command:      []string{"/opt/hermes/run"},
		Resources:    admission.ResourceLimits{MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256},
		Capabilities: admission.Capabilities{State: true, Inference: true, Service: true},
		State:        admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service:      admission.ServiceShape{ID: "hermes-api", Port: 8080},
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-a", PublicKey: base64.StdEncoding.EncodeToString(public),
			AllowedProfiles:     []admission.ProfileRef{{ID: "hermes-v1", Version: "v1"}},
			AllowedRepositories: []string{"example.invalid/hermes"},
			ResourceCeiling:     admission.ResourceLimits{MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256},
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-a"},
			ResourceCeiling:   admission.ResourceLimits{MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256},
			InferenceRouteIDs: []string{"local"}, InferenceModelAliases: []string{"default"},
			ServiceIDs: []string{"hermes-api"},
		}},
	}
	verified := admission.VerifiedCapsuleImport{
		Capsule: capsule, SitePolicy: policy, Profile: admission.DefaultProfiles()[1],
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
		PublisherKeyID: "publisher-a", SiteRootKeyID: "site-root",
	}
	intent, err := BuildIntent(bundle, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if intent.InferenceRouteID != "local" || intent.ModelAlias != "default" || intent.ServiceID != "hermes-api" ||
		intent.StateDisposition != "new" || intent.CapsuleDigest != verified.CapsuleDigest {
		t.Fatalf("intent=%#v", intent)
	}
	lowerResources := bundle
	lowerResources.Definition.Resources.MemoryMiB = 512
	lowerResources.SourceDigest, _ = DigestJSON(lowerResources.Definition)
	if _, err := BuildIntent(lowerResources, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err != nil {
		t.Fatalf("resources below capsule ceiling were rejected: %v", err)
	}

	tampered := bundle
	tampered.Definition.Runtime.Image = "example.invalid/other@sha256:" + strings.Repeat("a", 64)
	tampered.SourceDigest, _ = DigestJSON(tampered.Definition)
	if _, err := BuildIntent(tampered, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil ||
		!strings.Contains(err.Error(), "image") {
		t.Fatalf("mismatched image error=%v", err)
	}
	if _, err := BuildIntent(bundle, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 0); err == nil {
		t.Fatal("zero generation accepted")
	}
	invalidBundle := bundle
	invalidBundle.Definition.Name = ""
	if _, err := BuildIntent(invalidBundle, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil {
		t.Fatal("invalid agent bundle accepted")
	}
	wrongProfile := verified
	wrongProfile.Capsule.Profile.ID = "hermes-research-v1"
	if _, err := BuildIntent(bundle, wrongProfile, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil {
		t.Fatal("mismatched capsule profile accepted")
	}
	wrongService := verified
	wrongService.Capsule.Service.Port = 0
	if _, err := BuildIntent(bundle, wrongService, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil {
		t.Fatal("missing capsule service accepted")
	}
	excess := bundle
	excess.Definition.Capabilities.ControllerEvents = true
	excess.SourceDigest, _ = DigestJSON(excess.Definition)
	if _, err := BuildIntent(excess, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil {
		t.Fatal("capability above capsule ceiling accepted")
	}
	denied := verified
	denied.SitePolicy.Tenants = append([]admission.TenantRule(nil), verified.SitePolicy.Tenants...)
	denied.SitePolicy.Tenants[0].InferenceRouteIDs = nil
	if _, err := BuildIntent(bundle, denied, "tenant-a", "node-a", "agent-a", "lineage-a", 1); err == nil {
		t.Fatal("site policy inference denial accepted")
	}
	resumed := bundle
	resumed.Definition.State.SnapshotID = "snapshot-a"
	resumed.SourceDigest, _ = DigestJSON(resumed.Definition)
	resumeIntent, err := BuildIntent(resumed, verified, "tenant-a", "node-a", "agent-a", "lineage-a", 1)
	if err != nil || resumeIntent.StateDisposition != "resume" {
		t.Fatalf("resume intent=(%+v, %v)", resumeIntent, err)
	}
	for name, policy := range map[string]admission.SitePolicy{
		"optional": {Tenants: []admission.TenantRule{{TenantID: "tenant-a", AuthorizedEffects: &admission.AuthorizedEffectsPolicy{Mode: admission.AuthorizedEffectsOptional}}}},
		"required": {Tenants: []admission.TenantRule{{TenantID: "tenant-a", AuthorizedEffects: &admission.AuthorizedEffectsPolicy{Mode: admission.AuthorizedEffectsRequired}}}},
	} {
		if mode, err := defaultEffectMode(policy, "tenant-a"); err != nil || mode == "" {
			t.Fatalf("%s effect mode=(%q, %v)", name, mode, err)
		}
	}
	invalidEffects := admission.SitePolicy{Tenants: []admission.TenantRule{{
		TenantID: "tenant-a", AuthorizedEffects: &admission.AuthorizedEffectsPolicy{Mode: "invalid"},
	}}}
	if _, err := defaultEffectMode(invalidEffects, "tenant-a"); err == nil {
		t.Fatal("invalid authorized-effects policy accepted")
	}
	if _, err := defaultEffectMode(admission.SitePolicy{}, "tenant-a"); err == nil {
		t.Fatal("missing tenant policy accepted")
	}
}

func TestDecodeDefinitionRejectsUnknownDuplicateAndUnpinned(t *testing.T) {
	definition := validDefinition()
	raw, _ := json.Marshal(definition)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"name":`), []byte(`"unknown":1,"name":`), 1)
		},
		"duplicate": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"name":`), []byte(`"name":"other","name":`), 1)
		},
		"unpinned": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`example.invalid/hermes@sha256:`+strings.Repeat("a", 64)), []byte(`example.invalid/hermes:latest`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDefinition(mutate(raw)); err == nil {
				t.Fatal("malformed definition accepted")
			}
		})
	}
}

func TestScheduleFiltersAndScoresDeterministically(t *testing.T) {
	bundle, _ := Build(validDefinition(), nil)
	base := Resources{CPUMillis: 8000, MemoryMiB: 16384, DiskMiB: 100000, PIDs: 4096}
	inventory := NodeInventory{Schema: InventorySchema, Nodes: []Node{
		{ID: "node-z", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "hardened", Labels: []Label{{Key: "zone", Value: "west"}}, Capacity: base, ActiveAgents: 2},
		{ID: "node-a", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "hardened", Labels: []Label{{Key: "zone", Value: "west"}}, Capacity: base, Images: []string{bundle.Definition.Runtime.Image}, ActiveAgents: 20},
		{ID: "node-dev", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "development", Labels: []Label{{Key: "zone", Value: "west"}}, Capacity: base},
	}}
	raw, _ := json.Marshal(inventory)
	decoded, err := DecodeInventory(raw)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Schedule(bundle, "tenant-a", decoded)
	if err != nil {
		t.Fatal(err)
	}
	if decision.SelectedNode != "node-a" {
		t.Fatalf("selected=%q candidates=%#v", decision.SelectedNode, decision.Candidates)
	}
	if decision.Candidates[1].NodeID != "node-dev" || decision.Candidates[1].Eligible {
		t.Fatalf("development node was not rejected: %#v", decision.Candidates)
	}
	second, _ := Schedule(bundle, "tenant-a", decoded)
	left, _ := MarshalCanonical(decision)
	right, _ := MarshalCanonical(second)
	if !bytes.Equal(left, right) {
		t.Fatal("scheduler is not deterministic")
	}
}

func TestForkCreatesFreshBoundedLineage(t *testing.T) {
	bundle, _ := Build(validDefinition(), nil)
	digest, _ := DigestJSON(bundle)
	snapshot := Snapshot{Schema: SnapshotSchema, ID: "snap-1", BundleDigest: digest, RuntimeEngine: "hermes", StateDigest: "sha256:" + strings.Repeat("b", 64), SourceLineage: "lineage-old", CreatedAt: "2026-07-18T00:00:00Z"}
	plan, err := Fork(bundle, snapshot, "agent-fork-1", "lineage-new", time.Hour, "destroy", time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Generation != 1 || plan.ExpiresAt != "2026-07-18T02:00:00Z" || plan.LineageID == snapshot.SourceLineage {
		t.Fatalf("plan=%#v", plan)
	}
	if _, err := Fork(bundle, snapshot, "agent-fork-1", snapshot.SourceLineage, time.Hour, "destroy", time.Now()); err == nil {
		t.Fatal("source lineage reused")
	}
}

func TestLoadDefinitionAndOPAUseBoundedExternalTools(t *testing.T) {
	directory := t.TempDir()
	definition := validDefinition()
	raw, _ := json.Marshal(definition)
	definitionPath := filepath.Join(directory, "Stewardfile.cue")
	if err := os.WriteFile(definitionPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	cue := filepath.Join(directory, "cue")
	if err := os.WriteFile(cue, []byte("#!/bin/sh\nprintf '%s' '"+string(raw)+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDefinition(context.Background(), definitionPath, cue)
	if err != nil || loaded.Name != definition.Name {
		t.Fatalf("definition=%#v err=%v", loaded, err)
	}
	bundlePath := filepath.Join(directory, "policy.tar.gz")
	if err := os.WriteFile(bundlePath, []byte("offline-policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	opa := filepath.Join(directory, "opa")
	if err := os.WriteFile(opa, []byte("#!/bin/sh\nprintf true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	evidence, err := EvaluateOPA(context.Background(), opa, bundlePath, "data.steward.agent.allow", raw)
	if err != nil || !evidence.Allowed || !validDigest(evidence.BundleDigest) {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
	if err := os.WriteFile(opa, []byte("#!/bin/sh\nprintf false\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateOPA(context.Background(), opa, bundlePath, "data.steward.agent.allow", raw); err == nil {
		t.Fatal("OPA denial accepted")
	}
}

func TestReadBoundedRegularRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedRegular(link, 10); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestDefinitionValidationRejectsEveryAuthorityShape(t *testing.T) {
	tooMany := make([]string, 65)
	for index := range tooMany {
		tooMany[index] = "skill-" + strings.Repeat("x", index%4) + string(rune('a'+index%26))
	}
	tests := map[string]func(*Definition){
		"schema":                   func(v *Definition) { v.Schema = "other" },
		"name":                     func(v *Definition) { v.Name = "UPPER" },
		"engine contract":          func(v *Definition) { v.Runtime.AdapterContract = "wrong" },
		"model":                    func(v *Definition) { v.Model.Route = "" },
		"resources":                func(v *Definition) { v.Resources.MemoryMiB = 1 },
		"architectures empty":      func(v *Definition) { v.Placement.Architectures = nil },
		"architecture unsupported": func(v *Definition) { v.Placement.Architectures = []string{"s390x"} },
		"architecture duplicate":   func(v *Definition) { v.Placement.Architectures = []string{"amd64", "amd64"} },
		"isolation":                func(v *Definition) { v.Placement.Isolation = "magic" },
		"required labels": func(v *Definition) {
			v.Placement.RequiredLabels = []Label{{Key: "same", Value: "a"}, {Key: "same", Value: "b"}}
		},
		"preferred labels": func(v *Definition) { v.Placement.PreferredLabels = []Label{{Key: "", Value: "a"}} },
		"spread":           func(v *Definition) { v.Placement.SpreadBy = " bad" },
		"list limit":       func(v *Definition) { v.Skills = tooMany },
		"list duplicate":   func(v *Definition) { v.MCP = []string{"server", "server"} },
		"egress route":     func(v *Definition) { v.Capabilities.EgressRouteIDs = []string{"https://example.com"} },
		"connector duplicate": func(v *Definition) {
			v.Capabilities.ConnectorIDs = []string{"calendar", "calendar"}
		},
		"snapshot":         func(v *Definition) { v.State.Persistent = false; v.State.SnapshotID = "snap" },
		"task expiry":      func(v *Definition) { v.Lifetime = Lifetime{Mode: "task", TTLSeconds: 60} },
		"temporary expiry": func(v *Definition) { v.Lifetime = Lifetime{Mode: "temporary", TTLSeconds: 1, OnExpiry: "retain"} },
		"lifetime":         func(v *Definition) { v.Lifetime = Lifetime{Mode: "forever"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validDefinition()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid definition accepted")
			}
		})
	}
}

func TestInventoryAndScheduleRejectMalformedOrIneligibleNodes(t *testing.T) {
	base := Node{ID: "node-1", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "hardened", Capacity: Resources{CPUMillis: 4000, MemoryMiB: 4096, DiskMiB: 4096, PIDs: 512}}
	tests := map[string]func(*NodeInventory){
		"schema":       func(v *NodeInventory) { v.Schema = "other" },
		"duplicate":    func(v *NodeInventory) { v.Nodes = append(v.Nodes, v.Nodes[0]) },
		"architecture": func(v *NodeInventory) { v.Nodes[0].Architecture = "s390x" },
		"isolation":    func(v *NodeInventory) { v.Nodes[0].Isolation = "unknown" },
		"labels":       func(v *NodeInventory) { v.Nodes[0].Labels = []Label{{Key: "", Value: "x"}} },
		"list":         func(v *NodeInventory) { v.Nodes[0].Taints = make([]string, 257) },
		"identifier":   func(v *NodeInventory) { v.Nodes[0].Images = []string{" bad"} },
		"capacity":     func(v *NodeInventory) { v.Nodes[0].Allocated.CPUMillis = 5000 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			inventory := NodeInventory{Schema: InventorySchema, Nodes: []Node{base}}
			mutate(&inventory)
			raw, _ := json.Marshal(inventory)
			if _, err := DecodeInventory(raw); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	bundle, _ := Build(validDefinition(), nil)
	decision, err := Schedule(bundle, "tenant-a", NodeInventory{Schema: InventorySchema, Nodes: []Node{{ID: "node-1", Ready: false, Tenants: []string{"other"}, Architecture: "arm64", Isolation: "development", Capacity: base.Capacity, Taints: []string{"reserved"}}}})
	if err == nil || decision.SelectedNode != "" || len(decision.Candidates[0].Reasons) < 4 {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if _, err := Schedule(bundle, " bad", NodeInventory{}); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	tampered := bundle
	tampered.SourceDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := Schedule(tampered, "tenant-a", NodeInventory{Schema: InventorySchema, Nodes: []Node{base}}); err == nil {
		t.Fatal("direct tampered bundle accepted")
	}
	if _, err := Schedule(bundle, "tenant-a", NodeInventory{}); err == nil {
		t.Fatal("direct invalid inventory accepted")
	}
}

func TestDecodeSnapshotAndForkFailures(t *testing.T) {
	bundle, _ := Build(validDefinition(), nil)
	digest, _ := DigestJSON(bundle)
	snapshot := Snapshot{Schema: SnapshotSchema, ID: "snap-1", BundleDigest: digest, RuntimeEngine: "hermes", StateDigest: "sha256:" + strings.Repeat("b", 64), SourceLineage: "old", CreatedAt: "2026-07-18T00:00:00Z"}
	raw, _ := json.Marshal(snapshot)
	decoded, err := DecodeSnapshot(raw)
	if err != nil || decoded.ID != "snap-1" {
		t.Fatalf("snapshot=%#v err=%v", decoded, err)
	}
	snapshot.CreatedAt = "yesterday"
	raw, _ = json.Marshal(snapshot)
	if _, err := DecodeSnapshot(raw); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
	snapshot.CreatedAt = "2026-07-18T00:00:00Z"
	snapshot.BundleDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := Fork(bundle, snapshot, "new-agent", "new-lineage", 0, "", time.Now()); err == nil {
		t.Fatal("incompatible snapshot accepted")
	}
	snapshot.BundleDigest = digest
	invalid := snapshot
	invalid.Schema = "other"
	if _, err := Fork(bundle, invalid, "new-agent", "new-lineage", 0, "", time.Now()); err == nil {
		t.Fatal("direct invalid snapshot accepted")
	}
	if _, err := Fork(bundle, snapshot, "new-agent", "new-lineage", 0, "destroy", time.Now()); err == nil {
		t.Fatal("expiry without TTL accepted")
	}
	if _, err := Fork(bundle, snapshot, "new-agent", "new-lineage", time.Second, "destroy", time.Now()); err == nil {
		t.Fatal("short TTL accepted")
	}
	if _, err := Fork(bundle, snapshot, "new-agent", "new-lineage", time.Hour, "hibernate", time.Now()); err == nil {
		t.Fatal("unsupported fork hibernation accepted")
	}
}

func TestForkPlanStrictDecodingAndValidation(t *testing.T) {
	valid := ForkPlan{
		Schema: ForkSchema, SnapshotID: "snapshot-a", BundleDigest: "sha256:" + strings.Repeat("a", 64),
		InstanceID: "fork-a", LineageID: "lineage-fork", SourceLineageID: "lineage-source", Generation: 1,
		ExpiresAt: "2026-07-21T12:00:00Z", OnExpiry: "destroy",
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeForkPlan(raw); err != nil || decoded != valid {
		t.Fatalf("decode fork plan = (%+v, %v)", decoded, err)
	}
	if _, err := DecodeForkPlan(append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)); err == nil {
		t.Fatal("fork plan with unknown field was accepted")
	}
	for name, mutate := range map[string]func(*ForkPlan){
		"schema":         func(value *ForkPlan) { value.Schema = "other" },
		"snapshot":       func(value *ForkPlan) { value.SnapshotID = "bad snapshot" },
		"bundle":         func(value *ForkPlan) { value.BundleDigest = "bad" },
		"instance":       func(value *ForkPlan) { value.InstanceID = "" },
		"lineage":        func(value *ForkPlan) { value.LineageID = value.SourceLineageID },
		"source lineage": func(value *ForkPlan) { value.SourceLineageID = "" },
		"generation":     func(value *ForkPlan) { value.Generation = 0 },
		"expiry":         func(value *ForkPlan) { value.ExpiresAt = "not-a-time" },
		"action":         func(value *ForkPlan) { value.OnExpiry = "hibernate" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid fork plan accepted: %+v", candidate)
			}
		})
	}
	withoutExpiry := valid
	withoutExpiry.ExpiresAt = ""
	if err := withoutExpiry.Validate(); err == nil {
		t.Fatal("fork expiry action without expiry was accepted")
	}
	withoutExpiry.OnExpiry = ""
	if err := withoutExpiry.Validate(); err != nil {
		t.Fatalf("durable fork plan rejected: %v", err)
	}
}

func TestToolBoundaryErrorPathsAndSanitization(t *testing.T) {
	if got := sanitizeToolError([]byte("bad\x1b[31m\nline\x00")); strings.ContainsAny(got, "\x1b\x00\n") || !strings.Contains(got, "bad?") {
		t.Fatalf("sanitized=%q", got)
	}
	writer := &limitedBuffer{maximum: 3}
	if _, err := writer.Write([]byte("abcd")); err == nil || !writer.overflow || string(writer.Bytes()) != "abc" {
		t.Fatalf("writer=%#v err=%v", writer, err)
	}
	if _, err := LoadDefinition(context.Background(), filepath.Join(t.TempDir(), "missing.json"), ""); err == nil {
		t.Fatal("missing JSON accepted")
	}
	if _, err := EvaluateOPA(context.Background(), "missing-opa", "bundle", "not-data", []byte("{}")); err == nil {
		t.Fatal("invalid query accepted")
	}
	if _, err := EvaluateOPA(context.Background(), "missing-opa", "bundle", "data.steward.allow", nil); err == nil {
		t.Fatal("empty input accepted")
	}
}
