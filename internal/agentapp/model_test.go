package agentapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
