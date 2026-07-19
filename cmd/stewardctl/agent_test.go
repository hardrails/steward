package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/agentapp"
)

func TestAgentInitBuildAndPlanJSONWorkflow(t *testing.T) {
	directory := t.TempDir()
	var output bytes.Buffer
	if err := run([]string{"agent", "init", "-runtime", "openclaw", "-name", "auditor", directory}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cueRaw, err := os.ReadFile(filepath.Join(directory, "Stewardfile.cue"))
	if err != nil || !bytes.Contains(cueRaw, []byte(`adapter_contract: "steward.openclaw.v1"`)) {
		t.Fatalf("Stewardfile=%s err=%v", cueRaw, err)
	}
	definition := agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "auditor",
		Runtime:   agentapp.Runtime{Engine: "openclaw", Image: "example.invalid/openclaw@sha256:" + strings.Repeat("a", 64), AdapterContract: "steward.openclaw.v1"},
		Model:     agentapp.Model{Route: "local/default"},
		Resources: agentapp.Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256},
		Placement: agentapp.Placement{Architectures: []string{"amd64"}, Isolation: "hardened"},
		State:     agentapp.State{Persistent: true}, Lifetime: agentapp.Lifetime{Mode: "service"},
	}
	definitionRaw, _ := json.Marshal(definition)
	definitionPath := filepath.Join(directory, "agent.json")
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(definitionPath, definitionRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"agent", "build", "-file", definitionPath, "-out", bundlePath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"runtime":"openclaw"`) {
		t.Fatalf("build output=%s", output.String())
	}
	inventory := agentapp.NodeInventory{Schema: agentapp.InventorySchema, Nodes: []agentapp.Node{{
		ID: "node-1", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "hardened",
		Capacity: agentapp.Resources{CPUMillis: 4000, MemoryMiB: 8192, DiskMiB: 10000, PIDs: 1024},
	}}}
	inventoryRaw, _ := json.Marshal(inventory)
	inventoryPath := filepath.Join(directory, "nodes.json")
	if err := os.WriteFile(inventoryPath, inventoryRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"agent", "plan", "-bundle", bundlePath, "-nodes", inventoryPath, "-tenant", "tenant-a"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"selected_node":"node-1"`) {
		t.Fatalf("plan output=%s", output.String())
	}
}

func TestAgentPlanReturnsExplanationsWhenUnschedulable(t *testing.T) {
	directory := t.TempDir()
	definition := agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "secure-agent",
		Runtime: agentapp.Runtime{Engine: "hermes", Image: "example.invalid/hermes@sha256:" + strings.Repeat("a", 64), AdapterContract: "steward.hermes-agent.v1"},
		Model:   agentapp.Model{Route: "local/default"}, Resources: agentapp.Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256},
		Placement: agentapp.Placement{Architectures: []string{"amd64"}, Isolation: "hardened"}, State: agentapp.State{}, Lifetime: agentapp.Lifetime{Mode: "task"},
	}
	bundle, _ := agentapp.Build(definition, nil)
	bundleRaw, _ := agentapp.MarshalCanonical(bundle)
	inventory := agentapp.NodeInventory{Schema: agentapp.InventorySchema, Nodes: []agentapp.Node{{ID: "mac-dev", Ready: true, Tenants: []string{"tenant-a"}, Architecture: "amd64", Isolation: "development", Capacity: agentapp.Resources{CPUMillis: 4000, MemoryMiB: 4096, DiskMiB: 4096, PIDs: 512}}}}
	inventoryRaw, _ := json.Marshal(inventory)
	bundlePath, nodesPath := filepath.Join(directory, "bundle.json"), filepath.Join(directory, "nodes.json")
	_ = os.WriteFile(bundlePath, bundleRaw, 0o600)
	_ = os.WriteFile(nodesPath, inventoryRaw, 0o600)
	var output bytes.Buffer
	err := run([]string{"agent", "plan", "-bundle", bundlePath, "-nodes", nodesPath, "-tenant", "tenant-a"}, &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(output.String(), "hardened_isolation_required") {
		t.Fatalf("output=%s err=%v", output.String(), err)
	}
}

func TestAgentDoctorAndCompletion(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"agent", "doctor"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"architecture"`) || !strings.Contains(output.String(), `"profile"`) {
		t.Fatalf("doctor=%s", output.String())
	}
	candidates := stewardctlCompletionCandidates([]string{"stewardctl", "agent", ""})
	if !containsString(candidates, "build") || !containsString(candidates, "fork") {
		t.Fatalf("candidates=%v", candidates)
	}
}

func TestAgentInitForceDoesNotFollowSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	project := filepath.Join(directory, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(project, "Stewardfile.cue")); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{"agent", "init", "-force", project}, &output, &bytes.Buffer{})
	if err == nil {
		t.Fatal("force followed a symlink")
	}
	raw, readErr := os.ReadFile(target)
	if readErr != nil || string(raw) != "keep" {
		t.Fatalf("target=%q err=%v", raw, readErr)
	}
}

func TestAgentInitRejectsInvalidNameBeforeWriting(t *testing.T) {
	directory := t.TempDir()
	var output bytes.Buffer
	if err := run([]string{"agent", "init", "-name", "Invalid Name", directory}, &output, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid project name accepted")
	}
	if _, err := os.Stat(filepath.Join(directory, "Stewardfile.cue")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid project wrote a file: %v", err)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
