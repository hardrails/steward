package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAgentInitBuildAndPlanJSONWorkflow(t *testing.T) {
	directory := t.TempDir()
	var output bytes.Buffer
	if err := run([]string{"agent", "init", "-runtime", "hermes", "-name", "auditor", directory}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cueRaw, err := os.ReadFile(filepath.Join(directory, "Stewardfile.cue"))
	if err != nil || !bytes.Contains(cueRaw, []byte(`adapter_contract: "steward.hermes-agent.v1"`)) {
		t.Fatalf("Stewardfile=%s err=%v", cueRaw, err)
	}
	output.Reset()
	if err := run([]string{"agent", "init", "-force", "-runtime", "hermes", "-name", "auditor", directory}, &output, &bytes.Buffer{}); err != nil {
		t.Fatalf("force init: %v", err)
	}
	definition := agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "auditor",
		Runtime:   agentapp.Runtime{Engine: "hermes", Image: "example.invalid/hermes@sha256:" + strings.Repeat("a", 64), AdapterContract: "steward.hermes-agent.v1"},
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
	if err := run([]string{"agent", "validate", "-file", definitionPath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"valid":true`) ||
		!strings.Contains(output.String(), `"name":"auditor"`) {
		t.Fatalf("validate output=%s", output.String())
	}
	output.Reset()
	if err := run([]string{"agent", "build", "-file", definitionPath, "-out", bundlePath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"runtime":"hermes"`) {
		t.Fatalf("build output=%s", output.String())
	}
	policyPath := filepath.Join(directory, "policy.tar.gz")
	opaPath := filepath.Join(directory, "opa")
	policyBundlePath := filepath.Join(directory, "agent.policy.bundle.json")
	if err := os.WriteFile(policyPath, []byte("offline-policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opaPath, []byte("#!/bin/sh\nprintf true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{
		"agent", "build", "-file", definitionPath, "-out", policyBundlePath,
		"-policy-bundle", policyPath, "-opa", opaPath,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"policy_evaluated":true`) {
		t.Fatalf("policy build output=%s", output.String())
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

	bundleRaw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := agentapp.DigestJSON(bundle)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := agentapp.Snapshot{
		Schema: agentapp.SnapshotSchema, ID: "snapshot-a", BundleDigest: bundleDigest,
		RuntimeEngine: "hermes", StateDigest: "sha256:" + strings.Repeat("b", 64),
		SourceNodeID: "node-a", SourceLineage: "lineage-parent", CreatedAt: "2026-07-19T12:00:00Z",
	}
	snapshotRaw, _ := json.Marshal(snapshot)
	snapshotPath := filepath.Join(directory, "snapshot.json")
	forkPath := filepath.Join(directory, "fork.json")
	if err := os.WriteFile(snapshotPath, snapshotRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{
		"agent", "fork", "forked-auditor", "-bundle", bundlePath, "-snapshot", snapshotPath,
		"-instance-id", "auditor-fork", "-lineage-id", "lineage-fork",
		"-ttl", "1h", "-out", forkPath,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"instance_id":"auditor-fork"`) {
		t.Fatalf("fork output=%s", output.String())
	}
	forkRaw, err := os.ReadFile(forkPath)
	if err != nil {
		t.Fatal(err)
	}
	var fork agentapp.ForkPlan
	if err := json.Unmarshal(forkRaw, &fork); err != nil || fork.OnExpiry != "destroy" || fork.ExpiresAt == "" ||
		fork.DeploymentID != "forked-auditor" || fork.SourceNodeID != "node-a" || fork.SourceLineageID != "lineage-parent" {
		t.Fatalf("fork plan=%s err=%v", forkRaw, err)
	}
	generatedForkPath := filepath.Join(directory, "generated-fork.json")
	output.Reset()
	if err := run([]string{
		"agent", "fork", "-bundle", bundlePath, "-snapshot", snapshotPath,
		"-out", generatedForkPath,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"instance_id":"agent-`) ||
		!strings.Contains(output.String(), `"lineage_id":"lineage-`) {
		t.Fatalf("generated fork output=%s", output.String())
	}
}

func TestAgentCreateUsesTheCanonicalInitPath(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "auditor")
	var output bytes.Buffer
	if err := run([]string{"agent", "create", "auditor", "-runtime", "hermes", directory}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "Stewardfile.cue"))
	if err != nil || !bytes.Contains(raw, []byte(`name: "auditor"`)) ||
		!bytes.Contains(raw, []byte(`engine: "hermes"`)) {
		t.Fatalf("Stewardfile=%s err=%v", raw, err)
	}
	if err := run([]string{"agent", "create", "auditor", "-name", "other", directory}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("agent create accepted two names")
	}
}

func TestAgentCreateDefaultsToSameNamedProjectDirectory(t *testing.T) {
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	var output bytes.Buffer
	if err := run([]string{"agent", "create", "auditor", "-runtime", "hermes"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "auditor", "Stewardfile.cue"))
	if err != nil || !bytes.Contains(raw, []byte(`name: "auditor"`)) ||
		!bytes.Contains(raw, []byte(`engine: "hermes"`)) {
		t.Fatalf("Stewardfile=%s err=%v", raw, err)
	}
	if strings.Contains(output.String(), `"file":"Stewardfile.cue"`) {
		t.Fatalf("agent create reported the expert current-directory default: %s", output.String())
	}
}

func TestAgentTemplatesExposeAndRenderEnforcedCapabilityPresets(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"agent", "template", "list"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, template := range []string{`"id":"workspace"`, `"id":"research"`, `"id":"developer"`} {
		if !strings.Contains(output.String(), template) {
			t.Fatalf("template list omitted %s: %s", template, output.String())
		}
	}
	output.Reset()
	if err := run([]string{"agent", "template", "show", "research"}, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"tool_profile":"research"`) {
		t.Fatalf("research template=%s err=%v", output.String(), err)
	}
	directory := filepath.Join(t.TempDir(), "researcher")
	output.Reset()
	if err := run([]string{
		"agent", "create", "researcher", "-template", "research", directory,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "Stewardfile.cue"))
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range []string{
		`tool_profile: "research"`,
		`skills: ["steward-research"]`,
		`"steward-browser-search"`,
		`"steward-research-extract"`,
		`controller_events: true`,
		`memory_mib: 4096`,
	} {
		if !bytes.Contains(raw, []byte(binding)) {
			t.Fatalf("research Stewardfile omitted %q:\n%s", binding, raw)
		}
	}
	if err := run([]string{
		"agent", "create", "invalid", "-template", "unknown", filepath.Join(t.TempDir(), "invalid"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown agent template was accepted")
	}
}

func TestAgentValidateAndForkRejectAmbiguousArguments(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(existing, "Stewardfile.cue"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(directory, "snapshot.json")
	if err := os.WriteFile(snapshot, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		arguments []string
		message   string
	}{
		{[]string{"agent"}, "agent requires"},
		{[]string{"agent", "unknown"}, "unknown agent command"},
		{[]string{"agent", "init", "-runtime", "unknown"}, "runtime must be"},
		{[]string{"agent", "init", "-runtime", "openclaw"}, "runtime must be hermes"},
		{[]string{"agent", "init", "-name", "INVALID"}, "agent name"},
		{[]string{"agent", "init", "one", "two"}, "at most one"},
		{[]string{"agent", "init", existing}, "already exists"},
		{[]string{"agent", "validate", "-file", filepath.Join(directory, "missing.json")}, "no such file"},
		{[]string{"agent", "validate", "extra"}, "only named flags"},
		{[]string{"agent", "build", "extra"}, "only named flags"},
		{[]string{"agent", "build", "-file", filepath.Join(directory, "missing.json")}, "no such file"},
		{[]string{"agent", "plan", "extra"}, "only named flags"},
		{[]string{"agent", "plan", "-bundle", filepath.Join(directory, "missing.json")}, "no such file"},
		{[]string{"agent", "fork"}, "requires -snapshot"},
		{[]string{"agent", "fork", "-snapshot", snapshot, "-bundle", filepath.Join(directory, "missing.json")}, "no such file"},
		{[]string{"agent", "doctor", "extra"}, "accepts no arguments"},
	} {
		if err := run(test.arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
			!strings.Contains(err.Error(), test.message) {
			t.Fatalf("run %v error = %v", test.arguments, err)
		}
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
	if !containsString(candidates, "build") || !containsString(candidates, "apply") ||
		!containsString(candidates, "deploy") || !containsString(candidates, "fork") {
		t.Fatalf("candidates=%v", candidates)
	}
}

func TestAgentApplyAdmitsAndStartsAuthenticatedBundle(t *testing.T) {
	directory := t.TempDir()
	definition := agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "auditor",
		Runtime: agentapp.Runtime{
			Engine: "hermes", Image: "example.invalid/hermes@sha256:" + strings.Repeat("a", 64),
			AdapterContract: "steward.hermes-agent.v1",
		},
		Model:     agentapp.Model{Route: "local/default"},
		Resources: agentapp.Resources{CPUMillis: 1000, MemoryMiB: 1024, DiskMiB: 2048, PIDs: 256},
		Placement: agentapp.Placement{Architectures: []string{"amd64"}, Isolation: "hardened"},
		State:     agentapp.State{Persistent: true}, Lifetime: agentapp.Lifetime{Mode: "service"},
	}
	bundle, err := agentapp.Build(definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, _ := agentapp.MarshalCanonical(bundle)
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	publisherPublic, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	commandPublic, commandPrivate, err := ed25519.GenerateKey(rand.Reader)
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
		Command: []string{"serve"},
		Resources: admission.ResourceLimits{
			MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256,
		},
		Capabilities: admission.Capabilities{State: true, Inference: true, Service: true},
		State:        admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service:      admission.ServiceShape{ID: "hermes-api", Port: 8766},
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-a", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{{ID: "hermes-v1", Version: "v1"}},
			AllowedRepositories: []string{"example.invalid/hermes"},
			ResourceCeiling:     admission.ResourceLimits{MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256},
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-a"},
			ResourceCeiling:   admission.ResourceLimits{MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256},
			InferenceRouteIDs: []string{"local"}, InferenceModelAliases: []string{"default"},
			ServiceIDs: []string{"hermes-api"}, CommandKeys: []admission.CommandKey{{
				KeyID: "command-a", PublicKey: base64.StdEncoding.EncodeToString(commandPublic),
				Operations: []string{"admit", "start"},
			}},
		}},
	}
	capsulePath := writeAgentSignedJSON(t, directory, "capsule.dsse.json", admission.CapsulePayloadType, capsule, "publisher-a", publisherPrivate)
	policyPath := writeAgentSignedJSON(t, directory, "policy.dsse.json", admission.PolicyPayloadType, policy, "site-root", rootPrivate)
	rootPath := filepath.Join(directory, "site-root.pub")
	if err := os.WriteFile(rootPath, []byte(base64.StdEncoding.EncodeToString(rootPublic)), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "executor.token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runtimeRef := "executor-" + strings.Repeat("c", 64)
	requests := make([]string, 0, 2)
	admissions := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
		}
		requests = append(requests, request.Method+" "+request.URL.Path)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/admissions":
			admissions++
			status := "created"
			if admissions > 1 {
				status = "running"
			}
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"` + status + `"}`))
		case "/v1/workloads/" + runtimeRef + "/start":
			_, _ = response.Write([]byte(`{"runtime_ref":"` + runtimeRef + `","status":"running"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	priorNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = priorNow })
	var output bytes.Buffer
	err = run([]string{
		"agent", "apply", "-bundle", bundlePath, "-capsule", capsulePath, "-policy", policyPath,
		"-site-root-public-key", rootPath, "-site-root-key-id", "site-root", "-tenant", "tenant-a",
		"-node-id", "node-a", "-node-url", server.URL, "-token-file", tokenPath,
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"running"`) || !strings.Contains(output.String(), runtimeRef) {
		t.Fatalf("output=%s", output.String())
	}
	if strings.Join(requests, ",") != "POST /v1/admissions,POST /v1/workloads/"+runtimeRef+"/start" {
		t.Fatalf("requests=%v", requests)
	}
	var first agentApplyResult
	if err := json.Unmarshal(output.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err = run([]string{
		"agent", "apply", "-bundle", bundlePath, "-capsule", capsulePath, "-policy", policyPath,
		"-site-root-public-key", rootPath, "-site-root-key-id", "site-root", "-tenant", "tenant-a",
		"-node-id", "node-a", "-node-url", server.URL, "-token-file", tokenPath,
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var second agentApplyResult
	if err := json.Unmarshal(output.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if first.LineageID == "" || first.LineageID != second.LineageID {
		t.Fatalf("first lineage=%q second lineage=%q", first.LineageID, second.LineageID)
	}
	if strings.Join(requests, ",") != "POST /v1/admissions,POST /v1/workloads/"+runtimeRef+"/start,POST /v1/admissions" {
		t.Fatalf("retry requests=%v", requests)
	}
	t.Run("deploy through control", func(t *testing.T) {
		testAgentDeployThroughControl(
			t, bundlePath, capsulePath, policyPath, rootPath, tokenPath,
			commandPublic, commandPrivate, runtimeRef,
		)
	})
}

func testAgentDeployThroughControl(
	t *testing.T,
	bundlePath, capsulePath, policyPath, rootPath, tokenPath string,
	commandPublic ed25519.PublicKey,
	commandPrivate ed25519.PrivateKey,
	runtimeRef string,
) {
	t.Helper()
	commandKeyPath := filepath.Join(t.TempDir(), "command.pem")
	writeAgentPrivateKey(t, commandKeyPath, commandPrivate)
	capsuleRaw, err := os.ReadFile(capsulePath)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	statements := make(map[string]admission.CommandStatement)
	commandRaws := make(map[string][]byte)
	commandKinds := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("control authorization=%q", request.Header.Get("Authorization"))
		}
		if request.Method == http.MethodPost {
			var input struct {
				Command string `json:"command_dsse_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode submit: %v", err)
				return
			}
			raw, err := base64.StdEncoding.DecodeString(input.Command)
			if err != nil {
				t.Errorf("decode command: %v", err)
				return
			}
			payload, _, err := dsse.Verify(raw, admission.CommandPayloadType, map[string]ed25519.PublicKey{"command-a": commandPublic})
			if err != nil {
				t.Errorf("verify command: %v", err)
				return
			}
			var statement admission.CommandStatement
			if err := json.Unmarshal(payload, &statement); err != nil {
				t.Errorf("decode statement: %v", err)
				return
			}
			statements[statement.CommandID] = statement
			commandRaws[statement.CommandID] = raw
			commandKinds = append(commandKinds, statement.Kind)
			writeAgentControlCommand(response, statement, raw, runtimeRef, capsuleRaw, policyRaw, false)
			return
		}
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		commandID := parts[len(parts)-1]
		statement, ok := statements[commandID]
		if !ok {
			http.NotFound(response, request)
			return
		}
		writeAgentControlCommand(response, statement, commandRaws[commandID], runtimeRef, capsuleRaw, policyRaw, true)
	}))
	defer server.Close()

	var output bytes.Buffer
	err = run([]string{
		"agent", "deploy", "-bundle", bundlePath, "-capsule", capsulePath, "-policy", policyPath,
		"-site-root-public-key", rootPath, "-site-root-key-id", "site-root", "-tenant", "tenant-a",
		"-node-id", "node-a", "-control-url", server.URL, "-token-file", tokenPath,
		"-command-key", commandKeyPath, "-command-key-id", "command-a", "-timeout", "10s",
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"running"`) || !strings.Contains(output.String(), runtimeRef) {
		t.Fatalf("deploy output=%s", output.String())
	}
	if strings.Join(commandKinds, ",") != "admit,start" {
		t.Fatalf("command kinds=%v", commandKinds)
	}
}

func writeAgentControlCommand(
	response http.ResponseWriter,
	statement admission.CommandStatement,
	commandRaw []byte,
	runtimeRef string,
	capsuleRaw, policyRaw []byte,
	terminal bool,
) {
	value := map[string]any{
		"command_id": statement.CommandID, "delivery_id": "delivery-" + strings.Repeat("d", 64),
		"tenant_id": statement.TenantID, "node_id": statement.NodeID,
		"command_digest": dsse.Digest(commandRaw), "command_kind": statement.Kind,
		"signed_runtime_ref": statement.RuntimeRef, "signed_claim_generation": statement.ClaimGeneration,
		"signed_instance_generation": statement.InstanceGeneration, "state": "pending",
	}
	if terminal {
		value["state"] = "terminal"
		value["delivery_protocol"] = 4
		value["delivery_generation"] = 1
		value["terminal_status"] = "done"
		value["reported_status"] = "running"
		value["claim_generation"] = statement.ClaimGeneration
		value["result"] = map[string]any{"runtime_ref": runtimeRef}
		if statement.Kind == "admit" {
			value["reported_status"] = "stopped"
			value["admission_projection_state"] = "present"
			value["result"] = map[string]any{
				"runtime_ref": runtimeRef,
				"admission": map[string]any{
					"schema_version": "steward.executor-admission-projection.v1",
					"runtime_ref":    runtimeRef, "status": "created",
					"capsule_digest": dsse.Digest(capsuleRaw), "policy_digest": dsse.Digest(policyRaw),
					"generation": statement.InstanceGeneration, "evidence_key_id": strings.Repeat("e", 32),
				},
			}
		}
	}
	_ = json.NewEncoder(response).Encode(value)
}

func writeAgentPrivateKey(t *testing.T, path string, privateKey ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAgentSignedJSON(t *testing.T, directory, name, payloadType string, value any, keyID string, privateKey ed25519.PrivateKey) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(payloadType, payload, keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
