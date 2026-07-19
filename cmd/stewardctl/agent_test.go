package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	if !containsString(candidates, "build") || !containsString(candidates, "apply") || !containsString(candidates, "fork") {
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
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: "hermes-a", PublisherKeyID: "publisher-a",
		Profile: admission.ProfileRef{ID: "hermes-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository: "example.invalid/hermes", ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			ConfigDigest: "sha256:" + strings.Repeat("b", 64), Platform: admission.Platform{OS: "linux", Architecture: "amd64"},
		},
		Command: []string{"/opt/hermes/run"},
		Resources: admission.ResourceLimits{
			MemoryBytes: 1024 << 20, CPUMillis: 1000, PIDs: 256,
		},
		Capabilities: admission.Capabilities{State: true, Inference: true, Service: true},
		State:        admission.StateShape{SchemaVersion: "v1", Path: "/opt/data"},
		Service:      admission.ServiceShape{ID: "hermes-api", Port: 8080},
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
			ServiceIDs: []string{"hermes-api"},
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
