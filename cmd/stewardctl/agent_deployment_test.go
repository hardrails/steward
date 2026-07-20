package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestAgentDeploymentCommandsConvergeDesiredStateWithShortDefaults(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	previousNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousNow })

	directory := t.TempDir()
	bundle, err := agentapp.Build(agentapp.Definition{
		Schema: agentapp.DefinitionSchema, Name: "auditor",
		Runtime: agentapp.Runtime{
			Engine: "hermes", Image: "example.invalid/hermes@sha256:" + strings.Repeat("a", 64),
			AdapterContract: "steward.hermes-agent.v1",
		},
		Model:     agentapp.Model{Route: "local/default"},
		Resources: agentapp.Resources{CPUMillis: 500, MemoryMiB: 512, DiskMiB: 1024, PIDs: 128},
		Placement: agentapp.Placement{Architectures: []string{"amd64"}, Isolation: "hardened"},
		State:     agentapp.State{Persistent: true}, Lifetime: agentapp.Lifetime{Mode: "service"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundleRaw, _ := agentapp.MarshalCanonical(bundle)
	bundleDigest, _ := agentapp.DigestJSON(bundle)
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	capsuleEnvelope, err := dsse.Sign(admission.CapsulePayloadType, []byte(`{}`), "publisher-a", signer)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, _ := json.Marshal(capsuleEnvelope)
	controllerPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1, DelegationID: "auditor-authority",
		TenantID: "tenant-a", ControllerKeyID: "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "destroy", "start", "stop"}, NodeIDs: []string{"node-a"},
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: "auditor-0", LineageID: "auditor-lineage", MinInstanceGeneration: 1, MaxInstanceGeneration: 2,
		}},
		ClaimGeneration: 1,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest:    dsse.Digest(capsuleRaw),
			Resources:        admission.ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 500, PIDs: 128},
			StateDisposition: "none",
		},
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	delegationPayload, err := admission.MarshalCommandDelegation(delegation)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := dsse.Sign(admission.CommandDelegationPayloadType, delegationPayload, "tenant-command", signer)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, _ := json.Marshal(delegationEnvelope)
	for name, raw := range map[string][]byte{
		"auditor.bundle.json":     bundleRaw,
		"auditor.capsule.json":    capsuleRaw,
		"auditor.delegation.json": delegationRaw,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	view := controlclient.Deployment{
		TenantID: "tenant-a", DeploymentID: "auditor", Generation: 1, Revision: 1,
		AgentName: "auditor", BundleDigest: bundleDigest,
		CapsuleDigest: dsse.Digest(capsuleRaw), DelegationDigest: dsse.Digest(delegationRaw),
		DelegationID: delegation.DelegationID, ControllerKeyID: delegation.ControllerKeyID,
		ClaimGeneration: 1, AllowedNodeIDs: []string{"node-a"}, DelegationExpiresAt: delegation.ExpiresAt,
		DesiredState: controlstore.DeploymentRunning, Phase: controlstore.DeploymentPending,
		Instances: []controlstore.DeploymentInstance{{
			InstanceID: "auditor-0", LineageID: "auditor-lineage", Generation: 1,
			Phase: controlstore.DeploymentInstancePending, TransitionedAt: now.Format(time.RFC3339Nano),
		}},
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	requests := make([]string, 0, 6)
	getCount := 0
	putCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
		}
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			getCount++
			if getCount == 1 {
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte(`{"error":"not_found","message":"deployment was not found"}`))
				return
			}
			if request.URL.Path == "/v1/tenants/tenant-a/deployments" {
				_ = json.NewEncoder(writer).Encode(controlclient.DeploymentList{Deployments: []controlclient.Deployment{view}})
				return
			}
			_ = json.NewEncoder(writer).Encode(view)
		case http.MethodPut:
			putCount++
			var input struct {
				Generation       uint64 `json:"generation"`
				ExpectedRevision uint64 `json:"expected_revision"`
			}
			wantRevision := uint64(0)
			if putCount > 1 {
				wantRevision = 1
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Generation != 1 || input.ExpectedRevision != wantRevision {
				t.Errorf("apply input=%+v err=%v", input, err)
			}
			if putCount == 1 {
				writer.WriteHeader(http.StatusCreated)
			}
			_ = json.NewEncoder(writer).Encode(view)
		case http.MethodDelete:
			removed := view
			removed.Revision = 2
			removed.DesiredState = controlstore.DeploymentAbsent
			removed.Phase = controlstore.DeploymentStopping
			_ = json.NewEncoder(writer).Encode(removed)
		default:
			t.Errorf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	withWorkingDirectory(t, directory)
	common := []string{"-tenant", "tenant-a", "-control-url", server.URL, "-token-file", tokenPath}
	var output bytes.Buffer
	for _, command := range [][]string{
		append([]string{
			"agent", "deployment", "apply", "auditor",
			"-bundle", "auditor.bundle.json", "-capsule", "auditor.capsule.json",
			"-delegation", "auditor.delegation.json",
		}, common...),
		append([]string{
			"agent", "deployment", "apply", "auditor",
			"-bundle", "auditor.bundle.json", "-capsule", "auditor.capsule.json",
			"-delegation", "auditor.delegation.json",
		}, common...),
		append([]string{"agent", "deployment", "status", "auditor"}, common...),
		append([]string{"agent", "deployment", "list"}, common...),
		append([]string{"agent", "deployment", "remove", "auditor"}, common...),
	} {
		output.Reset()
		if err := run(command, &output, &bytes.Buffer{}); err != nil {
			t.Fatalf("run %v: %v", command, err)
		}
		if !strings.Contains(output.String(), `"deployment_id":"auditor"`) &&
			!strings.Contains(output.String(), `"deployments":[`) {
			t.Fatalf("run %v output=%s", command, output.String())
		}
	}
	wantRequests := "GET /v1/tenants/tenant-a/deployments/auditor," +
		"PUT /v1/tenants/tenant-a/deployments/auditor," +
		"GET /v1/tenants/tenant-a/deployments/auditor," +
		"PUT /v1/tenants/tenant-a/deployments/auditor," +
		"GET /v1/tenants/tenant-a/deployments/auditor," +
		"GET /v1/tenants/tenant-a/deployments?limit=100," +
		"GET /v1/tenants/tenant-a/deployments/auditor," +
		"DELETE /v1/tenants/tenant-a/deployments/auditor"
	if strings.Join(requests, ",") != wantRequests {
		t.Fatalf("requests=%v", requests)
	}
}

func withWorkingDirectory(t *testing.T, directory string) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
}
