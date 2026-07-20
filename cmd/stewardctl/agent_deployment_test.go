package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
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
		Operations:          []string{"admit", "destroy", "renew", "start", "stop"}, NodeIDs: []string{"node-a"},
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

func TestAgentDeploymentWaitExportsOneTaskReadyInstance(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsuleDigest := "sha256:" + strings.Repeat("a", 64)
	runtimeRef := "executor-" + strings.Repeat("b", 64)
	grantID := "grant-" + strings.Repeat("c", 64)
	view := controlclient.Deployment{
		TenantID: "tenant-a", DeploymentID: "auditor", Generation: 1, Revision: 4,
		AgentName: "auditor", BundleDigest: "sha256:" + strings.Repeat("d", 64),
		CapsuleDigest: capsuleDigest, DelegationDigest: "sha256:" + strings.Repeat("e", 64),
		DelegationID: "auditor-authority", ControllerKeyID: "controller-a", ClaimGeneration: 1,
		AllowedNodeIDs: []string{"node-a"}, DelegationExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		DesiredState: controlstore.DeploymentRunning, Phase: controlstore.DeploymentReady,
		Instances: []controlstore.DeploymentInstance{{
			InstanceID: "auditor-0", LineageID: "auditor-lineage", Generation: 1, NodeID: "node-a",
			Phase: controlstore.DeploymentInstanceRunning, TransitionedAt: now.Format(time.RFC3339Nano),
			Intent: &admission.InstanceIntent{
				TenantID: "tenant-a", NodeID: "node-a", InstanceID: "auditor-0", LineageID: "auditor-lineage",
				Generation: 1, CapsuleDigest: capsuleDigest,
				Resources:    admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
				Capabilities: admission.Capabilities{Service: true}, StateDisposition: "none", ServiceID: "hermes-api",
			},
			Admission: &controlprotocol.ExecutorAdmissionProjectionV1{
				SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
				RuntimeRef:    runtimeRef, Status: "created", CapsuleDigest: capsuleDigest,
				PolicyDigest: "sha256:" + strings.Repeat("f", 64), Generation: 1,
				EvidenceKeyID: strings.Repeat("1", 32), GrantID: grantID,
				ServicePath: "/v1/services/" + grantID + "/", ServiceID: "hermes-api",
				TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
					KeyID: "tenant-task", PublicKey: base64.StdEncoding.EncodeToString(public),
				}},
				RoutePolicyDigest: "sha256:" + strings.Repeat("2", 64),
			},
		}},
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/tenants/tenant-a/deployments/auditor" ||
			request.Header.Get("Authorization") != "Bearer operator" {
			t.Errorf("unexpected request %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(view)
	}))
	defer server.Close()
	outputPath := filepath.Join(directory, "agent.deployment.json")
	var output bytes.Buffer
	err = run([]string{
		"agent", "deployment", "wait", "auditor", "-tenant", "tenant-a",
		"-control-url", server.URL, "-token-file", tokenPath, "-out", outputPath, "-timeout", "1s",
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("deployment output info=%v error=%v", info, err)
	}
	admitted, intent, err := readTaskDeployment(outputPath)
	if err != nil || admitted.RuntimeRef != runtimeRef || intent.InstanceID != "auditor-0" {
		t.Fatalf("task-ready deployment admission=%+v intent=%+v error=%v", admitted, intent, err)
	}
	if !strings.Contains(output.String(), `"output":"`+outputPath+`"`) || strings.Contains(output.String(), string(public)) {
		t.Fatalf("wait output=%s", output.String())
	}

	output.Reset()
	err = run([]string{
		"agent", "deployment", "wait", "-tenant", "tenant-a", "-control-url", server.URL,
		"-token-file", tokenPath, "-timeout", "1s", "auditor",
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var ready agentDeployResult
	if err := json.Unmarshal(output.Bytes(), &ready); err != nil || ready.InstanceID != "auditor-0" || ready.RuntimeRef != runtimeRef {
		t.Fatalf("stdout deployment=%+v error=%v output=%s", ready, err, output.Bytes())
	}
}

func TestTaskReadyDeploymentSelectionFailsClosed(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	valid := taskRunControlDeploymentFixture(fixture)
	if selected, err := taskReadyDeploymentResult(valid, valid.Instances[0].InstanceID); err != nil ||
		selected.InstanceID != valid.Instances[0].InstanceID {
		t.Fatalf("selected=%+v error=%v", selected, err)
	}

	missing := valid
	missing.Instances = append([]controlstore.DeploymentInstance(nil), valid.Instances...)
	missing.Instances[0].Phase = controlstore.DeploymentInstanceStarting
	if _, err := taskReadyDeploymentResult(missing, ""); err == nil || !strings.Contains(err.Error(), "no running") {
		t.Fatalf("no-running error=%v", err)
	}
	if _, err := taskReadyDeploymentResult(valid, "missing"); err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("missing selection error=%v", err)
	}

	multiple := valid
	multiple.Instances = append([]controlstore.DeploymentInstance(nil), valid.Instances...)
	second := multiple.Instances[0]
	second.InstanceID = "agent-b"
	second.LineageID = "lineage-b"
	multiple.Instances = append(multiple.Instances, second)
	if _, err := taskReadyDeploymentResult(multiple, ""); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("multiple selection error=%v", err)
	}

	legacy := valid
	legacy.Instances = append([]controlstore.DeploymentInstance(nil), valid.Instances...)
	legacy.Instances[0].Intent = nil
	if _, err := taskReadyDeploymentResult(legacy, ""); err == nil || !strings.Contains(err.Error(), "predates") {
		t.Fatalf("legacy deployment error=%v", err)
	}

	noService := valid
	noService.Instances = append([]controlstore.DeploymentInstance(nil), valid.Instances...)
	projection := *valid.Instances[0].Admission
	projection.ServiceID = ""
	projection.TaskAuthorities = nil
	noService.Instances[0].Admission = &projection
	if _, err := taskReadyDeploymentResult(noService, ""); err == nil || !strings.Contains(err.Error(), "task service") {
		t.Fatalf("no-service error=%v", err)
	}

	if summary := deploymentFailureSummary(controlclient.Deployment{}); summary != "no failure detail was reported" {
		t.Fatalf("empty failure summary=%q", summary)
	}
	failed := controlclient.Deployment{Instances: []controlstore.DeploymentInstance{
		{InstanceID: "a", LastError: "first"}, {InstanceID: "b"}, {InstanceID: "c", LastError: "third"},
	}}
	if summary := deploymentFailureSummary(failed); summary != "a=first, c=third" {
		t.Fatalf("failure summary=%q", summary)
	}
}

func TestWaitForTaskReadyDeploymentStopsOnTerminalConditions(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	base := taskRunControlDeploymentFixture(fixture)
	for _, test := range []struct {
		name    string
		phase   controlstore.DeploymentPhase
		detail  string
		want    string
		timeout time.Duration
	}{
		{name: "degraded", phase: controlstore.DeploymentDegraded, detail: "policy_denied", want: "policy_denied", timeout: time.Second},
		{name: "stopping", phase: controlstore.DeploymentStopping, want: "not becoming ready", timeout: time.Second},
		{name: "removed", phase: controlstore.DeploymentRemoved, want: "not becoming ready", timeout: time.Second},
		{name: "timeout", phase: controlstore.DeploymentPending, want: "context deadline exceeded", timeout: 10 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := base
			view.Phase = test.phase
			view.Instances = append([]controlstore.DeploymentInstance(nil), base.Instances...)
			view.Instances[0].LastError = test.detail
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(view)
			}))
			defer server.Close()
			tokenPath := filepath.Join(t.TempDir(), "operator.token")
			if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			client, err := controlclient.NewFromFiles(server.URL, tokenPath, "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			if _, err := waitForTaskReadyDeployment(ctx, client, "tenant-a", "auditor", ""); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wait error=%v", err)
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":"unavailable","message":"control is unavailable"}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := controlclient.NewFromFiles(server.URL, tokenPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := waitForTaskReadyDeployment(context.Background(), client, "tenant-a", "auditor", ""); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("Control failure error=%v", err)
	}
}

func TestAgentDeploymentCommandAndLifecycleValidationErrors(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}} {
		if err := agentDeployment(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("deployment arguments %v were accepted", arguments)
		}
	}
	if !deploymentLifecycleGranted([]string{"admit", "destroy", "renew", "start", "stop"}) ||
		deploymentLifecycleGranted([]string{"admit", "destroy", "start", "stop"}) {
		t.Fatal("deployment lifecycle scope validation is inconsistent")
	}
	withoutContext, err := applyTaskRunContext([]string{"-no-context", "-deployment", "agent.json"})
	if err != nil || slices.Contains(withoutContext, "-no-context") ||
		!slices.Equal(withoutContext, []string{"-deployment", "agent.json"}) {
		t.Fatalf("task run no-context arguments=%v error=%v", withoutContext, err)
	}
	if _, err := applyTaskRunContext([]string{"-no-context", "--no-context"}); err == nil {
		t.Fatal("duplicate task run no-context flag was accepted")
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
