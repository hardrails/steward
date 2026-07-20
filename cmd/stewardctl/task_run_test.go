package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestTaskRunPersistsAuthorityBeforeDispatchAndReturnsVerifiedResult(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	controlTokenPath := filepath.Join(fixture.directory, "control.token")
	if err := os.WriteFile(controlTokenPath, []byte("control-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controlView := taskRunControlDeploymentFixture(fixture)
	controlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/tenants/tenant-a/deployments/auditor" ||
			request.Header.Get("Authorization") != "Bearer control-secret" {
			t.Errorf("unexpected Control request %s %s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(controlView)
	}))
	defer controlServer.Close()
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(fixture.directory, "task.result.json")
	result := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed","result":{"changed":true}}`)
	var mu sync.Mutex
	var taskDigest, permitDigest string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer gateway-secret" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
		}
		if strings.HasPrefix(request.URL.Path, "/v1/services/") {
			bundle, err := readHistoricalLifecycleTaskBundle(fixture.bundlePath)
			if err != nil {
				t.Errorf("read bundle before dispatch: %v", err)
				return
			}
			mu.Lock()
			taskDigest = taskpermit.TaskDigest(
				bundle.Verified.Statement.TenantID,
				bundle.Verified.Statement.InstanceID,
				bundle.Verified.Statement.TaskID,
			)
			permitDigest = bundle.Verified.EnvelopeDigest
			mu.Unlock()
			writeTaskSubmitCLIResponse(writer, "run_0123456789abcdef0123456789abcdef", gatewayclient.TaskReceiptRecorded)
			return
		}
		mu.Lock()
		currentTaskDigest, currentPermitDigest := taskDigest, permitDigest
		mu.Unlock()
		want := "/v1/tasks/" + currentTaskDigest + "/permits/" + currentPermitDigest
		if request.Method == http.MethodGet && request.URL.Path == want {
			writeTaskRuntimeResponse(t, writer, fmt.Sprintf(
				`{"schema_version":"steward.task-status.v1","task_digest":%q,"permit_digest":%q,%s}`,
				currentTaskDigest, currentPermitDigest, terminalTaskRuntimeFields(result, "completed", false),
			))
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == want+"/observe" {
			writeTaskRuntimeResponse(t, writer, fmt.Sprintf(
				`{"schema_version":"steward.task-status.v1","task_digest":%q,"permit_digest":%q,%s}`,
				currentTaskDigest, currentPermitDigest, terminalTaskRuntimeFields(result, "completed", true),
			))
			return
		}
		t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
	}))
	defer server.Close()

	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	var output bytes.Buffer
	err := run([]string{
		"task", "run", "auditor", "-tenant", "tenant-a",
		"-control-url", controlServer.URL, "-control-token-file", controlTokenPath, "-deployment-timeout", "1s",
		"-trust", fixture.trustPath, "-request", fixture.requestPath,
		"-operation-id", fixture.operation.ID, "-task-id", "task.fixed", "-key", fixture.privatePath, "-key-id", fixture.keyID,
		"-bundle-out", fixture.bundlePath, "-result-out", resultPath,
		"-gateway-url", server.URL, "-gateway-token-file", tokenPath, "-wait-timeout", "1s",
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if saved, err := os.ReadFile(resultPath); err != nil || !bytes.Equal(saved, result) {
		t.Fatalf("result=%q error=%v", saved, err)
	}
	if info, err := os.Stat(fixture.bundlePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle info=%v error=%v", info, err)
	}
	var runResult taskRunResult
	if err := json.Unmarshal(output.Bytes(), &runResult); err != nil || runResult.SchemaVersion != taskRunSchema ||
		runResult.BundlePath != fixture.bundlePath || runResult.ResultPath != resultPath {
		t.Fatalf("run result=%+v error=%v output=%s", runResult, err, output.Bytes())
	}
	if bytes.Contains(output.Bytes(), result) || bytes.Contains(output.Bytes(), fixture.request) {
		t.Fatalf("task run exposed task content: %s", output.Bytes())
	}
}

func TestTaskRunRetainsSignedBundleWhenDispatchFails(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	deploymentPath := taskRunDeploymentFixture(t, fixture)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"error":"gateway_unavailable","message":"temporary failure"}`)
	}))
	defer server.Close()
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	err := run([]string{
		"task", "run", "-deployment", deploymentPath,
		"-trust", fixture.trustPath, "-request", fixture.requestPath,
		"-operation-id", fixture.operation.ID, "-key", fixture.privatePath, "-key-id", fixture.keyID,
		"-bundle-out", fixture.bundlePath, "-discard-result",
		"-gateway-url", server.URL, "-gateway-token-file", tokenPath,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "signed bundle retained") || !strings.Contains(err.Error(), "task submit") {
		t.Fatalf("dispatch error=%v", err)
	}
	if _, err := os.Stat(fixture.bundlePath); err != nil {
		t.Fatalf("signed recovery bundle missing: %v", err)
	}
}

func TestTaskRunRetainsSignedBundleWhenWaitFails(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	deploymentPath := taskRunDeploymentFixture(t, fixture)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/v1/services/") {
			writeTaskSubmitCLIResponse(writer, "run_0123456789abcdef0123456789abcdef", gatewayclient.TaskReceiptRecorded)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"error":"gateway_unavailable","message":"temporary failure"}`)
	}))
	defer server.Close()
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	err := run([]string{
		"task", "run", "-deployment", deploymentPath,
		"-trust", fixture.trustPath, "-request", fixture.requestPath,
		"-operation-id", fixture.operation.ID, "-key", fixture.privatePath, "-key-id", fixture.keyID,
		"-bundle-out", fixture.bundlePath, "-discard-result",
		"-gateway-url", server.URL, "-gateway-token-file", tokenPath, "-wait-timeout", "1s",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "signed bundle retained") || !strings.Contains(err.Error(), "task wait") {
		t.Fatalf("wait error=%v", err)
	}
	if _, err := os.Stat(fixture.bundlePath); err != nil {
		t.Fatalf("signed recovery bundle missing: %v", err)
	}
}

func TestTaskRunRejectsIncompleteAuthorityAndControlInputs(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(fixture.directory, "missing-contexts.json"))
	if err := runTask([]string{"-no-context", "-unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown task run flag was accepted")
	}
	if err := runTask([]string{"-no-context"}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete task run was accepted")
	}
	base := []string{
		"auditor", "-no-context", "-trust", fixture.trustPath, "-request", fixture.requestPath,
		"-operation-id", fixture.operation.ID, "-key", fixture.privatePath, "-key-id", fixture.keyID,
		"-bundle-out", fixture.bundlePath, "-gateway-token-file", fixture.requestPath, "-discard-result",
	}
	if err := runTask(base, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires a tenant") {
		t.Fatalf("missing durable Control authority error=%v", err)
	}
	withMissingToken := append(append([]string(nil), base...),
		"-tenant", "tenant-a", "-control-token-file", filepath.Join(fixture.directory, "missing.token"))
	if err := runTask(withMissingToken, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing Control token error=%v", err)
	}

	deploymentPath := taskRunDeploymentFixture(t, fixture)
	gatewayToken := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(gatewayToken, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runTask([]string{
		"-no-context", "-deployment", deploymentPath, "-trust", fixture.trustPath,
		"-request", filepath.Join(fixture.directory, "missing-request.json"), "-operation-id", fixture.operation.ID,
		"-key", fixture.privatePath, "-key-id", fixture.keyID, "-bundle-out", fixture.bundlePath,
		"-gateway-token-file", gatewayToken, "-discard-result",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "missing-request.json") {
		t.Fatalf("missing request error=%v", err)
	}
	if _, err := os.Stat(fixture.bundlePath); !os.IsNotExist(err) {
		t.Fatalf("invalid task unexpectedly created bundle: %v", err)
	}
}

func taskRunDeploymentFixture(t *testing.T, fixture *taskCLIFixture) string {
	t.Helper()
	authorities := make([]controlprotocol.ExecutorTaskAuthorityV1, 0, len(fixture.admitted.TaskAuthorities))
	for _, authority := range fixture.admitted.TaskAuthorities {
		authorities = append(authorities, controlprotocol.ExecutorTaskAuthorityV1{
			KeyID: authority.KeyID, PublicKey: authority.PublicKey,
		})
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    fixture.admitted.RuntimeRef, Status: "running",
		CapsuleDigest: fixture.admitted.CapsuleDigest, PolicyDigest: fixture.admitted.PolicyDigest,
		Generation: fixture.admitted.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		GrantID: fixture.admitted.GrantID, ServicePath: fixture.admitted.ServicePath,
		ServiceID: fixture.admitted.ServiceID, TaskAuthorities: authorities,
		RoutePolicyDigest: fixture.admitted.RoutePolicyDigest,
	}
	deployment := agentDeployResult{
		SchemaVersion: agentDeploymentSchema, AgentName: "auditor",
		BundleDigest: "sha256:" + strings.Repeat("f", 64), TenantID: fixture.intent.TenantID,
		NodeID: fixture.intent.NodeID, InstanceID: fixture.intent.InstanceID,
		LineageID: fixture.intent.LineageID, Generation: fixture.intent.Generation,
		RuntimeRef: projection.RuntimeRef, Status: "running", Intent: fixture.intent, Admission: projection,
	}
	return writePermitJSON(t, fixture.directory, "task-run.deployment.json", deployment)
}

func taskRunControlDeploymentFixture(fixture *taskCLIFixture) controlclient.Deployment {
	authorities := make([]controlprotocol.ExecutorTaskAuthorityV1, 0, len(fixture.admitted.TaskAuthorities))
	for _, authority := range fixture.admitted.TaskAuthorities {
		authorities = append(authorities, controlprotocol.ExecutorTaskAuthorityV1{
			KeyID: authority.KeyID, PublicKey: authority.PublicKey,
		})
	}
	intent := fixture.intent
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    fixture.admitted.RuntimeRef, Status: "running",
		CapsuleDigest: fixture.admitted.CapsuleDigest, PolicyDigest: fixture.admitted.PolicyDigest,
		Generation: fixture.admitted.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		GrantID: fixture.admitted.GrantID, ServicePath: fixture.admitted.ServicePath,
		ServiceID: fixture.admitted.ServiceID, TaskAuthorities: authorities,
		RoutePolicyDigest: fixture.admitted.RoutePolicyDigest,
	}
	return controlclient.Deployment{
		TenantID: "tenant-a", DeploymentID: "auditor", Generation: 1, Revision: 4,
		AgentName: "auditor", BundleDigest: "sha256:" + strings.Repeat("f", 64),
		CapsuleDigest: intent.CapsuleDigest, DelegationDigest: "sha256:" + strings.Repeat("1", 64),
		DelegationID: "auditor-authority", ControllerKeyID: "controller-a", ClaimGeneration: 1,
		AllowedNodeIDs:      []string{intent.NodeID},
		DelegationExpiresAt: fixture.now.Add(time.Hour).Format(time.RFC3339Nano),
		DesiredState:        controlstore.DeploymentRunning, Phase: controlstore.DeploymentReady,
		Instances: []controlstore.DeploymentInstance{{
			InstanceID: intent.InstanceID, LineageID: intent.LineageID, Generation: intent.Generation,
			NodeID: intent.NodeID, Intent: &intent, Admission: &projection,
			Phase: controlstore.DeploymentInstanceRunning, TransitionedAt: fixture.now.Format(time.RFC3339Nano),
		}},
		CreatedAt: fixture.now.Format(time.RFC3339Nano), UpdatedAt: fixture.now.Format(time.RFC3339Nano),
	}
}
