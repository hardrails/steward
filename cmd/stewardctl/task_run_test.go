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

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestTaskRunPersistsAuthorityBeforeDispatchAndReturnsVerifiedResult(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	deploymentPath := taskRunDeploymentFixture(t, fixture)
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
		"task", "run", "-deployment", deploymentPath,
		"-trust", fixture.trustPath, "-request", fixture.requestPath,
		"-operation-id", fixture.operation.ID, "-key", fixture.privatePath, "-key-id", fixture.keyID,
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
