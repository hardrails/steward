package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

type taskCLIFixture struct {
	directory     string
	privatePath   string
	publicPath    string
	requestPath   string
	intentPath    string
	admissionPath string
	trustPath     string
	bundlePath    string
	intent        admission.InstanceIntent
	admitted      permitAdmission
	operation     serviceTrustOperation
	request       []byte
	keyID         string
	now           time.Time
}

func newTaskCLIFixture(t *testing.T) *taskCLIFixture {
	t.Helper()
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "task-authority")
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	capsuleDigest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 7,
		CapsuleDigest: capsuleDigest, Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		Capabilities: admission.Capabilities{Service: true}, StateDisposition: "none", ServiceID: "hermes-api",
	}
	grantID := gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation)
	admitted := permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("b", 64), Status: "created", CapsuleDigest: capsuleDigest,
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), Generation: intent.Generation,
		EvidenceKeyID: "sha256:" + strings.Repeat("d", 64), GrantID: grantID,
		ServicePath: "/v1/services/" + grantID + "/", ServiceID: intent.ServiceID,
		TaskAuthorities:   []gateway.TaskAuthority{{KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(public)}},
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64),
	}
	operation := serviceTrustOperation{
		ServiceID: intent.ServiceID, ID: "hermes.run", Method: "POST", Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
		MaxSeconds: 30, MaxPermitSeconds: 600, TaskProtocol: gateway.TaskProtocolLifecycleV1,
		StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 15, PollIntervalSeconds: 2,
	}
	operation.PolicyDigest = gateway.ServiceOperationDigest(operation.gatewayOperation())
	request := []byte(`{"input":"STEWARD_WORKSPACE_AUDIT","session_id":"sovereign-work"}`)
	requestPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	return &taskCLIFixture{
		directory: directory, privatePath: privatePath, publicPath: publicPath, requestPath: requestPath,
		intentPath:    writePermitJSON(t, directory, "intent.json", intent),
		admissionPath: writePermitJSON(t, directory, "admission.json", admitted),
		trustPath: writePermitJSON(t, directory, "service-trust.json", serviceTrustInventory{
			SchemaVersion: serviceTrustSchemaV2, NodeID: intent.NodeID, TenantID: intent.TenantID,
			Services: []serviceTrustService{{ServiceID: intent.ServiceID, Operations: []serviceTrustOperation{operation}}},
		}),
		bundlePath: filepath.Join(directory, "task.bundle.json"), intent: intent, admitted: admitted,
		operation: operation, request: request, keyID: "task-approver", now: time.Now().UTC().Truncate(time.Second),
	}
}

func (fixture *taskCLIFixture) issueArguments() []string {
	return []string{
		"task", "issue", "-admission", fixture.admissionPath, "-intent", fixture.intentPath,
		"-trust", fixture.trustPath, "-request", fixture.requestPath, "-operation-id", fixture.operation.ID,
		"-key", fixture.privatePath, "-key-id", fixture.keyID, "-out", fixture.bundlePath,
	}
}

func (fixture *taskCLIFixture) issue(t *testing.T) taskpermit.Statement {
	t.Helper()
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	var output bytes.Buffer
	if err := run(fixture.issueArguments(), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var issued struct {
		TaskID        string `json:"task_id"`
		PermitDigest  string `json:"permit_digest"`
		RequestDigest string `json:"request_digest"`
	}
	if err := json.Unmarshal(output.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^task-[a-f0-9]{32}$`).MatchString(issued.TaskID) ||
		issued.RequestDigest != taskpermit.RequestDigest(fixture.request) || !strings.HasPrefix(issued.PermitDigest, "sha256:") {
		t.Fatalf("issued=%#v", issued)
	}
	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := readTaskBundle(fixture.bundlePath, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity)
	if err != nil {
		t.Fatal(err)
	}
	return verified.Verified.Statement
}

func TestTaskIssueAndVerifyProduceOneExactOwnerOnlyBundle(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	statement := fixture.issue(t)
	if statement.NodeID != fixture.intent.NodeID || statement.TenantID != fixture.intent.TenantID ||
		statement.InstanceID != fixture.intent.InstanceID || statement.RuntimeRef != fixture.admitted.RuntimeRef ||
		statement.GrantID != fixture.admitted.GrantID || statement.Generation != fixture.intent.Generation ||
		statement.CapsuleDigest != fixture.admitted.CapsuleDigest || statement.PolicyDigest != fixture.admitted.PolicyDigest ||
		statement.RoutePolicyDigest != fixture.admitted.RoutePolicyDigest || statement.ServiceID != fixture.intent.ServiceID ||
		statement.OperationID != fixture.operation.ID || statement.OperationPolicyDigest != fixture.operation.PolicyDigest ||
		statement.RequestDigest != taskpermit.RequestDigest(fixture.request) || statement.RequestBytes != int64(len(fixture.request)) ||
		statement.NotBefore != fixture.now.Add(-5*time.Second).Format(time.RFC3339) ||
		statement.ExpiresAt != fixture.now.Add(4*time.Minute+55*time.Second).Format(time.RFC3339) {
		t.Fatalf("statement=%#v", statement)
	}
	info, err := os.Stat(fixture.bundlePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode=%v err=%v", info.Mode(), err)
	}
	raw, err := os.ReadFile(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle taskBundle
	if err := dsse.DecodeStrictInto(raw, maxTaskBundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	request, err := base64.StdEncoding.DecodeString(bundle.Request)
	if err != nil || !bytes.Equal(request, fixture.request) || base64.StdEncoding.EncodeToString(request) != bundle.Request {
		t.Fatalf("bundled request changed: %q err=%v", request, err)
	}

	var output bytes.Buffer
	if err := run([]string{
		"task", "verify", "-in", fixture.bundlePath, "-public-key", fixture.publicPath, "-key-id", fixture.keyID,
		"-request", fixture.requestPath, "-at", fixture.now.Format(time.RFC3339),
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Valid       bool                 `json:"valid"`
		ServicePath string               `json:"service_path"`
		Statement   taskpermit.Statement `json:"statement"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.ServicePath != fixture.admitted.ServicePath || result.Statement != statement {
		t.Fatalf("verified=%#v", result)
	}

	if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("existing bundle error=%v", err)
	}
	if after, err := os.ReadFile(fixture.bundlePath); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("failed second issue changed the existing bundle")
	}
}

func TestTaskIssueConsumesAgentDeploymentHandoff(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	taskAuthorities := make([]controlprotocol.ExecutorTaskAuthorityV1, 0, len(fixture.admitted.TaskAuthorities))
	for _, authority := range fixture.admitted.TaskAuthorities {
		taskAuthorities = append(taskAuthorities, controlprotocol.ExecutorTaskAuthorityV1{
			KeyID: authority.KeyID, PublicKey: authority.PublicKey,
		})
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    fixture.admitted.RuntimeRef, Status: "running",
		CapsuleDigest: fixture.admitted.CapsuleDigest, PolicyDigest: fixture.admitted.PolicyDigest,
		Generation: fixture.admitted.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		GrantID: fixture.admitted.GrantID, ServicePath: fixture.admitted.ServicePath,
		ServiceID: fixture.admitted.ServiceID, TaskAuthorities: taskAuthorities,
		RoutePolicyDigest: fixture.admitted.RoutePolicyDigest,
	}
	deployment := agentDeployResult{
		SchemaVersion: agentDeploymentSchema, AgentName: "auditor",
		BundleDigest: "sha256:" + strings.Repeat("f", 64), TenantID: fixture.intent.TenantID,
		NodeID: fixture.intent.NodeID, InstanceID: fixture.intent.InstanceID,
		LineageID: fixture.intent.LineageID, Generation: fixture.intent.Generation,
		RuntimeRef: projection.RuntimeRef, Status: "running", AdmitCommandID: "admit-a",
		StartCommandID: "start-a", Intent: fixture.intent, Admission: projection,
	}
	deploymentPath := writePermitJSON(t, fixture.directory, "deployment.json", deployment)
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	arguments := []string{
		"task", "issue", "-deployment", deploymentPath, "-trust", fixture.trustPath,
		"-request", fixture.requestPath, "-operation-id", fixture.operation.ID,
		"-key", fixture.privatePath, "-key-id", fixture.keyID, "-out", fixture.bundlePath,
	}
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := readTaskBundle(
		fixture.bundlePath, map[string]ed25519.PublicKey{fixture.keyID: public},
		fixture.now, taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Verified.Statement.RuntimeRef != projection.RuntimeRef ||
		issued.Verified.Statement.RoutePolicyDigest != projection.RoutePolicyDigest {
		t.Fatalf("statement=%#v", issued.Verified.Statement)
	}

	bad := deployment
	bad.Intent.InstanceID = "different-agent"
	badPath := writePermitJSON(t, fixture.directory, "bad-deployment.json", bad)
	if _, _, err := readTaskDeployment(badPath); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("tampered deployment error=%v", err)
	}
}

func TestTaskIssueCarriesLifecyclePolicyInVersionedBundle(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	statement := fixture.issue(t)
	if statement.OperationPolicyDigest != fixture.operation.PolicyDigest {
		t.Fatalf("statement operation digest=%q want=%q", statement.OperationPolicyDigest, fixture.operation.PolicyDigest)
	}
	raw, err := os.ReadFile(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle taskBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != taskBundleSchemaV2 || bundle.Operation.TaskProtocol != gateway.TaskProtocolLifecycleV1 ||
		bundle.Operation.StatusPathPrefix != "/v1/runs/" || bundle.Operation.StatusMaxSeconds != 15 ||
		bundle.Operation.PollIntervalSeconds != 2 {
		t.Fatalf("lifecycle bundle=%#v", bundle)
	}

	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle.SchemaVersion = "steward.task-bundle.v1"
	if _, err := decodeTaskBundleValue(bundle, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity); err == nil ||
		!strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("v1 lifecycle bundle err=%v", err)
	}
	bundle.SchemaVersion = taskBundleSchemaV2
	bundle.Operation.TaskProtocol = ""
	if _, err := decodeTaskBundleValue(bundle, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity); err == nil ||
		!strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("v2 legacy bundle err=%v", err)
	}
}

func TestServiceTrustSchemaMatchesLifecycleContent(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	lifecycle := fixture.operation
	lifecycle.TaskProtocol = gateway.TaskProtocolLifecycleV1
	lifecycle.StatusPathPrefix = "/v1/runs/"
	lifecycle.StatusMaxSeconds = 15
	lifecycle.PollIntervalSeconds = 2
	lifecycle.PolicyDigest = gateway.ServiceOperationDigest(lifecycle.gatewayOperation())
	withoutLifecycle := lifecycle
	withoutLifecycle.TaskProtocol = ""
	withoutLifecycle.StatusPathPrefix = ""
	withoutLifecycle.StatusMaxSeconds = 0
	withoutLifecycle.PollIntervalSeconds = 0
	withoutLifecycle.PolicyDigest = gateway.ServiceOperationDigest(withoutLifecycle.gatewayOperation())

	for _, test := range []struct {
		name      string
		schema    string
		operation serviceTrustOperation
	}{
		{name: "v2 without lifecycle", schema: serviceTrustSchemaV2, operation: withoutLifecycle},
		{name: "unknown schema", schema: "steward.service-trust.unknown", operation: lifecycle},
	} {
		t.Run(test.name, func(t *testing.T) {
			writePermitJSONReplace(t, fixture.trustPath, serviceTrustInventory{
				SchemaVersion: test.schema, NodeID: fixture.intent.NodeID, TenantID: fixture.intent.TenantID,
				Services: []serviceTrustService{{ServiceID: fixture.intent.ServiceID, Operations: []serviceTrustOperation{test.operation}}},
			})
			if _, err := readServiceTrust(fixture.trustPath, fixture.intent, fixture.operation.ID); err == nil {
				t.Fatal("mismatched service trust schema accepted")
			}
		})
	}
}

func TestTaskIssueAndVerifyRejectEveryChangedAuthorityOrTransportBinding(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.issue(t)

	wrongPrivate, wrongPublic := generateTestKeyPair(t, fixture.directory, "wrong")
	_ = wrongPrivate
	if err := run([]string{"task", "verify", "-in", fixture.bundlePath, "-public-key", wrongPublic, "-key-id", fixture.keyID},
		&bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("wrong external key error=%v", err)
	}
	changedRequest := filepath.Join(fixture.directory, "changed-request.json")
	if err := os.WriteFile(changedRequest, append(append([]byte(nil), fixture.request...), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"task", "verify", "-in", fixture.bundlePath, "-public-key", fixture.publicPath,
		"-key-id", fixture.keyID, "-request", changedRequest}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "exact request") {
		t.Fatalf("changed exact request error=%v", err)
	}

	originalRaw, err := os.ReadFile(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var original taskBundle
	if err := json.Unmarshal(originalRaw, &original); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*taskBundle){
		"service path": func(value *taskBundle) {
			value.ServicePath = "/v1/services/" + gateway.GrantID("tenant-b", "agent-b", 1) + "/"
		},
		"operation path": func(value *taskBundle) { value.Operation.Path = "/v1/other" },
		"policy digest":  func(value *taskBundle) { value.Operation.PolicyDigest = "sha256:" + strings.Repeat("f", 64) },
		"request": func(value *taskBundle) {
			value.Request = base64.StdEncoding.EncodeToString([]byte(`{"input":"different"}`))
		},
		"permit":    func(value *taskBundle) { value.Permit = base64.StdEncoding.EncodeToString([]byte("not-dsse")) },
		"authority": func(value *taskBundle) { value.Authority.KeyID = "other-key" },
	}
	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := original
			mutate(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeTaskBundle(raw, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity); err == nil {
				t.Fatal("changed bundle accepted")
			}
		})
	}

	permitRaw, err := base64.StdEncoding.DecodeString(original.Permit)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := dsse.Verify(permitRaw, taskpermit.PayloadType, map[string]ed25519.PublicKey{fixture.keyID: public})
	if err != nil {
		t.Fatal(err)
	}
	var impossible taskpermit.Statement
	if err := dsse.DecodeStrictInto(payload, taskpermit.MaxEnvelopeBytes, &impossible); err != nil {
		t.Fatal(err)
	}
	impossible.GrantID = gateway.GrantID(impossible.TenantID, "different-instance", impossible.Generation)
	payload, err = json.Marshal(impossible)
	if err != nil {
		t.Fatal(err)
	}
	private, err := readPrivateKey(fixture.privatePath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, fixture.keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err = dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	candidate := original
	candidate.Permit = base64.StdEncoding.EncodeToString(permitRaw)
	candidate.ServicePath = "/v1/services/" + impossible.GrantID + "/"
	raw, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTaskBundle(raw, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity); err == nil ||
		!strings.Contains(err.Error(), "transport") {
		t.Fatalf("structurally impossible grant accepted: %v", err)
	}

	if err := os.Chmod(fixture.bundlePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"task", "verify", "-in", fixture.bundlePath, "-public-key", fixture.publicPath,
		"-key-id", fixture.keyID}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("loose bundle permissions error=%v", err)
	}
}

func TestTaskIssueRejectsUntrustedAdmissionInventoryAndAmbiguousRequest(t *testing.T) {
	for name, test := range map[string]struct {
		change   func(*taskCLIFixture)
		contains string
	}{
		"wrong admission generation": {func(f *taskCLIFixture) {
			f.admitted.Generation++
			writePermitJSONReplace(t, f.admissionPath, f.admitted)
		}, "do not bind"},
		"wrong admission key": {func(f *taskCLIFixture) {
			_, otherPublic := generateTestKeyPair(t, f.directory, "not-admitted")
			public, _ := readPublicKey(otherPublic)
			f.admitted.TaskAuthorities[0].PublicKey = base64.StdEncoding.EncodeToString(public)
			writePermitJSONReplace(t, f.admissionPath, f.admitted)
		}, "does not bind this task-authority"},
		"wrong trust node": {func(f *taskCLIFixture) {
			writePermitJSONReplace(t, f.trustPath, serviceTrustInventory{SchemaVersion: serviceTrustSchemaV2,
				NodeID: "node-b", TenantID: f.intent.TenantID,
				Services: []serviceTrustService{{ServiceID: f.intent.ServiceID, Operations: []serviceTrustOperation{f.operation}}}})
		}, "does not match"},
		"tampered trust operation": {func(f *taskCLIFixture) {
			operation := f.operation
			operation.Path = "/v1/other"
			writePermitJSONReplace(t, f.trustPath, serviceTrustInventory{SchemaVersion: serviceTrustSchemaV2,
				NodeID: f.intent.NodeID, TenantID: f.intent.TenantID,
				Services: []serviceTrustService{{ServiceID: f.intent.ServiceID, Operations: []serviceTrustOperation{operation}}}})
		}, "operations are invalid"},
		"ambiguous request": {func(f *taskCLIFixture) {
			_ = os.WriteFile(f.requestPath, []byte(`{"input":1,"input":2}`), 0o600)
		}, "ambiguous"},
		"writable admission": {func(f *taskCLIFixture) {
			if err := os.Chmod(f.admissionPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}, "permission policy"},
		"writable intent": {func(f *taskCLIFixture) {
			if err := os.Chmod(f.intentPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}, "permission policy"},
		"writable request": {func(f *taskCLIFixture) {
			if err := os.Chmod(f.requestPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}, "permission policy"},
		"too many total operations": {func(f *taskCLIFixture) {
			operations := func(serviceID, prefix string, count int) []serviceTrustOperation {
				result := make([]serviceTrustOperation, 0, count)
				for index := 0; index < count; index++ {
					operation := f.operation
					operation.ServiceID = serviceID
					operation.ID = fmt.Sprintf("op-%03d", index)
					operation.Path = fmt.Sprintf("/%s/%03d", prefix, index)
					operation.PolicyDigest = gateway.ServiceOperationDigest(operation.gatewayOperation())
					result = append(result, operation)
				}
				return result
			}
			hermesOperations := append([]serviceTrustOperation{f.operation}, operations(f.intent.ServiceID, "hermes", 64)...)
			writePermitJSONReplace(t, f.trustPath, serviceTrustInventory{SchemaVersion: serviceTrustSchemaV2,
				NodeID: f.intent.NodeID, TenantID: f.intent.TenantID,
				Services: []serviceTrustService{
					{ServiceID: "aux-api", Operations: operations("aux-api", "aux", 64)},
					{ServiceID: f.intent.ServiceID, Operations: hermesOperations},
				}})
		}, "at most 128 total operations"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTaskCLIFixture(t)
			test.change(fixture)
			priorNow := timeNow
			timeNow = func() time.Time { return fixture.now }
			defer func() { timeNow = priorNow }()
			if err := run(fixture.issueArguments(), &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error=%v", err)
			}
			if _, err := os.Lstat(fixture.bundlePath); !os.IsNotExist(err) {
				t.Fatalf("rejected issue left output: %v", err)
			}
		})
	}
}

func TestTaskAuditVerifiesExpiredPermitAtAuthorizationAndEveryReceiptBinding(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.now = time.Now().UTC().Truncate(time.Second)
	arguments := append(fixture.issueArguments(), "-task-id", "task-audit-1")
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now }
	t.Cleanup(func() { timeNow = priorNow })
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readTaskBundle(fixture.bundlePath, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity)
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivatePath, receiptPublicPath := generateTestKeyPair(t, fixture.directory, "receipt")
	receiptPrivate, err := readPrivateKey(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receiptsPath := filepath.Join(fixture.directory, "service-task-receipts.ndjson")
	ledger, err := connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 3)
	if err != nil {
		t.Fatal(err)
	}
	statement := bundle.Verified.Statement
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, Kind: connectorledger.ServiceTask,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef, CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest: statement.PolicyDigest, RoutePolicyDigest: statement.RoutePolicyDigest, Generation: statement.Generation,
		GrantID: statement.GrantID, ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest:            taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		AuthorityKeyID:        bundle.Verified.KeyID, PermitDigest: bundle.Verified.EnvelopeDigest,
		RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
	if _, err := ledger.Begin(event); err != nil {
		t.Fatal(err)
	}
	dispatch := event
	dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
	dispatch.HTTPStatus, dispatch.ResponseBytes, dispatch.RunID = 202, 46, "run_0123456789abcdef0123456789abcdef"
	if _, err := ledger.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	terminal := dispatch
	terminal.Phase, terminal.HTTPStatus, terminal.ResponseBytes = connectorledger.Terminal, 200, 84
	terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	terminal.ResultDigest = "sha256:" + strings.Repeat("f", 64)
	head, err := ledger.Finish(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	timeNow = func() time.Time { return fixture.now.Add(48 * time.Hour) }
	if err := run([]string{"task", "verify", "-in", fixture.bundlePath, "-public-key", fixture.publicPath,
		"-key-id", fixture.keyID}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired current verify error=%v", err)
	}
	auditArguments := []string{
		"task", "audit", "-in", fixture.bundlePath, "-public-key", fixture.publicPath, "-key-id", fixture.keyID,
		"-receipts", receiptsPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
		"-receipt-epoch", "3", "-request", fixture.requestPath, "-expected-sequence", "3",
		"-expected-chain-hash", head.ChainHash,
	}
	var output bytes.Buffer
	if err := run(auditArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var audited struct {
		Valid         bool                 `json:"valid"`
		PermitDigest  string               `json:"permit_digest"`
		Authorization taskAuditRecord      `json:"authorization"`
		Dispatch      *taskAuditRecord     `json:"dispatch"`
		Terminal      *taskAuditRecord     `json:"terminal"`
		Head          connectorledger.Head `json:"head"`
	}
	if err := json.Unmarshal(output.Bytes(), &audited); err != nil {
		t.Fatal(err)
	}
	if !audited.Valid || audited.PermitDigest != bundle.Verified.EnvelopeDigest || audited.Authorization.Sequence != 1 ||
		audited.Dispatch == nil || audited.Dispatch.Event.RunID != dispatch.RunID ||
		audited.Terminal == nil || audited.Terminal.Event.RunID != terminal.RunID || audited.Head != head {
		t.Fatalf("audited=%#v", audited)
	}

	wrongNodePath := filepath.Join(fixture.directory, "wrong-node.ndjson")
	wrongNodeLedger, err := connectorledger.Open(wrongNodePath, receiptPrivate, "node-b/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongNodeLedger.Begin(event); err != nil {
		t.Fatal(err)
	}
	if err := wrongNodeLedger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"task", "audit", "-in", fixture.bundlePath, "-public-key", fixture.publicPath, "-key-id", fixture.keyID,
		"-receipts", wrongNodePath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-b/gateway",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not match the task permit node") {
		t.Fatalf("wrong-node receipt error=%v", err)
	}

	mismatchPath := filepath.Join(fixture.directory, "mismatch.ndjson")
	mismatchLedger, err := connectorledger.Open(mismatchPath, receiptPrivate, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := event
	mismatched.OperationID = "hermes.other"
	if _, err := mismatchLedger.Begin(mismatched); err != nil {
		t.Fatal(err)
	}
	if err := mismatchLedger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"task", "audit", "-in", fixture.bundlePath, "-public-key", fixture.publicPath, "-key-id", fixture.keyID,
		"-receipts", mismatchPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "every task-permit binding") {
		t.Fatalf("mismatched receipt error=%v", err)
	}
}

func TestTaskAuditIncludesLifecycleDispatchAndTaskLocalChain(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	statement := fixture.issue(t)
	public, err := readPublicKey(fixture.publicPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := readTaskBundle(
		fixture.bundlePath, map[string]ed25519.PublicKey{fixture.keyID: public}, fixture.now, taskpermit.MaxValidity,
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptPrivatePath, receiptPublicPath := generateTestKeyPair(t, fixture.directory, "lifecycle-receipt")
	receiptPrivate, err := readPrivateKey(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receiptsPath := filepath.Join(fixture.directory, "lifecycle-task-receipts.ndjson")
	ledger, err := connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, Kind: connectorledger.ServiceTask,
		TenantID: statement.TenantID, RuntimeRef: statement.RuntimeRef, CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest: statement.PolicyDigest, RoutePolicyDigest: statement.RoutePolicyDigest, Generation: statement.Generation,
		GrantID: statement.GrantID, ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest:            taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		AuthorityKeyID:        bundle.Verified.KeyID, PermitDigest: bundle.Verified.EnvelopeDigest,
		RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
	authorizationHead, err := ledger.Begin(event)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := event
	dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
	dispatch.HTTPStatus, dispatch.ResponseBytes = http.StatusAccepted, 45
	dispatch.RunID = "run_0123456789abcdef0123456789abcdef"
	dispatchHead, err := ledger.Dispatch(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	terminal := dispatch
	terminal.Phase, terminal.HTTPStatus, terminal.ResponseBytes = connectorledger.Terminal, http.StatusOK, 84
	terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	terminal.ResultDigest = "sha256:" + strings.Repeat("f", 64)
	terminalHead, err := ledger.Finish(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{
		"task", "audit", "-in", fixture.bundlePath, "-public-key", fixture.publicPath, "-key-id", fixture.keyID,
		"-receipts", receiptsPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
		"-receipt-epoch", "4", "-expected-sequence", "3", "-expected-chain-hash", terminalHead.ChainHash,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var audited struct {
		Valid         bool             `json:"valid"`
		Authorization *taskAuditRecord `json:"authorization"`
		Dispatch      *taskAuditRecord `json:"dispatch"`
		Terminal      *taskAuditRecord `json:"terminal"`
	}
	if err := json.Unmarshal(output.Bytes(), &audited); err != nil {
		t.Fatal(err)
	}
	zero := "sha256:" + strings.Repeat("0", 64)
	if !audited.Valid || audited.Authorization == nil || audited.Dispatch == nil || audited.Terminal == nil ||
		audited.Authorization.SchemaVersion != connectorledger.SchemaV4 ||
		audited.Authorization.TaskSequence != 1 || audited.Authorization.PreviousTaskHash != zero ||
		audited.Dispatch.TaskSequence != 2 || audited.Dispatch.PreviousTaskHash != authorizationHead.ChainHash ||
		audited.Terminal.TaskSequence != 3 || audited.Terminal.PreviousTaskHash != dispatchHead.ChainHash ||
		audited.Terminal.Event.TaskStatus != connectorledger.TaskStatusAgentReportedCompleted {
		t.Fatalf("audited lifecycle=%#v", audited)
	}
}
