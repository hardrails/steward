package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
)

func TestPermitIssueAndVerifyExactRequest(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "approver")
	requestPath := filepath.Join(directory, "request.json")
	request := []byte(`{"title":"Review backup alarm","severity":"high"}`)
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 7,
		CapsuleDigest: digest, Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none", ConnectorIDs: []string{"ticketing"},
	}
	intentPath := writePermitJSON(t, directory, "intent.json", intent)
	admitted := permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("b", 64), Status: "created", CapsuleDigest: digest,
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), Generation: intent.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		GrantID:      gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation),
		ConnectorURL: "http://steward-relay:8081", ConnectorIDs: []string{"ticketing"},
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64),
	}
	admissionPath := writePermitJSON(t, directory, "admission.json", admitted)
	trustPath := writeActionTrustFixture(t, directory, intent.NodeID, intent.TenantID, "ticketing", "create-ticket",
		"approver-a", publicPath, 3600)
	permitPath := filepath.Join(directory, "permit.dsse.json")
	headerPath := filepath.Join(directory, "permit.header")
	fixedNow := time.Date(2026, time.July, 13, 18, 30, 0, 0, time.UTC)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })

	var output bytes.Buffer
	err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath, "-request", requestPath,
		"-connector-id", "ticketing", "-operation-id", "create-ticket", "-task-id", "task-123",
		"-valid-for", "10m", "-key", privatePath, "-key-id", "approver-a", "-out", permitPath,
		"-header-out", headerPath,
	}, &output, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "sha256:") {
		t.Fatalf("issue output=%q", output.String())
	}
	raw, err := os.ReadFile(permitPath)
	if err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := actionpermit.DecodeHeader(strings.TrimSpace(string(header)))
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("header decode=%q err=%v", decoded, err)
	}

	output.Reset()
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a",
		"-request", requestPath, "-max-validity", "10m",
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid       bool                   `json:"valid"`
		EvaluatedAt string                 `json:"evaluated_at"`
		Statement   actionpermit.Statement `json:"statement"`
	}
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || verified.Statement.NodeID != intent.NodeID ||
		verified.Statement.RequestDigest != actionpermit.RequestDigest(request) || verified.Statement.RequestBytes != int64(len(request)) ||
		verified.EvaluatedAt != "2026-07-13T18:30:00Z" || verified.Statement.NotBefore != "2026-07-13T18:29:55Z" ||
		verified.Statement.ExpiresAt != "2026-07-13T18:39:55Z" {
		t.Fatalf("verified=%#v", verified)
	}

	output.Reset()
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a",
		"-at", "2026-07-13T18:35:00Z",
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"evaluated_at":"2026-07-13T18:35:00Z"`) {
		t.Fatalf("historical verify output=%q", output.String())
	}
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a",
		"-at", "2026-07-13T11:35:00-07:00",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "canonical UTC") {
		t.Fatalf("noncanonical evaluation time error=%v", err)
	}

	if err := os.WriteFile(requestPath, append(request, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a", "-request", requestPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("changed request verify error=%v", err)
	}
}

func TestPermitIssueRejectsAuthorityMismatchAndUnsafeValidity(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "approver")
	digest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 1,
		CapsuleDigest: digest, Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none", ConnectorIDs: []string{"ticketing"},
	}
	intentPath := writePermitJSON(t, directory, "intent.json", intent)
	admitted := permitAdmission{
		CapsuleDigest: digest, PolicyDigest: "sha256:" + strings.Repeat("b", 64), Generation: 2,
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, 2), ConnectorIDs: []string{"ticketing"},
		RoutePolicyDigest: "sha256:" + strings.Repeat("c", 64),
	}
	admissionPath := writePermitJSON(t, directory, "admission.json", admitted)
	trustPath := writeActionTrustFixture(t, directory, intent.NodeID, intent.TenantID, "ticketing", "create",
		"approver-a", publicPath, 3600)
	base := []string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath, "-connector-id", "ticketing",
		"-operation-id", "create", "-task-id", "task-1", "-key", privatePath, "-key-id", "approver-a",
		"-out", filepath.Join(directory, "permit.json"),
	}
	if err := run(base, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "do not bind") {
		t.Fatalf("mismatched admission error=%v", err)
	}
	admitted.Generation = intent.Generation
	admitted.GrantID = gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation)
	writePermitJSONReplace(t, admissionPath, admitted)
	invalidLifetime := append(append([]string(nil), base...), "-valid-for", "1.5s")
	if err := run(invalidLifetime, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "whole seconds") {
		t.Fatalf("fractional validity error=%v", err)
	}
	invalidSkew := append(append([]string(nil), base...), "-valid-for", "5s", "-clock-skew", "5s")
	if err := run(invalidSkew, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("validity-sized skew error=%v", err)
	}
	tooMuchSkew := append(append([]string(nil), base...), "-clock-skew", "5m1s")
	if err := run(tooMuchSkew, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "clock skew") {
		t.Fatalf("unbounded skew error=%v", err)
	}
	tooLongForConnector := append(append([]string(nil), base...), "-valid-for", "1h1s")
	if err := run(tooLongForConnector, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exceeds connector maximum") {
		t.Fatalf("connector maximum error=%v", err)
	}
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongTrustPath := writePermitJSON(t, directory, "wrong-node-action-trust.json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1,
		NodeID:        "node-b",
		Authorities: []actionTrustAuthority{{
			KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{"ticketing"},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: "ticketing", CredentialEpoch: 1, MaxPermitSeconds: 3600,
			AuthorityKeyIDs: []string{"approver-a"}, OperationIDs: []string{"create"},
		}},
	})
	wrongTrust := append([]string(nil), base...)
	for index := range wrongTrust {
		if wrongTrust[index] == trustPath {
			wrongTrust[index] = wrongTrustPath
			break
		}
	}
	if err := run(wrongTrust, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not match the instance node") {
		t.Fatalf("wrong-node trust inventory error=%v", err)
	}

	requestPath := filepath.Join(directory, "invalid-request.json")
	for _, invalid := range []string{`{"duplicate":1,"duplicate":2}`, `{} {}`, `{`} {
		if err := os.WriteFile(requestPath, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		arguments := append(append([]string(nil), base...), "-request", requestPath)
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "one valid JSON value") {
			t.Fatalf("invalid request %q error=%v", invalid, err)
		}
	}

	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(base, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("loose private-key permissions error=%v", err)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}

	headerPath := filepath.Join(directory, "existing.header")
	if err := os.WriteFile(headerPath, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transactional := append(append([]string(nil), base...), "-header-out", headerPath)
	if err := run(transactional, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing header output error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "permit.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed multi-output issue left a permit file: %v", err)
	}
	if raw, err := os.ReadFile(headerPath); err != nil || string(raw) != "keep\n" {
		t.Fatalf("pre-existing header changed: %q err=%v", raw, err)
	}
}

func TestPermitAuditCorrelatesExpiredPermitAndExactReceiptBindings(t *testing.T) {
	directory := t.TempDir()
	actionPrivatePath, actionPublicPath := generateTestKeyPair(t, directory, "action-authority")
	receiptPrivatePath, receiptPublicPath := generateTestKeyPair(t, directory, "connector-receipt")
	request := []byte(`{"title":"Rotate the backup key"}`)
	requestPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	capsuleDigest := "sha256:" + strings.Repeat("a", 64)
	policyDigest := "sha256:" + strings.Repeat("b", 64)
	routePolicyDigest := "sha256:" + strings.Repeat("c", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 9,
		CapsuleDigest: capsuleDigest, Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none", ConnectorIDs: []string{"ticketing"},
	}
	intentPath := writePermitJSON(t, directory, "audit-intent.json", intent)
	admissionPath := writePermitJSON(t, directory, "audit-admission.json", permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("d", 64), Status: "created", CapsuleDigest: capsuleDigest,
		PolicyDigest: policyDigest, Generation: intent.Generation, EvidenceKeyID: strings.Repeat("e", 32),
		GrantID:      gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation),
		ConnectorURL: "http://steward-relay:8081", ConnectorIDs: []string{"ticketing"}, RoutePolicyDigest: routePolicyDigest,
	})
	trustPath := writeActionTrustFixture(t, directory, intent.NodeID, intent.TenantID, "ticketing", "create-ticket",
		"approver-a", actionPublicPath, 3600)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })
	permitPath := filepath.Join(directory, "audit-permit.dsse.json")
	issueArguments := []string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath, "-request", requestPath,
		"-connector-id", "ticketing", "-operation-id", "create-ticket", "-task-id", "task-audit-1",
		"-key", actionPrivatePath, "-key-id", "approver-a", "-out", permitPath,
	}
	if err := run(issueArguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	permitRaw, err := os.ReadFile(permitPath)
	if err != nil {
		t.Fatal(err)
	}
	permitDigest := dsse.Digest(permitRaw)
	requestDigest := actionpermit.RequestDigest(request)
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, TenantID: intent.TenantID,
		RuntimeRef: "executor-" + strings.Repeat("d", 64), CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		RoutePolicyDigest: routePolicyDigest, Generation: intent.Generation,
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation), ConnectorID: "ticketing",
		OperationID: "create-ticket", TaskDigest: gateway.ConnectorCallDigest(intent.TenantID, intent.InstanceID,
			"task-audit-1", "ticketing", "create-ticket"), AuthorityKeyID: "approver-a",
		PermitDigest: permitDigest, RequestDigest: requestDigest,
		RequestBytes: int64(len(request)),
	}
	receiptPrivate, err := readPrivateKey(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receiptsPath := filepath.Join(directory, "connector-receipts.ndjson")
	ledger, err := connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Begin(event); err != nil {
		t.Fatal(err)
	}
	terminalEvent := event
	terminalEvent.Phase = connectorledger.Terminal
	terminalEvent.Outcome = connectorledger.Responded
	terminalEvent.HTTPStatus = 201
	terminalEvent.ResponseBytes = 18
	head, err := ledger.Finish(terminalEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	// Current-time verification now fails, but the signed receipt proves that
	// Gateway authorized the request while the permit was valid.
	timeNow = func() time.Time { return fixedNow.Add(48 * time.Hour) }
	if err := run([]string{"permit", "verify", "-in", permitPath, "-public-key", actionPublicPath,
		"-key-id", "approver-a"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("current verification of expired permit error=%v", err)
	}
	auditArguments := []string{
		"permit", "audit", "-in", permitPath, "-public-key", actionPublicPath, "-key-id", "approver-a",
		"-receipts", receiptsPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
		"-receipt-epoch", "3", "-request", requestPath, "-expected-sequence", "2", "-expected-chain-hash", head.ChainHash,
	}
	var output bytes.Buffer
	if err := run(auditArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var audited struct {
		Valid         bool                   `json:"valid"`
		PermitDigest  string                 `json:"permit_digest"`
		RequestDigest string                 `json:"request_digest"`
		Statement     actionpermit.Statement `json:"statement"`
		Authorization permitAuditRecord      `json:"authorization"`
		Terminal      *permitAuditRecord     `json:"terminal"`
		Head          connectorledger.Head   `json:"head"`
	}
	if err := json.Unmarshal(output.Bytes(), &audited); err != nil {
		t.Fatal(err)
	}
	if !audited.Valid || audited.PermitDigest != permitDigest || audited.RequestDigest != requestDigest ||
		audited.Statement.TaskID != "task-audit-1" ||
		audited.Authorization.Sequence != 1 || audited.Terminal == nil || audited.Terminal.Sequence != 2 || audited.Head != head {
		t.Fatalf("audit=%#v", audited)
	}
	wrongCheckpoint := append([]string(nil), auditArguments...)
	wrongCheckpoint[len(wrongCheckpoint)-3] = "1"
	if err := run(wrongCheckpoint, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "advanced sequence") {
		t.Fatalf("wrong receipt checkpoint error=%v", err)
	}

	mismatchPath := filepath.Join(directory, "mismatched-receipts.ndjson")
	mismatchLedger, err := connectorledger.Open(mismatchPath, receiptPrivate, "node-a/mismatched-gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := event
	mismatched.OperationID = "delete-ticket"
	if _, err := mismatchLedger.Begin(mismatched); err != nil {
		t.Fatal(err)
	}
	if err := mismatchLedger.Close(); err != nil {
		t.Fatal(err)
	}
	mismatchAudit := []string{
		"permit", "audit", "-in", permitPath, "-public-key", actionPublicPath, "-key-id", "approver-a",
		"-receipts", mismatchPath, "-receipt-public-key", receiptPublicPath,
		"-receipt-node-id", "node-a/mismatched-gateway", "-receipt-epoch", "1",
	}
	if err := run(mismatchAudit, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "every available") {
		t.Fatalf("mismatched receipt binding error=%v", err)
	}

	// A valid signature is insufficient when the signed receipt shows that
	// authorization happened outside the permit's validity interval.
	oldPermitPath := filepath.Join(directory, "already-expired-at-authorization.dsse.json")
	oldIssue := append([]string(nil), issueArguments...)
	oldIssue[len(oldIssue)-1] = oldPermitPath
	oldIssue = append(oldIssue, "-valid-for", "1m", "-clock-skew", "0s")
	timeNow = func() time.Time { return fixedNow.Add(-10 * time.Minute) }
	if err := run(oldIssue, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	oldPermitRaw, err := os.ReadFile(oldPermitPath)
	if err != nil {
		t.Fatal(err)
	}
	oldEvent := event
	oldEvent.PermitDigest = dsse.Digest(oldPermitRaw)
	oldReceiptsPath := filepath.Join(directory, "late-authorization-receipts.ndjson")
	oldLedger, err := connectorledger.Open(oldReceiptsPath, receiptPrivate, "node-a/late-gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldLedger.Begin(oldEvent); err != nil {
		t.Fatal(err)
	}
	if err := oldLedger.Close(); err != nil {
		t.Fatal(err)
	}
	timeNow = func() time.Time { return fixedNow.Add(48 * time.Hour) }
	lateAudit := []string{
		"permit", "audit", "-in", oldPermitPath, "-public-key", actionPublicPath, "-key-id", "approver-a",
		"-receipts", oldReceiptsPath, "-receipt-public-key", receiptPublicPath,
		"-receipt-node-id", "node-a/late-gateway", "-receipt-epoch", "1",
	}
	if err := run(lateAudit, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "not valid at connector authorization time") || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("late authorization audit error=%v", err)
	}
}

func writePermitJSON(t *testing.T, directory, name string, value any) string {
	t.Helper()
	path := filepath.Join(directory, name)
	writePermitJSONReplace(t, path, value)
	return path
}

func writePermitJSONReplace(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeActionTrustFixture(
	t *testing.T,
	directory, nodeID, tenantID, connectorID, operationID, keyID, publicPath string,
	maxPermitSeconds int,
) string {
	t.Helper()
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	return writePermitJSON(t, directory, "action-trust-"+connectorID+".json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1,
		NodeID:        nodeID,
		Authorities: []actionTrustAuthority{{
			KeyID: keyID, TenantID: tenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{connectorID},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: connectorID, CredentialEpoch: 1, MaxPermitSeconds: maxPermitSeconds,
			AuthorityKeyIDs: []string{keyID}, OperationIDs: []string{operationID},
		}},
	})
}
