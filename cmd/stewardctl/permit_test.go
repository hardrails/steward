package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/influence"
)

func TestPermitContextReconstructsHistoryAndIssuesV5(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "context-approver")
	receiptPrivatePath, receiptPublicPath := generateTestKeyPair(t, directory, "context-receipt")
	request := []byte(`{"title":"Review backup alarm"}`)
	requestPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 9,
		CapsuleDigest: digest, Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none",
		ConnectorIDs: []string{"ticketing"}, EffectMode: admission.EffectModeAuthorized,
	}
	intentPath := writePermitJSON(t, directory, "context-intent.json", intent)
	grantID := gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation)
	admitted := permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("b", 64), CapsuleDigest: digest,
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), Generation: intent.Generation,
		GrantID: grantID, ConnectorIDs: intent.ConnectorIDs, RoutePolicyDigest: "sha256:" + strings.Repeat("d", 64),
		EffectMode: admission.EffectModeAuthorized, ActionApprovalThreshold: 1, ActionContextRequired: true,
	}
	admissionPath := writePermitJSON(t, directory, "context-admission.json", admitted)
	trustPath := writeActionTrustFixture(t, directory, intent.NodeID, intent.TenantID, "ticketing", "create-ticket",
		"approver-a", publicPath, 300)
	receiptPrivate, err := readPrivateKey(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	receiptsPath := filepath.Join(directory, "context-receipts.ndjson")
	ledger, err := connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	contextPath := filepath.Join(directory, "genesis-context.json")
	var contextOutput bytes.Buffer
	if err := run([]string{
		"permit", "context", "-admission", admissionPath, "-intent", intentPath, "-receipts", receiptsPath,
		"-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway", "-receipt-epoch", "4", "-out", contextPath,
	}, &contextOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	genesis, err := influence.Genesis(intent.TenantID, grantID, intent.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if contextOutput.String() != genesis.ChainHash+"\n" {
		t.Fatalf("context stdout=%q", contextOutput.String())
	}

	fixedNow := time.Date(2026, time.July, 17, 20, 0, 0, 0, time.UTC)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })
	permitPath := filepath.Join(directory, "context-permit.dsse.json")
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-context", contextPath,
		"-trust", trustPath, "-request", requestPath, "-connector-id", "ticketing", "-operation-id", "create-ticket",
		"-task-id", "task-context-1", "-key", privatePath, "-key-id", "approver-a", "-out", permitPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(permitPath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := actionpermit.Verify(raw, map[string]ed25519.PublicKey{"approver-a": public}, fixedNow, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PayloadType != actionpermit.PayloadTypeV5 || verified.Statement.InfluenceSequence != 0 ||
		verified.Statement.InfluenceHash != genesis.ChainHash || verified.Statement.ApprovalThreshold != 1 {
		t.Fatalf("context permit=%#v", verified)
	}

	ledger, err = connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, Kind: connectorledger.ConnectorCall,
		EffectMode: connectorledger.EffectModeAuthorized, TenantID: intent.TenantID, RuntimeRef: admitted.RuntimeRef,
		CapsuleDigest: admitted.CapsuleDigest, PolicyDigest: admitted.PolicyDigest, RoutePolicyDigest: admitted.RoutePolicyDigest,
		Generation: intent.Generation, GrantID: grantID, ConnectorID: "ticketing", OperationID: "create-ticket",
		OperationPolicyDigest: verified.Statement.OperationDigest,
		TaskDigest:            gateway.ConnectorCallDigest(intent.TenantID, intent.InstanceID, "task-context-1", "ticketing", "create-ticket"),
		AuthorityKeyID:        "approver-a", PermitDigest: verified.EnvelopeDigest, RequestDigest: verified.Statement.RequestDigest,
		RequestBytes: verified.Statement.RequestBytes, InfluenceHash: genesis.ChainHash,
	}
	if _, err := ledger.Begin(event); err != nil {
		t.Fatal(err)
	}
	terminal := event
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = connectorledger.Terminal, connectorledger.Responded, 201
	terminal.ResponseBytes, terminal.ResponseDigest = 12, actionpermit.RequestDigest([]byte(`{"ok":true}`))
	terminalHead, err := ledger.Finish(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	wantNext, err := influence.Advance(genesis, terminalHead.ChainHash)
	if err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(directory, "next-context.json")
	contextOutput.Reset()
	if err := run([]string{
		"permit", "context", "-admission", admissionPath, "-intent", intentPath, "-receipts", receiptsPath,
		"-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway", "-receipt-epoch", "4",
		"-expected-sequence", "2", "-expected-chain-hash", terminalHead.ChainHash, "-out", nextPath,
	}, &contextOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var gotNext influence.Head
	nextRaw, err := os.ReadFile(nextPath)
	if err != nil || json.Unmarshal(nextRaw, &gotNext) != nil || gotNext != wantNext {
		t.Fatalf("next context=%#v want=%#v err=%v", gotNext, wantNext, err)
	}

	base := []string{
		"permit", "context", "-admission", admissionPath, "-intent", intentPath, "-receipts", receiptsPath,
		"-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway", "-receipt-epoch", "4",
		"-out", filepath.Join(directory, "unused-context.json"),
	}
	assertContextError := func(arguments []string, contains string) {
		t.Helper()
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("permit context error=%v, want text %q", err, contains)
		}
	}
	assertContextError([]string{"permit"}, "requires context")
	assertContextError([]string{"permit", "unknown"}, "requires context")
	assertContextError([]string{"permit", "context"}, "requires -admission")
	assertContextError([]string{"permit", "context", "-receipt-epoch", "not-a-number"}, "invalid value")

	missingAdmission := append([]string(nil), base...)
	missingAdmission[3] = filepath.Join(directory, "missing-admission.json")
	assertContextError(missingAdmission, "read admission response")
	malformedAdmission := filepath.Join(directory, "malformed-admission.json")
	if err := os.WriteFile(malformedAdmission, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidAdmission := append([]string(nil), base...)
	invalidAdmission[3] = malformedAdmission
	assertContextError(invalidAdmission, "decode admission response")

	missingIntent := append([]string(nil), base...)
	missingIntent[5] = filepath.Join(directory, "missing-intent.json")
	assertContextError(missingIntent, "read instance intent")
	malformedIntent := filepath.Join(directory, "malformed-intent.json")
	if err := os.WriteFile(malformedIntent, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidIntent := append([]string(nil), base...)
	invalidIntent[5] = malformedIntent
	assertContextError(invalidIntent, "decode instance intent")
	invalidResources := intent
	invalidResources.Resources.MemoryBytes = 0
	invalidResourcesPath := writePermitJSON(t, directory, "invalid-resources-intent.json", invalidResources)
	invalidResourceArguments := append([]string(nil), base...)
	invalidResourceArguments[5] = invalidResourcesPath
	assertContextError(invalidResourceArguments, "resource limits must all be positive")

	nonContextAdmission := admitted
	nonContextAdmission.ActionContextRequired = false
	nonContextPath := writePermitJSON(t, directory, "non-context-admission.json", nonContextAdmission)
	mismatchedAdmission := append([]string(nil), base...)
	mismatchedAdmission[3] = nonContextPath
	assertContextError(mismatchedAdmission, "do not identify one context-locked grant")

	badReceiptKey := filepath.Join(directory, "bad-receipt.public")
	if err := os.WriteFile(badReceiptKey, []byte("not-base64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalidKey := append([]string(nil), base...)
	invalidKey[9] = badReceiptKey
	assertContextError(invalidKey, "public key")

	missingLedger := append([]string(nil), base...)
	missingLedger[7] = filepath.Join(directory, "missing-receipts.ndjson")
	assertContextError(missingLedger, "verify effect-context receipts")

	inFlightPath := filepath.Join(directory, "in-flight-receipts.ndjson")
	inFlightLedger, err := connectorledger.Open(inFlightPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inFlightLedger.Begin(event); err != nil {
		t.Fatal(err)
	}
	if err := inFlightLedger.Close(); err != nil {
		t.Fatal(err)
	}
	inFlight := append([]string(nil), base...)
	inFlight[7] = inFlightPath
	assertContextError(inFlight, "in-flight connector call")

	wrongInfluencePath := filepath.Join(directory, "wrong-influence-receipts.ndjson")
	wrongInfluenceLedger, err := connectorledger.Open(wrongInfluencePath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	wrongInfluence := event
	wrongInfluence.InfluenceHash = "sha256:" + strings.Repeat("f", 64)
	wrongInfluence.TaskDigest = gateway.ConnectorCallDigest(
		intent.TenantID, intent.InstanceID, "task-wrong-influence", "ticketing", "create-ticket",
	)
	if _, err := wrongInfluenceLedger.Begin(wrongInfluence); err != nil {
		t.Fatal(err)
	}
	if err := wrongInfluenceLedger.Close(); err != nil {
		t.Fatal(err)
	}
	wrongInfluenceArguments := append([]string(nil), base...)
	wrongInfluenceArguments[7] = wrongInfluencePath
	assertContextError(wrongInfluenceArguments, "does not continue the admitted grant's effect context")

	overlapPath := filepath.Join(directory, "overlap-receipts.ndjson")
	overlapLedger, err := connectorledger.Open(overlapPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlapLedger.Begin(event); err != nil {
		t.Fatal(err)
	}
	overlap := event
	overlap.TaskDigest = gateway.ConnectorCallDigest(
		intent.TenantID, intent.InstanceID, "task-overlap", "ticketing", "create-ticket",
	)
	if _, err := overlapLedger.Begin(overlap); err != nil {
		t.Fatal(err)
	}
	if err := overlapLedger.Close(); err != nil {
		t.Fatal(err)
	}
	overlapArguments := append([]string(nil), base...)
	overlapArguments[7] = overlapPath
	assertContextError(overlapArguments, "overlapping connector authorizations")

	ignoredPath := filepath.Join(directory, "other-grant-receipts.ndjson")
	ignoredLedger, err := connectorledger.Open(ignoredPath, receiptPrivate, "node-a/gateway", 4)
	if err != nil {
		t.Fatal(err)
	}
	ignored := event
	ignored.GrantID = "grant-" + strings.Repeat("e", 64)
	ignored.TaskDigest = gateway.ConnectorCallDigest(
		intent.TenantID, intent.InstanceID, "task-other-grant", "ticketing", "create-ticket",
	)
	if _, err := ignoredLedger.Begin(ignored); err != nil {
		t.Fatal(err)
	}
	ignoredTerminal := ignored
	ignoredTerminal.Phase, ignoredTerminal.Outcome = connectorledger.Terminal, connectorledger.Responded
	ignoredTerminal.HTTPStatus, ignoredTerminal.ResponseBytes = 200, 2
	ignoredTerminal.ResponseDigest = actionpermit.RequestDigest([]byte(`{}`))
	if _, err := ignoredLedger.Finish(ignoredTerminal); err != nil {
		t.Fatal(err)
	}
	if err := ignoredLedger.Close(); err != nil {
		t.Fatal(err)
	}
	ignoredArguments := append([]string(nil), base...)
	ignoredArguments[7] = ignoredPath
	ignoredArguments[len(ignoredArguments)-1] = filepath.Join(directory, "other-grant-context.json")
	contextOutput.Reset()
	if err := run(ignoredArguments, &contextOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if contextOutput.String() != genesis.ChainHash+"\n" {
		t.Fatalf("context with unrelated grant receipts=%q", contextOutput.String())
	}

	wrongHead := append(append([]string(nil), base...), "-expected-sequence", "1",
		"-expected-chain-hash", terminalHead.ChainHash)
	assertContextError(wrongHead, "advanced sequence")

	existingOutput := append([]string(nil), base...)
	existingOutput[len(existingOutput)-1] = nextPath
	assertContextError(existingOutput, "already exists")
	missingOutputDirectory := append([]string(nil), base...)
	missingOutputDirectory[len(missingOutputDirectory)-1] = filepath.Join(directory, "missing", "context.json")
	assertContextError(missingOutputDirectory, "no such file or directory")
}

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
	var issueSummary bytes.Buffer
	err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath, "-request", requestPath,
		"-connector-id", "ticketing", "-operation-id", "create-ticket", "-task-id", "task-123",
		"-valid-for", "10m", "-key", privatePath, "-key-id", "approver-a", "-out", permitPath,
		"-header-out", headerPath,
	}, &output, &issueSummary)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(permitPath)
	if err != nil {
		t.Fatal(err)
	}
	permitDigest := dsse.Digest(raw)
	if output.String() != permitDigest+"\n" {
		t.Fatalf("issue stdout=%q, want digest only", output.String())
	}
	var summary permitApprovalSummary
	if err := json.Unmarshal(issueSummary.Bytes(), &summary); err != nil {
		t.Fatalf("decode approval summary %q: %v", issueSummary.String(), err)
	}
	if summary.SchemaVersion != "steward.action-permit-approval-summary.v1" || summary.PermitDigest != permitDigest ||
		summary.EffectMode != admission.EffectModeStandard || summary.TenantID != intent.TenantID ||
		summary.NodeID != intent.NodeID || summary.InstanceID != intent.InstanceID || summary.Generation != intent.Generation ||
		summary.ConnectorID != "ticketing" || summary.OperationID != "create-ticket" || summary.Method != "POST" ||
		summary.Path != "/v1/tickets" || summary.TaskID != "task-123" ||
		summary.RequestDigest != actionpermit.RequestDigest(request) || summary.RequestBytes != int64(len(request)) ||
		summary.NotBefore != "2026-07-13T18:29:55Z" || summary.ExpiresAt != "2026-07-13T18:39:55Z" ||
		summary.AuthorityKey != "approver-a" {
		t.Fatalf("approval summary=%#v", summary)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.PayloadType != actionpermit.PayloadTypeV1 {
		t.Fatalf("legacy permit payload type = %q, want %q", envelope.PayloadType, actionpermit.PayloadTypeV1)
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
		verified.Statement.SchemaVersion != actionpermit.SchemaV1 || verified.Statement.EffectMode != "" ||
		verified.Statement.RequestDigest != actionpermit.RequestDigest(request) || verified.Statement.RequestBytes != int64(len(request)) ||
		verified.EvaluatedAt != "2026-07-13T18:30:00Z" || verified.Statement.NotBefore != "2026-07-13T18:29:55Z" ||
		verified.Statement.ExpiresAt != "2026-07-13T18:39:55Z" {
		t.Fatalf("verified=%#v", verified)
	}
	if err := os.Chmod(requestPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a", "-request", requestPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("verify writable request error=%v", err)
	}
	if err := os.Chmod(requestPath, 0o600); err != nil {
		t.Fatal(err)
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

	readTrustPath := writeActionTrustFixtureForOperation(t, directory, intent.NodeID, intent.TenantID, "ticketing", "read-ticket",
		"approver-a", publicPath, 3600, "GET", "/v1/tickets/current")
	bodylessPermitPath := filepath.Join(directory, "bodyless-permit.dsse.json")
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", readTrustPath,
		"-connector-id", "ticketing", "-operation-id", "read-ticket", "-task-id", "task-read-123",
		"-key", privatePath, "-key-id", "approver-a", "-out", bodylessPermitPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("issue bodyless permit: %v", err)
	}
	output.Reset()
	if err := run([]string{
		"permit", "verify", "-in", bodylessPermitPath, "-public-key", publicPath, "-key-id", "approver-a",
	}, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"content_type":""`) ||
		!strings.Contains(output.String(), `"request_bytes":0`) {
		t.Fatalf("verify bodyless permit output=%q error=%v", output.String(), err)
	}
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", readTrustPath,
		"-request", requestPath, "-connector-id", "ticketing", "-operation-id", "read-ticket", "-task-id", "task-read-body",
		"-key", privatePath, "-key-id", "approver-a", "-out", filepath.Join(directory, "invalid-read-permit.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not accept a request body") {
		t.Fatalf("body on GET trust error=%v", err)
	}
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath,
		"-connector-id", "ticketing", "-operation-id", "create-ticket", "-task-id", "task-post-empty",
		"-key", privatePath, "-key-id", "approver-a", "-out", filepath.Join(directory, "invalid-post-permit.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires -request") {
		t.Fatalf("missing POST body trust error=%v", err)
	}
}

func TestPermitIssueSelectsAuthorizedEffectsV2AndChecksAdmissionMode(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "authorized-effects-approver")
	requestPath := filepath.Join(directory, "request.json")
	request := []byte(`{"recipient":"security@example.test","body":"Rotate credentials"}`)
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 11,
		CapsuleDigest: digest, Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none", ConnectorIDs: []string{"mail"},
		EffectMode: admission.EffectModeAuthorized,
	}
	intentPath := writePermitJSON(t, directory, "authorized-intent.json", intent)
	admitted := permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("b", 64), Status: "created", CapsuleDigest: digest,
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), Generation: intent.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation), ConnectorIDs: []string{"mail"},
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64), EffectMode: admission.EffectModeAuthorized,
	}
	admissionPath := writePermitJSON(t, directory, "authorized-admission.json", admitted)
	trustPath := writeActionTrustFixture(t, directory, intent.NodeID, intent.TenantID, "mail", "send",
		"approver-a", publicPath, 300)
	fixedNow := time.Date(2026, time.July, 16, 20, 0, 0, 0, time.UTC)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })

	issue := func(outputPath string) error {
		return run([]string{
			"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath, "-request", requestPath,
			"-connector-id", "mail", "-operation-id", "send", "-task-id", "task-send-1", "-valid-for", "5m",
			"-key", privatePath, "-key-id", "approver-a", "-out", outputPath,
		}, &bytes.Buffer{}, &bytes.Buffer{})
	}
	permitPath := filepath.Join(directory, "authorized-permit.dsse.json")
	if err := issue(permitPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(permitPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.PayloadType != actionpermit.PayloadTypeV2 {
		t.Fatalf("authorized permit payload type = %q, want %q", envelope.PayloadType, actionpermit.PayloadTypeV2)
	}
	var output bytes.Buffer
	if err := run([]string{
		"permit", "verify", "-in", permitPath, "-public-key", publicPath, "-key-id", "approver-a", "-request", requestPath,
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid     bool                   `json:"valid"`
		Statement actionpermit.Statement `json:"statement"`
	}
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || verified.Statement.SchemaVersion != actionpermit.SchemaV2 ||
		verified.Statement.EffectMode != actionpermit.EffectModeAuthorized {
		t.Fatalf("authorized verify = %#v", verified)
	}
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	auditVerified, err := verifyPermitForAudit(raw, map[string]ed25519.PublicKey{"approver-a": public}, 5*time.Minute)
	if err != nil {
		t.Fatalf("verify authorized permit for audit: %v", err)
	}
	if auditVerified.PayloadType != actionpermit.PayloadTypeV2 ||
		auditVerified.Statement.EffectMode != actionpermit.EffectModeAuthorized {
		t.Fatalf("authorized audit verification = %#v", auditVerified)
	}
	statement := auditVerified.Statement
	receiptEvent := connectorledger.Event{
		TenantID: statement.TenantID, CapsuleDigest: statement.CapsuleDigest, PolicyDigest: statement.PolicyDigest,
		RoutePolicyDigest: statement.RoutePolicyDigest, Generation: statement.Generation,
		GrantID:     gateway.GrantID(statement.TenantID, statement.InstanceID, statement.Generation),
		ConnectorID: statement.ConnectorID, OperationID: statement.OperationID, EffectMode: statement.EffectMode,
		OperationPolicyDigest: statement.OperationDigest,
		TaskDigest: gateway.ConnectorCallDigest(statement.TenantID, statement.InstanceID, statement.TaskID,
			statement.ConnectorID, statement.OperationID),
		AuthorityKeyID: "approver-a", RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
	}
	if err := checkPermitReceiptBindings(statement, []string{"approver-a"}, receiptEvent); err != nil {
		t.Fatalf("authorized receipt bindings: %v", err)
	}
	for _, mutate := range []func(*connectorledger.Event){
		func(event *connectorledger.Event) { event.EffectMode = admission.EffectModeStandard },
		func(event *connectorledger.Event) { event.OperationPolicyDigest = "sha256:" + strings.Repeat("f", 64) },
	} {
		changed := receiptEvent
		mutate(&changed)
		if err := checkPermitReceiptBindings(statement, []string{"approver-a"}, changed); err == nil {
			t.Fatalf("receipt mutation was not rejected: %#v", changed)
		}
	}

	admitted.EffectMode = admission.EffectModeStandard
	writePermitJSONReplace(t, admissionPath, admitted)
	if err := issue(filepath.Join(directory, "mismatched-authorized.dsse.json")); err == nil ||
		!strings.Contains(err.Error(), "effect mode does not match") {
		t.Fatalf("mismatched authorized admission error = %v", err)
	}
	admitted.EffectMode = ""
	writePermitJSONReplace(t, admissionPath, admitted)
	if err := issue(filepath.Join(directory, "missing-authorized-mode.dsse.json")); err == nil ||
		!strings.Contains(err.Error(), "effect mode does not match") {
		t.Fatalf("missing authorized admission mode error = %v", err)
	}
	intent.EffectMode = admission.EffectModeStandard
	writePermitJSONReplace(t, intentPath, intent)
	admitted.EffectMode = admission.EffectModeAuthorized
	writePermitJSONReplace(t, admissionPath, admitted)
	if err := issue(filepath.Join(directory, "mismatched-standard.dsse.json")); err == nil ||
		!strings.Contains(err.Error(), "effect mode does not match") {
		t.Fatalf("mismatched standard admission error = %v", err)
	}
	admitted.EffectMode = admission.EffectModeStandard
	writePermitJSONReplace(t, admissionPath, admitted)
	standardPath := filepath.Join(directory, "standard-permit.dsse.json")
	if err := issue(standardPath); err != nil {
		t.Fatalf("issue standard-mode permit: %v", err)
	}
	standardRaw, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatal(err)
	}
	standardEnvelope, err := dsse.Parse(standardRaw)
	if err != nil {
		t.Fatal(err)
	}
	if standardEnvelope.PayloadType != actionpermit.PayloadTypeV1 {
		t.Fatalf("standard permit payload type = %q, want %q", standardEnvelope.PayloadType, actionpermit.PayloadTypeV1)
	}
	standardVerified, err := actionpermit.Verify(standardRaw, map[string]ed25519.PublicKey{"approver-a": public}, fixedNow, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if standardVerified.Statement.SchemaVersion != actionpermit.SchemaV1 || standardVerified.Statement.EffectMode != "" {
		t.Fatalf("standard mode leaked into legacy permit statement: %#v", standardVerified.Statement)
	}
}

func TestPermitMultiPartyApprovalHandoffIsExactAndNonOverwriting(t *testing.T) {
	directory := t.TempDir()
	privateA, publicAPath := generateTestKeyPair(t, directory, "approver-a")
	privateB, publicBPath := generateTestKeyPair(t, directory, "approver-b")
	publicA, err := readPublicKey(publicAPath)
	if err != nil {
		t.Fatal(err)
	}
	publicB, err := readPublicKey(publicBPath)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"account_id":"acct-42","rotate":true}`)
	requestPath := filepath.Join(directory, "request.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 3,
		CapsuleDigest: digest, Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none",
		ConnectorIDs: []string{"secrets-admin"}, EffectMode: admission.EffectModeAuthorized,
	}
	intentPath := writePermitJSON(t, directory, "intent.json", intent)
	authorities := []gateway.GrantActionAuthority{
		{KeyID: "approver-a", PublicKey: base64.StdEncoding.EncodeToString(publicA), ConnectorIDs: []string{"secrets-admin"}},
		{KeyID: "approver-b", PublicKey: base64.StdEncoding.EncodeToString(publicB), ConnectorIDs: []string{"secrets-admin"}},
	}
	admitted := permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("b", 64), Status: "created", CapsuleDigest: digest,
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), Generation: intent.Generation,
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation), ConnectorIDs: intent.ConnectorIDs,
		RoutePolicyDigest: "sha256:" + strings.Repeat("d", 64), EffectMode: admission.EffectModeAuthorized,
		ActionApprovalThreshold: 2, ActionAuthorities: authorities,
	}
	admissionPath := writePermitJSON(t, directory, "admission.json", admitted)
	operationDigest := mustOperationPolicyDigest(
		t, "https://accounts.example.test", 1, "secrets-admin", "rotate", "POST", "/v1/recovery/rotate",
	)
	trustPath := writePermitJSON(t, directory, "trust.json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1, NodeID: intent.NodeID, TenantID: intent.TenantID,
		Authorities: []actionTrustAuthority{
			{KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(publicA), ConnectorIDs: intent.ConnectorIDs},
			{KeyID: "approver-b", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(publicB), ConnectorIDs: intent.ConnectorIDs},
		},
		Connectors: []actionTrustConnector{{
			ConnectorID: "secrets-admin", BaseURL: "https://accounts.example.test", CredentialMode: gateway.CredentialModeBearer,
			CredentialEpoch: 1, MaxPermitSeconds: 300, AuthorityKeyIDs: []string{"approver-a", "approver-b"},
			Operations: []actionTrustOperation{{ID: "rotate", Method: "POST", Path: "/v1/recovery/rotate", PolicyDigest: operationDigest}},
		}},
	})
	fixedNow := time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })

	partialPath := filepath.Join(directory, "partial.dsse.json")
	noncanonical := admitted
	noncanonical.ActionAuthorities = append([]gateway.GrantActionAuthority(nil), admitted.ActionAuthorities...)
	noncanonical.ActionAuthorities[0].PublicKey = noncanonical.ActionAuthorities[0].PublicKey[:4] + "\n" +
		noncanonical.ActionAuthorities[0].PublicKey[4:]
	writePermitJSONReplace(t, admissionPath, noncanonical)
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath,
		"-request", requestPath, "-connector-id", "secrets-admin", "-operation-id", "rotate", "-task-id", "rotate-1",
		"-key", privateA, "-key-id", "approver-a", "-out", filepath.Join(directory, "noncanonical.dsse.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "first approval key") {
		t.Fatalf("noncanonical admitted key error = %v", err)
	}
	writePermitJSONReplace(t, admissionPath, admitted)
	var issueSummary bytes.Buffer
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath,
		"-request", requestPath, "-connector-id", "secrets-admin", "-operation-id", "rotate", "-task-id", "rotate-1",
		"-key", privateA, "-key-id", "approver-a", "-out", partialPath,
	}, &bytes.Buffer{}, &issueSummary); err != nil {
		t.Fatal(err)
	}
	var partialSummary permitApprovalSummary
	if err := json.Unmarshal(issueSummary.Bytes(), &partialSummary); err != nil {
		t.Fatal(err)
	}
	if partialSummary.Complete || partialSummary.ApprovalThreshold != 2 || partialSummary.ApprovalsCollected != 1 {
		t.Fatalf("partial summary = %+v", partialSummary)
	}
	if err := run([]string{
		"permit", "verify", "-in", partialPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "signature count") {
		t.Fatalf("incomplete verification error = %v", err)
	}

	completePath := filepath.Join(directory, "complete.dsse.json")
	headerPath := filepath.Join(directory, "complete.header")
	var approveSummary bytes.Buffer
	if err := run([]string{
		"permit", "approve", "-in", partialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-request", requestPath, "-key", privateB, "-key-id", "approver-b",
		"-out", completePath, "-header-out", headerPath,
	}, &bytes.Buffer{}, &approveSummary); err != nil {
		t.Fatal(err)
	}
	var completeSummary permitApprovalSummary
	if err := json.Unmarshal(approveSummary.Bytes(), &completeSummary); err != nil {
		t.Fatal(err)
	}
	if !completeSummary.Complete || !slices.Equal(completeSummary.AuthorityKeys, []string{"approver-a", "approver-b"}) {
		t.Fatalf("complete summary = %+v", completeSummary)
	}
	var verifiedOutput bytes.Buffer
	if err := run([]string{
		"permit", "verify", "-in", completePath, "-request", requestPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &verifiedOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(partialPath); err != nil || info.Size() == 0 {
		t.Fatalf("partial approval was overwritten: info=%v err=%v", info, err)
	}
	if header, err := os.ReadFile(headerPath); err != nil || len(bytes.TrimSpace(header)) == 0 {
		t.Fatalf("complete header = %q, %v", header, err)
	}
	if err := run([]string{
		"permit", "approve", "-in", partialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-request", requestPath, "-key", privateA, "-key-id", "approver-a",
		"-out", filepath.Join(directory, "duplicate.dsse.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already approved") {
		t.Fatalf("duplicate approval error = %v", err)
	}
	if err := os.WriteFile(requestPath, []byte(`{"account_id":"attacker","rotate":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "approve", "-in", partialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-request", requestPath, "-key", privateB, "-key-id", "approver-b",
		"-out", filepath.Join(directory, "tampered.dsse.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "exact request bytes") {
		t.Fatalf("tampered request approval error = %v", err)
	}

	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	admitted.ActionContextRequired = true
	writePermitJSONReplace(t, admissionPath, admitted)
	contextHead, err := influence.Genesis(intent.TenantID, admitted.GrantID, intent.Generation)
	if err != nil {
		t.Fatal(err)
	}
	contextPath := writePermitJSON(t, directory, "approval-context.json", contextHead)
	contextPartialPath := filepath.Join(directory, "context-partial.dsse.json")
	if err := run([]string{
		"permit", "issue", "-admission", admissionPath, "-intent", intentPath, "-context", contextPath, "-trust", trustPath,
		"-request", requestPath, "-connector-id", "secrets-admin", "-operation-id", "rotate", "-task-id", "rotate-context",
		"-key", privateA, "-key-id", "approver-a", "-out", contextPartialPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	contextCompletePath := filepath.Join(directory, "context-complete.dsse.json")
	if err := run([]string{
		"permit", "approve", "-in", contextPartialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-request", requestPath, "-key", privateB, "-key-id", "approver-b", "-out", contextCompletePath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	contextRaw, err := os.ReadFile(contextCompletePath)
	if err != nil {
		t.Fatal(err)
	}
	contextVerified, err := actionpermit.Verify(contextRaw, map[string]ed25519.PublicKey{
		"approver-a": publicA, "approver-b": publicB,
	}, fixedNow, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if contextVerified.PayloadType != actionpermit.PayloadTypeV5 ||
		contextVerified.Statement.InfluenceHash != contextHead.ChainHash || contextVerified.Statement.ApprovalThreshold != 2 {
		t.Fatalf("multi-party context permit=%#v", contextVerified)
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
	validRequestPath := filepath.Join(directory, "valid-request.json")
	if err := os.WriteFile(validRequestPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	baseWithRequest := append(append([]string(nil), base...), "-request", validRequestPath)
	for _, input := range []struct {
		name string
		path string
	}{
		{name: "admission", path: admissionPath},
		{name: "intent", path: intentPath},
		{name: "request", path: validRequestPath},
	} {
		if err := os.Chmod(input.path, 0o666); err != nil {
			t.Fatal(err)
		}
		err := run(baseWithRequest, &bytes.Buffer{}, &bytes.Buffer{})
		if restoreErr := os.Chmod(input.path, 0o600); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if err == nil || !strings.Contains(err.Error(), "permission policy") {
			t.Fatalf("writable %s error=%v", input.name, err)
		}
	}
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
		TenantID:      intent.TenantID,
		Authorities: []actionTrustAuthority{{
			KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{"ticketing"},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: "ticketing", BaseURL: "https://tickets.example.test", CredentialMode: gateway.CredentialModeBearer,
			CredentialEpoch: 1, MaxPermitSeconds: 3600,
			AuthorityKeyIDs: []string{"approver-a"}, Operations: []actionTrustOperation{{
				ID: "create", Method: "POST", Path: "/v1/tickets",
				PolicyDigest: mustOperationPolicyDigest(t, "https://tickets.example.test", 1, "ticketing", "create", "POST", "/v1/tickets"),
			}},
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
	tamperedTrustPath := writePermitJSON(t, directory, "tampered-operation-action-trust.json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1,
		NodeID:        intent.NodeID,
		TenantID:      intent.TenantID,
		Authorities: []actionTrustAuthority{{
			KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{"ticketing"},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: "ticketing", BaseURL: "https://tickets.example.test", CredentialMode: gateway.CredentialModeBearer,
			CredentialEpoch: 1, MaxPermitSeconds: 3600,
			AuthorityKeyIDs: []string{"approver-a"}, Operations: []actionTrustOperation{{
				ID: "create", Method: "PUT", Path: "/v1/tickets",
				PolicyDigest: mustOperationPolicyDigest(t, "https://tickets.example.test", 1, "ticketing", "create", "POST", "/v1/tickets"),
			}},
		}},
	})
	tamperedTrust := append([]string(nil), base...)
	for index := range tamperedTrust {
		if tamperedTrust[index] == trustPath {
			tamperedTrust[index] = tamperedTrustPath
			break
		}
	}
	if err := run(tamperedTrust, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "inconsistent connector operation policy") {
		t.Fatalf("tampered operation trust inventory error=%v", err)
	}
	tamperedModeTrustPath := writePermitJSON(t, directory, "tampered-mode-action-trust.json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1,
		NodeID:        intent.NodeID,
		TenantID:      intent.TenantID,
		Authorities: []actionTrustAuthority{{
			KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{"ticketing"},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: "ticketing", BaseURL: "https://tickets.example.test", CredentialMode: gateway.CredentialModeXAPIKey,
			CredentialEpoch: 1, MaxPermitSeconds: 3600, AuthorityKeyIDs: []string{"approver-a"},
			Operations: []actionTrustOperation{{
				ID: "create", Method: "POST", Path: "/v1/tickets",
				PolicyDigest: mustOperationPolicyDigest(t, "https://tickets.example.test", 1, "ticketing", "create", "POST", "/v1/tickets"),
			}},
		}},
	})
	tamperedModeTrust := append([]string(nil), base...)
	for index := range tamperedModeTrust {
		if tamperedModeTrust[index] == trustPath {
			tamperedModeTrust[index] = tamperedModeTrustPath
			break
		}
	}
	if err := run(tamperedModeTrust, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "inconsistent connector operation policy") {
		t.Fatalf("tampered credential mode trust inventory error=%v", err)
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
	transactional := append(append([]string(nil), base...), "-request", validRequestPath, "-header-out", headerPath)
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
	if err := os.Chmod(requestPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := run(auditArguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("audit writable request error=%v", err)
	}
	if err := os.Chmod(requestPath, 0o600); err != nil {
		t.Fatal(err)
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
	return writeActionTrustFixtureForOperation(t, directory, nodeID, tenantID, connectorID, operationID,
		keyID, publicPath, maxPermitSeconds, "POST", "/v1/tickets")
}

func writeActionTrustFixtureForOperation(
	t *testing.T,
	directory, nodeID, tenantID, connectorID, operationID, keyID, publicPath string,
	maxPermitSeconds int,
	method, path string,
) string {
	t.Helper()
	public, err := readPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	return writePermitJSON(t, directory, "action-trust-"+connectorID+"-"+operationID+".json", actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1,
		NodeID:        nodeID,
		TenantID:      tenantID,
		Authorities: []actionTrustAuthority{{
			KeyID: keyID, TenantID: tenantID, PublicKeyDigest: dsse.Digest(public), ConnectorIDs: []string{connectorID},
		}},
		Connectors: []actionTrustConnector{{
			ConnectorID: connectorID, BaseURL: "https://tickets.example.test", CredentialMode: gateway.CredentialModeBearer,
			CredentialEpoch: 1, MaxPermitSeconds: maxPermitSeconds,
			AuthorityKeyIDs: []string{keyID}, Operations: []actionTrustOperation{{
				ID: operationID, Method: method, Path: path,
				PolicyDigest: mustOperationPolicyDigest(t, "https://tickets.example.test", 1, connectorID, operationID, method, path),
			}},
		}},
	})
}

func mustOperationPolicyDigest(t *testing.T, baseURL string, epoch uint64, connectorID, operationID, method, path string) string {
	t.Helper()
	digest, err := gateway.ConnectorOperationPolicyDigest(baseURL, gateway.CredentialModeBearer, epoch, connectorID, gateway.ConnectorOperation{
		ID: operationID, Method: method, Path: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
