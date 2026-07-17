package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
)

func TestEffectBundleIssueApproveVerifyAndPartialAudit(t *testing.T) {
	directory := t.TempDir()
	privateA, publicAPath := generateTestKeyPair(t, directory, "bundle-approver-a")
	privateB, publicBPath := generateTestKeyPair(t, directory, "bundle-approver-b")
	publicA, err := readPublicKey(publicAPath)
	if err != nil {
		t.Fatal(err)
	}
	publicB, err := readPublicKey(publicBPath)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte(`{"recipient":"ops@example.test","message":"release complete"}`)
	requestPath := filepath.Join(directory, "notify.json")
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	capsuleDigest := "sha256:" + strings.Repeat("a", 64)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-a", LineageID: "lineage-a", Generation: 4,
		CapsuleDigest: capsuleDigest, Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
		Capabilities: admission.Capabilities{Connector: true}, StateDisposition: "none",
		ConnectorIDs: []string{"mail", "ticketing"}, EffectMode: admission.EffectModeAuthorized,
	}
	intentPath := writePermitJSON(t, directory, "bundle-intent.json", intent)
	connectorIDs := []string{"mail", "ticketing"}
	authorities := []gateway.GrantActionAuthority{
		{KeyID: "approver-a", PublicKey: base64.StdEncoding.EncodeToString(publicA), ConnectorIDs: connectorIDs},
		{KeyID: "approver-b", PublicKey: base64.StdEncoding.EncodeToString(publicB), ConnectorIDs: connectorIDs},
	}
	policyDigest := "sha256:" + strings.Repeat("b", 64)
	routePolicyDigest := "sha256:" + strings.Repeat("c", 64)
	admissionPath := writePermitJSON(t, directory, "bundle-admission.json", permitAdmission{
		RuntimeRef: "executor-" + strings.Repeat("d", 64), Status: "created", CapsuleDigest: capsuleDigest,
		PolicyDigest: policyDigest, Generation: intent.Generation,
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation), ConnectorIDs: connectorIDs,
		RoutePolicyDigest: routePolicyDigest, EffectMode: admission.EffectModeAuthorized,
		ActionApprovalThreshold: 2, ActionAuthorities: authorities,
	})
	mailDigest := mustOperationPolicyDigest(t, "https://mail.example.test", 2, "mail", "send", "POST", "/v1/messages")
	ticketDigest := mustOperationPolicyDigest(t, "https://tickets.example.test", 7, "ticketing", "read", "GET", "/v1/tickets/current")
	trustInventory := actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1, NodeID: intent.NodeID, TenantID: intent.TenantID,
		Authorities: []actionTrustAuthority{
			{KeyID: "approver-a", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(publicA), ConnectorIDs: connectorIDs},
			{KeyID: "approver-b", TenantID: intent.TenantID, PublicKeyDigest: dsse.Digest(publicB), ConnectorIDs: connectorIDs},
		},
		Connectors: []actionTrustConnector{
			{ConnectorID: "mail", BaseURL: "https://mail.example.test", CredentialMode: gateway.CredentialModeBearer,
				CredentialEpoch: 2, MaxPermitSeconds: 300, AuthorityKeyIDs: []string{"approver-a", "approver-b"},
				Operations: []actionTrustOperation{{ID: "send", Method: "POST", Path: "/v1/messages", PolicyDigest: mailDigest}}},
			{ConnectorID: "ticketing", BaseURL: "https://tickets.example.test", CredentialMode: gateway.CredentialModeBearer,
				CredentialEpoch: 7, MaxPermitSeconds: 300, AuthorityKeyIDs: []string{"approver-a", "approver-b"},
				Operations: []actionTrustOperation{{ID: "read", Method: "GET", Path: "/v1/tickets/current", PolicyDigest: ticketDigest}}},
		},
	}
	trustPath := writePermitJSON(t, directory, "bundle-trust.json", trustInventory)
	plan := effectBundlePlan{
		SchemaVersion: effectBundleInputSchemaV1, BundleID: "release.42",
		Steps: []effectBundlePlanStep{
			{StepID: "02.read", ConnectorID: "ticketing", OperationID: "read", TaskID: "task.read"},
			{StepID: "01.notify", ConnectorID: "mail", OperationID: "send", TaskID: "task.notify", RequestPath: requestPath},
		},
	}
	planPath := writePermitJSON(t, directory, "bundle-plan.json", plan)
	fixedNow := time.Now().UTC().Truncate(time.Second)
	priorNow := timeNow
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = priorNow })

	partialPath := filepath.Join(directory, "bundle-partial.dsse.json")
	var issueSummary bytes.Buffer
	if err := run([]string{
		"permit", "bundle", "issue", "-admission", admissionPath, "-intent", intentPath, "-trust", trustPath,
		"-plan", planPath, "-key", privateA, "-key-id", "approver-a", "-out", partialPath,
	}, &bytes.Buffer{}, &issueSummary); err != nil {
		t.Fatal(err)
	}
	var partialSummary effectBundleApprovalSummary
	if err := json.Unmarshal(issueSummary.Bytes(), &partialSummary); err != nil {
		t.Fatal(err)
	}
	if partialSummary.Complete || partialSummary.ApprovalsCollected != 1 ||
		partialSummary.Bundle.ApprovalThreshold != 2 || partialSummary.Bundle.Steps[0].StepID != "01.notify" {
		t.Fatalf("partial bundle summary = %+v", partialSummary)
	}
	if err := run([]string{
		"permit", "bundle", "verify", "-in", partialPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "signature count") {
		t.Fatalf("incomplete bundle verification error = %v", err)
	}

	completePath := filepath.Join(directory, "bundle-complete.dsse.json")
	headerPath := filepath.Join(directory, "bundle.header")
	if err := os.WriteFile(requestPath, []byte(`{"recipient":"attacker@example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "bundle", "approve", "-in", partialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-plan", planPath, "-key", privateB, "-key-id", "approver-b",
		"-out", filepath.Join(directory, "tampered-approval.dsse.json"),
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not match the admitted exact effect plan") {
		t.Fatalf("changed request approval error = %v", err)
	}
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "bundle", "approve", "-in", partialPath, "-admission", admissionPath, "-intent", intentPath,
		"-trust", trustPath, "-plan", planPath, "-key", privateB, "-key-id", "approver-b",
		"-out", completePath, "-header-out", headerPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if header, err := os.ReadFile(headerPath); err != nil || len(bytes.TrimSpace(header)) == 0 {
		t.Fatalf("complete bundle header = %q, %v", header, err)
	}
	if err := run([]string{
		"permit", "bundle", "verify", "-in", completePath, "-plan", planPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires -plan and -trust together") {
		t.Fatalf("plan without trust verification error = %v", err)
	}
	var verifyOutput bytes.Buffer
	if err := run([]string{
		"permit", "bundle", "verify", "-in", completePath, "-plan", planPath, "-trust", trustPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &verifyOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		Valid  bool                         `json:"valid"`
		KeyIDs []string                     `json:"key_ids"`
		Bundle actionpermit.BundleStatement `json:"bundle"`
	}
	if err := json.Unmarshal(verifyOutput.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || !slices.Equal(verified.KeyIDs, []string{"approver-a", "approver-b"}) ||
		verified.Bundle.BundleID != plan.BundleID || verified.Bundle.Steps[0].RequestDigest != actionpermit.RequestDigest(request) ||
		verified.Bundle.Steps[1].RequestDigest != actionpermit.RequestDigest(nil) {
		t.Fatalf("verified bundle = %+v", verified)
	}
	staleTrust := trustInventory
	staleTrust.Connectors = append([]actionTrustConnector(nil), trustInventory.Connectors...)
	staleTrust.Connectors[0].CredentialEpoch = 3
	staleTrust.Connectors[0].Operations = append([]actionTrustOperation(nil), trustInventory.Connectors[0].Operations...)
	staleTrust.Connectors[0].Operations[0].PolicyDigest = mustOperationPolicyDigest(
		t, "https://mail.example.test", 3, "mail", "send", "POST", "/v1/messages",
	)
	staleTrustPath := writePermitJSON(t, directory, "bundle-stale-trust.json", staleTrust)
	if err := run([]string{
		"permit", "bundle", "verify", "-in", completePath, "-plan", planPath, "-trust", staleTrustPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "current trusted operation") {
		t.Fatalf("stale operation trust verification error = %v", err)
	}
	if err := os.WriteFile(requestPath, []byte(`{"recipient":"attacker@example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"permit", "bundle", "verify", "-in", completePath, "-plan", planPath, "-trust", trustPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("changed bundle request verification error = %v", err)
	}
	if err := os.WriteFile(requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}

	receiptPrivatePath, receiptPublicPath := generateTestKeyPair(t, directory, "bundle-receipt")
	receiptPrivate, err := readPrivateKey(receiptPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := os.ReadFile(completePath)
	if err != nil {
		t.Fatal(err)
	}
	step := verified.Bundle.Steps[0]
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, Kind: connectorledger.ConnectorCall,
		EffectMode: actionpermit.EffectModeAuthorized, TenantID: intent.TenantID,
		RuntimeRef: "executor-" + strings.Repeat("d", 64), CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		RoutePolicyDigest: routePolicyDigest, Generation: intent.Generation,
		GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation), ConnectorID: step.ConnectorID,
		OperationID: step.OperationID, OperationPolicyDigest: step.OperationDigest,
		TaskDigest:      gateway.ConnectorCallDigest(intent.TenantID, intent.InstanceID, step.TaskID, step.ConnectorID, step.OperationID),
		AuthorityKeySet: "approver-a,approver-b", ApprovalThreshold: 2,
		PermitDigest: dsse.Digest(permitRaw), RequestDigest: step.RequestDigest, RequestBytes: step.RequestBytes,
	}
	receiptsPath := filepath.Join(directory, "bundle-receipts.ndjson")
	ledger, err := connectorledger.Open(receiptsPath, receiptPrivate, "node-a/gateway", 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Begin(event); err != nil {
		t.Fatal(err)
	}
	terminal := event
	terminal.Phase = connectorledger.Terminal
	terminal.Outcome = connectorledger.Responded
	terminal.HTTPStatus = 204
	head, err := ledger.Finish(terminal)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	timeNow = func() time.Time { return fixedNow.Add(48 * time.Hour) }
	var auditOutput bytes.Buffer
	if err := run([]string{
		"permit", "bundle", "audit", "-in", completePath, "-plan", planPath, "-trust", trustPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
		"-receipts", receiptsPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
		"-receipt-epoch", "3", "-expected-sequence", "2", "-expected-chain-hash", head.ChainHash,
	}, &auditOutput, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var audited struct {
		Valid           bool                    `json:"valid"`
		ExecutionStatus string                  `json:"execution_status"`
		AllTerminal     bool                    `json:"all_terminal"`
		UnspentSteps    int                     `json:"unspent_steps"`
		AuthorizedSteps int                     `json:"authorized_steps"`
		TerminalSteps   int                     `json:"terminal_steps"`
		Steps           []effectBundleAuditStep `json:"steps"`
		Head            connectorledger.Head    `json:"head"`
	}
	if err := json.Unmarshal(auditOutput.Bytes(), &audited); err != nil {
		t.Fatal(err)
	}
	if !audited.Valid || audited.ExecutionStatus != "incomplete" || audited.AllTerminal ||
		audited.UnspentSteps != 1 || audited.AuthorizedSteps != 0 || audited.TerminalSteps != 1 ||
		len(audited.Steps) != 2 || audited.Steps[0].Status != "terminal" ||
		audited.Steps[0].Authorization == nil || audited.Steps[0].Terminal == nil ||
		audited.Steps[1].Status != "unspent" || audited.Head != head {
		t.Fatalf("bundle audit = %+v", audited)
	}
	if err := run([]string{
		"permit", "bundle", "audit", "-in", completePath, "-plan", planPath, "-trust", trustPath,
		"-authority", "approver-a=" + publicAPath, "-authority", "approver-b=" + publicBPath,
		"-receipts", receiptsPath, "-receipt-public-key", receiptPublicPath, "-receipt-node-id", "node-a/gateway",
		"-receipt-epoch", "3", "-expected-sequence", "2", "-expected-chain-hash", head.ChainHash,
		"-require-all-terminal",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "terminal evidence for every step") {
		t.Fatalf("require-all-terminal audit error = %v", err)
	}
}

func TestEffectBundlePlanRejectsAmbiguousAndUnsafeInputs(t *testing.T) {
	directory := t.TempDir()
	base := effectBundlePlan{
		SchemaVersion: effectBundleInputSchemaV1, BundleID: "bundle.safe",
		Steps: []effectBundlePlanStep{{StepID: "01.step", ConnectorID: "mail", OperationID: "send", TaskID: "task.one"}},
	}
	for _, test := range []struct {
		name   string
		mutate func(*effectBundlePlan)
		want   string
	}{
		{"relative request", func(plan *effectBundlePlan) { plan.Steps[0].RequestPath = "request.json" }, "absolute and clean"},
		{"duplicate task", func(plan *effectBundlePlan) {
			plan.Steps = append(plan.Steps, effectBundlePlanStep{StepID: "02.step", ConnectorID: "mail", OperationID: "send", TaskID: "task.one"})
		}, "repeats task"},
		{"invalid bundle ID", func(plan *effectBundlePlan) { plan.BundleID = "bundle/unsafe" }, "must use"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			plan.Steps = append([]effectBundlePlanStep(nil), base.Steps...)
			test.mutate(&plan)
			path := writePermitJSON(t, directory, strings.ReplaceAll(test.name, " ", "-")+".json", plan)
			if _, err := loadEffectBundlePlan(path); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("load plan error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestEffectBundleRejectsMalformedAdmissionAuthorityIDEvenWhenUnused(t *testing.T) {
	public := make(ed25519.PublicKey, ed25519.PublicKeySize)
	admitted := permitAdmission{ActionAuthorities: []gateway.GrantActionAuthority{{
		KeyID:     "unused/unsafe",
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}}}
	if err := requireAdmittedBundleAuthority(admitted, "approver-a", public, []string{"mail"}); err == nil || !strings.Contains(err.Error(), "invalid action authority ID") {
		t.Fatalf("admitted authority error = %v", err)
	}
	_, _, err := trustedEffectBundleAuthorities(
		effectBundleContext{admitted: admitted, threshold: 1},
		effectBundlePlan{Steps: []effectBundlePlanStep{{ConnectorID: "mail"}}},
		"unused", time.Minute,
	)
	if err == nil || !strings.Contains(err.Error(), "invalid action authority ID") {
		t.Fatalf("trusted authority error = %v", err)
	}
}
