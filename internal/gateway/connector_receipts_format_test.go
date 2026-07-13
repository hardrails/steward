package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
)

func TestInspectConnectorReceiptFormatIsReadOnlyForProspectiveAndActualLedger(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "connector-receipts.ndjson")
	config := Config{
		ConnectorReceiptFile: path, ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 7,
		connectorReceiptKey: private,
	}

	summary, err := InspectConnectorReceiptFormat(config)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Present || summary.FormatVersion != 0 {
		t.Fatalf("prospective summary = %#v", summary)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("inspection created prospective ledger: %v", err)
	}

	ledger, err := connectorledger.Open(path, private, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest, err := connectorledger.TaskDigest("format-inspection-task")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), RoutePolicyDigest: "sha256:" + strings.Repeat("d", 64),
		Generation: 1, GrantID: "grant-" + strings.Repeat("e", 64), ConnectorID: "ticketing",
		OperationID: "create-ticket", TaskDigest: taskDigest, ErrorCode: "policy_denied",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	summary, err = InspectConnectorReceiptFormat(config)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Present || summary.FormatVersion != 1 {
		t.Fatalf("actual summary = %#v", summary)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("receipt-format inspection rewrote the ledger")
	}

	config.ActionAuthorities = []ActionAuthority{{KeyID: "approver-a", TenantID: "tenant-a", PublicKey: "configured-by-validated-loader"}}
	summary, err = InspectConnectorReceiptFormat(config)
	if err != nil || !summary.Present || summary.FormatVersion != 2 {
		t.Fatalf("permit-capable summary = %#v, error = %v", summary, err)
	}

	config.ActionAuthorities = nil
	config.ServiceOperations = []ServiceOperation{{
		ServiceID: "hermes-api", ID: "hermes.run", Method: "POST", Path: "/v1/runs", ContentType: "application/json",
		MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20, MaxSeconds: 30, MaxPermitSeconds: 300,
	}}
	summary, err = InspectConnectorReceiptFormat(config)
	if err != nil || !summary.Present || summary.FormatVersion != 3 {
		t.Fatalf("service-task-capable summary = %#v, error = %v", summary, err)
	}

	config.ServiceOperations = nil
	ledger, err = connectorledger.Open(path, private, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch)
	if err != nil {
		t.Fatal(err)
	}
	v3TaskDigest, err := connectorledger.TaskDigest("format-inspection-v3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append(connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, Kind: connectorledger.ConnectorCall, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), RoutePolicyDigest: "sha256:" + strings.Repeat("d", 64),
		Generation: 1, GrantID: "grant-" + strings.Repeat("e", 64), ConnectorID: "ticketing",
		OperationID: "create-ticket", TaskDigest: v3TaskDigest, ErrorCode: "policy_denied",
	}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err = InspectConnectorReceiptFormat(config)
	if err != nil || !summary.Present || summary.FormatVersion != 3 {
		t.Fatalf("observed v3 summary = %#v, error = %v", summary, err)
	}
}
