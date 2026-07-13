package executoruplink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestDeliveryStorePersistsFsyncBeforeEffectPhases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixture("delivery-1", 1)
	decision, terminal, err := store.Accept(delivery)
	if err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf("accept decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil || reloaded.records[delivery.DeliveryID].Phase != deliveryPhaseAccepted {
		t.Fatalf("accepted phase was not durable: %#v %v", reloaded, err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	reloaded, err = LoadDeliveryStore(path, "node-1")
	if err != nil || reloaded.records[delivery.DeliveryID].Phase != deliveryPhaseExecuting {
		t.Fatalf("executing phase was not durable: %#v %v", reloaded, err)
	}
	if err := reloaded.RecoverExecuting(); err != nil {
		t.Fatal(err)
	}
	decision, terminal, err = reloaded.Accept(delivery)
	if err != nil || decision != deliveryReport || terminal.Status != controlprotocol.ExecutorStatusOutcomeUnknown {
		t.Fatalf("recovered decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
}

func TestDeliveryStoreReclaimResendsTerminalWithoutExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixture("delivery-1", 1)
	if decision, _, err := store.Accept(delivery); err != nil || decision != deliveryExecute {
		t.Fatalf("accept=%v err=%v", decision, err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	report := reportFixture(delivery, controlprotocol.ExecutorStatusDone)
	if err := store.MarkTerminal(report); err != nil {
		t.Fatal(err)
	}
	delivery.DeliveryGeneration = 2
	decision, terminal, err := store.Accept(delivery)
	if err != nil || decision != deliveryReport || terminal.DeliveryGeneration != 2 || terminal.Status != controlprotocol.ExecutorStatusDone {
		t.Fatalf("reclaim decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	if err := store.Settle(delivery.DeliveryID, 2); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	record := reloaded.records[delivery.DeliveryID]
	if record.SettledGeneration != 2 || record.Phase != deliveryPhaseTerminal {
		t.Fatalf("record=%#v", record)
	}
}

func TestDeliveryStoreRejectsIdentityReuseAndStaleGeneration(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	delivery := deliveryFixture("delivery-1", 2)
	if _, _, err := store.Accept(delivery); err != nil {
		t.Fatal(err)
	}
	stale := delivery
	stale.DeliveryGeneration = 1
	if decision, _, err := store.Accept(stale); err != nil || decision != deliveryStale {
		t.Fatalf("stale decision=%v err=%v", decision, err)
	}
	mutated := delivery
	mutated.CommandDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := store.Accept(mutated); err == nil {
		t.Fatal("delivery ID reuse with another digest was accepted")
	}
}

func TestDeliveryStoreIsOwnerOnlyNodeBoundAndStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deliveries.json")
	store := newDeliveryStore(t, path)
	if store.NodeID() != "node-1" {
		t.Fatalf("node=%q", store.NodeID())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	if _, err := LoadDeliveryStore(path, "node-2"); err == nil {
		t.Fatal("delivery state was accepted for another node")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(path, "node-1"); err == nil {
		t.Fatal("group-readable delivery state was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(link, "node-1"); err == nil {
		t.Fatal("symlink delivery state was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"node_id":"node-1","records":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(path, "node-1"); err == nil {
		t.Fatal("null records silently reset delivery state")
	}
}

func newDeliveryStore(t *testing.T, path string) *DeliveryStore {
	t.Helper()
	if err := InitializeDeliveryStore(path, "node-1"); err != nil {
		t.Fatal(err)
	}
	store, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func deliveryFixture(id string, generation uint64) controlprotocol.ExecutorDeliveryV3 {
	return controlprotocol.ExecutorDeliveryV3{
		DeliveryID: id, DeliveryGeneration: generation, CommandID: "command-1",
		CommandDigest: "sha256:" + strings.Repeat("a", 64), CommandDSSEBase64: "e30=",
	}
}

func reportFixture(delivery controlprotocol.ExecutorDeliveryV3, status string) controlprotocol.ExecutorReportV3 {
	return controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: status, ReportedStatus: "running", ClaimGeneration: 1,
		Result: controlprotocol.ExecutorReportResultV3{RuntimeRef: "executor-ref"},
	}
}
