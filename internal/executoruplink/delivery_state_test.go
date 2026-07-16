package executoruplink

import (
	"encoding/json"
	"fmt"
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
	decision, terminal, err := store.Accept(delivery, "tenant-a")
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
	decision, terminal, err = reloaded.Accept(delivery, "tenant-a")
	if err != nil || decision != deliveryReport || terminal.Status != controlprotocol.ExecutorStatusOutcomeUnknown {
		t.Fatalf("recovered decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
}

func TestDeliveryStoreReclaimResendsTerminalWithoutExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixture("delivery-1", 1)
	if decision, _, err := store.Accept(delivery, "tenant-a"); err != nil || decision != deliveryExecute {
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
	decision, terminal, err := store.Accept(delivery, "tenant-a")
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

func TestDeliveryStoreListsBoundedUnacknowledgedReportsDeterministically(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	for _, deliveryID := range []string{"delivery-c", "delivery-a", "delivery-b", "delivery-settled"} {
		delivery := deliveryFixture(deliveryID, 1)
		delivery.CommandID = "command-" + deliveryID
		if decision, _, err := store.Accept(delivery, "tenant-a"); err != nil || decision != deliveryExecute {
			t.Fatalf("accept %s: decision=%v err=%v", deliveryID, decision, err)
		}
		if err := store.MarkExecuting(deliveryID); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkTerminal(reportFixture(delivery, controlprotocol.ExecutorStatusDone)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Settle("delivery-settled", 1); err != nil {
		t.Fatal(err)
	}

	reports, more, err := store.UnacknowledgedReports(2)
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(reports) != 2 || reports[0].DeliveryID != "delivery-a" || reports[1].DeliveryID != "delivery-b" {
		t.Fatalf("reports=%#v more=%v", reports, more)
	}
	reports[0].CommandID = "mutated-copy"
	if store.records["delivery-a"].Terminal.CommandID == "mutated-copy" {
		t.Fatal("returned report aliases durable delivery state")
	}
	for _, report := range reports {
		if err := store.Settle(report.DeliveryID, report.DeliveryGeneration); err != nil {
			t.Fatal(err)
		}
	}
	reports, more, err = store.UnacknowledgedReports(2)
	if err != nil || more || len(reports) != 1 || reports[0].DeliveryID != "delivery-c" {
		t.Fatalf("remaining reports=%#v more=%v err=%v", reports, more, err)
	}
	if _, _, err := store.UnacknowledgedReports(0); err == nil {
		t.Fatal("zero report limit was accepted")
	}
	if _, _, err := store.UnacknowledgedReports(controlprotocol.MaxExecutorDeliveries + 1); err == nil {
		t.Fatal("report limit above the protocol bound was accepted")
	}
}

func TestDeliveryStoreRejectsIdentityReuseAndStaleGeneration(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	delivery := deliveryFixture("delivery-1", 2)
	if _, _, err := store.Accept(delivery, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	stale := delivery
	stale.DeliveryGeneration = 1
	if decision, _, err := store.Accept(stale, "tenant-a"); err != nil || decision != deliveryStale {
		t.Fatalf("stale decision=%v err=%v", decision, err)
	}
	mutated := delivery
	mutated.CommandDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := store.Accept(mutated, "tenant-a"); err == nil {
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
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := InspectDeliveryStateFormat(path)
	if err != nil || !summary.Present || summary.FormatVersion != deliveryStateVersion {
		t.Fatalf("format summary=%#v err=%v", summary, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("format inspection changed state: err=%v", err)
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
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"version":%d,"node_id":"node-1","records":null}`, deliveryStateVersion)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(path, "node-1"); err == nil {
		t.Fatal("null records silently reset delivery state")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"node_id":"node-1","records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(path, "node-1"); err == nil || !strings.Contains(err.Error(), "unsupported format version 1") {
		t.Fatalf("pre-tenant delivery format was accepted: %v", err)
	}
	missingTenant := deliveryFixture("missing-tenant", 1)
	raw, err := json.Marshal(deliveryStateFile{Version: deliveryStateVersion, NodeID: "node-1", Records: []deliveryRecord{{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      missingTenant.DeliveryID, DeliveryGeneration: 1,
		CommandID: missingTenant.CommandID, CommandDigest: missingTenant.CommandDigest, Phase: deliveryPhaseAccepted,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDeliveryStore(path, "node-1"); err == nil || !strings.Contains(err.Error(), "missing verified tenant identity") {
		t.Fatalf("tenantless accepted record was loaded: %v", err)
	}
}

func TestDeliveryStoreCompactsAcknowledgedTerminalRecordsAtCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	full := make(map[string]deliveryRecord, maxDeliveryRecords)
	for index := 0; index < maxDeliveryRecords; index++ {
		delivery := deliveryFixture(fmt.Sprintf("settled-%04d", index), 1)
		delivery.CommandID = fmt.Sprintf("command-%04d", index)
		report := reportFixture(delivery, controlprotocol.ExecutorStatusDone)
		full[delivery.DeliveryID] = deliveryRecord{
			DeliveryID: delivery.DeliveryID, DeliveryGeneration: 1, SettledGeneration: 1,
			TenantID: fmt.Sprintf("tenant-%04d", index), CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
			Phase: deliveryPhaseTerminal, Terminal: &report,
		}
	}
	store.records = full
	newcomer := deliveryFixture("zz-new-delivery", 1)
	newcomer.CommandID = "new-command"
	decision, terminal, err := store.Accept(newcomer, "tenant-a")
	if err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf("accept decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	if len(store.records) != deliveryCompactionTarget+1 {
		t.Fatalf("records=%d, want %d", len(store.records), deliveryCompactionTarget+1)
	}
	if _, exists := store.records["settled-0000"]; exists {
		t.Fatal("deterministic oldest candidate was not compacted")
	}
	if _, exists := store.records["settled-4095"]; !exists {
		t.Fatal("compaction removed more records than its target")
	}
	if _, exists := store.records[newcomer.DeliveryID]; !exists {
		t.Fatal("new delivery was not retained")
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil || len(reloaded.records) != deliveryCompactionTarget+1 {
		t.Fatalf("compacted state was not durable: records=%d err=%v", len(reloaded.records), err)
	}
}

func TestDeliveryStoreCompactionNeverEvictsUnsettledOrAmbiguousOutcomes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	full := make(map[string]deliveryRecord, maxDeliveryRecords)
	for index := 0; index < maxDeliveryRecords-2; index++ {
		delivery := deliveryFixture(fmt.Sprintf("unsettled-%04d", index), 1)
		delivery.CommandID = fmt.Sprintf("command-%04d", index)
		report := reportFixture(delivery, controlprotocol.ExecutorStatusDone)
		full[delivery.DeliveryID] = deliveryRecord{
			DeliveryID: delivery.DeliveryID, DeliveryGeneration: 1,
			TenantID: fmt.Sprintf("tenant-%04d", index), CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
			Phase: deliveryPhaseTerminal, Terminal: &report,
		}
	}
	failed := deliveryFixture("settled-failed", 1)
	failedReport := reportFixture(failed, controlprotocol.ExecutorStatusFailed)
	full[failed.DeliveryID] = deliveryRecord{
		DeliveryID: failed.DeliveryID, DeliveryGeneration: 1, SettledGeneration: 1,
		TenantID: "tenant-failed", CommandID: failed.CommandID, CommandDigest: failed.CommandDigest,
		Phase: deliveryPhaseTerminal, Terminal: &failedReport,
	}
	rejected := deliveryFixture("settled-rejected", 1)
	rejectedReport := reportFixture(rejected, controlprotocol.ExecutorStatusRejected)
	full[rejected.DeliveryID] = deliveryRecord{
		DeliveryID: rejected.DeliveryID, DeliveryGeneration: 1, SettledGeneration: 1,
		TenantID: "tenant-rejected", CommandID: rejected.CommandID, CommandDigest: rejected.CommandDigest,
		Phase: deliveryPhaseTerminal, Terminal: &rejectedReport,
	}
	store.records = full
	newcomer := deliveryFixture("zz-new-delivery", 1)
	newcomer.CommandID = "new-command"
	if decision, _, err := store.Accept(newcomer, "tenant-a"); err != nil || decision != deliveryExecute {
		t.Fatalf("accept decision=%v err=%v", decision, err)
	}
	if len(store.records) != maxDeliveryRecords {
		t.Fatalf("records=%d, want %d", len(store.records), maxDeliveryRecords)
	}
	if _, exists := store.records[rejected.DeliveryID]; exists {
		t.Fatal("acknowledged safe terminal record was not compacted")
	}
	if _, exists := store.records[failed.DeliveryID]; !exists {
		t.Fatal("ambiguous failed outcome was compacted")
	}
	for index := 0; index < maxDeliveryRecords-2; index++ {
		if _, exists := store.records[fmt.Sprintf("unsettled-%04d", index)]; !exists {
			t.Fatalf("unsettled outcome %d was compacted", index)
		}
	}
}

func TestDeliveryStoreTenantQuotaPreservesSiblingCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	fullTenant := make(map[string]deliveryRecord, maxDeliveryRecordsPerTenant)
	for index := 0; index < maxDeliveryRecordsPerTenant; index++ {
		delivery := deliveryFixture(fmt.Sprintf("tenant-a-ambiguous-%03d", index), 1)
		delivery.CommandID = fmt.Sprintf("tenant-a-command-%03d", index)
		report := reportFixture(delivery, controlprotocol.ExecutorStatusOutcomeUnknown)
		fullTenant[delivery.DeliveryID] = deliveryRecord{
			DeliveryID: delivery.DeliveryID, DeliveryGeneration: 1, SettledGeneration: 1,
			TenantID: "tenant-a", CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
			Phase: deliveryPhaseTerminal, Terminal: &report,
		}
	}
	store.records = fullTenant

	blocked := deliveryFixture("tenant-a-blocked", 1)
	blocked.CommandID = "tenant-a-blocked-command"
	if _, _, err := store.Accept(blocked, "tenant-a"); err == nil || !strings.Contains(err.Error(), "tenant \"tenant-a\"") {
		t.Fatalf("saturated tenant accepted another ambiguous record: %v", err)
	}
	if len(store.records) != maxDeliveryRecordsPerTenant {
		t.Fatalf("rejected tenant admission changed record count to %d", len(store.records))
	}

	sibling := deliveryFixture("tenant-b-delivery", 1)
	sibling.CommandID = "tenant-b-command"
	decision, terminal, err := store.Accept(sibling, "tenant-b")
	if err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf("sibling admission = (%v, %#v, %v)", decision, terminal, err)
	}
	if len(store.records) != maxDeliveryRecordsPerTenant+1 {
		t.Fatalf("sibling record count = %d", len(store.records))
	}
}

func TestDeliveryStoreTenantCompactionReclaimsOnlySettledSafeOutcomes(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	fullTenant := make(map[string]deliveryRecord, maxDeliveryRecordsPerTenant)
	for index := 0; index < maxDeliveryRecordsPerTenant; index++ {
		delivery := deliveryFixture(fmt.Sprintf("tenant-a-rejected-%03d", index), 1)
		delivery.CommandID = fmt.Sprintf("tenant-a-command-%03d", index)
		report := reportFixture(delivery, controlprotocol.ExecutorStatusRejected)
		fullTenant[delivery.DeliveryID] = deliveryRecord{
			DeliveryID: delivery.DeliveryID, DeliveryGeneration: 1, SettledGeneration: 1,
			TenantID: "tenant-a", CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
			Phase: deliveryPhaseTerminal, Terminal: &report,
		}
	}
	store.records = fullTenant
	newcomer := deliveryFixture("tenant-a-new", 1)
	newcomer.CommandID = "tenant-a-new-command"
	if decision, _, err := store.Accept(newcomer, "tenant-a"); err != nil || decision != deliveryExecute {
		t.Fatalf("tenant admission after safe compaction = (%v, %v)", decision, err)
	}
	if got := deliveryRecordsForTenant(store.records, "tenant-a"); got != tenantDeliveryCompactionTarget+1 {
		t.Fatalf("tenant records after compaction = %d, want %d", got, tenantDeliveryCompactionTarget+1)
	}
}

func TestDeliveryStoreReservesWorstCaseTerminalBytesBeforeExecution(t *testing.T) {
	recordsAt := func(count int) map[string]deliveryRecord {
		records := make(map[string]deliveryRecord, count)
		for index := 0; index < count; index++ {
			tenantID := fmt.Sprintf("reserve-tenant-%04d", index)
			record := maximumIdentityAcceptedRecord(index, tenantID)
			records[record.DeliveryID] = record
		}
		return records
	}
	low, high := 0, maxDeliveryRecords
	for low < high {
		mid := low + (high-low+1)/2
		if err := ensureDeliveryTerminalCapacity("node-1", recordsAt(mid)); err == nil {
			low = mid
		} else {
			high = mid - 1
		}
	}
	if low <= 0 || low >= maxDeliveryRecords {
		t.Fatalf("unexpected terminal reservation boundary %d", low)
	}
	safe := recordsAt(low)
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	store.mu.Lock()
	if err := store.persistLocked(safe); err != nil {
		store.mu.Unlock()
		t.Fatalf("persist last safely reserved state: %v", err)
	}
	store.mu.Unlock()

	overflow := deliveryFixture("terminal-reserve-overflow", 1)
	overflow.CommandID = strings.Repeat("<", 256)
	if _, _, err := store.Accept(overflow, "overflow-tenant"); err == nil || !strings.Contains(err.Error(), "reserve worst-case terminal delivery state") {
		t.Fatalf("delivery without terminal reserve was accepted: %v", err)
	}
	if len(store.records) != low {
		t.Fatalf("failed reservation changed durable records to %d, want %d", len(store.records), low)
	}
	reserved := reservedDeliveryRecord(maximumIdentityAcceptedRecord(0, "tenant-a"))
	if reserved.Terminal == nil || reserved.Terminal.Validate() != nil || reserved.SettledGeneration != reserved.DeliveryGeneration {
		t.Fatalf("worst-case terminal reservation is not a valid settled report: %#v", reserved)
	}
}

func TestDeliveryStoreTenantByteReservePreservesSibling(t *testing.T) {
	tenantID := strings.Repeat("<", 128)
	records := make(map[string]deliveryRecord)
	for index := 0; index < maxDeliveryRecordsPerTenant; index++ {
		record := maximumIdentityAcceptedRecord(index, tenantID)
		records[record.DeliveryID] = record
		if reservedDeliveryBytesForTenant(records, tenantID) > maxDeliveryReservedBytesPerTenant {
			delete(records, record.DeliveryID)
			break
		}
	}
	if len(records) == 0 || len(records) >= maxDeliveryRecordsPerTenant {
		t.Fatalf("test did not reach the tenant byte boundary before its record boundary: %d", len(records))
	}
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	store.mu.Lock()
	if err := store.persistLocked(records); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()

	blocked := deliveryFixture("tenant-byte-overflow", 1)
	blocked.CommandID = strings.Repeat("<", 256)
	if _, _, err := store.Accept(blocked, tenantID); err == nil || !strings.Contains(err.Error(), "byte terminal reserve") {
		t.Fatalf("tenant byte overflow was accepted: %v", err)
	}
	sibling := deliveryFixture("tenant-byte-sibling", 1)
	sibling.CommandID = "sibling-command"
	if decision, _, err := store.Accept(sibling, "tenant-b"); err != nil || decision != deliveryExecute {
		t.Fatalf("sibling was denied by another tenant's byte reserve: (%v, %v)", decision, err)
	}
}

func maximumIdentityAcceptedRecord(index int, tenantID string) deliveryRecord {
	suffix := fmt.Sprintf("-%04d", index)
	commandID := strings.Repeat("<", 256-len(suffix)) + suffix
	return deliveryRecord{
		DeliveryID: fmt.Sprintf("reserve-delivery-%04d", index), DeliveryGeneration: 1,
		TenantID: tenantID, CommandID: commandID,
		CommandDigest: "sha256:" + strings.Repeat("a", 64), Phase: deliveryPhaseAccepted,
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
