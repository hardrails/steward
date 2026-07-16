package executoruplink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestDeliveryStoreMigratesReadableV2ToWriteV3WithoutReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	delivery := deliveryFixture("legacy-terminal", 1)
	report := reportFixture(delivery, controlprotocol.ExecutorStatusDone)
	legacy := deliveryStateFileV2{
		Version: 2,
		NodeID:  "node-1",
		Records: []deliveryRecordV2{{
			DeliveryID: delivery.DeliveryID, DeliveryGeneration: 1,
			TenantID: "tenant-a", CommandID: delivery.CommandID,
			CommandDigest: delivery.CommandDigest, Phase: deliveryPhaseTerminal,
			Terminal: &report,
		}},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := InspectDeliveryStateFormat(path)
	if err != nil || summary.FormatVersion != 2 {
		t.Fatalf("legacy format summary=%#v err=%v", summary, err)
	}
	store, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	afterLoad, err := os.ReadFile(path)
	if err != nil || string(afterLoad) != string(before) {
		t.Fatalf("read-only load rewrote legacy state: err=%v", err)
	}
	record := store.records[delivery.DeliveryID]
	if record.ProtocolVersion != controlprotocol.ExecutorProtocolV3 ||
		record.Terminal == nil ||
		record.Terminal.CommandID != delivery.CommandID {
		t.Fatalf("legacy record was not preserved: %#v", record)
	}
	if err := store.MigrateFormat(); err != nil {
		t.Fatal(err)
	}
	summary, err = InspectDeliveryStateFormat(path)
	if err != nil || summary.FormatVersion != deliveryStateWriteVersion {
		t.Fatalf("migrated format summary=%#v err=%v", summary, err)
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	record = reloaded.records[delivery.DeliveryID]
	if record.ProtocolVersion != controlprotocol.ExecutorProtocolV3 ||
		record.Terminal == nil ||
		record.Terminal.CommandID != delivery.CommandID {
		t.Fatalf("migrated record changed: %#v", record)
	}
}

func TestDeliveryStoreProtocolSelectionNeverSilentlyDowngrades(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	active := deliveryFixture("active-v3", 1)
	if decision, _, err := store.Accept(active, "tenant-a"); err != nil ||
		decision != deliveryExecute {
		t.Fatalf("accept active protocol-3 record: decision=%v err=%v", decision, err)
	}
	if err := store.PrepareProtocol(controlprotocol.ExecutorProtocolV4, true); err == nil ||
		!strings.Contains(err.Error(), "retains protocol 3") {
		t.Fatalf("protocol-4 validation accepted active protocol-3 state: %v", err)
	}
	if store.records[active.DeliveryID].ProtocolVersion != controlprotocol.ExecutorProtocolV3 {
		t.Fatal("failed protocol preparation changed retained state")
	}

	settled := newDeliveryStore(t, filepath.Join(t.TempDir(), "settled.json"))
	delivery := deliveryFixture("settled-v3", 1)
	if _, _, err := settled.Accept(delivery, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := settled.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if err := settled.MarkTerminal(reportFixture(delivery, controlprotocol.ExecutorStatusDone)); err != nil {
		t.Fatal(err)
	}
	if err := settled.Settle(delivery.DeliveryID, delivery.DeliveryGeneration); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(settled.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := settled.PrepareProtocol(controlprotocol.ExecutorProtocolV4, true); err != nil {
		t.Fatal(err)
	}
	afterValidation, err := os.ReadFile(settled.path)
	if err != nil || string(afterValidation) != string(before) {
		t.Fatalf("validation-only protocol preparation changed state: err=%v", err)
	}
	if err := settled.PrepareProtocol(controlprotocol.ExecutorProtocolV4, false); err != nil {
		t.Fatal(err)
	}
	if len(settled.records) != 0 {
		t.Fatalf("safe settled records were not compacted: %#v", settled.records)
	}
}

func TestDeliveryStorePersistsAndRecoversProtocolV4Reports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixtureV4("delivery-v4", 1)
	if decision, terminal, err := store.AcceptV4(delivery, "tenant-a", 7); err != nil ||
		decision != deliveryExecute ||
		terminal != nil {
		t.Fatalf("accept protocol-4 delivery: decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	projection := projectionFixtureV4()
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
		ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: projection.RuntimeRef,
			Admission:  &projection,
		},
	}
	if err := store.MarkTerminalV4(report); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	reports, more, err := reloaded.UnacknowledgedReportsV4(1)
	if err != nil || more || len(reports) != 1 {
		t.Fatalf("retained protocol-4 reports=%#v more=%v err=%v", reports, more, err)
	}
	if reports[0].Result.Admission == nil ||
		reports[0].Result.Admission.PolicyDigest != projection.PolicyDigest ||
		reports[0].ClaimGeneration != 7 {
		t.Fatalf("retained protocol-4 report changed: %#v", reports[0])
	}
	reports[0].Result.Admission.PolicyDigest = ""
	reports, _, err = reloaded.UnacknowledgedReportsV4(1)
	if err != nil || reports[0].Result.Admission.PolicyDigest != projection.PolicyDigest {
		t.Fatalf("returned projection aliases durable state: reports=%#v err=%v", reports, err)
	}
	if v3Reports, _, err := reloaded.UnacknowledgedReports(1); err != nil ||
		len(v3Reports) != 0 {
		t.Fatalf("protocol-4 terminal leaked into protocol-3 retry: %#v err=%v", v3Reports, err)
	}
}

func TestDeliveryStoreV4RejectsClaimAndProtocolIdentityReuse(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	delivery := deliveryFixtureV4("identity-v4", 1)
	if _, _, err := store.AcceptV4(delivery, "tenant-a", 7); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AcceptV4(delivery, "tenant-a", 8); err == nil ||
		!strings.Contains(err.Error(), "claim generations") {
		t.Fatalf("delivery identity was reused across claims: %v", err)
	}
	v3 := executorDeliveryV3(delivery)
	if _, _, err := store.Accept(v3, "tenant-a"); err == nil ||
		!strings.Contains(err.Error(), "protocol versions") {
		t.Fatalf("delivery identity was reused across protocols: %v", err)
	}
}

func TestDeliveryStoreV4PreverificationRejectionRemainsReplayable(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	delivery := deliveryFixtureV4("rejected-v4", 1)
	rejected := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusRejected, ReportedStatus: "failed",
		ErrorCode: "invalid_signed_command",
		Result:    controlprotocol.ExecutorReportResultV4{Error: "signed command was rejected"},
	}
	if terminal, err := store.RejectV4(delivery, rejected); err != nil ||
		terminal == nil || terminal.ClaimGeneration != 0 {
		t.Fatalf("initial rejection=%#v err=%v", terminal, err)
	}
	decision, terminal, err := store.AcceptV4(delivery, "tenant-a", 7)
	if err != nil || decision != deliveryReport || terminal == nil ||
		terminal.Status != controlprotocol.ExecutorStatusRejected ||
		terminal.ClaimGeneration != 0 {
		t.Fatalf("verified replay decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	reloaded, err := LoadDeliveryStore(store.path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	reports, _, err := reloaded.UnacknowledgedReportsV4(1)
	if err != nil || len(reports) != 1 ||
		reports[0].Status != controlprotocol.ExecutorStatusRejected ||
		reports[0].ClaimGeneration != 0 {
		t.Fatalf("reloaded rejection=%#v err=%v", reports, err)
	}
}

func TestDeliveryStoreV4RejectsInvalidTerminalStorageMarker(t *testing.T) {
	projection := projectionFixtureV4()
	record := deliveryRecord{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      "marker-v4", DeliveryGeneration: 1,
		TenantID: "tenant-a", CommandID: "command-v4",
		CommandDigest:   "sha256:" + strings.Repeat("a", 64),
		ClaimGeneration: 7,
		Phase:           deliveryPhaseTerminal,
		Terminal: &controlprotocol.ExecutorReportV3{
			ProtocolVersion: 99,
			DeliveryID:      "marker-v4", DeliveryGeneration: 1,
			CommandID: "command-v4", CommandDigest: "sha256:" + strings.Repeat("a", 64),
			Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
			ClaimGeneration: 7,
			Result:          controlprotocol.ExecutorReportResultV3{RuntimeRef: projection.RuntimeRef},
		},
		Admission: &projection,
	}
	if err := validateDeliveryRecord(record); err == nil {
		t.Fatal("invalid protocol-4 terminal storage marker was accepted")
	}
}

func TestDeliveryStoreV4CrashRecoveryCannotCarryAdmissionProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store := newDeliveryStore(t, path)
	delivery := deliveryFixtureV4("crashed-v4", 1)
	if _, _, err := store.AcceptV4(delivery, "tenant-a", 9); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadDeliveryStore(path, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.RecoverExecuting(); err != nil {
		t.Fatal(err)
	}
	reports, _, err := reloaded.UnacknowledgedReportsV4(1)
	if err != nil || len(reports) != 1 {
		t.Fatalf("recovered reports=%#v err=%v", reports, err)
	}
	if reports[0].Status != controlprotocol.ExecutorStatusOutcomeUnknown ||
		reports[0].ClaimGeneration != 9 ||
		reports[0].Result.Admission != nil {
		t.Fatalf("recovered protocol-4 outcome=%#v", reports[0])
	}
}

func TestDeliveryStoreV4ReservesFullBoundedTerminalReport(t *testing.T) {
	record := deliveryRecord{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      "reserve-v4", DeliveryGeneration: 1,
		TenantID: "tenant-a", CommandID: "command-v4",
		CommandDigest:   "sha256:" + strings.Repeat("a", 64),
		ClaimGeneration: 1,
		Phase:           deliveryPhaseAccepted,
	}
	reserved := map[string]deliveryRecord{record.DeliveryID: record}
	base := map[string]deliveryRecord{
		record.DeliveryID: reservedDeliveryRecord(record),
	}
	baseRaw, err := marshalDeliveryState("node-1", base)
	if err != nil {
		t.Fatal(err)
	}
	reservedSize, err := reservedDeliveryStateSize("node-1", reserved)
	if err != nil {
		t.Fatal(err)
	}
	if reservedSize-len(baseRaw) != controlprotocol.MaxExecutorReportBytes {
		t.Fatalf(
			"protocol-4 reserve=%d, want %d",
			reservedSize-len(baseRaw),
			controlprotocol.MaxExecutorReportBytes,
		)
	}
}

func deliveryFixtureV4(id string, generation uint64) controlprotocol.ExecutorDeliveryV4 {
	return controlprotocol.ExecutorDeliveryV4{
		DeliveryID: id, DeliveryGeneration: generation, CommandID: "command-v4",
		CommandDigest:     "sha256:" + strings.Repeat("a", 64),
		CommandDSSEBase64: "e30=",
	}
}

func projectionFixtureV4() controlprotocol.ExecutorAdmissionProjectionV1 {
	return controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    "executor-" + strings.Repeat("b", 64),
		Status:        "created",
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("d", 64),
		Generation:    1,
		EvidenceKeyID: strings.Repeat("e", 32),
	}
}
