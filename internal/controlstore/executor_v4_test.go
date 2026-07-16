package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestExecutorV4PollReportPersistsExactAdmissionProjection(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	raw, binding := signedV4Command(t, "command-v4", "tenant-a", "node-1", "admit", 7, 11)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", "node-1", raw, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll v4 = (%+v, %v)", deliveries, err)
	}
	projection := minimalStoreAdmissionProjection(binding.RuntimeRef, binding.InstanceGeneration)
	report := reportV4For(deliveries[0], binding.ClaimGeneration, projection)
	applied, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(4*time.Minute))
	if err != nil || !applied {
		t.Fatalf("apply report v4 = (%v, %v)", applied, err)
	}

	retained, found, err := fixture.store.GetCommand(
		fixture.admin, "tenant-a", "node-1", binding.CommandID,
	)
	if err != nil || !found {
		t.Fatalf("get retained command = (%v, %v)", found, err)
	}
	if retained.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
		retained.Terminal == nil ||
		retained.Terminal.Report.ProtocolVersion != controlprotocol.ExecutorProtocolV4 ||
		!reflect.DeepEqual(retained.Terminal.Admission, &projection) {
		t.Fatalf("retained protocol-4 command = %#v", retained)
	}
	if retry, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(5*time.Minute)); err != nil || retry {
		t.Fatalf("exact report retry = (%v, %v)", retry, err)
	}
	v3 := controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      report.DeliveryID, DeliveryGeneration: report.DeliveryGeneration,
		CommandID: report.CommandID, CommandDigest: report.CommandDigest,
		Status: report.Status, ReportedStatus: report.ReportedStatus,
		ClaimGeneration: report.ClaimGeneration,
		Result:          controlprotocol.ExecutorReportResultV3{RuntimeRef: report.Result.RuntimeRef},
	}
	if _, err := fixture.store.ApplyReport(node, v3, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("protocol-3 report closed a protocol-4 lease: %v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	fixture.store = reopened
	retained, found, err = reopened.GetCommand(
		fixture.admin, "tenant-a", "node-1", binding.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.Admission, &projection) {
		t.Fatalf("reopened admission projection = (%#v, %v, %v)", retained.Terminal, found, err)
	}
}

func TestExecutorV4AdmissionProjectionRequiresExactSignedAdmitBinding(t *testing.T) {
	tests := map[string]func(*admission.CommandStatement, *controlprotocol.ExecutorReportV4){
		"non-admit command": func(statement *admission.CommandStatement, _ *controlprotocol.ExecutorReportV4) {
			statement.Kind = "start"
		},
		"claim generation": func(_ *admission.CommandStatement, report *controlprotocol.ExecutorReportV4) {
			report.ClaimGeneration++
		},
		"runtime reference": func(_ *admission.CommandStatement, report *controlprotocol.ExecutorReportV4) {
			report.Result.RuntimeRef = "executor-" + strings.Repeat("b", 64)
			report.Result.Admission.RuntimeRef = report.Result.RuntimeRef
		},
		"instance generation": func(_ *admission.CommandStatement, report *controlprotocol.ExecutorReportV4) {
			report.Result.Admission.Generation++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRecordsFixture(t, DefaultLimits())
			fixture.createTenant(t, "tenant-a")
			_, node := fixture.createNode(t, "tenant-a")
			statement := baseV4CommandStatement("command-v4", "tenant-a", "node-1", "admit", 7, 11)
			delivery := submitAndPollV4(t, fixture, node, &statement)
			projection := minimalStoreAdmissionProjection(statement.RuntimeRef, statement.InstanceGeneration)
			report := reportV4For(delivery, statement.ClaimGeneration, projection)
			mutate(&statement, &report)
			if name == "non-admit command" {
				fixture = newRecordsFixture(t, DefaultLimits())
				fixture.createTenant(t, "tenant-a")
				_, node = fixture.createNode(t, "tenant-a")
				delivery = submitAndPollV4(t, fixture, node, &statement)
				report = reportV4For(delivery, statement.ClaimGeneration, projection)
			}
			if err := report.Validate(); err != nil {
				t.Fatalf("test report failed protocol validation before store correlation: %v", err)
			}
			if _, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
				t.Fatalf("mismatched projection error = %v", err)
			}
		})
	}
}

func TestExecutorV4SuccessfulAdmitRetainsMissingProjectionWithoutInference(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement("command-v4", "tenant-a", "node-1", "admit", 7, 11)
	delivery := submitAndPollV4(t, fixture, node, &statement)
	report := reportV4For(
		delivery,
		statement.ClaimGeneration,
		minimalStoreAdmissionProjection(statement.RuntimeRef, statement.InstanceGeneration),
	)
	report.Result.Admission = nil
	if applied, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("projection-free successful report = (%v, %v)", applied, err)
	}
	retained, found, err := fixture.store.GetCommand(fixture.admin, "tenant-a", "node-1", statement.CommandID)
	if err != nil || !found || retained.CommandKind != "admit" || retained.Terminal == nil ||
		retained.Terminal.Admission != nil || retained.Terminal.Report.Status != controlprotocol.ExecutorStatusDone {
		t.Fatalf("missing projection was inferred or became ambiguous: (%#v, %v, %v)", retained, found, err)
	}
}

func TestExecutorReportProtocolCannotCrossAStoredLeaseFence(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	raw, statement := signedV4Command(t, "command-v3", "tenant-a", "node-1", "start", 7, 11)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", "node-1", raw, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.Poll(
		node, []string{"delivery-leases-v3"}, fixture.now.Add(3*time.Minute), time.Minute, 1,
	)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll v3 = (%+v, %v)", deliveries, err)
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		CommandID: deliveries[0].CommandID, CommandDigest: deliveries[0].CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "completed",
		ClaimGeneration: statement.ClaimGeneration,
		Result:          controlprotocol.ExecutorReportResultV4{RuntimeRef: statement.RuntimeRef},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("protocol-4 report closed a protocol-3 lease: %v", err)
	}
}

func TestCommandBindingRejectsUnboundedRetainedMetadata(t *testing.T) {
	for name, mutate := range map[string]func(*admission.CommandStatement){
		"runtime": func(value *admission.CommandStatement) { value.RuntimeRef = strings.Repeat("x", 1025) },
		"kind":    func(value *admission.CommandStatement) { value.Kind = strings.Repeat("x", 65) },
		"control": func(value *admission.CommandStatement) { value.Kind = "admit\n" },
	} {
		t.Run(name, func(t *testing.T) {
			statement := baseV4CommandStatement("command-v4", "tenant-a", "node-1", "admit", 7, 11)
			mutate(&statement)
			if _, err := parseCommandBindingForSubmission(signV4CommandStatement(t, statement)); err == nil {
				t.Fatal("unbounded command metadata was retained")
			}
		})
	}
}

func TestExecutorV4LegacyUnboundedBindingCannotBrickUpgrade(t *testing.T) {
	current, limits := populatedControlState(t)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Commands) != 1 {
		t.Fatalf("commands = %d", len(snapshot.Commands))
	}
	stored := &snapshot.Commands[0]
	statement := baseV4CommandStatement(
		stored.ID,
		stored.TenantID,
		stored.NodeID,
		"admit\nlegacy",
		7,
		11,
	)
	statement.RuntimeRef = strings.Repeat("x", 1025)
	commandRaw := signV4CommandStatement(t, statement)
	stored.CommandDSSEBase64 = base64.StdEncoding.EncodeToString(commandRaw)
	stored.Digest = digestBytes(commandRaw)
	stored.State = CommandPending
	stored.DeliveryProtocol = 0
	stored.DeliveryGeneration = 0
	stored.LeaseUntil = ""
	stored.Terminal = nil
	snapshot.Version = stateFormatEvidenceVersion
	legacyRaw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	migrated, err := decodeState(legacyRaw, limits.MaxStateBytes)
	if err != nil {
		t.Fatalf("legacy command prevented upgrade: %v", err)
	}
	command := firstCommand(migrated)
	if command.CommandKind != "" || command.SignedRuntimeRef != "" {
		t.Fatalf("unsafe legacy metadata escaped quarantine: kind=%q runtime=%q", command.CommandKind, command.SignedRuntimeRef)
	}
	if !strings.EqualFold(command.ID, statement.CommandID) ||
		!reflect.DeepEqual(command.CommandDSSE, commandRaw) {
		t.Fatal("legacy command bytes or identity were not preserved")
	}

	migratedRaw, err := encodeState(migrated, limits.MaxStateBytes)
	if err != nil {
		t.Fatalf("write migrated snapshot: %v", err)
	}
	if _, err := decodeState(migratedRaw, limits.MaxStateBytes); err != nil {
		t.Fatalf("reopen migrated snapshot: %v", err)
	}
}

func TestExecutorV4RecoveryRejectsProjectionContradictingSignedCommand(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement("command-v4", "tenant-a", "node-1", "admit", 7, 11)
	delivery := submitAndPollV4(t, fixture, node, &statement)
	report := reportV4For(
		delivery,
		statement.ClaimGeneration,
		minimalStoreAdmissionProjection(statement.RuntimeRef, statement.InstanceGeneration),
	)
	if applied, err := fixture.store.ApplyReportV4(node, report, fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("apply report v4 = (%v, %v)", applied, err)
	}
	fixture.store.mu.Lock()
	current := fixture.store.current.clone()
	fixture.store.mu.Unlock()
	raw, err := encodeState(current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	terminal := snapshot.Commands[0].Terminal
	if terminal == nil || terminal.Admission == nil {
		t.Fatal("fixture lost terminal admission projection")
	}
	terminal.Admission.Generation++
	contradictory, err := terminalReportBytes(*terminal)
	if err != nil {
		t.Fatal(err)
	}
	terminal.Digest = digestBytes(contradictory)
	poisoned, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := decodeState(poisoned, fixture.limits.MaxStateBytes)
	if err == nil {
		err = validateState(recovered, fixture.limits)
	}
	if err == nil {
		t.Fatal("recovery accepted an admission projection contradicting the signed command")
	}
}

func TestExecutorStaleReportSettlesAcrossProtocolLeaseChange(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	raw, statement := signedV4Command(t, "command-stale", "tenant-a", "node-1", "start", 7, 11)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, statement.TenantID, statement.NodeID, raw, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	v3, err := fixture.store.Poll(
		node, []string{"delivery-leases-v3"}, fixture.now.Add(3*time.Minute), time.Minute, 1,
	)
	if err != nil || len(v3) != 1 {
		t.Fatalf("poll v3 = (%+v, %v)", v3, err)
	}
	v4, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		fixture.now.Add(5*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v4) != 1 || v4[0].DeliveryGeneration <= v3[0].DeliveryGeneration {
		t.Fatalf("poll v4 = (%+v, %v)", v4, err)
	}
	if applied, err := fixture.store.ApplyReport(
		node,
		reportFor(v3[0], controlprotocol.ExecutorStatusDone),
		fixture.now.Add(6*time.Minute),
	); err != nil || applied {
		t.Fatalf("stale protocol-3 report = (%v, %v)", applied, err)
	}
	currentV3 := reportFor(v3[0], controlprotocol.ExecutorStatusDone)
	currentV3.DeliveryGeneration = v4[0].DeliveryGeneration
	if _, err := fixture.store.ApplyReport(node, currentV3, fixture.now.Add(6*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("current cross-protocol report error = %v", err)
	}
}

func TestExecutorV4FormatRangeMigratesV2AndRejectsAuthoritySmuggling(t *testing.T) {
	if DefaultLimits().MaxReportBytes != 64<<10 ||
		controlprotocol.MaxExecutorReportBytes != 16<<10 {
		t.Fatal("controller or protocol report byte cap changed")
	}
	if stateFormatMinReadVersion != 1 || stateFormatMaxReadVersion != 3 ||
		stateFormatWriteVersion != stateFormatMaxReadVersion ||
		transactionFormatMinReadVersion != 1 || transactionFormatMaxReadVersion != 3 ||
		transactionFormatWriteVersion != transactionFormatMaxReadVersion {
		t.Fatal("control store read/write ranges changed without an explicit migration")
	}
	current, limits := populatedControlState(t)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != stateFormatWriteVersion {
		t.Fatalf("snapshot write version = %d", snapshot.Version)
	}
	snapshot.Version = stateFormatEvidenceVersion
	for index := range snapshot.Commands {
		snapshot.Commands[index].DeliveryProtocol = 0
	}
	legacyRaw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyRaw, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if firstCommand(migrated).DeliveryProtocol != controlprotocol.ExecutorProtocolV3 {
		t.Fatal("v2 command delivery protocol was not migrated explicitly to v3")
	}

	snapshot.Commands[0].DeliveryProtocol = controlprotocol.ExecutorProtocolV4
	smuggled, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("v2 snapshot smuggled a protocol-4 delivery fence")
	}
	snapshot.Commands[0].DeliveryProtocol = 0
	projection := minimalStoreAdmissionProjection(
		"executor-"+strings.Repeat("a", 64),
		1,
	)
	snapshot.Commands[0].Terminal.Admission = &projection
	smuggled, err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("v2 snapshot smuggled an admission projection")
	}

	command := commandToStored(firstCommand(current))
	command.DeliveryProtocol = 0
	legacyTransaction := transaction{
		Version:   transactionEvidenceVersion,
		Mutations: []mutation{{Kind: mutationCommand, Command: &command}},
	}
	if _, err := applyTransaction(current, legacyTransaction); err != nil {
		t.Fatalf("v2 transaction did not migrate a protocol-3 command: %v", err)
	}
	command.DeliveryProtocol = controlprotocol.ExecutorProtocolV4
	if _, err := applyTransaction(current, legacyTransaction); err == nil {
		t.Fatal("v2 WAL transaction smuggled a protocol-4 delivery fence")
	}

	encoded, err := encodeTransaction(mutation{Kind: mutationCommand, Command: &command})
	if err != nil {
		t.Fatal(err)
	}
	var written transaction
	if err := json.Unmarshal(encoded, &written); err != nil {
		t.Fatal(err)
	}
	if written.Version != transactionFormatWriteVersion {
		t.Fatalf("WAL write version = %d", written.Version)
	}
	for _, version := range []int{stateFormatMinReadVersion - 1, stateFormatMaxReadVersion + 1} {
		snapshot.Version = version
		candidate, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeState(candidate, limits.MaxStateBytes); err == nil {
			t.Fatalf("snapshot version %d was accepted", version)
		}
	}
}

func submitAndPollV4(
	t *testing.T,
	fixture recordsFixture,
	node controlauth.NodeIdentity,
	statement *admission.CommandStatement,
) controlprotocol.ExecutorDeliveryV4 {
	t.Helper()
	raw := signV4CommandStatement(t, *statement)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, statement.TenantID, statement.NodeID, raw, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll v4 = (%+v, %v)", deliveries, err)
	}
	return deliveries[0]
}

func signedV4Command(
	t *testing.T,
	commandID, tenantID, nodeID, kind string,
	claimGeneration, instanceGeneration uint64,
) ([]byte, admission.CommandStatement) {
	t.Helper()
	statement := baseV4CommandStatement(
		commandID, tenantID, nodeID, kind, claimGeneration, instanceGeneration,
	)
	return signV4CommandStatement(t, statement), statement
}

func baseV4CommandStatement(
	commandID, tenantID, nodeID, kind string,
	claimGeneration, instanceGeneration uint64,
) admission.CommandStatement {
	return admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2,
		CommandID:     commandID, TenantID: tenantID, NodeID: nodeID,
		InstanceID: "agent-1", RuntimeRef: "executor-" + strings.Repeat("a", 64),
		Kind: kind, ClaimGeneration: claimGeneration, InstanceGeneration: instanceGeneration,
		CommandSequence: 1, IssuedAt: "2026-07-13T12:00:00Z",
		ExpiresAt: "2026-07-13T13:00:00Z", Payload: json.RawMessage(`{}`),
	}
}

func signV4CommandStatement(t *testing.T, statement admission.CommandStatement) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, "tenant-key", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func minimalStoreAdmissionProjection(runtimeRef string, generation uint64) controlprotocol.ExecutorAdmissionProjectionV1 {
	return controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    runtimeRef, Status: "created",
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
		Generation:    generation, EvidenceKeyID: strings.Repeat("d", 32),
	}
}

func reportV4For(
	delivery controlprotocol.ExecutorDeliveryV4,
	claimGeneration uint64,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
) controlprotocol.ExecutorReportV4 {
	return controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
		ClaimGeneration: claimGeneration,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: projection.RuntimeRef, Admission: &projection,
		},
	}
}
