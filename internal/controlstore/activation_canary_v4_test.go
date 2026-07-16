package controlstore

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestActivationCanaryLeaseRequiresProtocolV4Capability(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"canary-command", "tenant-a", "node-1", "activation-canary", 7, 11,
	)
	raw := signV4CommandStatement(t, statement)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		raw,
		fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit activation canary = (%v, %v)", created, err)
	}

	v3, err := fixture.store.Poll(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v3) != 0 {
		t.Fatalf("protocol 3 leased activation canary: deliveries=%+v err=%v", v3, err)
	}
	v4WithoutCapability, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v4WithoutCapability) != 0 {
		t.Fatalf("old protocol-4 node leased activation canary: deliveries=%+v err=%v", v4WithoutCapability, err)
	}
	retained, found, err := fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.State != CommandPending || retained.DeliveryGeneration != 0 {
		t.Fatalf("ineligible polls changed pending canary: command=%+v found=%v err=%v", retained, found, err)
	}
	v4, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v4) != 1 || v4[0].CommandID != statement.CommandID {
		t.Fatalf("capable protocol-4 node did not lease canary: deliveries=%+v err=%v", v4, err)
	}
}

func TestActivationCanaryProjectionPersistsAndDeepClonesAcrossRecovery(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"canary-command", "tenant-a", "node-1", "activation-canary", 7, 11,
	)
	delivery := submitAndPollActivationCanaryV4(t, fixture, node, statement)
	projection := storeCanaryResultFixture()
	report := activationCanaryReportV4(delivery, statement, projection)
	if applied, err := fixture.store.ApplyReportV4(
		node,
		report,
		fixture.now.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply activation canary report = (%v, %v)", applied, err)
	}

	retained, found, err := fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("retained activation canary = (%+v, %v, %v)", retained.Terminal, found, err)
	}
	retained.Terminal.ActivationCanary.ActivationID = "mutated"
	retained, found, err = fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("returned canary aliases retained state: (%+v, %v, %v)", retained.Terminal, found, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	retained, found, err = reopened.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("reopened activation canary = (%+v, %v, %v)", retained.Terminal, found, err)
	}
	if applied, err := reopened.ApplyReportV4(
		node,
		report,
		fixture.now.Add(5*time.Minute),
	); err != nil || applied {
		t.Fatalf("exact recovered report retry = (%v, %v)", applied, err)
	}
}

func TestActivationCanaryProjectionRequiresExactSignedCommandBinding(t *testing.T) {
	projection := storeCanaryResultFixture()
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	base := Command{
		CommandKind:              "activation-canary",
		SignedRuntimeRef:         runtimeRef,
		SignedClaimGeneration:    7,
		SignedInstanceGeneration: 11,
		DeliveryProtocol:         controlprotocol.ExecutorProtocolV4,
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      "delivery-1", DeliveryGeneration: 1,
		CommandID: "command-1", CommandDigest: "sha256:" + strings.Repeat("a", 64),
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
		ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: runtimeRef, ActivationCanary: &projection,
		},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutorReportV4Binding(base, report); err != nil {
		t.Fatalf("valid canary binding: %v", err)
	}
	tests := map[string]func(*Command, *controlprotocol.ExecutorReportV4){
		"command kind": func(command *Command, _ *controlprotocol.ExecutorReportV4) { command.CommandKind = "start" },
		"runtime reference": func(_ *Command, value *controlprotocol.ExecutorReportV4) {
			value.Result.RuntimeRef = "executor-" + strings.Repeat("b", 64)
		},
		"claim generation":    func(_ *Command, value *controlprotocol.ExecutorReportV4) { value.ClaimGeneration++ },
		"instance generation": func(command *Command, _ *controlprotocol.ExecutorReportV4) { command.SignedInstanceGeneration = 0 },
		"delivery protocol": func(command *Command, _ *controlprotocol.ExecutorReportV4) {
			command.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			command := base
			candidate := report
			projectionCopy := projection
			candidate.Result.ActivationCanary = &projectionCopy
			mutate(&command, &candidate)
			if err := validateExecutorReportV4Binding(command, candidate); err == nil {
				t.Fatal("mismatched activation canary binding was accepted")
			}
		})
	}
}

func submitAndPollActivationCanaryV4(
	t *testing.T,
	fixture recordsFixture,
	node controlauth.NodeIdentity,
	statement admission.CommandStatement,
) controlprotocol.ExecutorDeliveryV4 {
	t.Helper()
	raw := signV4CommandStatement(t, statement)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		raw,
		fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit activation canary = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll activation canary = (%+v, %v)", deliveries, err)
	}
	return deliveries[0]
}

func storeCanaryResultFixture() controlprotocol.ExecutorActivationCanaryResultV1 {
	terminal := []byte(`{"ok":true}`)
	receipts := []byte("authorize\nterminal\nexport\n")
	return controlprotocol.ExecutorActivationCanaryResultV1{
		SchemaVersion:        controlprotocol.ExecutorActivationCanaryResultSchemaV1,
		ActivationID:         "activation-1",
		AdmissionDigest:      "sha256:" + strings.Repeat("1", 64),
		TaskDigest:           "sha256:" + strings.Repeat("2", 64),
		PermitDigest:         "sha256:" + strings.Repeat("3", 64),
		RunID:                "run_" + strings.Repeat("4", 32),
		TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: "sha256:" + strings.Repeat("5", 64),
		Qualified:                  true,
	}
}

func activationCanaryReportV4(
	delivery controlprotocol.ExecutorDeliveryV4,
	statement admission.CommandStatement,
	projection controlprotocol.ExecutorActivationCanaryResultV1,
) controlprotocol.ExecutorReportV4 {
	return controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
		ClaimGeneration: statement.ClaimGeneration,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: statement.RuntimeRef, ActivationCanary: &projection,
		},
	}
}
