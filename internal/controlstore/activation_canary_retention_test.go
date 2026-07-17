package controlstore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestControllerPrunesSettledTerminalCanaryFailuresBeyondCapacity(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 32
	limits.MaxCommandsPerTenant = 32
	limits.MaxCommandsPerNode = 32
	limits.TerminalRetention = time.Second
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")

	for index := 0; index <= limits.MaxCommandsPerTenant; index++ {
		statement := baseV4CommandStatement(
			fmt.Sprintf("canary-%02d", index),
			"tenant-a",
			"node-1",
			"activation-canary",
			7,
			11,
		)
		submittedAt := fixture.now.Add(2*time.Minute + time.Duration(index)*3*time.Second)
		if _, created, err := fixture.store.SubmitCommand(
			fixture.admin,
			statement.TenantID,
			statement.NodeID,
			signV4CommandStatement(t, statement),
			submittedAt,
		); err != nil || !created {
			t.Fatalf("submit canary %d = (%v, %v)", index, created, err)
		}
		deliveries, err := fixture.store.PollV4(
			node,
			[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
			submittedAt.Add(time.Second),
			time.Minute,
			1,
		)
		if err != nil || len(deliveries) != 1 || deliveries[0].CommandID != statement.CommandID {
			t.Fatalf("poll canary %d = (%+v, %v)", index, deliveries, err)
		}
		errorCode, reportedStatus := "activation_canary_failed", "failed"
		if index%2 == 1 {
			errorCode, reportedStatus = "activation_canary_cancelled", "cancelled"
		}
		report := terminalCanaryFailureReport(
			deliveries[0],
			statement,
			errorCode,
			reportedStatus,
		)
		if applied, err := fixture.store.ApplyReportV4(
			node,
			report,
			submittedAt.Add(2*time.Second),
		); err != nil || !applied {
			t.Fatalf("apply canary %d = (%v, %v)", index, applied, err)
		}
	}

	status, err := fixture.store.Status()
	if err != nil || status.Commands != limits.MaxCommands {
		t.Fatalf("controller command count=(%d, %v)", status.Commands, err)
	}
	if _, found, err := fixture.store.GetCommand(
		fixture.admin,
		"tenant-a",
		"node-1",
		"canary-00",
	); err != nil || found {
		t.Fatalf("oldest failed canary was not pruned: found=%v err=%v", found, err)
	}
	if newest, found, err := fixture.store.GetCommand(
		fixture.admin,
		"tenant-a",
		"node-1",
		"canary-32",
	); err != nil || !found || newest.Terminal == nil ||
		newest.Terminal.Report.Status != controlprotocol.ExecutorStatusFailed {
		t.Fatalf("newest failed canary=(%#v, %v, %v)", newest.Terminal, found, err)
	}
}

func TestControllerRejectsReservedCanaryFailureCodeForOtherCommand(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"ordinary-command",
		"tenant-a",
		"node-1",
		"start",
		7,
		11,
	)
	delivery := submitAndPollV4(t, fixture, node, &statement)
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         delivery.DeliveryID,
		DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID:          delivery.CommandID,
		CommandDigest:      delivery.CommandDigest,
		Status:             controlprotocol.ExecutorStatusFailed,
		ReportedStatus:     "failed",
		ClaimGeneration:    statement.ClaimGeneration,
		ErrorCode:          "activation_canary_failed",
		Result: controlprotocol.ExecutorReportResultV4{
			Error: "known terminal Gateway outcome",
		},
	}
	if _, err := fixture.store.ApplyReportV4(
		node,
		report,
		fixture.now.Add(4*time.Minute),
	); err != ErrConflict {
		t.Fatalf("ordinary command accepted reserved canary code: %v", err)
	}
}

func TestRetainedCanaryFailureRequiresExactWireMapping(t *testing.T) {
	command := Command{
		CommandKind:              "activation-canary",
		DeliveryProtocol:         controlprotocol.ExecutorProtocolV4,
		SignedClaimGeneration:    7,
		SignedInstanceGeneration: 11,
	}
	base := controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         "delivery-1",
		DeliveryGeneration: 1,
		CommandID:          "command-1",
		CommandDigest:      "sha256:" + strings.Repeat("a", 64),
		Status:             controlprotocol.ExecutorStatusFailed,
		ReportedStatus:     "failed",
		ClaimGeneration:    7,
		ErrorCode:          "activation_canary_failed",
		Result: controlprotocol.ExecutorReportResultV4{
			Error: "agent reported a terminal failure",
		},
	}
	if err := validateRetainedExecutorReportV4Binding(command, base); err != nil {
		t.Fatalf("valid failed mapping: %v", err)
	}
	cancelled := base
	cancelled.ErrorCode = "activation_canary_cancelled"
	cancelled.ReportedStatus = "cancelled"
	if err := validateRetainedExecutorReportV4Binding(command, cancelled); err != nil {
		t.Fatalf("valid cancelled mapping: %v", err)
	}

	for name, mutate := range map[string]func(*controlprotocol.ExecutorReportV4){
		"failed reported as cancelled": func(report *controlprotocol.ExecutorReportV4) {
			report.ReportedStatus = "cancelled"
		},
		"cancelled reported as failed": func(report *controlprotocol.ExecutorReportV4) {
			report.ErrorCode = "activation_canary_cancelled"
		},
		"empty detail": func(report *controlprotocol.ExecutorReportV4) {
			report.Result.Error = ""
		},
		"done status": func(report *controlprotocol.ExecutorReportV4) {
			report.Status = controlprotocol.ExecutorStatusDone
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := validateRetainedExecutorReportV4Binding(command, candidate); err == nil {
				t.Fatal("invalid terminal canary mapping was retained")
			}
		})
	}
}

func TestOpenRejectsMalformedRetainedCanaryFailureMapping(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"canary-command",
		"tenant-a",
		"node-1",
		"activation-canary",
		7,
		11,
	)
	delivery := submitAndPollActivationCanaryV4(t, fixture, node, statement)
	report := terminalCanaryFailureReport(
		delivery,
		statement,
		"activation_canary_cancelled",
		"cancelled",
	)
	if applied, err := fixture.store.ApplyReportV4(
		node,
		report,
		fixture.now.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply valid cancelled canary = (%v, %v)", applied, err)
	}

	fixture.store.mu.Lock()
	key := commandKey(statement.TenantID, statement.NodeID, statement.CommandID)
	command := fixture.store.current.commands[key]
	command.Terminal.Report.ReportedStatus = "failed"
	raw, err := terminalReportBytes(*command.Terminal)
	if err == nil {
		command.Terminal.Digest = digestBytes(raw)
		fixture.store.current.commands[key] = command
		err = fixture.store.compactLocked()
	}
	fixture.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(fixture.dir, fixture.limits); err == nil {
		_ = reopened.Close()
		t.Fatal("recovery accepted a cancelled code reported as failed")
	}
}

func TestCanaryTenantRotationSurvivesReportsRestartAndPruning(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 5
	limits.MaxCommandsPerTenant = 5
	limits.MaxCommandsPerNode = 5
	limits.TerminalRetention = time.Second
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, node := fixture.createNode(t, "tenant-a", "tenant-b")

	statements := map[string]admission.CommandStatement{}
	for _, item := range []struct {
		id       string
		tenantID string
	}{
		{id: "a-canary-1", tenantID: "tenant-a"},
		{id: "a-canary-2", tenantID: "tenant-a"},
		{id: "b-canary-1", tenantID: "tenant-b"},
	} {
		statement := baseV4CommandStatement(
			item.id,
			item.tenantID,
			"node-1",
			"activation-canary",
			7,
			11,
		)
		statements[item.id] = statement
		submitControlCommand(t, fixture, statement, fixture.now.Add(2*time.Minute))
	}
	for _, id := range []string{"ordinary-1", "ordinary-2"} {
		statement := baseV4CommandStatement(
			id,
			"tenant-a",
			"node-1",
			"read",
			7,
			11,
		)
		statements[id] = statement
		submitControlCommand(t, fixture, statement, fixture.now.Add(2*time.Minute))
	}

	capabilities := []string{controlprotocol.ExecutorCapabilityActivationCanaryV1}
	first := pollControlV4(t, fixture.store, node, capabilities, fixture.now.Add(3*time.Minute), 3)
	assertControlDeliveryIDs(t, first, "a-canary-1", "ordinary-1", "ordinary-2")
	applyControlDeliveries(t, fixture.store, node, statements, first, fixture.now.Add(4*time.Minute))

	reopenControlFixture(t, &fixture)
	for _, id := range []string{"ordinary-3", "ordinary-4"} {
		statement := baseV4CommandStatement(
			id,
			"tenant-a",
			"node-1",
			"read",
			7,
			11,
		)
		statements[id] = statement
		submitControlCommand(t, fixture, statement, fixture.now.Add(6*time.Minute))
	}
	if _, found, err := fixture.store.GetCommand(
		fixture.admin,
		"tenant-a",
		"node-1",
		"a-canary-1",
	); err != nil || !found {
		t.Fatalf("rotation cursor was pruned before the next tenant: found=%v err=%v", found, err)
	}
	second := pollControlV4(t, fixture.store, node, capabilities, fixture.now.Add(7*time.Minute), 3)
	assertControlDeliveryIDs(t, second, "b-canary-1", "ordinary-3", "ordinary-4")
	applyControlDeliveries(t, fixture.store, node, statements, second, fixture.now.Add(8*time.Minute))

	statement := baseV4CommandStatement(
		"ordinary-5",
		"tenant-a",
		"node-1",
		"read",
		7,
		11,
	)
	statements[statement.CommandID] = statement
	submitControlCommand(t, fixture, statement, fixture.now.Add(10*time.Minute))
	if _, found, err := fixture.store.GetCommand(
		fixture.admin,
		"tenant-a",
		"node-1",
		"a-canary-1",
	); err != nil || found {
		t.Fatalf("superseded rotation cursor was not pruned: found=%v err=%v", found, err)
	}
	reopenControlFixture(t, &fixture)
	third := pollControlV4(t, fixture.store, node, capabilities, fixture.now.Add(11*time.Minute), 2)
	assertControlDeliveryIDs(t, third, "a-canary-2", "ordinary-5")
}

func TestCanaryTenantRotationOrdersCanonicalTimestampsChronologically(t *testing.T) {
	commands := map[string]Command{
		"a-terminal": {
			NodeID: "node-1", TenantID: "tenant-a",
			CommandKind: "activation-canary", DeliveryGeneration: 1,
			State: CommandTerminal,
			Terminal: &TerminalReport{
				CompletedAt: "2026-07-16T12:00:00Z",
			},
		},
		"b-terminal": {
			NodeID: "node-1", TenantID: "tenant-b",
			CommandKind: "activation-canary", DeliveryGeneration: 1,
			State: CommandTerminal,
			Terminal: &TerminalReport{
				CompletedAt: "2026-07-16T12:00:00.5Z",
			},
		},
	}
	candidates := []Command{
		{TenantID: "tenant-a", CommandKind: "activation-canary"},
		{TenantID: "tenant-b", CommandKind: "activation-canary"},
	}
	if tenant := activationCanaryTenantForPoll(
		commands,
		"node-1",
		candidates,
	); tenant != "tenant-a" {
		t.Fatalf("tenant after the chronologically latest cursor = %q", tenant)
	}
}

func TestRetainedTimestampOrderingHandlesOptionalFraction(t *testing.T) {
	whole := "2026-07-16T12:00:00Z"
	fractional := "2026-07-16T12:00:00.5Z"
	if !retainedTimestampLess(whole, fractional) {
		t.Fatal("whole-second timestamp was not ordered before a later fractional timestamp")
	}
	if retainedTimestampLess(fractional, whole) {
		t.Fatal("later fractional timestamp was ordered before the whole second")
	}
	if retainedTimestampLess(whole, whole) {
		t.Fatal("equal timestamps were ordered")
	}
}

func terminalCanaryFailureReport(
	delivery controlprotocol.ExecutorDeliveryV4,
	statement admission.CommandStatement,
	errorCode,
	reportedStatus string,
) controlprotocol.ExecutorReportV4 {
	return controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         delivery.DeliveryID,
		DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID:          delivery.CommandID,
		CommandDigest:      delivery.CommandDigest,
		Status:             controlprotocol.ExecutorStatusFailed,
		ReportedStatus:     reportedStatus,
		ClaimGeneration:    statement.ClaimGeneration,
		ErrorCode:          errorCode,
		Result: controlprotocol.ExecutorReportResultV4{
			Error: "Gateway returned a known terminal agent outcome",
		},
	}
}

func submitControlCommand(
	t *testing.T,
	fixture recordsFixture,
	statement admission.CommandStatement,
	now time.Time,
) {
	t.Helper()
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		signV4CommandStatement(t, statement),
		now,
	); err != nil || !created {
		t.Fatalf("submit %s = (%v, %v)", statement.CommandID, created, err)
	}
}

func pollControlV4(
	t *testing.T,
	store *Store,
	node controlauth.NodeIdentity,
	capabilities []string,
	now time.Time,
	max int,
) []controlprotocol.ExecutorDeliveryV4 {
	t.Helper()
	deliveries, err := store.PollV4(node, capabilities, now, time.Minute, max)
	if err != nil {
		t.Fatal(err)
	}
	return deliveries
}

func applyControlDeliveries(
	t *testing.T,
	store *Store,
	node controlauth.NodeIdentity,
	statements map[string]admission.CommandStatement,
	deliveries []controlprotocol.ExecutorDeliveryV4,
	now time.Time,
) {
	t.Helper()
	for offset, delivery := range deliveries {
		statement := statements[delivery.CommandID]
		var report controlprotocol.ExecutorReportV4
		if statement.Kind == "activation-canary" {
			report = terminalCanaryFailureReport(
				delivery,
				statement,
				"activation_canary_failed",
				"failed",
			)
		} else {
			report = controlprotocol.ExecutorReportV4{
				ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
				DeliveryID:         delivery.DeliveryID,
				DeliveryGeneration: delivery.DeliveryGeneration,
				CommandID:          delivery.CommandID,
				CommandDigest:      delivery.CommandDigest,
				Status:             controlprotocol.ExecutorStatusDone,
				ReportedStatus:     "completed",
				ClaimGeneration:    statement.ClaimGeneration,
				Result: controlprotocol.ExecutorReportResultV4{
					RuntimeRef: statement.RuntimeRef,
				},
			}
		}
		if applied, err := store.ApplyReportV4(
			node,
			report,
			now.Add(time.Duration(offset)*time.Second),
		); err != nil || !applied {
			t.Fatalf("apply %s = (%v, %v)", delivery.CommandID, applied, err)
		}
	}
}

func assertControlDeliveryIDs(
	t *testing.T,
	deliveries []controlprotocol.ExecutorDeliveryV4,
	want ...string,
) {
	t.Helper()
	got := make(map[string]bool, len(deliveries))
	for _, delivery := range deliveries {
		got[delivery.CommandID] = true
	}
	if len(got) != len(want) {
		t.Fatalf("delivery IDs=%v, want %v", got, want)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("delivery IDs=%v, missing %s", got, id)
		}
	}
}

func reopenControlFixture(t *testing.T, fixture *recordsFixture) {
	t.Helper()
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
}
