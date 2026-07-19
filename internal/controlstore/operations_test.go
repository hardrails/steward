package controlstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executor"
)

func TestOperationsThresholdsAndCapacityEqualityAreBounded(t *testing.T) {
	defaults := DefaultOperationsThresholds()
	if defaults.NodeStaleAfter != 2*time.Minute ||
		defaults.EvidenceStaleAfter != 5*time.Minute ||
		defaults.CommandOverdueAfter != 5*time.Minute ||
		defaults.CapacityWarningPercent != 80 ||
		defaults.Validate() != nil {
		t.Fatalf("unexpected operations defaults: %+v", defaults)
	}
	for name, mutate := range map[string]func(*OperationsThresholds){
		"zero node":         func(value *OperationsThresholds) { value.NodeStaleAfter = 0 },
		"negative evidence": func(value *OperationsThresholds) { value.EvidenceStaleAfter = -time.Second },
		"excess command": func(value *OperationsThresholds) {
			value.CommandOverdueAfter = MaxOperationsThreshold + time.Nanosecond
		},
		"zero capacity":   func(value *OperationsThresholds) { value.CapacityWarningPercent = 0 },
		"excess capacity": func(value *OperationsThresholds) { value.CapacityWarningPercent = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := defaults
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	if !elapsedThreshold(now, canonicalTimestamp(now.Add(-2*time.Minute)), 2*time.Minute) {
		t.Fatal("threshold equality did not require attention")
	}
	if elapsedThreshold(now.Add(-time.Nanosecond), canonicalTimestamp(now.Add(-2*time.Minute)), 2*time.Minute) {
		t.Fatal("threshold fired before equality")
	}
	if !capacityAtOrAbove(4, 5, 80) || capacityAtOrAbove(3, 5, 80) {
		t.Fatal("capacity warning did not use an exact ceiling threshold")
	}
}

func TestCommandInventoryPaginatesFiltersAndProjectsTenants(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, _ = fixture.createNode(t, "tenant-a", "tenant-b")
	operatorA := operationsTenantOperator(t, fixture, "tenant-a", "operator-a")

	for index, input := range []struct {
		tenantID string
		id       string
	}{
		{"tenant-a", "command-pending"},
		{"tenant-a", "command-leased"},
		{"tenant-b", "command-failed"},
	} {
		if _, created, err := fixture.store.SubmitCommand(
			fixture.admin, input.tenantID, "node-1",
			signedCommand(t, input.id, input.tenantID, "node-1", index),
			fixture.now.Add(time.Duration(index+2)*time.Minute),
		); err != nil || !created {
			t.Fatalf("submit %s = (%v, %v)", input.id, created, err)
		}
	}
	operationsSetCommandState(
		t, fixture, "tenant-a", "node-1", "command-leased",
		CommandLeased, "", fixture.now.Add(20*time.Minute),
	)
	operationsSetCommandState(
		t, fixture, "tenant-b", "node-1", "command-failed",
		CommandTerminal, controlprotocol.ExecutorStatusFailed, fixture.now.Add(10*time.Minute),
	)

	first, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{Limit: 2})
	if err != nil || len(first.Commands) != 2 || first.NextCursor == "" {
		t.Fatalf("first command page = (%+v, %v)", first, err)
	}
	second, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		Limit: 2, Cursor: first.NextCursor,
	})
	if err != nil || len(second.Commands) != 1 || second.NextCursor != "" {
		t.Fatalf("second command page = (%+v, %v)", second, err)
	}
	ids := []string{first.Commands[0].ID, first.Commands[1].ID, second.Commands[0].ID}
	if !slices.Equal(ids, []string{"command-leased", "command-pending", "command-failed"}) {
		t.Fatalf("command page order = %v", ids)
	}
	failed, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		State: CommandTerminal, TerminalStatus: controlprotocol.ExecutorStatusFailed,
	})
	if err != nil || len(failed.Commands) != 1 || failed.Commands[0].ID != "command-failed" ||
		failed.Commands[0].TerminalStatus != controlprotocol.ExecutorStatusFailed {
		t.Fatalf("failed command filter = (%+v, %v)", failed, err)
	}
	raw, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "command_dsse") ||
		strings.Contains(string(raw), "runtime_ref") ||
		strings.Contains(string(raw), "reported_status") ||
		strings.Contains(string(raw), "error_code") ||
		strings.Contains(string(raw), "operations-test") {
		t.Fatalf("command inventory exposed payload or result data: %s", raw)
	}

	tenantPage, err := fixture.store.ListCommandInventory(operatorA, CommandInventoryQuery{})
	if err != nil || len(tenantPage.Commands) != 2 {
		t.Fatalf("tenant command page = (%+v, %v)", tenantPage, err)
	}
	for _, command := range tenantPage.Commands {
		if command.TenantID != "tenant-a" {
			t.Fatalf("tenant command inventory leaked %q", command.TenantID)
		}
	}
	operatorFirst, err := fixture.store.ListCommandInventory(operatorA, CommandInventoryQuery{Limit: 1})
	if err != nil || operatorFirst.NextCursor == "" {
		t.Fatalf("implicit tenant command cursor page = (%+v, %v)", operatorFirst, err)
	}
	operatorSecond, err := fixture.store.ListCommandInventory(operatorA, CommandInventoryQuery{
		TenantID: "tenant-a", Limit: 1, Cursor: operatorFirst.NextCursor,
	})
	if err != nil || len(operatorSecond.Commands) != 1 {
		t.Fatalf("effective tenant scope cursor reuse = (%+v, %v)", operatorSecond, err)
	}
	if _, err := fixture.store.ListCommandInventory(operatorA, CommandInventoryQuery{TenantID: "tenant-b"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant command inventory error = %v", err)
	}
	if _, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		State: CommandPending, TerminalStatus: controlprotocol.ExecutorStatusFailed,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("terminal status without terminal state error = %v", err)
	}
	if _, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		State: CommandPending, Cursor: first.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed-filter command cursor error = %v", err)
	}
	tenantFirst, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		TenantID: "tenant-a", Limit: 1,
	})
	if err != nil || tenantFirst.NextCursor == "" {
		t.Fatalf("tenant command cursor page = (%+v, %v)", tenantFirst, err)
	}
	if _, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		TenantID: "tenant-b", Limit: 1, Cursor: tenantFirst.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-scope command cursor error = %v", err)
	}
	canonical := encodeOperationsCursor(
		operationsCursorBinding("command-v1", operationsScope{siteWide: true}, "", "", ""),
		"x",
	)
	if _, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		Cursor: operationsCursorTrailingBitAlias(t, canonical),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical command cursor error = %v", err)
	}
	if _, err := fixture.store.ListCommandInventory(fixture.admin, CommandInventoryQuery{
		Cursor: encodeOperationsCursor(
			operationsCursorBinding("credential-v1", operationsScope{siteWide: true}, "", "", "", "any"),
			"credential",
		),
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-domain cursor error = %v", err)
	}
}

func TestAgentInventoryCorrelatesSignedRuntimeWithoutInventingDesiredState(t *testing.T) {
	if key := agentInventorySortKey(AgentMetadata{
		TenantID: "tenant-a", NodeID: "node-a", RuntimeRef: "runtime-a", InstanceGeneration: 2,
	}); key != "tenant-a\x00node-a\x00runtime-a\x002" {
		t.Fatalf("agent inventory sort key = %q", key)
	}
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	operator := operationsTenantOperator(t, fixture, "tenant-a", "agent-inventory-operator")

	admit := baseV4CommandStatement("agent-admit", "tenant-a", "node-1", "admit", 7, 11)
	admit.RuntimeRef = "uplink:v2:8:tenant-a:6:node-1:agent-1"
	admitDelivery := submitAndPollV4(t, fixture, node, &admit)
	executorRuntimeRef := executor.RuntimeRef(admit.TenantID, admit.InstanceID)
	projection := minimalStoreAdmissionProjection(executorRuntimeRef, admit.InstanceGeneration)
	projection.GrantID = "grant-" + strings.Repeat("e", 64)
	projection.EgressProxy = "http://steward-relay:8082"
	projection.EgressRouteIDs = []string{"inference"}
	projection.ConnectorURL = "http://steward-relay:8081"
	projection.ConnectorIDs = []string{"calendar"}
	projection.RoutePolicyDigest = "sha256:" + strings.Repeat("f", 64)
	admitReport := reportV4For(admitDelivery, admit.ClaimGeneration, projection)
	if applied, err := fixture.store.ApplyReportV4(node, admitReport, fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("apply admit report = (%v, %v)", applied, err)
	}

	start := baseV4CommandStatement("agent-start", "tenant-a", "node-1", "start", 7, 11)
	start.RuntimeRef = admit.RuntimeRef
	start.CommandSequence = 2
	startDelivery := submitAndPollV4(t, fixture, node, &start)
	startReport := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      startDelivery.DeliveryID, DeliveryGeneration: startDelivery.DeliveryGeneration,
		CommandID: startDelivery.CommandID, CommandDigest: startDelivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running", ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{RuntimeRef: executorRuntimeRef},
	}
	if applied, err := fixture.store.ApplyReportV4(node, startReport, fixture.now.Add(5*time.Minute)); err != nil || !applied {
		t.Fatalf("apply start report = (%v, %v)", applied, err)
	}

	stop := baseV4CommandStatement("agent-stop", "tenant-a", "node-1", "stop", 7, 11)
	stop.RuntimeRef = admit.RuntimeRef
	stop.CommandSequence = 3
	stopDelivery := submitAndPollV4(t, fixture, node, &stop)
	stopReport := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      stopDelivery.DeliveryID, DeliveryGeneration: stopDelivery.DeliveryGeneration,
		CommandID: stopDelivery.CommandID, CommandDigest: stopDelivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusFailed, ReportedStatus: "failed", ClaimGeneration: 7,
		ErrorCode: "runtime_failure",
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: executorRuntimeRef, Error: "sensitive node detail",
		},
	}
	if applied, err := fixture.store.ApplyReportV4(node, stopReport, fixture.now.Add(6*time.Minute)); err != nil || !applied {
		t.Fatalf("apply stop report = (%v, %v)", applied, err)
	}
	replacement := baseV4CommandStatement("agent-replacement", "tenant-a", "node-1", "admit", 8, 12)
	replacement.RuntimeRef = admit.RuntimeRef
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, replacement.TenantID, replacement.NodeID,
		signV4CommandStatement(t, replacement), fixture.now.Add(7*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit replacement generation = (%v, %v)", created, err)
	}

	page, err := fixture.store.ListAgentInventory(operator, AgentInventoryQuery{Status: "running"})
	if err != nil || len(page.Agents) != 1 {
		t.Fatalf("agent inventory = (%+v, %v)", page, err)
	}
	agent := page.Agents[0]
	if agent.TenantID != "tenant-a" || agent.NodeID != "node-1" ||
		agent.RuntimeRef != executorRuntimeRef || agent.InstanceGeneration != 11 ||
		agent.ClaimGeneration != 7 || agent.ObservedStatus != "running" ||
		agent.LatestCommandID != "agent-stop" || agent.LatestCommandKind != "stop" ||
		agent.LatestTerminalStatus != controlprotocol.ExecutorStatusFailed ||
		!slices.Equal(agent.EgressRouteIDs, []string{"inference"}) ||
		!slices.Equal(agent.ConnectorIDs, []string{"calendar"}) {
		t.Fatalf("agent projection = %+v", agent)
	}
	all, err := fixture.store.ListAgentInventory(operator, AgentInventoryQuery{})
	if err != nil || len(all.Agents) != 2 ||
		all.Agents[0].InstanceGeneration == all.Agents[1].InstanceGeneration {
		t.Fatalf("agent lifetimes were collapsed = (%+v, %v)", all, err)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sensitive node detail", "task_authorities", "public_key", "egress_proxy", "connector_url"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("agent inventory exposed %q: %s", forbidden, raw)
		}
	}
	if _, err := fixture.store.ListAgentInventory(operator, AgentInventoryQuery{Status: "destroyed"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid status filter = %v", err)
	}
}

func TestCredentialInventoryNeverReturnsSecretsAndProjectsMultiTenantNodes(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	nodeRaw, nodeIdentity := fixture.createNode(t, "tenant-a", "tenant-b")
	operatorA := operationsTenantOperator(t, fixture, "tenant-a", "operator-a")
	_ = operationsTenantOperator(t, fixture, "tenant-b", "operator-b")

	page, err := fixture.store.ListCredentialInventory(operatorA, CredentialInventoryQuery{})
	if err != nil || len(page.Credentials) != 2 {
		t.Fatalf("tenant credential page = (%+v, %v)", page, err)
	}
	foundNode := false
	for _, credential := range page.Credentials {
		if credential.Role == controlauth.RoleSiteAdmin || credential.TenantID == "tenant-b" {
			t.Fatalf("tenant credential inventory leaked cross-scope metadata: %+v", credential)
		}
		if credential.Kind == controlauth.KindNode {
			foundNode = true
			if !slices.Equal(credential.TenantIDs, []string{"tenant-a"}) {
				t.Fatalf("node credential tenant projection = %v", credential.TenantIDs)
			}
		}
	}
	if !foundNode {
		t.Fatal("tenant credential inventory omitted its node credential")
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "token_mac") || strings.Contains(string(raw), nodeRaw) {
		t.Fatalf("credential inventory exposed secret material: %s", raw)
	}

	global, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{Limit: 2})
	if err != nil || len(global.Credentials) != 2 || global.NextCursor == "" {
		t.Fatalf("global credential page = (%+v, %v)", global, err)
	}
	if _, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{
		Kind: controlauth.KindOperator, Cursor: global.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed-filter credential cursor error = %v", err)
	}
	tenantFirst, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{
		TenantID: "tenant-a", Limit: 1,
	})
	if err != nil || tenantFirst.NextCursor == "" {
		t.Fatalf("tenant credential cursor page = (%+v, %v)", tenantFirst, err)
	}
	if _, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{
		TenantID: "tenant-b", Limit: 1, Cursor: tenantFirst.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-scope credential cursor error = %v", err)
	}
	active := false
	activeFirst, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{
		Revoked: &active, Limit: 1,
	})
	if err != nil || activeFirst.NextCursor == "" {
		t.Fatalf("active credential cursor page = (%+v, %v)", activeFirst, err)
	}
	revoked := true
	if _, err := fixture.store.ListCredentialInventory(fixture.admin, CredentialInventoryQuery{
		Revoked: &revoked, Cursor: activeFirst.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed-revocation credential cursor error = %v", err)
	}
	cursorRaw, err := base64.RawURLEncoding.DecodeString(activeFirst.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{nodeRaw, fixture.adminRaw, "token_mac"} {
		if strings.Contains(string(cursorRaw), secret) || strings.Contains(activeFirst.NextCursor, secret) {
			t.Fatalf("credential cursor exposed secret material %q", secret)
		}
	}
	for name, query := range map[string]CredentialInventoryQuery{
		"role with node":      {Role: controlauth.RoleTenantOperator, NodeID: "node-1"},
		"node kind with role": {Kind: controlauth.KindNode, Role: controlauth.RoleTenantOperator},
		"operator with node":  {Kind: controlauth.KindOperator, NodeID: "node-1"},
	} {
		if _, err := fixture.store.ListCredentialInventory(fixture.admin, query); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s credential filter error = %v", name, err)
		}
	}
	if _, revoked, err := fixture.store.RevokeNodeCredential(
		fixture.admin, nodeIdentity.CredentialID, fixture.now.Add(5*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revoke node credential = (%v, %v)", revoked, err)
	}
	revokedOnly := true
	revokedPage, err := fixture.store.ListCredentialInventory(operatorA, CredentialInventoryQuery{
		Kind: controlauth.KindNode, Revoked: &revokedOnly,
	})
	if err != nil || len(revokedPage.Credentials) != 1 || !revokedPage.Credentials[0].Revoked {
		t.Fatalf("revoked credential filter = (%+v, %v)", revokedPage, err)
	}
	if _, err := fixture.store.ListCredentialInventory(operatorA, CredentialInventoryQuery{TenantID: "tenant-b"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant credential inventory error = %v", err)
	}
}

func TestAttentionAndSummaryAreDeterministicProjectedStickyAndNonMutating(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommands = 5
	limits.MaxCommandsPerTenant = 5
	limits.MaxCommandsPerNode = 5
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	operatorA := operationsTenantOperator(t, fixture, "tenant-a", "attention-operator-a")
	now := fixture.now.Add(10 * time.Minute)

	never := Node{
		ID: "node-never", TenantIDs: []string{"tenant-a"},
		Capabilities: []string{}, CreatedAt: canonicalTimestamp(now.Add(-5 * time.Minute)), Active: true,
	}
	stale := Node{
		ID: "node-stale", TenantIDs: []string{"tenant-a", "tenant-b"},
		Capabilities: []string{}, CreatedAt: canonicalTimestamp(now.Add(-10 * time.Minute)),
		LastSeenAt: canonicalTimestamp(now.Add(-2 * time.Minute)), Active: true,
	}
	staleEvidence := testEvidenceWitness(t, stale)
	stale.Evidence = &staleEvidence
	mixed := Node{
		ID: "node-mixed", TenantIDs: []string{"tenant-a"},
		Capabilities: []string{}, CreatedAt: canonicalTimestamp(now.Add(-10 * time.Minute)),
		LastSeenAt: canonicalTimestamp(now), RevokedAt: canonicalTimestamp(now.Add(-time.Minute)), Active: false,
	}
	mixedEvidence := operationsMixedEvidenceWitness(t, mixed, now)
	mixed.Evidence = &mixedEvidence
	for _, node := range []Node{never, stale, mixed} {
		if err := fixture.store.applyMutations(mutation{Kind: mutationNode, Node: &node}); err != nil {
			t.Fatalf("retain operations node %s: %v", node.ID, err)
		}
	}
	fixture.store.mu.Lock()
	fixture.store.recordExecutorEvidenceReportLocked(stale.ID, now.Add(-5*time.Minute))
	fixture.store.recordExecutorEvidenceReportLocked(mixed.ID, now)
	fixture.store.mu.Unlock()

	for index, commandID := range []string{"pending", "leased", "failed", "unknown"} {
		if _, created, err := fixture.store.SubmitCommand(
			fixture.admin, "tenant-a", never.ID,
			signedCommand(t, commandID, "tenant-a", never.ID, index),
			now.Add(-5*time.Minute),
		); err != nil || !created {
			t.Fatalf("submit attention command %s = (%v, %v)", commandID, created, err)
		}
	}
	operationsSetCommandState(t, fixture, "tenant-a", never.ID, "leased", CommandLeased, "", now)
	operationsSetCommandState(
		t, fixture, "tenant-a", never.ID, "failed",
		CommandTerminal, controlprotocol.ExecutorStatusFailed, now.Add(-time.Minute),
	)
	operationsSetCommandState(
		t, fixture, "tenant-a", never.ID, "unknown",
		CommandTerminal, controlprotocol.ExecutorStatusOutcomeUnknown, now.Add(-time.Minute),
	)

	sequence := fixture.store.sequence
	items := operationsAllAttention(t, fixture.store, fixture.admin, "", now, 3)
	repeated := operationsAllAttention(t, fixture.store, fixture.admin, "", now, 4)
	if fixture.store.sequence != sequence {
		t.Fatalf("attention query mutated WAL sequence %d -> %d", sequence, fixture.store.sequence)
	}
	if len(items) != 14 || len(repeated) != len(items) {
		t.Fatalf("attention item counts = %d and %d, want 14", len(items), len(repeated))
	}
	for index := range items {
		if items[index].ID != repeated[index].ID || items[index].Reason != repeated[index].Reason {
			t.Fatalf("attention order or identity changed at %d: %+v vs %+v", index, items[index], repeated[index])
		}
	}
	reasons := make(map[AttentionReason]int)
	ids := make(map[string]struct{})
	for _, item := range items {
		reasons[item.Reason]++
		if _, duplicate := ids[item.ID]; duplicate {
			t.Fatalf("duplicate stable attention identity %q", item.ID)
		}
		ids[item.ID] = struct{}{}
	}
	for _, reason := range []AttentionReason{
		AttentionNodeNeverSeen, AttentionNodeStale, AttentionEvidenceUnwitnessed,
		AttentionEvidenceStale, AttentionRollbackDetected, AttentionEquivocationDetected,
		AttentionCommandPendingOverdue, AttentionCommandLeaseExpired, AttentionCommandFailed,
		AttentionCommandOutcomeUnknown, AttentionCapacityWarning,
	} {
		if reasons[reason] == 0 {
			t.Fatalf("attention reason %q was not emitted: %v", reason, reasons)
		}
	}
	if reasons[AttentionRollbackDetected] != 1 || reasons[AttentionEquivocationDetected] != 1 {
		t.Fatalf("mixed sticky finding was hidden: %v", reasons)
	}
	if reasons[AttentionNodeStale] != 2 || reasons[AttentionEvidenceStale] != 2 {
		t.Fatalf("multi-tenant node was not projected per tenant: %v", reasons)
	}

	summary, err := fixture.store.OperationsSummary(
		fixture.admin, "", now, DefaultOperationsThresholds(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Commands != (CommandSummary{
		Total: 4, Pending: 1, Leased: 1, Terminal: 2, Failed: 1, OutcomeUnknown: 1,
	}) {
		t.Fatalf("command summary = %+v", summary.Commands)
	}
	if summary.Evidence.RollbackDetected != 1 || summary.Evidence.EquivocationDetected != 1 ||
		summary.Evidence.Stale != 1 || summary.Evidence.Unwitnessed != 1 {
		t.Fatalf("evidence summary = %+v", summary.Evidence)
	}
	operationsAssertAttentionSummaryParity(t, items, summary.Attention)
	if fixture.store.sequence != sequence {
		t.Fatal("operations summary mutated retained state")
	}
	firstAttention, err := fixture.store.ListAttention(fixture.admin, AttentionQuery{
		Now: now, Thresholds: DefaultOperationsThresholds(), Limit: 1,
	})
	if err != nil || firstAttention.NextCursor == "" {
		t.Fatalf("attention cursor page = (%+v, %v)", firstAttention, err)
	}
	if _, err := fixture.store.ListAttention(fixture.admin, AttentionQuery{
		Reason: AttentionNodeStale, Now: now, Thresholds: DefaultOperationsThresholds(),
		Cursor: firstAttention.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed-filter attention cursor error = %v", err)
	}
	tenantAttention, err := fixture.store.ListAttention(fixture.admin, AttentionQuery{
		TenantID: "tenant-a", Now: now, Thresholds: DefaultOperationsThresholds(), Limit: 1,
	})
	if err != nil || tenantAttention.NextCursor == "" {
		t.Fatalf("tenant attention cursor page = (%+v, %v)", tenantAttention, err)
	}
	if _, err := fixture.store.ListAttention(fixture.admin, AttentionQuery{
		TenantID: "tenant-b", Now: now, Thresholds: DefaultOperationsThresholds(),
		Cursor: tenantAttention.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-scope attention cursor error = %v", err)
	}

	tenantItems := operationsAllAttention(t, fixture.store, operatorA, "", now, 500)
	if len(tenantItems) != 11 {
		t.Fatalf("tenant A attention count = %d, want 11", len(tenantItems))
	}
	for _, item := range tenantItems {
		if item.TenantID != "tenant-a" {
			t.Fatalf("tenant attention leaked projection %+v", item)
		}
	}
	if _, err := fixture.store.ListAttention(operatorA, AttentionQuery{
		TenantID: "tenant-b", Now: now, Thresholds: DefaultOperationsThresholds(),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant attention error = %v", err)
	}
}

func TestEvidenceFreshnessRefreshesInMemoryAndIsConservativeAfterRestart(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	node, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", fixture.identity.NodeID)
	if err != nil || !found || node.Evidence == nil {
		t.Fatalf("evidence node = (%+v, %v, %v)", node, found, err)
	}
	pinnedAt, err := parseTimestamp(node.Evidence.PinnedAt)
	if err != nil {
		t.Fatal(err)
	}
	beforeStale := pinnedAt.Add(5*time.Minute - time.Nanosecond)
	if count := operationsAttentionReasonCount(
		t, fixture.store, fixture.admin, "tenant-a", beforeStale, AttentionEvidenceStale,
	); count != 0 {
		t.Fatalf("evidence became stale before equality: %d", count)
	}
	atEquality := pinnedAt.Add(5 * time.Minute)
	if count := operationsAttentionReasonCount(
		t, fixture.store, fixture.admin, "tenant-a", atEquality, AttentionEvidenceStale,
	); count != 1 {
		t.Fatalf("evidence stale equality count = %d", count)
	}

	poll := fixture.poll(t, atEquality.Add(time.Minute))
	refreshReport := fixture.signedReport(
		t, zeroEvidenceCoordinate(), 0, zeroEvidenceHash(), poll.Challenge, nil,
	)
	sequence := fixture.store.sequence
	refreshedAt := atEquality.Add(time.Minute + time.Second)
	response, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, refreshReport, refreshedAt,
	)
	if err != nil || response.Applied || fixture.store.sequence != sequence {
		t.Fatalf("freshness-only report = (%+v, sequence %d -> %d, %v)",
			response, sequence, fixture.store.sequence, err)
	}
	if count := operationsAttentionReasonCount(
		t, fixture.store, fixture.admin, "tenant-a", refreshedAt.Add(4*time.Minute), AttentionEvidenceStale,
	); count != 0 {
		t.Fatalf("authenticated report did not refresh evidence: %d", count)
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
	if count := operationsAttentionReasonCount(
		t, reopened, fixture.admin, "tenant-a", refreshedAt.Add(time.Second), AttentionEvidenceStale,
	); count != 1 {
		t.Fatalf("restart did not conservatively mark unknown evidence freshness: %d", count)
	}
}

func operationsTenantOperator(t *testing.T, fixture recordsFixture, tenantID, requestID string) controlauth.Identity {
	t.Helper()
	raw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, tenantID,
		fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixture.store.AuthenticateOperator(fixture.auth, raw)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func operationsSetCommandState(
	t *testing.T,
	fixture recordsFixture,
	tenantID, nodeID, commandID string,
	state CommandState,
	status string,
	at time.Time,
) {
	t.Helper()
	command, found, err := fixture.store.GetCommand(fixture.admin, tenantID, nodeID, commandID)
	if err != nil || !found {
		t.Fatalf("get command %s = (%v, %v)", commandID, found, err)
	}
	switch state {
	case CommandLeased:
		command.State = CommandLeased
		command.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		command.DeliveryGeneration = 1
		command.LeaseUntil = canonicalTimestamp(at)
	case CommandTerminal:
		delivery, err := deliveryFor(command, 1)
		if err != nil {
			t.Fatal(err)
		}
		report := reportFor(delivery, status)
		report.ErrorCode = "operations-test"
		digest, _, err := reportDigest(report)
		if err != nil {
			t.Fatal(err)
		}
		command.State = CommandTerminal
		command.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		command.DeliveryGeneration = 1
		command.LeaseUntil = ""
		command.Terminal = &TerminalReport{
			Report: report, Digest: digest, CompletedAt: canonicalTimestamp(at),
		}
	default:
		t.Fatalf("unsupported test command state %q", state)
	}
	if err := fixture.store.applyMutations(commandMutation(command)); err != nil {
		t.Fatalf("set command %s state %s: %v", commandID, state, err)
	}
}

func operationsMixedEvidenceWitness(t *testing.T, node Node, now time.Time) EvidenceWitness {
	t.Helper()
	witness := testEvidenceWitness(t, node)
	currentHash := digestBytes([]byte("mixed-current"))
	forkHash := digestBytes([]byte("mixed-fork"))
	witness.Sequence = 1
	witness.ChainHash = currentHash
	witness.AdvancedAt = canonicalTimestamp(now.Add(-8 * time.Minute))
	witness.RecordsAccepted = 1
	witness.LastBatchStart = 1
	witness.LastBatchEnd = 1
	witness.LastBatchDigest = digestBytes([]byte("mixed-batch"))
	witness.Finding = &EvidenceFinding{
		FirstReason:           EvidenceRollback,
		FirstComparedSequence: 1, FirstComparedChainHash: currentHash,
		FirstSequence: 0, FirstChainHash: zeroEvidenceHash(),
		FirstObservedAt:      canonicalTimestamp(now.Add(-7 * time.Minute)),
		LastReason:           EvidenceFork,
		LastComparedSequence: 1, LastComparedChainHash: currentHash,
		LastSequence: 1, LastChainHash: forkHash,
		LastObservedAt: canonicalTimestamp(now.Add(-6 * time.Minute)),
		Count:          2,
	}
	return witness
}

func operationsAllAttention(
	t *testing.T,
	store *Store,
	actor controlauth.Identity,
	tenantID string,
	now time.Time,
	limit int,
) []AttentionItem {
	t.Helper()
	var result []AttentionItem
	cursor := ""
	for {
		page, err := store.ListAttention(actor, AttentionQuery{
			TenantID: tenantID, Now: now, Thresholds: DefaultOperationsThresholds(),
			Limit: limit, Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, page.Items...)
		if page.NextCursor == "" {
			return result
		}
		if page.NextCursor == cursor {
			t.Fatal("attention pagination cursor did not advance")
		}
		cursor = page.NextCursor
	}
}

func operationsAssertAttentionSummaryParity(t *testing.T, items []AttentionItem, summary AttentionSummary) {
	t.Helper()
	counts := make(map[string]int)
	warnings, critical := 0, 0
	for _, item := range items {
		counts[string(item.Reason)+"\x00"+string(item.Severity)]++
		switch item.Severity {
		case AttentionWarning:
			warnings++
		case AttentionCritical:
			critical++
		}
	}
	if summary.Total != len(items) || summary.Warnings != warnings || summary.Critical != critical {
		t.Fatalf("attention summary totals = %+v, items=%d warnings=%d critical=%d",
			summary, len(items), warnings, critical)
	}
	if len(summary.Counts) != len(counts) {
		t.Fatalf("attention summary count groups = %d, want %d", len(summary.Counts), len(counts))
	}
	for _, count := range summary.Counts {
		key := string(count.Reason) + "\x00" + string(count.Severity)
		if counts[key] != count.Count {
			t.Fatalf("attention count %+v, want %d", count, counts[key])
		}
	}
}

func operationsAttentionReasonCount(
	t *testing.T,
	store *Store,
	actor controlauth.Identity,
	tenantID string,
	now time.Time,
	reason AttentionReason,
) int {
	t.Helper()
	page, err := store.ListAttention(actor, AttentionQuery{
		TenantID: tenantID, Reason: reason, Now: now,
		Thresholds: DefaultOperationsThresholds(), Limit: MaxInventoryPageLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor != "" {
		t.Fatal("reason-specific attention test unexpectedly exceeded one page")
	}
	return len(page.Items)
}

func zeroEvidenceCoordinate() evidence.Coordinate { return evidence.Coordinate{} }

func operationsCursorTrailingBitAlias(t *testing.T, canonical string) string {
	t.Helper()
	unusedBits := 0
	switch len(canonical) % 4 {
	case 2:
		unusedBits = 4
	case 3:
		unusedBits = 2
	default:
		t.Fatalf("cursor has no unused trailing bits: %q", canonical)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	index := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	if index < 0 {
		t.Fatalf("cursor has invalid final character: %q", canonical)
	}
	alias := []byte(canonical)
	alias[len(alias)-1] = alphabet[index^(1<<(unusedBits-1))]
	canonicalRaw, canonicalErr := base64.RawURLEncoding.DecodeString(canonical)
	aliasRaw, aliasErr := base64.RawURLEncoding.DecodeString(string(alias))
	if canonicalErr != nil || aliasErr != nil || !slices.Equal(canonicalRaw, aliasRaw) {
		t.Fatal("test setup did not produce an equivalent trailing-bit alias")
	}
	return string(alias)
}
