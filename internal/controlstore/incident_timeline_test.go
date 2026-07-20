package controlstore

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestIncidentTimelineProjectsRetainedFactsWithoutSensitiveData(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, _ = fixture.createNode(t, "tenant-a", "tenant-b")
	operatorA := operationsTenantOperator(t, fixture, "tenant-a", "operator-a")
	_, revokedRecord, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "operator-b", controlauth.RoleTenantOperator,
		"tenant-b", fixture.now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := fixture.store.RevokeOperator(
		fixture.admin, revokedRecord.ID, fixture.now.Add(3*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revoke operator = (%v, %v)", revoked, err)
	}
	const commandID = "sensitive-command"
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", "node-1",
		signedCommand(t, commandID, "tenant-a", "node-1", 11),
		fixture.now.Add(3*time.Minute+time.Second),
	); err != nil || !created {
		t.Fatalf("submit sensitive command = (%v, %v)", created, err)
	}
	if _, changed, err := fixture.store.ChangeOperationalFreeze(
		fixture.admin, "", OperationalFreezeActionFreeze, 0,
		"investigating controller compromise", fixture.now.Add(4*time.Minute),
	); err != nil || !changed {
		t.Fatalf("site freeze = (%v, %v)", changed, err)
	}
	if _, changed, err := fixture.store.ChangeOperationalFreeze(
		fixture.admin, "tenant-b", OperationalFreezeActionFreeze, 0,
		"tenant-b private incident", fixture.now.Add(5*time.Minute),
	); err != nil || !changed {
		t.Fatalf("tenant freeze = (%v, %v)", changed, err)
	}
	if _, changed, err := fixture.store.ChangeSnapshotQuarantine(
		fixture.admin, "tenant-a", "node-1", "snapshot-a",
		SnapshotQuarantineActionSet, 0, "untrusted snapshot", fixture.now.Add(6*time.Minute),
	); err != nil || !changed {
		t.Fatalf("snapshot quarantine = (%v, %v)", changed, err)
	}
	if _, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, "node-1", NodePlacementQuarantine,
		"evidence mismatch", fixture.now.Add(7*time.Minute),
	); err != nil || !changed {
		t.Fatalf("node quarantine = (%v, %v)", changed, err)
	}

	fixture.store.mu.Lock()
	node := cloneNode(fixture.store.current.nodes["node-1"])
	witness := operationsMixedEvidenceWitness(t, node, fixture.now.Add(14*time.Minute))
	node.Evidence = &witness
	fixture.store.mu.Unlock()
	if err := fixture.store.applyMutations(mutation{Kind: mutationNode, Node: &node}); err != nil {
		t.Fatal(err)
	}

	operationsSetCommandState(
		t, fixture, "tenant-a", "node-1", commandID,
		CommandTerminal, controlprotocol.ExecutorStatusFailed, fixture.now.Add(10*time.Minute),
	)

	sequence := fixture.store.sequence
	page, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.store.sequence != sequence {
		t.Fatalf("read-only timeline changed sequence %d -> %d", sequence, fixture.store.sequence)
	}
	if len(page.Events) < 8 {
		t.Fatalf("timeline has too few retained facts: %+v", page.Events)
	}
	for index := 1; index < len(page.Events); index++ {
		if incidentTimelineSortKey(page.Events[index-1]) >= incidentTimelineSortKey(page.Events[index]) {
			t.Fatalf("timeline is not strict newest-first at %d: %+v", index, page.Events)
		}
	}
	kinds := make(map[IncidentKind]bool)
	actions := make(map[string]bool)
	for _, event := range page.Events {
		kinds[event.Kind] = true
		actions[event.Action] = true
		if !strings.HasPrefix(event.ID, "incident-") || len(event.ID) != len("incident-")+64 {
			t.Fatalf("invalid event ID %q", event.ID)
		}
	}
	for _, kind := range []IncidentKind{IncidentContainment, IncidentEvidence, IncidentAccess, IncidentWorkload} {
		if !kinds[kind] {
			t.Fatalf("missing incident kind %q in %+v", kind, page.Events)
		}
	}
	for _, action := range []string{
		"freeze_set", "snapshot_quarantined", "node_quarantined",
		"credential_revoked", "evidence_fork", "command_failed",
	} {
		if !actions[action] {
			t.Fatalf("missing action %q in %+v", action, page.Events)
		}
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"command_dsse", "runtime_ref", "reported_status", "error_code", "operations-test",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("timeline exposed sensitive field %q: %s", forbidden, raw)
		}
	}

	tenantPage, err := fixture.store.ListIncidentTimeline(operatorA, IncidentTimelineQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tenantPage.Events) == 0 {
		t.Fatal("tenant timeline is empty")
	}
	sawSiteFreeze := false
	for _, event := range tenantPage.Events {
		if event.TenantID != "" && event.TenantID != "tenant-a" {
			t.Fatalf("tenant timeline leaked %q: %+v", event.TenantID, event)
		}
		if event.Reason == "tenant-b private incident" || event.ResourceID == revokedRecord.ID {
			t.Fatalf("tenant timeline leaked tenant-b event: %+v", event)
		}
		if event.Action == "freeze_set" && event.Scope == "site" {
			sawSiteFreeze = true
		}
	}
	if !sawSiteFreeze {
		t.Fatalf("tenant timeline did not project effective site freeze: %+v", tenantPage.Events)
	}

	repeated, err := fixture.store.ListIncidentTimeline(operatorA, IncidentTimelineQuery{})
	if err != nil || !slices.Equal(tenantPage.Events, repeated.Events) {
		t.Fatalf("timeline is not stable: (%+v, %v)", repeated, err)
	}
}

func TestIncidentTimelineFiltersAndBindsPagination(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, _ = fixture.createNode(t, "tenant-a", "tenant-b")
	operatorA := operationsTenantOperator(t, fixture, "tenant-a", "operator-a")
	for index, tenantID := range []string{"tenant-a", "tenant-b"} {
		if _, changed, err := fixture.store.ChangeOperationalFreeze(
			fixture.admin, tenantID, OperationalFreezeActionFreeze, 0,
			"incident "+tenantID, fixture.now.Add(time.Duration(index+2)*time.Minute),
		); err != nil || !changed {
			t.Fatalf("freeze %s = (%v, %v)", tenantID, changed, err)
		}
	}
	if _, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, "node-1", NodePlacementCordon, "maintenance", fixture.now.Add(4*time.Minute),
	); err != nil || !changed {
		t.Fatalf("cordon = (%v, %v)", changed, err)
	}

	first, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{Limit: 2})
	if err != nil || len(first.Events) != 2 || first.NextCursor == "" {
		t.Fatalf("first timeline page = (%+v, %v)", first, err)
	}
	second, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{
		Limit: 2, Cursor: first.NextCursor,
	})
	if err != nil || len(second.Events) == 0 {
		t.Fatalf("second timeline page = (%+v, %v)", second, err)
	}
	if incidentTimelineSortKey(first.Events[len(first.Events)-1]) >= incidentTimelineSortKey(second.Events[0]) {
		t.Fatalf("pages overlap or reorder: first=%+v second=%+v", first, second)
	}
	if _, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{
		Kind: IncidentContainment, Cursor: first.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed-filter cursor error = %v", err)
	}
	tenantFirst, err := fixture.store.ListIncidentTimeline(operatorA, IncidentTimelineQuery{Limit: 1})
	if err != nil || tenantFirst.NextCursor == "" {
		t.Fatalf("tenant first timeline page = (%+v, %v)", tenantFirst, err)
	}
	if _, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{
		TenantID: "tenant-b", Cursor: tenantFirst.NextCursor,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-scope cursor error = %v", err)
	}
	if _, err := fixture.store.ListIncidentTimeline(operatorA, IncidentTimelineQuery{TenantID: "tenant-b"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant timeline error = %v", err)
	}
	filtered, err := fixture.store.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{
		NodeID: "node-1", Kind: IncidentContainment, Severity: IncidentWarning,
	})
	if err != nil || len(filtered.Events) != 2 {
		t.Fatalf("filtered timeline = (%+v, %v)", filtered, err)
	}
	for _, event := range filtered.Events {
		if event.NodeID != "node-1" || event.Kind != IncidentContainment || event.Severity != IncidentWarning {
			t.Fatalf("filter mismatch: %+v", event)
		}
	}

	for name, query := range map[string]IncidentTimelineQuery{
		"bad node":     {NodeID: "bad node"},
		"bad kind":     {Kind: "unknown"},
		"bad severity": {Severity: "urgent"},
		"bad limit":    {Limit: MaxInventoryPageLimit + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.store.ListIncidentTimeline(fixture.admin, query); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	var unavailable *Store
	if _, err := unavailable.ListIncidentTimeline(fixture.admin, IncidentTimelineQuery{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store error = %v", err)
	}
}
