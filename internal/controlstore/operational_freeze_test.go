package controlstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

func TestOperationalFreezeTransitionsAreScopedOptimisticAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	tenantA := operationalFreezeTenantOperator(t, fixture, "tenant-a", "freeze-operator-a")
	tenantB := operationalFreezeTenantOperator(t, fixture, "tenant-b", "freeze-operator-b")

	if _, _, err := fixture.store.ChangeOperationalFreeze(
		tenantA, "", OperationalFreezeActionFreeze, 0, "site incident", fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant operator site freeze error = %v", err)
	}
	if _, err := fixture.store.InspectOperationalFreeze(tenantA, "tenant-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant freeze inspection error = %v", err)
	}

	site, changed, err := fixture.store.ChangeOperationalFreeze(
		fixture.admin, "", OperationalFreezeActionFreeze, 0, "upstream credential incident", fixture.now.Add(3*time.Minute),
	)
	if err != nil || !changed || site.Site == nil || site.Site.Revision != 1 || site.Effective == nil ||
		site.Effective.Scope != OperationalFreezeSite {
		t.Fatalf("site freeze = (%+v, %v, %v)", site, changed, err)
	}
	tenant, changed, err := fixture.store.ChangeOperationalFreeze(
		tenantA, "tenant-a", OperationalFreezeActionFreeze, 0, "tenant investigation", fixture.now.Add(4*time.Minute),
	)
	if err != nil || !changed || tenant.Tenant == nil || tenant.Tenant.Revision != 1 || tenant.Effective == nil ||
		tenant.Effective.Scope != OperationalFreezeSite {
		t.Fatalf("tenant freeze under site freeze = (%+v, %v, %v)", tenant, changed, err)
	}
	if _, changed, err := fixture.store.ChangeOperationalFreeze(
		tenantA, "tenant-a", OperationalFreezeActionFreeze, 1, "tenant investigation", fixture.now.Add(5*time.Minute),
	); err != nil || changed {
		t.Fatalf("idempotent tenant freeze = (%v, %v)", changed, err)
	}
	if _, _, err := fixture.store.ChangeOperationalFreeze(
		tenantA, "tenant-a", OperationalFreezeActionUnfreeze, 0, "", fixture.now.Add(5*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale tenant unfreeze error = %v", err)
	}

	site, changed, err = fixture.store.ChangeOperationalFreeze(
		fixture.admin, "", OperationalFreezeActionUnfreeze, 1, "", fixture.now.Add(6*time.Minute),
	)
	if err != nil || !changed || site.Site == nil || site.Site.Frozen || site.Site.Revision != 2 {
		t.Fatalf("site unfreeze = (%+v, %v, %v)", site, changed, err)
	}
	tenant, err = fixture.store.InspectOperationalFreeze(tenantA, "tenant-a")
	if err != nil || tenant.Effective == nil || tenant.Effective.Scope != OperationalFreezeTenant {
		t.Fatalf("tenant freeze after site recovery = (%+v, %v)", tenant, err)
	}
	if _, err := fixture.store.InspectOperationalFreeze(tenantB, "tenant-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B observed tenant A freeze: %v", err)
	}
	tenant, changed, err = fixture.store.ChangeOperationalFreeze(
		tenantA, "tenant-a", OperationalFreezeActionUnfreeze, 1, "", fixture.now.Add(7*time.Minute),
	)
	if err != nil || !changed || tenant.Tenant == nil || tenant.Tenant.Frozen || tenant.Tenant.Revision != 2 ||
		tenant.Effective != nil {
		t.Fatalf("tenant unfreeze = (%+v, %v, %v)", tenant, changed, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	status, err := reopened.InspectOperationalFreeze(fixture.admin, "tenant-a")
	if err != nil || status.Site == nil || status.Site.Revision != 2 ||
		status.Tenant == nil || status.Tenant.Revision != 2 || status.Effective != nil {
		t.Fatalf("reopened freeze status = (%+v, %v)", status, err)
	}
}

func TestOperationalFreezeStopsOnlyNewOrFrozenTenantDelivery(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	_, node := fixture.createNode(t, "tenant-a", "tenant-b")
	tenantACommand := signedCommand(t, "tenant-a-before-freeze", "tenant-a", node.NodeID, 0)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", node.NodeID, tenantACommand, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit tenant A command = (%v, %v)", created, err)
	}
	if _, _, err := fixture.store.ChangeOperationalFreeze(
		fixture.admin, "tenant-a", OperationalFreezeActionFreeze, 0, "tenant containment", fixture.now.Add(3*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", node.NodeID, tenantACommand, fixture.now.Add(4*time.Minute),
	); err != nil || created {
		t.Fatalf("idempotent pre-freeze retry = (%v, %v)", created, err)
	}
	if _, _, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", node.NodeID,
		signedCommand(t, "tenant-a-after-freeze", "tenant-a", node.NodeID, 0), fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrOperationallyFrozen) {
		t.Fatalf("new frozen-tenant command error = %v", err)
	} else {
		var freezeError *OperationalFreezeError
		if !errors.As(err, &freezeError) || freezeError.Scope != OperationalFreezeTenant ||
			freezeError.Error() != ErrOperationallyFrozen.Error() {
			t.Fatalf("new frozen-tenant command detail = %#v", err)
		}
	}
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-b", node.NodeID,
		signedCommand(t, "tenant-b-command", "tenant-b", node.NodeID, 0), fixture.now.Add(4*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit tenant B command = (%v, %v)", created, err)
	}

	deliveries, err := fixture.store.Poll(node, []string{}, fixture.now.Add(5*time.Minute), time.Minute, 10)
	if err != nil || len(deliveries) != 1 || deliveries[0].CommandID != "tenant-b-command" {
		t.Fatalf("poll with tenant freeze = (%+v, %v)", deliveries, err)
	}
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || nodes[0].LastSeenAt == "" {
		t.Fatalf("frozen poll liveness = (%+v, %v)", nodes, err)
	}
	if _, _, err := fixture.store.ChangeOperationalFreeze(
		fixture.admin, "tenant-a", OperationalFreezeActionUnfreeze, 1, "", fixture.now.Add(6*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	deliveries, err = fixture.store.Poll(node, []string{}, fixture.now.Add(7*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].CommandID != "tenant-a-before-freeze" {
		t.Fatalf("poll after tenant unfreeze = (%+v, %v)", deliveries, err)
	}
}

func TestOperationalFreezeFormatRejectsLegacySmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	freeze := OperationalFreeze{
		Scope: OperationalFreezeTenant, TenantID: "tenant-a", Frozen: true,
		Revision: 1, Reason: "format test", ChangedAt: firstTenant(current).CreatedAt,
	}
	current.freezes[operationalFreezeKey(freeze.Scope, freeze.TenantID)] = freeze
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeState(raw, limits.MaxStateBytes)
	if err != nil || len(decoded.freezes) != 1 {
		t.Fatalf("freeze round trip = (%+v, %v)", decoded.freezes, err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = stateFormatRolloutVersion
	snapshot.Quarantines = nil
	smuggled, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted operational freeze state")
	}
	snapshot.Freezes = nil
	legacy, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacy, limits.MaxStateBytes)
	if err != nil || migrated.freezes == nil || len(migrated.freezes) != 0 {
		t.Fatalf("legacy freeze migration = (%+v, %v)", migrated.freezes, err)
	}
	if _, err := applyTransaction(current, transaction{
		Version:   transactionRolloutVersion,
		Mutations: []mutation{{Kind: mutationOperationalFreeze, Freeze: &freeze}},
	}); err == nil {
		t.Fatal("legacy transaction accepted operational freeze state")
	}
}

func operationalFreezeTenantOperator(t *testing.T, fixture recordsFixture, tenantID, requestID string) controlauth.Identity {
	t.Helper()
	raw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, requestID, controlauth.RoleTenantOperator, tenantID, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := fixture.store.AuthenticateOperator(fixture.auth, raw)
	if err != nil {
		t.Fatal(err)
	}
	return operator
}
