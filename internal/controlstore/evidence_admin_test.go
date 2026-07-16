package controlstore

import (
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

func TestInspectExecutorEvidenceIsSiteAdminOnlyAndForensic(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")

	inspection, err := fixture.store.InspectExecutorEvidence(fixture.admin, nodeIdentity.NodeID)
	if err != nil || inspection.IdentityProof == nil ||
		inspection.IdentityProof.Claim.ControlNodeID != nodeIdentity.NodeID ||
		inspection.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		inspection.Status.Head == nil || inspection.Status.Head.Sequence != 0 {
		t.Fatalf("initial inspection=%#v err=%v", inspection, err)
	}
	inspection.Status.Head.Sequence = 99
	inspection.IdentityProof.Claim.ControlNodeID = "mutated"
	reloaded, err := fixture.store.InspectExecutorEvidence(fixture.admin, nodeIdentity.NodeID)
	if err != nil || reloaded.Status.Head == nil || reloaded.Status.Head.Sequence != 0 ||
		reloaded.IdentityProof == nil || reloaded.IdentityProof.Claim.ControlNodeID != nodeIdentity.NodeID {
		t.Fatalf("inspection aliased durable state=%#v err=%v", reloaded, err)
	}

	operatorRaw, _, created, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "evidence-tenant-operator", controlauth.RoleTenantOperator,
		"tenant-a", fixture.now.Add(time.Minute),
	)
	if err != nil || !created {
		t.Fatalf("issue tenant operator=(%v, %v)", created, err)
	}
	operator, err := fixture.store.AuthenticateOperator(fixture.auth, operatorRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.InspectExecutorEvidence(operator, nodeIdentity.NodeID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant operator evidence inspection error=%v", err)
	}
	if _, err := fixture.store.InspectExecutorEvidence(fixture.admin, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing node inspection error=%v", err)
	}

	if _, err := fixture.store.RevokeNode(fixture.admin, nodeIdentity.NodeID, fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	forensic, err := fixture.store.InspectExecutorEvidence(fixture.admin, nodeIdentity.NodeID)
	if err != nil || forensic.Status.Head == nil {
		t.Fatalf("revoked node evidence was not retained: inspection=%#v err=%v", forensic, err)
	}
}

func TestInspectExecutorEvidenceReportsLegacyNodeAsUnwitnessed(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	fixture.store.mu.Lock()
	node := cloneNode(fixture.store.current.nodes[nodeIdentity.NodeID])
	node.Evidence = nil
	fixture.store.current.nodes[nodeIdentity.NodeID] = node
	fixture.store.mu.Unlock()

	inspection, err := fixture.store.InspectExecutorEvidence(fixture.admin, nodeIdentity.NodeID)
	if err != nil || inspection.IdentityProof != nil ||
		inspection.Status.State != controlprotocol.ExecutorEvidenceStatusUnwitnessed {
		t.Fatalf("legacy inspection=%#v err=%v", inspection, err)
	}
}

func TestExecutorEvidenceSnapshotDetectsWitnessMutationAndIgnoresRevocation(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t, "tenant-a")
	snapshot, err := fixture.store.SnapshotExecutorEvidence(fixture.admin, fixture.identity.NodeID)
	if err != nil || snapshot.Inspection.Status.Head == nil {
		t.Fatalf("initial snapshot=%#v err=%v", snapshot.Inspection, err)
	}
	snapshot.Inspection.Status.Head.Sequence = 99
	current, err := fixture.store.ExecutorEvidenceSnapshotCurrent(
		fixture.admin, fixture.identity.NodeID, snapshot,
	)
	if err != nil || !current {
		t.Fatalf("caller mutation changed opaque snapshot: current=%v err=%v", current, err)
	}

	fixture.appendReceipt(t, "tenant-a")
	poll := fixture.poll(t, fixture.now.Add(2*time.Minute))
	report, _ := fixture.reportFrom(t, evidence.Coordinate{}, poll.Challenge)
	if _, err := fixture.store.ApplyExecutorEvidenceReport(
		fixture.auth, fixture.identity, report, fixture.now.Add(2*time.Minute+time.Second),
	); err != nil {
		t.Fatal(err)
	}
	current, err = fixture.store.ExecutorEvidenceSnapshotCurrent(
		fixture.admin, fixture.identity.NodeID, snapshot,
	)
	if err != nil || current {
		t.Fatalf("changed witness snapshot current=%v err=%v", current, err)
	}

	fresh, err := fixture.store.SnapshotExecutorEvidence(fixture.admin, fixture.identity.NodeID)
	if err != nil || fresh.Inspection.Status.Head == nil || fresh.Inspection.Status.Head.Sequence != 1 {
		t.Fatalf("fresh snapshot=%#v err=%v", fresh.Inspection, err)
	}
	if _, err := fixture.store.RevokeNode(
		fixture.admin, fixture.identity.NodeID, fixture.now.Add(3*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	current, err = fixture.store.ExecutorEvidenceSnapshotCurrent(
		fixture.admin, fixture.identity.NodeID, fresh,
	)
	if err != nil || !current {
		t.Fatalf("node revocation erased forensic snapshot: current=%v err=%v", current, err)
	}
	revoked, err := fixture.store.SnapshotExecutorEvidence(fixture.admin, fixture.identity.NodeID)
	if err != nil || revoked.Inspection.Status.Head == nil || revoked.Inspection.Status.Head.Sequence != 1 {
		t.Fatalf("revoked node snapshot=%#v err=%v", revoked.Inspection, err)
	}
}

func TestInspectExecutorEvidenceRejectsUnavailableStore(t *testing.T) {
	var store *Store
	if _, err := store.InspectExecutorEvidence(controlauth.Identity{Role: controlauth.RoleSiteAdmin}, "node-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store inspection error=%v", err)
	}
}
