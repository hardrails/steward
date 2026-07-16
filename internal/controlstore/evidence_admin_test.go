package controlstore

import (
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
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

func TestInspectExecutorEvidenceRejectsUnavailableStore(t *testing.T) {
	var store *Store
	if _, err := store.InspectExecutorEvidence(controlauth.Identity{Role: controlauth.RoleSiteAdmin}, "node-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store inspection error=%v", err)
	}
}
