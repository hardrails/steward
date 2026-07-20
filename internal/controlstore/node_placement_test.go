package controlstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

func TestNodePlacementTransitionsAreDurableAndFailClosed(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")

	initial, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUncordon, "", fixture.now.Add(2*time.Minute),
	)
	if err != nil || changed || EffectiveNodePlacement(initial).Mode != NodeSchedulable {
		t.Fatalf("legacy schedulable transition = (%+v, %v, %v)", initial, changed, err)
	}
	cordoned, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementCordon, "kernel maintenance", fixture.now.Add(3*time.Minute),
	)
	if err != nil || !changed || EffectiveNodePlacement(cordoned).Mode != NodeCordoned {
		t.Fatalf("cordon = (%+v, %v, %v)", cordoned, changed, err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementCordon, "different reason", fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("cordon reason replacement error = %v", err)
	}
	quarantined, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementQuarantine, "suspected credential theft", fixture.now.Add(5*time.Minute),
	)
	if err != nil || !changed || EffectiveNodePlacement(quarantined).Mode != NodeQuarantined {
		t.Fatalf("quarantine = (%+v, %v, %v)", quarantined, changed, err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUncordon, "", fixture.now.Add(6*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("ordinary uncordon weakened quarantine: %v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	nodes, err := reopened.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || EffectiveNodePlacement(nodes[0]).Mode != NodeQuarantined {
		t.Fatalf("reopened quarantine = (%+v, %v)", nodes, err)
	}
}

func TestNodePlacementRejectsInvalidOrWeakeningTransitions(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	if _, _, err := fixture.store.ChangeNodePlacement(
		controlauth.Identity{}, identity.NodeID, NodePlacementCordon, "maintenance", fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unprivileged placement error = %v", err)
	}
	for _, test := range []struct {
		nodeID string
		action NodePlacementAction
		reason string
		now    time.Time
	}{
		{"bad id", NodePlacementCordon, "maintenance", fixture.now.Add(time.Minute)},
		{identity.NodeID, "unknown", "maintenance", fixture.now.Add(time.Minute)},
		{identity.NodeID, NodePlacementCordon, "", fixture.now.Add(time.Minute)},
		{identity.NodeID, NodePlacementUncordon, "unexpected", fixture.now.Add(time.Minute)},
		{identity.NodeID, NodePlacementCordon, " line padding", fixture.now.Add(time.Minute)},
		{identity.NodeID, NodePlacementCordon, "line\nbreak", fixture.now.Add(time.Minute)},
		{identity.NodeID, NodePlacementCordon, "maintenance", time.Time{}},
	} {
		if _, _, err := fixture.store.ChangeNodePlacement(
			fixture.admin, test.nodeID, test.action, test.reason, test.now,
		); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid transition %+v error = %v", test, err)
		}
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, "missing", NodePlacementCordon, "maintenance", fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing node placement error = %v", err)
	}
	cordoned, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementCordon, "maintenance", fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed {
		t.Fatalf("cordon = (%+v, %v, %v)", cordoned, changed, err)
	}
	if _, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementCordon, "maintenance", fixture.now.Add(3*time.Minute),
	); err != nil || changed {
		t.Fatalf("idempotent cordon = (%v, %v)", changed, err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUncordon, "", fixture.now.Add(time.Minute),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("backward transition time error = %v", err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementQuarantine, "incident", fixture.now.Add(4*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementQuarantine, "changed incident", fixture.now.Add(5*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("quarantine reason replacement error = %v", err)
	}
	if _, changed, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUnquarantine, "", fixture.now.Add(6*time.Minute),
	); err != nil || !changed {
		t.Fatalf("unquarantine = (%v, %v)", changed, err)
	}
	if _, revoked, err := fixture.store.RevokeNodeCredential(
		fixture.admin, identity.CredentialID, fixture.now.Add(7*time.Minute),
	); err != nil || !revoked {
		t.Fatalf("revoke node credential = (%v, %v)", revoked, err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementCordon, "maintenance", fixture.now.Add(8*time.Minute),
	); err != nil {
		t.Fatalf("credential rotation incorrectly disabled node placement: %v", err)
	}
	if _, err := fixture.store.RevokeNode(fixture.admin, identity.NodeID, fixture.now.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUncordon, "", fixture.now.Add(10*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked node placement error = %v", err)
	}
}

func TestQuarantinedNodeCannotLeaseCommandsButCanReportLiveness(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	if _, _, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", identity.NodeID,
		signedCommand(t, "quarantined-command", "tenant-a", identity.NodeID, 0),
		fixture.now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementQuarantine, "investigation", fixture.now.Add(3*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.Poll(identity, []string{}, fixture.now.Add(4*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("quarantined poll = (%+v, %v)", deliveries, err)
	}
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || nodes[0].LastSeenAt == "" {
		t.Fatalf("quarantined liveness = (%+v, %v)", nodes, err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, identity.NodeID, NodePlacementUnquarantine, "", fixture.now.Add(5*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	deliveries, err = fixture.store.Poll(identity, []string{}, fixture.now.Add(6*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("unquarantined poll = (%+v, %v)", deliveries, err)
	}
}

func TestNodePlacementFormatRejectsLegacySmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	node := firstNode(current)
	node.Placement = &NodePlacement{
		Mode: NodeCordoned, Reason: "maintenance", ChangedAt: node.CreatedAt,
	}
	current.nodes[node.ID] = node
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = stateFormatSchedulingVersion
	legacy, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacy, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted node placement state")
	}
	if _, err := applyTransaction(emptyState(), transaction{
		Version:   transactionSchedulingVersion,
		Mutations: []mutation{{Kind: mutationNode, Node: &node}},
	}); err == nil {
		t.Fatal("legacy transaction accepted node placement state")
	}
}
