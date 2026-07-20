package controlstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestNodeDrainIsIdempotentCordonsAndPersists(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	now := fixture.now.Add(2 * time.Minute)

	node, changed, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-1", "kernel upgrade", now,
	)
	if err != nil || !changed || node.Drain == nil || node.Drain.State != NodeDrainActive ||
		EffectiveNodePlacement(node).Mode != NodeCordoned {
		t.Fatalf("start drain = (%+v, %v, %v)", node, changed, err)
	}
	retry, changed, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-1", "kernel upgrade", now.Add(time.Second),
	)
	if err != nil || changed || retry.Drain == nil || retry.Drain.RequestID != "maintenance-1" {
		t.Fatalf("retry drain = (%+v, %v, %v)", retry, changed, err)
	}
	if _, _, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-2", "other work", now.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("competing drain error = %v", err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, "node-1", NodePlacementUncordon, "", now.Add(time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("uncordon active drain error = %v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	nodes, err := reopened.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || nodes[0].Drain == nil ||
		nodes[0].Drain.RequestID != "maintenance-1" {
		t.Fatalf("reopened drain = (%+v, %v)", nodes, err)
	}
	cancelled, changed, err := reopened.CancelNodeDrain(
		fixture.admin, "node-1", "maintenance-1", now.Add(2*time.Second),
	)
	if err != nil || !changed || cancelled.Drain.State != NodeDrainCancelled ||
		cancelled.Drain.CompletedAt == "" || EffectiveNodePlacement(cancelled).Mode != NodeCordoned {
		t.Fatalf("cancel drain = (%+v, %v, %v)", cancelled, changed, err)
	}
}

func TestDeploymentDrainEnforcesBudgetAndAdvancesGenerationAfterRemoval(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	budget := DeploymentDisruptionBudget{MaxUnavailable: 1}
	input := deploymentApplyFixture(t, fixture.now, "deployment-a", 1)
	input.DisruptionBudget = &budget
	created, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for index := range created.Instances {
		created.Instances[index].NodeID = "node-1"
		created.Instances[index].Phase = DeploymentInstanceRunning
	}
	created.Phase = DeploymentReady
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = created
	fixture.store.mu.Unlock()

	startedAt := fixture.now.Add(3 * time.Minute)
	if _, _, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-1", "kernel upgrade", startedAt,
	); err != nil {
		t.Fatal(err)
	}
	marked, changed, err := fixture.store.BeginDeploymentInstanceDrain(
		"tenant-a", "deployment-a", created.Instances[0].InstanceID, "node-1",
		"maintenance-1", created.Revision, startedAt.Add(time.Second),
	)
	if err != nil || !changed || marked.Instances[0].Drain == nil {
		t.Fatalf("begin instance drain = (%+v, %v, %v)", marked, changed, err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceDrain(
		"tenant-a", "deployment-a", created.Instances[1].InstanceID, "node-1",
		"maintenance-1", marked.Revision, startedAt.Add(2*time.Second),
	); !errors.Is(err, ErrDisruptionBudget) {
		t.Fatalf("second instance drain error = %v", err)
	}

	removed := marked
	removed.Instances[0].Phase = DeploymentInstanceRemoved
	removed.Revision++
	removed.UpdatedAt = canonicalTimestamp(startedAt.Add(3 * time.Second))
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = removed
	fixture.store.mu.Unlock()
	replaced, changed, err := fixture.store.ReplaceDrainedDeploymentInstance(
		"tenant-a", "deployment-a", removed.Instances[0].InstanceID,
		removed.Revision, startedAt.Add(4*time.Second),
	)
	if err != nil || !changed || replaced.Instances[0].Generation != 2 ||
		replaced.Instances[0].NodeID != "" || replaced.Instances[0].Phase != DeploymentInstancePending ||
		replaced.Instances[0].Drain == nil {
		t.Fatalf("replace drained instance = (%+v, %v, %v)", replaced.Instances[0], changed, err)
	}
	if completed, err := fixture.store.CompleteFinishedNodeDrains(startedAt.Add(5 * time.Second)); err != nil || completed != 0 {
		t.Fatalf("complete with replacement pending = (%d, %v)", completed, err)
	}
	absent, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", replaced.Revision,
		DeploymentAbsent, startedAt.Add(6*time.Second),
	)
	if err != nil || !changed {
		t.Fatalf("remove replacement deployment = (%+v, %v, %v)", absent, changed, err)
	}
	removedPending, changed, err := fixture.store.RemovePendingDeploymentInstance(
		"tenant-a", "deployment-a", replaced.Instances[0].InstanceID,
		absent.Revision, startedAt.Add(7*time.Second),
	)
	if err != nil || !changed || removedPending.Instances[0].Drain != nil {
		t.Fatalf("remove pending drained replacement = (%+v, %v, %v)", removedPending.Instances[0], changed, err)
	}
}

func TestFleetOperationsFormatRejectsLegacySmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	node := firstNode(current)
	node.Drain = &NodeDrain{
		RequestID: "maintenance-1", State: NodeDrainActive, Reason: "kernel upgrade",
		RequestedAt: node.CreatedAt, UpdatedAt: node.CreatedAt,
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
	snapshot.Version = stateFormatNodePlacementVersion
	legacy, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacy, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted node drain state")
	}
	if _, err := applyTransaction(emptyState(), transaction{
		Version:   transactionNodePlacementVersion,
		Mutations: []mutation{{Kind: mutationNode, Node: &node}},
	}); err == nil {
		t.Fatal("legacy transaction accepted node drain state")
	}

	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	if _, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1), fixture.now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	deploymentRaw, err := encodeState(fixture.store.current, fixture.limits.MaxStateBytes)
	fixture.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var deploymentSnapshot snapshotState
	if err := json.Unmarshal(deploymentRaw, &deploymentSnapshot); err != nil {
		t.Fatal(err)
	}
	deploymentSnapshot.Version = stateFormatNodePlacementVersion
	smuggled, err := json.Marshal(deploymentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, fixture.limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted deployment fleet operations state")
	}
	deploymentSnapshot.Deployments[0].DisruptionBudget = DeploymentDisruptionBudget{}
	legacyDeployment, err := json.Marshal(deploymentSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyDeployment, fixture.limits.MaxStateBytes)
	if err != nil || migrated.deployments[deploymentKey("tenant-a", "deployment-a")].DisruptionBudget.MaxUnavailable != 1 {
		t.Fatalf("legacy deployment budget migration = (%+v, %v)", migrated.deployments, err)
	}
}
