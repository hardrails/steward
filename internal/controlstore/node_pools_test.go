package controlstore

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestNodePoolCapacityIntentIsOptimisticBoundedAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	poolInput := NodePool{
		ID: "research-amd64", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 1, DesiredNodes: 2, MaxNodes: 4,
	}
	pool, changed, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 0, fixture.now.Add(time.Minute))
	if err != nil || !changed || pool.Revision != 1 || pool.CreatedAt != pool.UpdatedAt {
		t.Fatalf("create pool=(%+v, %v, %v)", pool, changed, err)
	}
	poolInput.TenantIDs[0] = "mutated"
	listed, err := fixture.store.ListNodePools(fixture.admin)
	if err != nil || len(listed) != 1 || listed[0].TenantIDs[0] != "tenant-a" {
		t.Fatalf("list pools=(%+v, %v)", listed, err)
	}
	retry := listed[0]
	retry.Revision = 0
	retry.CreatedAt = ""
	retry.UpdatedAt = ""
	pool, changed, err = fixture.store.ApplyNodePool(fixture.admin, retry, 1, fixture.now.Add(2*time.Minute))
	if err != nil || changed || pool.Revision != 1 {
		t.Fatalf("idempotent pool=(%+v, %v, %v)", pool, changed, err)
	}
	retry.DesiredNodes = 3
	pool, changed, err = fixture.store.ApplyNodePool(fixture.admin, retry, 1, fixture.now.Add(3*time.Minute))
	if err != nil || !changed || pool.Revision != 2 || pool.DesiredNodes != 3 || pool.CreatedAt == pool.UpdatedAt {
		t.Fatalf("update pool=(%+v, %v, %v)", pool, changed, err)
	}
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, retry, 1, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update error=%v", err)
	}
	if err := fixture.store.DeleteNodePool(fixture.admin, pool.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete error=%v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	listed, err = reopened.ListNodePools(fixture.admin)
	if err != nil || len(listed) != 1 || listed[0].Revision != 2 {
		t.Fatalf("reopened pools=(%+v, %v)", listed, err)
	}
	if err := reopened.DeleteNodePool(fixture.admin, pool.ID, 2); err != nil {
		t.Fatal(err)
	}
	listed, err = reopened.ListNodePools(fixture.admin)
	if err != nil || len(listed) != 0 {
		t.Fatalf("deleted pools=(%+v, %v)", listed, err)
	}
}

func TestNodePoolStatusReportsCapacityWithoutGrantingPlacementAuthority(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	pool, _, err := fixture.store.ApplyNodePool(fixture.admin, NodePool{
		ID: "research-amd64", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 1, DesiredNodes: 2, MaxNodes: 4,
	}, 0, fixture.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	observation := storeSchedulingObservation(identity.NodeID)
	observation.Labels = append(observation.Labels, controlprotocol.ExecutorSchedulingLabelV1{
		Key: NodePoolLabelKey, Value: pool.ID,
	})
	sort.Slice(observation.Labels, func(i, j int) bool { return observation.Labels[i].Key < observation.Labels[j].Key })
	observedAt := fixture.now.Add(2 * time.Minute)
	if _, applied, err := fixture.store.ObserveNodeScheduling(identity, observation, observedAt); err != nil || !applied {
		t.Fatalf("observe pool node=(%v, %v)", applied, err)
	}
	status, err := fixture.store.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(30*time.Second), time.Minute)
	if err != nil || status.RegisteredNodes != 1 || status.ReadyNodes != 1 || status.ScaleOutNeeded != 1 ||
		!slices.Equal(status.Conditions, []string{NodePoolConditionCapacityShortfall}) || len(status.ScaleInCandidates) != 0 {
		t.Fatalf("pool status=(%+v, %v)", status, err)
	}
	status, err = fixture.store.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(2*time.Minute), time.Minute)
	if err != nil || status.ReadyNodes != 0 || status.Nodes[0].Reason != "scheduling_stale" ||
		!slices.Equal(status.Conditions, []string{NodePoolConditionCapacityShortfall, NodePoolConditionNodesNotReady}) {
		t.Fatalf("stale pool status=(%+v, %v)", status, err)
	}
	if _, err := fixture.store.GetNodePoolStatus(
		controlauth.Identity{Role: controlauth.RoleTenantOperator, TenantID: "tenant-a"},
		pool.ID, observedAt, time.Minute,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant pool status error=%v", err)
	}
}

func TestNodePoolScaleInCandidatesRequireCompletedDrainAndEmptyNode(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pool := NodePool{
		ID: "pool-a", Revision: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 0, DesiredNodes: 0, MaxNodes: 2,
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	observation := storeSchedulingObservation("node-a")
	observation.Labels = append(observation.Labels, controlprotocol.ExecutorSchedulingLabelV1{Key: NodePoolLabelKey, Value: pool.ID})
	sort.Slice(observation.Labels, func(i, j int) bool { return observation.Labels[i].Key < observation.Labels[j].Key })
	node := Node{
		ID: "node-a", Active: true, TenantIDs: []string{"tenant-a"},
		Scheduling: &NodeScheduling{Observation: observation, ObservedAt: now.Format(time.RFC3339Nano)},
		Drain: &NodeDrain{RequestID: "drain-a", State: NodeDrainCompleted, Reason: "scale in",
			RequestedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano)},
	}
	current := emptyState()
	current.nodes[node.ID] = node
	status := nodePoolStatusLocked(current, pool, now.Add(time.Second), time.Minute)
	if !slices.Equal(status.ScaleInCandidates, []string{"node-a"}) ||
		!slices.Contains(status.Conditions, NodePoolConditionScaleInAvailable) {
		t.Fatalf("empty drained status=%+v", status)
	}
	current.deployments["tenant-a/deployment-a"] = Deployment{Instances: []DeploymentInstance{{
		NodeID: node.ID, Phase: DeploymentInstanceRunning,
	}}}
	status = nodePoolStatusLocked(current, pool, now.Add(time.Second), time.Minute)
	if len(status.ScaleInCandidates) != 0 || slices.Contains(status.Conditions, NodePoolConditionScaleInAvailable) {
		t.Fatalf("assigned drained status=%+v", status)
	}
}

func TestNodePoolRejectsInvalidCapacityAndFailsClosed(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	valid := NodePool{ID: "pool-a", TenantIDs: []string{"tenant-a"}, MinNodes: 0, DesiredNodes: 1, MaxNodes: 2}
	invalid := []NodePool{
		{ID: "bad pool", TenantIDs: []string{"tenant-a"}, MinNodes: 0, DesiredNodes: 1, MaxNodes: 2},
		{ID: "pool-a", TenantIDs: []string{"tenant-a"}, MinNodes: 2, DesiredNodes: 1, MaxNodes: 2},
		{ID: "pool-a", TenantIDs: []string{"tenant-a"}, MinNodes: 0, DesiredNodes: 3, MaxNodes: 2},
		{ID: "pool-a", TenantIDs: []string{"missing"}, MinNodes: 0, DesiredNodes: 1, MaxNodes: 2},
	}
	for _, candidate := range invalid {
		if _, _, err := fixture.store.ApplyNodePool(fixture.admin, candidate, 0, fixture.now); err == nil {
			t.Fatalf("invalid pool accepted: %+v", candidate)
		}
	}
	var unavailable *Store
	if _, err := unavailable.ListNodePools(fixture.admin); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil list error=%v", err)
	}
	if _, _, err := unavailable.ApplyNodePool(fixture.admin, valid, 0, fixture.now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil apply error=%v", err)
	}
}

func TestNodePoolStateFormatRejectsLegacySmugglingAndDuplicateIdentity(t *testing.T) {
	current, limits := populatedControlState(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	pool := NodePool{
		ID: "pool-a", Revision: 1, TenantIDs: []string{"tenant-a"},
		MinNodes: 0, DesiredNodes: 1, MaxNodes: 2, CreatedAt: now, UpdatedAt: now,
	}
	current.nodePools[pool.ID] = pool
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}

	legacy := snapshot
	legacy.Version = stateFormatNodePoolVersion - 1
	legacy.NodePools = nil
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyRaw, limits.MaxStateBytes)
	if err != nil || migrated.nodePools == nil || len(migrated.nodePools) != 0 {
		t.Fatalf("legacy node pool migration=(%+v, %v)", migrated.nodePools, err)
	}

	legacy.NodePools = []NodePool{pool}
	smuggled, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled node pool state")
	}
	if _, err := applyTransaction(emptyState(), transaction{
		Version:   transactionNodePoolVersion - 1,
		Mutations: []mutation{{Kind: mutationNodePool, NodePool: &pool}},
	}); err == nil {
		t.Fatal("legacy transaction smuggled node pool state")
	}

	snapshot.NodePools = append(snapshot.NodePools, pool)
	duplicate, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(duplicate, limits.MaxStateBytes); err == nil {
		t.Fatal("snapshot accepted duplicate node pool identity")
	}
}
