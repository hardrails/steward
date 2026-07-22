package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/poolmembership"
)

func TestNodePoolCapacityIntentIsOptimisticBoundedAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	poolInput := NodePool{
		ID: "research-amd64", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 1, DesiredNodes: 2, MaxNodes: 4,
	}
	pool, changed, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 0, fixture.now.Add(time.Minute))
	if err != nil || !changed || pool.Revision != 1 || pool.MembershipGeneration != 1 || pool.CreatedAt != pool.UpdatedAt {
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
	if err != nil || !changed || pool.Revision != 2 || pool.MembershipGeneration != 1 || pool.DesiredNodes != 3 || pool.CreatedAt == pool.UpdatedAt {
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

func TestNodePoolMembershipGenerationChangesOnlyWithSecurityScope(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := NodePool{
		ID: "pool-a", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 0, DesiredNodes: 1, MaxNodes: 3, MembershipKeyID: "authority-a",
		MembershipPublicKeyBase64: base64.StdEncoding.EncodeToString(publicA),
	}
	pool, _, err := fixture.store.ApplyNodePool(fixture.admin, input, 0, fixture.now.Add(time.Minute))
	if err != nil || pool.Revision != 1 || pool.MembershipGeneration != 1 {
		t.Fatalf("create pool=%+v err=%v", pool, err)
	}
	input.DesiredNodes = 2
	pool, _, err = fixture.store.ApplyNodePool(fixture.admin, input, 1, fixture.now.Add(2*time.Minute))
	if err != nil || pool.Revision != 2 || pool.MembershipGeneration != 1 {
		t.Fatalf("capacity update pool=%+v err=%v", pool, err)
	}
	input.MembershipKeyID = "authority-b"
	input.MembershipPublicKeyBase64 = base64.StdEncoding.EncodeToString(publicB)
	pool, _, err = fixture.store.ApplyNodePool(fixture.admin, input, 2, fixture.now.Add(3*time.Minute))
	if err != nil || pool.Revision != 3 || pool.MembershipGeneration != 2 {
		t.Fatalf("authority rotation pool=%+v err=%v", pool, err)
	}
}

func TestSignedPoolMembershipControlsElasticEligibilityAndSurvivesRestart(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pool, _, err := fixture.store.ApplyNodePool(fixture.admin, NodePool{
		ID: "verified-pool", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 0, DesiredNodes: 1, MaxNodes: 2, MembershipKeyID: "pool-authority-1",
		MembershipPublicKeyBase64: base64.StdEncoding.EncodeToString(public),
	}, 0, fixture.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	observation := storeSchedulingObservation(identity.NodeID)
	observation.Labels = append(observation.Labels, controlprotocol.ExecutorSchedulingLabelV1{Key: NodePoolLabelKey, Value: pool.ID})
	sort.Slice(observation.Labels, func(i, j int) bool { return observation.Labels[i].Key < observation.Labels[j].Key })
	observedAt := fixture.now.Add(2 * time.Minute)
	if _, applied, err := fixture.store.ObserveNodeScheduling(identity, observation, observedAt); err != nil || !applied {
		t.Fatalf("observe=(%v,%v)", applied, err)
	}
	status, err := fixture.store.GetNodePoolStatus(fixture.admin, pool.ID, observedAt, time.Minute)
	if err != nil || status.RegisteredNodes != 1 || status.EligibleNodes != 0 || status.ScaleOutNeeded != 1 ||
		status.Nodes[0].Reason != "membership_missing" || !slices.Contains(status.Conditions, NodePoolConditionMembershipUnverified) {
		t.Fatalf("unverified status=%+v err=%v", status, err)
	}
	statement := poolmembership.Statement{
		SchemaVersion: 1, ControllerInstanceID: fixture.auth.InstanceID(), PoolID: pool.ID, PoolMembershipGeneration: pool.MembershipGeneration,
		PoolCreatedAt: pool.CreatedAt,
		NodeID:        identity.NodeID, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		BootIdentitySHA256:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchedulingPolicySHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:               observedAt.Format(time.RFC3339Nano), NotAfter: observedAt.Add(time.Hour).Format(time.RFC3339Nano),
	}
	raw, err := poolmembership.Sign(statement, pool.MembershipKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.store.BindNodePoolMembership(identity, fixture.auth, raw, observedAt.Add(10*time.Second))
	if err != nil || node.PoolMembership == nil || node.PoolMembership.Digest == "" {
		t.Fatalf("bind node=%+v err=%v", node, err)
	}
	if _, err := fixture.store.BindNodePoolMembership(identity, fixture.auth, raw, observedAt.Add(20*time.Second)); err != nil {
		t.Fatalf("idempotent bind: %v", err)
	}
	encoded, err := encodeState(fixture.store.current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var tampered snapshotState
	if err := json.Unmarshal(encoded, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Nodes[0].PoolMembership.Digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	tamperedRaw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(tamperedRaw, fixture.limits.MaxStateBytes); err == nil {
		t.Fatal("snapshot accepted membership metadata that disagrees with its retained envelope")
	}
	status, err = fixture.store.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(30*time.Second), time.Minute)
	if err != nil || status.EligibleNodes != 1 || status.ReadyNodes != 1 || status.ScaleOutNeeded != 0 || !status.Nodes[0].Eligible {
		t.Fatalf("eligible status=%+v err=%v", status, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	status, err = reopened.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(30*time.Second), time.Minute)
	if err != nil || status.EligibleNodes != 1 || status.Nodes[0].MembershipDigest == "" {
		t.Fatalf("reopened status=%+v err=%v", status, err)
	}
	status, err = reopened.GetNodePoolStatus(fixture.admin, pool.ID, statementNotAfter(t, statement), time.Minute)
	if err != nil || status.EligibleNodes != 0 || status.Nodes[0].Reason != "membership_expired" {
		t.Fatalf("expired status=%+v err=%v", status, err)
	}
	capacityInput := NodePool{
		ID: pool.ID, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 0, DesiredNodes: 2, MaxNodes: 2, MembershipKeyID: pool.MembershipKeyID,
		MembershipPublicKeyBase64: pool.MembershipPublicKeyBase64,
	}
	updated, _, err := reopened.ApplyNodePool(fixture.admin, capacityInput, 1, observedAt.Add(31*time.Second))
	if err != nil || updated.Revision != 2 || updated.MembershipGeneration != 1 {
		t.Fatalf("capacity update=%+v err=%v", updated, err)
	}
	status, err = reopened.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(32*time.Second), time.Minute)
	if err != nil || status.EligibleNodes != 1 {
		t.Fatalf("capacity update invalidated membership: status=%+v err=%v", status, err)
	}
	capacityInput.Architecture = ""
	updated, _, err = reopened.ApplyNodePool(fixture.admin, capacityInput, 2, observedAt.Add(33*time.Second))
	if err != nil || updated.Revision != 3 || updated.MembershipGeneration != 2 {
		t.Fatalf("security-scope update=%+v err=%v", updated, err)
	}
	if _, err := reopened.BindNodePoolMembership(identity, fixture.auth, raw, observedAt.Add(34*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale membership generation bind error=%v", err)
	}
	status, err = reopened.GetNodePoolStatus(fixture.admin, pool.ID, observedAt.Add(35*time.Second), time.Minute)
	if err != nil || status.EligibleNodes != 0 || status.Nodes[0].Reason != "membership_mismatch" {
		t.Fatalf("security-scope status=%+v err=%v", status, err)
	}
	if err := reopened.DeleteNodePool(fixture.admin, pool.ID, 3); err != nil {
		t.Fatal(err)
	}
	capacityInput.Architecture = "amd64"
	recreated, _, err := reopened.ApplyNodePool(fixture.admin, capacityInput, 0, observedAt.Add(36*time.Second))
	if err != nil || recreated.Revision != 1 || recreated.MembershipGeneration != 1 || recreated.CreatedAt == pool.CreatedAt {
		t.Fatalf("recreated pool=%+v err=%v", recreated, err)
	}
	if _, err := reopened.BindNodePoolMembership(identity, fixture.auth, raw, observedAt.Add(37*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted-pool membership replay error=%v", err)
	}
}

func statementNotAfter(t *testing.T, statement poolmembership.Statement) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339Nano, statement.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	return value
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
		ID: "pool-a", Revision: 1, MembershipGeneration: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
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

func TestNodePoolScaleInCandidatesNeverExceedSurplus(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pool := NodePool{
		ID: "pool-a", Revision: 1, MembershipGeneration: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 1, DesiredNodes: 4, MaxNodes: 6,
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	current := emptyState()
	for index := 0; index < 5; index++ {
		nodeID := "node-" + string(rune('a'+index))
		observation := storeSchedulingObservation(nodeID)
		observation.Labels = append(observation.Labels, controlprotocol.ExecutorSchedulingLabelV1{
			Key: NodePoolLabelKey, Value: pool.ID,
		})
		sort.Slice(observation.Labels, func(i, j int) bool { return observation.Labels[i].Key < observation.Labels[j].Key })
		node := Node{
			ID: nodeID, Active: true, TenantIDs: []string{"tenant-a"},
			Scheduling: &NodeScheduling{Observation: observation, ObservedAt: now.Format(time.RFC3339Nano)},
		}
		if index < 3 {
			node.Drain = &NodeDrain{
				RequestID: "drain-" + nodeID, State: NodeDrainCompleted, Reason: "scale in",
				RequestedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
			}
		}
		current.nodes[nodeID] = node
	}
	status := nodePoolStatusLocked(current, pool, now.Add(time.Second), time.Minute)
	if status.RegisteredNodes != 5 || !slices.Equal(status.ScaleInCandidates, []string{"node-a"}) ||
		!slices.Contains(status.Conditions, NodePoolConditionScaleInAvailable) {
		t.Fatalf("bounded scale-in status=%+v", status)
	}
	if err := status.Validate(); err != nil {
		t.Fatalf("bounded scale-in status rejected: %v", err)
	}
	status.ScaleInCandidates = []string{"node-a", "node-b"}
	if err := status.Validate(); err == nil {
		t.Fatal("status accepted scale-in candidates beyond the pool surplus")
	}
}

func TestNodePoolNodeStateValidationRejectsContradictoryDrainFacts(t *testing.T) {
	valid := []NodePoolNode{
		{NodeID: "ready", Ready: true, Eligible: true},
		{NodeID: "cancelled", Ready: true, Eligible: true, DrainState: NodeDrainCancelled},
		{NodeID: "unavailable", Eligible: true, Reason: "scheduling_unavailable"},
		{NodeID: "stale-active", Eligible: true, Reason: "scheduling_stale", DrainState: NodeDrainActive},
		{NodeID: "blocked", Eligible: true, Reason: "placement_blocked"},
		{NodeID: "missing", Reason: "membership_missing"},
		{NodeID: "draining", Eligible: true, Reason: "draining", DrainState: NodeDrainActive},
		{NodeID: "drained", Eligible: true, Reason: "drained", DrainState: NodeDrainCompleted},
		{NodeID: "failed", Eligible: true, Reason: "drain_failed", DrainState: NodeDrainFailed},
	}
	for _, node := range valid {
		if !validNodePoolNodeState(node) {
			t.Fatalf("valid node-pool state rejected: %+v", node)
		}
	}

	invalid := []NodePoolNode{
		{NodeID: "missing-reason"},
		{NodeID: "ready-with-reason", Ready: true, Reason: "scheduling_stale"},
		{NodeID: "unknown-reason", Reason: "unknown"},
		{NodeID: "unknown-drain", Ready: true, DrainState: "unknown"},
		{NodeID: "ready-active", Ready: true, DrainState: NodeDrainActive},
		{NodeID: "wrong-active", Reason: "draining", DrainState: NodeDrainCompleted},
		{NodeID: "wrong-completed", Reason: "drained", DrainState: NodeDrainFailed},
		{NodeID: "wrong-failed", Reason: "drain_failed", DrainState: NodeDrainActive},
	}
	for _, node := range invalid {
		if validNodePoolNodeState(node) {
			t.Fatalf("contradictory node-pool state accepted: %+v", node)
		}
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

func TestNodePoolOperationsFailClosedAcrossAuthorizationAndRevisionBoundaries(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxNodePools = 1
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	poolInput := NodePool{ID: "pool-a", TenantIDs: []string{"tenant-a"}, MinNodes: 0, DesiredNodes: 1, MaxNodes: 2}
	notAdmin := controlauth.Identity{Role: controlauth.RoleTenantOperator, TenantID: "tenant-a", CredentialID: "tenant-operator"}
	staleAdmin := fixture.admin
	staleAdmin.CredentialID = "missing-credential"

	if _, err := fixture.store.ListNodePools(notAdmin); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant list error=%v", err)
	}
	if _, err := fixture.store.GetNodePoolStatus(notAdmin, poolInput.ID, fixture.now, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant status error=%v", err)
	}
	if _, err := fixture.store.ListNodePoolStatuses(notAdmin, fixture.now, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant status list error=%v", err)
	}
	if _, _, err := fixture.store.ApplyNodePool(notAdmin, poolInput, 0, fixture.now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant apply error=%v", err)
	}
	if err := fixture.store.DeleteNodePool(notAdmin, poolInput.ID, 1); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant delete error=%v", err)
	}
	if _, err := fixture.store.GetNodePoolStatus(fixture.admin, "bad pool", fixture.now, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid status error=%v", err)
	}
	if _, err := fixture.store.ListNodePoolStatuses(fixture.admin, time.Time{}, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid status list error=%v", err)
	}
	if err := fixture.store.DeleteNodePool(fixture.admin, poolInput.ID, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid delete error=%v", err)
	}
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 1, fixture.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("create with revision error=%v", err)
	}
	created, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 0, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, NodePool{
		ID: "pool-b", TenantIDs: []string{"tenant-a"}, MinNodes: 0, DesiredNodes: 1, MaxNodes: 2,
	}, 0, fixture.now); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("pool capacity error=%v", err)
	}
	if _, err := fixture.store.GetNodePoolStatus(fixture.admin, "missing", fixture.now, time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing status error=%v", err)
	}
	if err := fixture.store.DeleteNodePool(fixture.admin, "missing", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing delete error=%v", err)
	}
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, created.Revision, fixture.now.Add(-time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retrograde update error=%v", err)
	}

	fixture.store.mu.Lock()
	retained := fixture.store.current.nodePools[poolInput.ID]
	retained.Revision = math.MaxUint64
	fixture.store.current.nodePools[poolInput.ID] = retained
	fixture.store.mu.Unlock()
	poolInput.DesiredNodes = 2
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, math.MaxUint64, fixture.now.Add(time.Minute)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("revision exhaustion error=%v", err)
	}

	fixture.store.mu.Lock()
	retained.Revision = 1
	retained.MembershipGeneration = math.MaxUint64
	fixture.store.current.nodePools[poolInput.ID] = retained
	fixture.store.mu.Unlock()
	poolInput.Architecture = "amd64"
	if _, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 1, fixture.now.Add(time.Minute)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("membership generation exhaustion error=%v", err)
	}

	for name, check := range map[string]func() error{
		"list": func() error { _, err := fixture.store.ListNodePools(staleAdmin); return err },
		"get": func() error {
			_, err := fixture.store.GetNodePoolStatus(staleAdmin, poolInput.ID, fixture.now, time.Minute)
			return err
		},
		"list status": func() error {
			_, err := fixture.store.ListNodePoolStatuses(staleAdmin, fixture.now, time.Minute)
			return err
		},
		"apply": func() error {
			_, _, err := fixture.store.ApplyNodePool(staleAdmin, poolInput, 1, fixture.now)
			return err
		},
		"delete": func() error { return fixture.store.DeleteNodePool(staleAdmin, poolInput.ID, 1) },
	} {
		if err := check(); !errors.Is(err, controlauth.ErrUnauthorized) {
			t.Fatalf("stale administrator %s error=%v", name, err)
		}
	}

	fixture.store.mu.Lock()
	fixture.store.closed = true
	fixture.store.mu.Unlock()
	for name, check := range map[string]func() error{
		"list": func() error { _, err := fixture.store.ListNodePools(fixture.admin); return err },
		"get": func() error {
			_, err := fixture.store.GetNodePoolStatus(fixture.admin, poolInput.ID, fixture.now, time.Minute)
			return err
		},
		"list status": func() error {
			_, err := fixture.store.ListNodePoolStatuses(fixture.admin, fixture.now, time.Minute)
			return err
		},
		"apply": func() error {
			_, _, err := fixture.store.ApplyNodePool(fixture.admin, poolInput, 1, fixture.now)
			return err
		},
		"delete": func() error { return fixture.store.DeleteNodePool(fixture.admin, poolInput.ID, 1) },
	} {
		if err := check(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("closed store %s error=%v", name, err)
		}
	}
}

func TestNodePoolStateFormatRejectsLegacySmugglingAndDuplicateIdentity(t *testing.T) {
	current, limits := populatedControlState(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	pool := NodePool{
		ID: "pool-a", Revision: 1, MembershipGeneration: 1, TenantIDs: []string{"tenant-a"},
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

	versionNineteen := snapshot
	versionNineteen.Version = stateFormatPoolMembershipVersion - 1
	versionNineteen.NodePools = []NodePool{pool}
	versionNineteen.NodePools[0].MembershipGeneration = 0
	versionNineteenRaw, err := json.Marshal(versionNineteen)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err = decodeState(versionNineteenRaw, limits.MaxStateBytes)
	if err != nil || migrated.nodePools[pool.ID].MembershipGeneration != 1 {
		t.Fatalf("membership generation migration=(%+v, %v)", migrated.nodePools, err)
	}

	smuggledMembership := versionNineteen
	smuggledMembership.NodePools[0].MembershipKeyID = "authority-a"
	smuggledMembership.NodePools[0].MembershipPublicKeyBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	smuggledMembershipRaw, err := json.Marshal(smuggledMembership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggledMembershipRaw, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled node-pool membership authority")
	}

	legacyPool := pool
	legacyPool.MembershipGeneration = 0
	migratedTransaction, err := applyTransaction(emptyState(), transaction{
		Version: transactionPoolMembershipVersion - 1, Mutations: []mutation{{Kind: mutationNodePool, NodePool: &legacyPool}},
	})
	if err != nil || migratedTransaction.nodePools[pool.ID].MembershipGeneration != 1 {
		t.Fatalf("membership transaction migration=(%+v, %v)", migratedTransaction.nodePools, err)
	}
}
