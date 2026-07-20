package controlstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestObserveNodeSchedulingIsAuthenticatedBoundedAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	observation := storeSchedulingObservation("node-1")
	node, applied, err := fixture.store.ObserveNodeScheduling(identity, observation, fixture.now.Add(2*time.Minute))
	if err != nil || !applied || node.Scheduling == nil {
		t.Fatalf("first observation = (%+v, %v, %v)", node, applied, err)
	}
	originalObservedAt := node.Scheduling.ObservedAt
	observation.Labels[0].Value = "mutated"
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || nodes[0].Scheduling.Observation.Labels[0].Value != "west" {
		t.Fatalf("caller mutated retained observation = (%+v, %v)", nodes, err)
	}
	unchanged := storeSchedulingObservation("node-1")
	node, applied, err = fixture.store.ObserveNodeScheduling(identity, unchanged, fixture.now.Add(2*time.Minute+30*time.Second))
	if err != nil || applied || node.Scheduling.ObservedAt != originalObservedAt {
		t.Fatalf("early equal observation = (%+v, %v, %v)", node, applied, err)
	}
	node, applied, err = fixture.store.ObserveNodeScheduling(identity, unchanged, fixture.now.Add(3*time.Minute))
	if err != nil || !applied || node.Scheduling.ObservedAt == originalObservedAt {
		t.Fatalf("refreshed observation = (%+v, %v, %v)", node, applied, err)
	}
	wrong := unchanged
	wrong.NodeID = "node-2"
	if _, _, err := fixture.store.ObserveNodeScheduling(identity, wrong, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong-node observation error = %v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	nodes, err = reopened.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 1 || nodes[0].Scheduling == nil ||
		nodes[0].Scheduling.Observation.Policy.Host.Workloads != 4 {
		t.Fatalf("reopened scheduling observation = (%+v, %v)", nodes, err)
	}
}

func TestCheckNodeSchedulingEnforcesPlacementAndAggregateReservations(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	observation := storeSchedulingObservation("node-1")
	node := Node{
		ID: "node-1", Scheduling: &NodeScheduling{
			Observation: observation, ObservedAt: now.Format(time.RFC3339Nano),
		},
	}
	capsule := admission.ProfileCapsule{
		Image: admission.ImageIdentity{Platform: admission.Platform{OS: "linux", Architecture: "amd64"}},
	}
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-1",
		Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
	}
	existing := Deployment{
		TenantID: "tenant-a",
		Instances: []DeploymentInstance{{
			NodeID: "node-1", Phase: DeploymentInstanceRunning,
			Intent: &admission.InstanceIntent{
				TenantID: "tenant-a", Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
			},
		}},
	}
	if err := CheckNodeScheduling(node, []Deployment{existing}, "tenant-a", intent, capsule, nil, now, time.Minute); err != nil {
		t.Fatalf("fit observation: %v", err)
	}

	stale := node
	stale.Scheduling = cloneNodeScheduling(node.Scheduling)
	stale.Scheduling.ObservedAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if err := CheckNodeScheduling(stale, nil, "tenant-a", intent, capsule, nil, now, time.Minute); !errors.Is(err, ErrNodeSchedulingUnavailable) {
		t.Fatalf("stale observation error = %v", err)
	}

	wrongArchitecture := capsule
	wrongArchitecture.Image.Platform.Architecture = "arm64"
	if err := CheckNodeScheduling(node, nil, "tenant-a", intent, wrongArchitecture, nil, now, time.Minute); !errors.Is(err, ErrNodeSchedulingConstraint) {
		t.Fatalf("architecture error = %v", err)
	}

	tainted := cloneNode(node)
	tainted.Scheduling.Observation.Taints = []string{"dedicated"}
	if err := CheckNodeScheduling(tainted, nil, "tenant-a", intent, capsule, nil, now, time.Minute); !errors.Is(err, ErrNodeSchedulingConstraint) {
		t.Fatalf("untolerated taint error = %v", err)
	}
	placement := &admission.CommandDelegationPlacement{
		RequiredIsolation: "gvisor",
		RequiredLabels:    []admission.CommandDelegationLabel{{Key: "region", Value: "west"}},
		Tolerations:       []string{"dedicated"},
	}
	if err := CheckNodeScheduling(tainted, nil, "tenant-a", intent, capsule, placement, now, time.Minute); err != nil {
		t.Fatalf("signed placement fit: %v", err)
	}

	tenantFull := cloneNode(node)
	tenantFull.Scheduling.Observation.Policy.Tenant.Workloads = 1
	if err := CheckNodeScheduling(tenantFull, []Deployment{existing}, "tenant-a", intent, capsule, nil, now, time.Minute); !errors.Is(err, ErrTenantCapacityExceeded) {
		t.Fatalf("tenant capacity error = %v", err)
	}

	nodeFull := cloneNode(node)
	nodeFull.Scheduling.Observation.Policy.Host.Workloads = 1
	nodeFull.Scheduling.Observation.Policy.Tenant.Workloads = 1
	if err := CheckNodeScheduling(nodeFull, []Deployment{existing}, "tenant-a", intent, capsule, nil, now, time.Minute); !errors.Is(err, ErrNodeCapacityExceeded) {
		t.Fatalf("node capacity error = %v", err)
	}

	runtimeIntent := intent
	runtimeIntent.Capabilities.Inference = true
	runtimeLimited := cloneNode(node)
	runtimeLimited.Scheduling.Observation.Policy.Host.MemoryBytes = intent.Resources.MemoryBytes
	runtimeLimited.Scheduling.Observation.Policy.Tenant.MemoryBytes = intent.Resources.MemoryBytes
	if err := CheckNodeScheduling(runtimeLimited, nil, "tenant-a", runtimeIntent, capsule, nil, now, time.Minute); !errors.Is(err, ErrNodeCapacityExceeded) {
		t.Fatalf("runtime overhead error = %v", err)
	}
}

func TestSchedulingFormatRejectsLegacyStateSmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	node := firstNode(current)
	node.Scheduling = &NodeScheduling{
		Observation: storeSchedulingObservation(node.ID),
		ObservedAt:  node.CreatedAt,
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
	snapshot.Version = stateFormatWorkloadLeaseVersion
	smuggled, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled scheduling observation")
	}
	transaction := transaction{
		Version:   transactionWorkloadLeaseVersion,
		Mutations: []mutation{{Kind: mutationNode, Node: &node}},
	}
	if _, err := applyTransaction(current, transaction); err == nil {
		t.Fatal("legacy transaction smuggled scheduling observation")
	}
}

func storeSchedulingObservation(nodeID string) controlprotocol.ExecutorSchedulingObservationV1 {
	return controlprotocol.ExecutorSchedulingObservationV1{
		SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
		NodeID:        nodeID, CredentialScope: "node", OS: "linux", Architecture: "amd64",
		Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor,
		Labels:    []controlprotocol.ExecutorSchedulingLabelV1{{Key: "region", Value: "west"}},
		Taints:    []string{},
		Policy: controlprotocol.ExecutorSchedulingPolicyV1{
			PerWorkload:     controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128, Workloads: 1},
			Host:            controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2 << 30, CPUMillis: 4000, PIDs: 1024, Workloads: 4},
			Tenant:          controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 512, Workloads: 2},
			RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32},
		},
	}
}
