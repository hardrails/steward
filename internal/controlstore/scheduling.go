package controlstore

import (
	"errors"
	"math"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

var (
	ErrNodeSchedulingUnavailable = errors.New("node scheduling observation is unavailable")
	ErrNodeSchedulingConstraint  = errors.New("node does not satisfy signed placement constraints")
	ErrNodeCapacityExceeded      = errors.New("node scheduling capacity exceeded")
	ErrTenantCapacityExceeded    = errors.New("tenant scheduling capacity exceeded")
)

// CheckNodeScheduling verifies freshness, signed placement constraints, and
// resource headroom against one immutable deployment snapshot. Enqueue repeats
// this check under the store mutex before it commits an admit command.
func CheckNodeScheduling(
	node Node,
	deployments []Deployment,
	tenantID string,
	intent admission.InstanceIntent,
	capsule admission.ProfileCapsule,
	placement *admission.CommandDelegationPlacement,
	now time.Time,
	staleAfter time.Duration,
) error {
	if now.IsZero() || staleAfter <= 0 || staleAfter > MaxOperationsThreshold || node.Scheduling == nil {
		return ErrNodeSchedulingUnavailable
	}
	observedAt, err := parseTimestamp(node.Scheduling.ObservedAt)
	if err != nil || !now.Before(observedAt.Add(staleAfter)) {
		return ErrNodeSchedulingUnavailable
	}
	observation := node.Scheduling.Observation
	if observation.Validate() != nil || observation.NodeID != node.ID ||
		observation.OS != capsule.Image.Platform.OS ||
		observation.Architecture != capsule.Image.Platform.Architecture ||
		!schedulingPlacementMatches(observation, placement) {
		return ErrNodeSchedulingConstraint
	}
	perWorkload := controlprotocol.ExecutorSchedulingResourcesV1{
		MemoryBytes: intent.Resources.MemoryBytes, CPUMillis: intent.Resources.CPUMillis,
		PIDs: intent.Resources.PIDs, Workloads: 1,
	}
	requested, err := schedulingReservation(intent, observation.Policy)
	if err != nil || exceedsSchedulingCapacity(
		controlprotocol.ExecutorSchedulingResourcesV1{}, perWorkload, observation.Policy.PerWorkload,
	) {
		return ErrNodeCapacityExceeded
	}
	host, tenant, err := deploymentSchedulingUsage(deployments, node.ID, tenantID, observation.Policy)
	if err != nil || exceedsSchedulingCapacity(host, requested, observation.Policy.Host) {
		return ErrNodeCapacityExceeded
	}
	if exceedsSchedulingCapacity(tenant, requested, observation.Policy.Tenant) {
		return ErrTenantCapacityExceeded
	}
	return nil
}

func deploymentSchedulingUsage(
	deployments []Deployment,
	nodeID, tenantID string,
	policy controlprotocol.ExecutorSchedulingPolicyV1,
) (controlprotocol.ExecutorSchedulingResourcesV1, controlprotocol.ExecutorSchedulingResourcesV1, error) {
	var host, tenant controlprotocol.ExecutorSchedulingResourcesV1
	for _, deployment := range deployments {
		for _, instance := range deployment.Instances {
			if instance.NodeID != nodeID || instance.Intent == nil || instance.Phase == DeploymentInstanceRemoved {
				continue
			}
			reservation, err := schedulingReservation(*instance.Intent, policy)
			if err != nil || addSchedulingResources(&host, reservation) != nil {
				return host, tenant, ErrNodeCapacityExceeded
			}
			if deployment.TenantID == tenantID && addSchedulingResources(&tenant, reservation) != nil {
				return host, tenant, ErrTenantCapacityExceeded
			}
		}
	}
	return host, tenant, nil
}

func schedulingReservation(
	intent admission.InstanceIntent,
	policy controlprotocol.ExecutorSchedulingPolicyV1,
) (controlprotocol.ExecutorSchedulingResourcesV1, error) {
	reservation := controlprotocol.ExecutorSchedulingResourcesV1{
		MemoryBytes: intent.Resources.MemoryBytes,
		CPUMillis:   intent.Resources.CPUMillis,
		PIDs:        intent.Resources.PIDs,
		Workloads:   1,
	}
	capabilities := intent.Capabilities
	if capabilities.Inference || capabilities.Service || capabilities.Egress || capabilities.Connector {
		if err := addSchedulingResources(&reservation, policy.RuntimeOverhead); err != nil {
			return controlprotocol.ExecutorSchedulingResourcesV1{}, err
		}
	}
	return reservation, nil
}

func addSchedulingResources(
	total *controlprotocol.ExecutorSchedulingResourcesV1,
	add controlprotocol.ExecutorSchedulingResourcesV1,
) error {
	if total == nil || add.MemoryBytes < 0 || add.CPUMillis < 0 || add.PIDs < 0 || add.Workloads < 0 ||
		total.MemoryBytes > math.MaxInt64-add.MemoryBytes ||
		total.CPUMillis > math.MaxInt64-add.CPUMillis ||
		total.PIDs > math.MaxInt64-add.PIDs || total.Workloads > math.MaxInt64-add.Workloads {
		return errors.New("scheduling resource sum overflows")
	}
	total.MemoryBytes += add.MemoryBytes
	total.CPUMillis += add.CPUMillis
	total.PIDs += add.PIDs
	total.Workloads += add.Workloads
	return nil
}

func exceedsSchedulingCapacity(
	used, add, maximum controlprotocol.ExecutorSchedulingResourcesV1,
) bool {
	return exceedsSchedulingValue(used.MemoryBytes, add.MemoryBytes, maximum.MemoryBytes) ||
		exceedsSchedulingValue(used.CPUMillis, add.CPUMillis, maximum.CPUMillis) ||
		exceedsSchedulingValue(used.PIDs, add.PIDs, maximum.PIDs) ||
		exceedsSchedulingValue(used.Workloads, add.Workloads, maximum.Workloads)
}

func exceedsSchedulingValue(used, add, maximum int64) bool {
	return used < 0 || add < 0 || maximum < 0 || add > maximum || used > maximum-add
}

func schedulingPlacementMatches(
	observation controlprotocol.ExecutorSchedulingObservationV1,
	placement *admission.CommandDelegationPlacement,
) bool {
	if placement == nil {
		return len(observation.Taints) == 0
	}
	if placement.RequiredIsolation != "" && placement.RequiredIsolation != observation.Isolation {
		return false
	}
	for _, required := range placement.RequiredLabels {
		index := sort.Search(len(observation.Labels), func(index int) bool {
			return observation.Labels[index].Key >= required.Key
		})
		if index >= len(observation.Labels) || observation.Labels[index].Key != required.Key ||
			observation.Labels[index].Value != required.Value {
			return false
		}
	}
	for _, taint := range observation.Taints {
		index := sort.SearchStrings(placement.Tolerations, taint)
		if index >= len(placement.Tolerations) || placement.Tolerations[index] != taint {
			return false
		}
	}
	return true
}

// ObserveNodeScheduling records a bounded scheduling profile only after the
// node credential has been revalidated under the store mutex. Equal profiles
// refresh at most once per observation interval to bound WAL growth.
func (store *Store) ObserveNodeScheduling(
	identity controlauth.NodeIdentity,
	observation controlprotocol.ExecutorSchedulingObservationV1,
	now time.Time,
) (Node, bool, error) {
	if store == nil {
		return Node{}, false, ErrUnavailable
	}
	if now.IsZero() || identity.Audience != "executor" ||
		!validRecordID(identity.NodeID, 128) || !validTenantSet(identity.TenantIDs) ||
		observation.Validate() != nil || observation.NodeID != identity.NodeID {
		return Node{}, false, invalid("node scheduling observation or identity is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Node{}, false, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return Node{}, false, err
	}
	node, found := store.current.nodes[identity.NodeID]
	if !found || !node.Active || !tenantSubset(identity.TenantIDs, node.TenantIDs) {
		return Node{}, false, ErrNotFound
	}
	if node.Scheduling != nil && schedulingObservationsEqual(node.Scheduling.Observation, observation) &&
		!observationDue(node.Scheduling.ObservedAt, now) {
		return cloneNode(node), false, nil
	}
	updated := cloneNode(node)
	updated.Scheduling = &NodeScheduling{
		Observation: cloneSchedulingObservation(observation),
		ObservedAt:  canonicalTimestamp(now),
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &updated}); err != nil {
		return Node{}, false, err
	}
	return cloneNode(updated), true, nil
}

func cloneSchedulingObservation(
	value controlprotocol.ExecutorSchedulingObservationV1,
) controlprotocol.ExecutorSchedulingObservationV1 {
	if value.Labels != nil {
		value.Labels = append([]controlprotocol.ExecutorSchedulingLabelV1{}, value.Labels...)
	}
	if value.Taints != nil {
		value.Taints = append([]string{}, value.Taints...)
	}
	return value
}

func schedulingObservationsEqual(
	left, right controlprotocol.ExecutorSchedulingObservationV1,
) bool {
	if left.SchemaVersion != right.SchemaVersion || left.NodeID != right.NodeID ||
		left.CredentialScope != right.CredentialScope || left.OS != right.OS ||
		left.Architecture != right.Architecture || left.Isolation != right.Isolation ||
		left.Policy != right.Policy || !equalSchedulingLabels(left.Labels, right.Labels) ||
		!equalStrings(left.Taints, right.Taints) {
		return false
	}
	return true
}

func equalSchedulingLabels(
	left, right []controlprotocol.ExecutorSchedulingLabelV1,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
