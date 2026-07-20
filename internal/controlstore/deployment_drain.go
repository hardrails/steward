package controlstore

import (
	"errors"
	"math"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
)

var (
	ErrDisruptionBudget = errors.New("deployment disruption budget is exhausted")
	ErrStatefulDrain    = errors.New("stateful deployment drain requires a snapshot backend")
)

// BeginDeploymentInstanceDrain records an unavailable replica before Control
// sends its first stop command. The budget check and marker write share the
// store mutex, so concurrent reconcilers cannot begin too many moves.
func (store *Store) BeginDeploymentInstanceDrain(
	tenantID, deploymentID, instanceID, sourceNodeID, requestID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) ||
		!validRecordID(sourceNodeID, 128) || !validRecordID(requestID, 128) {
		return Deployment{}, false, invalid("deployment drain input is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, found := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !found {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.Revision != expectedRevision || deployment.DesiredState != DeploymentRunning {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.Drain != nil {
		if instance.Drain.SourceNodeID == sourceNodeID && instance.Drain.RequestID == requestID {
			return cloneDeployment(deployment), false, nil
		}
		return Deployment{}, false, ErrConflict
	}
	if instance.NodeID != sourceNodeID || instance.Phase != DeploymentInstanceRunning ||
		deploymentCommandInFlight(instance) {
		return Deployment{}, false, ErrConflict
	}
	node, found := store.current.nodes[sourceNodeID]
	if !found || node.Drain == nil || node.Drain.State != NodeDrainActive || node.Drain.RequestID != requestID {
		return Deployment{}, false, ErrConflict
	}
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil || delegation.Admission == nil {
		return Deployment{}, false, ErrConflict
	}
	if delegation.Admission.Capabilities.State {
		return Deployment{}, false, ErrStatefulDrain
	}
	delegated, ok := deploymentDelegatedInstance(delegation.Instances, instanceID)
	if !ok || instance.Generation == math.MaxUint64 || instance.Generation+1 > delegated.MaxInstanceGeneration {
		return Deployment{}, false, ErrCapacityExceeded
	}
	unavailable := deploymentUnavailableInstances(deployment)
	if deployment.DisruptionBudget.MaxUnavailable == 0 ||
		unavailable >= deployment.DisruptionBudget.MaxUnavailable {
		return Deployment{}, false, ErrDisruptionBudget
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.Drain = &DeploymentInstanceDrain{
		RequestID: requestID, SourceNodeID: sourceNodeID, StartedAt: canonicalTimestamp(now),
	}
	instance.LastError = ""
	instance.TransitionedAt = canonicalTimestamp(now)
	deployment.Instances[index] = instance
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	deployment.Phase = deploymentAggregatePhase(deployment)
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

// ReplaceDrainedDeploymentInstance advances generation only after a successful
// destroy terminal report made the old runtime absent. The drain marker remains
// until the replacement reaches running on another node.
func (store *Store) ReplaceDrainedDeploymentInstance(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) {
		return Deployment{}, false, invalid("drained deployment replacement input is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, found := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !found {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.Revision != expectedRevision || deployment.DesiredState != DeploymentRunning {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.Drain == nil || instance.NodeID != instance.Drain.SourceNodeID ||
		instance.Phase != DeploymentInstanceRemoved {
		return Deployment{}, false, ErrConflict
	}
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil || delegation.Admission == nil || delegation.Admission.Capabilities.State {
		return Deployment{}, false, ErrConflict
	}
	delegated, ok := deploymentDelegatedInstance(delegation.Instances, instanceID)
	if !ok || instance.Generation == math.MaxUint64 || instance.Generation+1 > delegated.MaxInstanceGeneration ||
		deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.Generation++
	instance.NodeID = ""
	instance.Placement = nil
	instance.Intent = nil
	instance.Admission = nil
	instance.LeaseExpiresAt = ""
	instance.Phase = DeploymentInstancePending
	instance.CommandID = ""
	instance.CommandOperation = ""
	instance.LastError = ""
	instance.TransitionedAt = canonicalTimestamp(now)
	deployment.Instances[index] = instance
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	deployment.Phase = deploymentAggregatePhase(deployment)
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

// CompleteFinishedNodeDrains seals active drains whose source node no longer
// owns an instance and has no in-progress drain marker. It updates at most one
// bounded transaction per reconciliation pass.
func (store *Store) CompleteFinishedNodeDrains(now time.Time) (int, error) {
	if store == nil {
		return 0, ErrUnavailable
	}
	if now.IsZero() {
		return 0, invalid("node drain completion time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return 0, err
	}
	nodeIDs := make([]string, 0, len(store.current.nodes))
	for nodeID := range store.current.nodes {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	mutations := make([]mutation, 0)
	for _, nodeID := range nodeIDs {
		node := store.current.nodes[nodeID]
		if node.Drain == nil || node.Drain.State != NodeDrainActive || nodeDrainHasWork(store.current.deployments, node.ID) {
			continue
		}
		updatedAt, _ := parseTimestamp(node.Drain.UpdatedAt)
		if now.Before(updatedAt) {
			return 0, invalid("node drain completion predates retained state")
		}
		updated := cloneNode(node)
		updated.Drain.State = NodeDrainCompleted
		updated.Drain.UpdatedAt = canonicalTimestamp(now)
		updated.Drain.CompletedAt = canonicalTimestamp(now)
		mutations = append(mutations, mutation{Kind: mutationNode, Node: &updated})
		if len(mutations) == maxMutationsPerRecord {
			break
		}
	}
	if len(mutations) == 0 {
		return 0, nil
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return 0, err
	}
	return len(mutations), nil
}

func deploymentUnavailableInstances(deployment Deployment) int {
	unavailable := 0
	for _, instance := range deployment.Instances {
		if instance.Drain != nil || instance.Phase != DeploymentInstanceRunning {
			unavailable++
		}
	}
	return unavailable
}

func nodeDrainHasWork(deployments map[string]Deployment, nodeID string) bool {
	for _, deployment := range deployments {
		for _, instance := range deployment.Instances {
			if (instance.Drain != nil && instance.Drain.SourceNodeID == nodeID) ||
				(instance.NodeID == nodeID && instance.Phase != DeploymentInstanceRemoved) {
				return true
			}
		}
	}
	return false
}

// failDeploymentInstanceDrainLocked abandons a planned move after an
// unrepeatable lifecycle command fails. It clears the per-instance marker so a
// cancelled or failed request cannot poison later maintenance, while leaving
// the instance failed and the node cordoned because the runtime outcome is not
// known to be safe. The caller must hold store.mu and persist the returned node
// mutation with the deployment mutation.
func (store *Store) failDeploymentInstanceDrainLocked(
	instance *DeploymentInstance,
	now time.Time,
) *Node {
	if instance == nil || instance.Drain == nil {
		return nil
	}
	drain := *instance.Drain
	instance.Drain = nil
	node, found := store.current.nodes[drain.SourceNodeID]
	if !found || node.Drain == nil || node.Drain.RequestID != drain.RequestID ||
		node.Drain.State != NodeDrainActive {
		return nil
	}
	updated := cloneNode(node)
	updated.Drain.State = NodeDrainFailed
	updated.Drain.UpdatedAt = canonicalTimestamp(now)
	updated.Drain.CompletedAt = canonicalTimestamp(now)
	updated.Drain.FailedInstanceID = instance.InstanceID
	return &updated
}
