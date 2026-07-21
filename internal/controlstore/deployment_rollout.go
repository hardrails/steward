package controlstore

import (
	"bytes"
	"math"
	"time"

	"github.com/hardrails/steward/internal/admission"
)

// BeginDeploymentInstanceRollout spends one disruption-budget slot before the
// first stop command. The source authority remains selected until a successful
// destroy report proves that the former runtime is absent.
func (store *Store) BeginDeploymentInstanceRollout(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) {
		return Deployment{}, false, invalid("deployment rollout input is invalid")
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
	if deployment.Revision != expectedRevision || deployment.DesiredState != DeploymentRunning ||
		deployment.Rollout == nil || deployment.Rollout.PausedAt != "" {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.Rollout != nil {
		return cloneDeployment(deployment), false, nil
	}
	if instance.Drain != nil || instance.NodeID == "" || instance.Phase != DeploymentInstanceRunning ||
		deploymentCommandInFlight(instance) {
		return Deployment{}, false, ErrConflict
	}
	_, authority, err := DeploymentAuthorityForInstance(deployment, instance)
	if err != nil || bytes.Equal(authority, deployment.DelegationDSSE) {
		return Deployment{}, false, ErrConflict
	}
	if node, found := store.current.nodes[instance.NodeID]; !found ||
		node.Drain != nil && node.Drain.State == NodeDrainActive {
		return Deployment{}, false, ErrConflict
	}
	if deployment.DisruptionBudget.MaxUnavailable == 0 ||
		deploymentUnavailableInstances(deployment) >= deployment.DisruptionBudget.MaxUnavailable {
		return Deployment{}, false, ErrDisruptionBudget
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.Rollout = &DeploymentInstanceRollout{Stage: "draining", StartedAt: canonicalTimestamp(now)}
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

// AdvanceDeploymentInstanceRollout switches to target authority only after the
// source destroy completed. It retains the node so stateful volumes stay local;
// rollout apply already proved that the target delegation permits this node.
func (store *Store) AdvanceDeploymentInstanceRollout(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) {
		return Deployment{}, false, invalid("deployment rollout advance input is invalid")
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
	if deployment.Revision != expectedRevision || deployment.DesiredState != DeploymentRunning ||
		deployment.Rollout == nil {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.Rollout == nil || instance.Rollout.Stage != "draining" ||
		instance.Phase != DeploymentInstanceRemoved || instance.NodeID == "" {
		return Deployment{}, false, ErrConflict
	}
	target, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		return Deployment{}, false, ErrConflict
	}
	delegated, found := deploymentDelegatedInstance(target.Instances, instanceID)
	if !found || delegated.MinInstanceGeneration <= instance.Generation ||
		delegated.MinInstanceGeneration > delegated.MaxInstanceGeneration || deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.Generation = delegated.MinInstanceGeneration
	instance.Placement = nil
	instance.Intent = nil
	instance.Admission = nil
	instance.LeaseExpiresAt = ""
	instance.Phase = DeploymentInstancePending
	instance.CommandID = ""
	instance.CommandOperation = ""
	instance.LastError = ""
	instance.Rollout.Stage = "deploying"
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
