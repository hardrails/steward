package controlstore

import (
	"bytes"
	"slices"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/dsse"
)

// DeploymentApply is the complete immutable input for one desired deployment
// generation. Signed artifacts are public authority envelopes, never private
// signing material.
type DeploymentApply struct {
	TenantID         string
	ID               string
	Generation       uint64
	ExpectedRevision uint64
	AgentName        string
	BundleDigest     string
	CapsuleDSSE      []byte
	DelegationDSSE   []byte
}

// ApplyDeployment creates or rolls forward desired state. Exact retries are
// idempotent. A changed generation requires the last observed revision so two
// operators cannot silently overwrite each other.
func (store *Store) ApplyDeployment(
	actor controlauth.Identity,
	input DeploymentApply,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, input.TenantID) {
		return Deployment{}, false, ErrNotFound
	}
	if now.IsZero() || !validRecordID(input.TenantID, 128) || !validRecordID(input.ID, 128) ||
		!validRecordID(input.AgentName, 128) || !validSHA256Digest(input.BundleDigest) || input.Generation == 0 ||
		len(input.CapsuleDSSE) == 0 || len(input.CapsuleDSSE) > store.limits.MaxCommandBytes ||
		len(input.DelegationDSSE) == 0 || len(input.DelegationDSSE) > store.limits.MaxCommandBytes {
		return Deployment{}, false, invalid("deployment input is invalid or exceeds its bound")
	}
	delegation, err := admission.InspectCommandDelegation(input.DelegationDSSE, now)
	if err != nil || delegation.TenantID != input.TenantID || delegation.Admission == nil ||
		delegation.Admission.CapsuleDigest != dsse.Digest(input.CapsuleDSSE) ||
		!hasDeploymentLifecycle(delegation.Operations) {
		return Deployment{}, false, invalid("deployment delegation does not grant the exact lifecycle scope")
	}
	if envelope, err := dsse.Parse(input.CapsuleDSSE); err != nil || envelope.PayloadType != admission.CapsulePayloadType {
		return Deployment{}, false, invalid("deployment capsule envelope is invalid")
	}
	instances := make([]DeploymentInstance, len(delegation.Instances))
	for index, delegated := range delegation.Instances {
		instances[index] = DeploymentInstance{
			InstanceID: delegated.InstanceID, LineageID: delegated.LineageID,
			Generation: delegated.MinInstanceGeneration, Phase: DeploymentInstancePending,
			TransitionedAt: canonicalTimestamp(now),
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Deployment{}, false, err
	}
	tenant, ok := store.current.tenants[input.TenantID]
	if !ok || !tenant.Active {
		return Deployment{}, false, ErrNotFound
	}
	for _, nodeID := range delegation.NodeIDs {
		node, found := store.current.nodes[nodeID]
		if !found || !node.Active || !tenantMember(node.TenantIDs, input.TenantID) {
			return Deployment{}, false, invalid("deployment delegation references an unavailable tenant node")
		}
	}
	key := deploymentKey(input.TenantID, input.ID)
	existing, exists := store.current.deployments[key]
	if exists && deploymentSpecEqual(existing, input) {
		return cloneDeployment(existing), false, nil
	}
	if !exists && input.ExpectedRevision != 0 || exists && input.ExpectedRevision != existing.Revision {
		return Deployment{}, false, ErrConflict
	}
	if exists && input.Generation <= existing.Generation {
		return Deployment{}, false, ErrConflict
	}
	if exists && !deploymentInstancesRollForward(existing.Instances, instances) {
		return Deployment{}, false, ErrConflict
	}
	createdAt := canonicalTimestamp(now)
	revision := uint64(1)
	if exists {
		createdAt = existing.CreatedAt
		if existing.Revision == ^uint64(0) {
			return Deployment{}, false, ErrCapacityExceeded
		}
		revision = existing.Revision + 1
	}
	deployment := Deployment{
		TenantID: input.TenantID, ID: input.ID, Generation: input.Generation, Revision: revision,
		AgentName: input.AgentName, BundleDigest: input.BundleDigest,
		CapsuleDSSE:    append([]byte(nil), input.CapsuleDSSE...),
		DelegationDSSE: append([]byte(nil), input.DelegationDSSE...),
		DesiredState:   DeploymentRunning, Phase: DeploymentPending, Instances: instances,
		CreatedAt: createdAt, UpdatedAt: canonicalTimestamp(now),
	}
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

// SetDeploymentDesiredState marks a deployment for convergence without
// deleting its audit and reconciliation cursor.
func (store *Store) SetDeploymentDesiredState(
	actor controlauth.Identity,
	tenantID, deploymentID string,
	expectedRevision uint64,
	desired DeploymentDesiredState,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Deployment{}, false, ErrNotFound
	}
	if !validRecordID(tenantID, 128) || !validRecordID(deploymentID, 128) || expectedRevision == 0 ||
		now.IsZero() || desired != DeploymentRunning && desired != DeploymentAbsent {
		return Deployment{}, false, invalid("deployment desired-state update is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Deployment{}, false, err
	}
	key := deploymentKey(tenantID, deploymentID)
	deployment, exists := store.current.deployments[key]
	if !exists {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.DesiredState == desired {
		return cloneDeployment(deployment), false, nil
	}
	if deployment.Revision != expectedRevision {
		return Deployment{}, false, ErrConflict
	}
	if deployment.Revision == ^uint64(0) {
		return Deployment{}, false, ErrCapacityExceeded
	}
	deployment.DesiredState = desired
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	if desired == DeploymentAbsent {
		deployment.Phase = DeploymentStopping
	} else {
		deployment.Phase = DeploymentPending
	}
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

func (store *Store) GetDeployment(
	actor controlauth.Identity,
	tenantID, deploymentID string,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Deployment{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) || !validRecordID(deploymentID, 128) {
		return Deployment{}, false, nil
	}
	deployment, found := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	return cloneDeployment(deployment), found, nil
}

func (store *Store) ListDeployments(actor controlauth.Identity, tenantID string) ([]Deployment, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	if tenantID != "" && !controlauth.AuthorizedTenant(actor, tenantID) {
		return nil, ErrNotFound
	}
	result := make([]Deployment, 0)
	for _, deployment := range store.current.deployments {
		if tenantID != "" && deployment.TenantID != tenantID ||
			tenantID == "" && !controlauth.AuthorizedTenant(actor, deployment.TenantID) {
			continue
		}
		result = append(result, cloneDeployment(deployment))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TenantID != result[j].TenantID {
			return result[i].TenantID < result[j].TenantID
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}

func deploymentMutation(deployment Deployment) mutation {
	stored := deploymentToStored(deployment)
	return mutation{Kind: mutationDeployment, Deployment: &stored}
}

func deploymentSpecEqual(existing Deployment, input DeploymentApply) bool {
	return existing.TenantID == input.TenantID && existing.ID == input.ID &&
		existing.Generation == input.Generation && existing.AgentName == input.AgentName &&
		existing.BundleDigest == input.BundleDigest && existing.DesiredState == DeploymentRunning &&
		bytes.Equal(existing.CapsuleDSSE, input.CapsuleDSSE) &&
		bytes.Equal(existing.DelegationDSSE, input.DelegationDSSE)
}

func hasDeploymentLifecycle(operations []string) bool {
	for _, operation := range []string{"admit", "destroy", "start", "stop"} {
		if !slices.Contains(operations, operation) {
			return false
		}
	}
	return true
}

func deploymentInstancesRollForward(previous, next []DeploymentInstance) bool {
	previousByID := make(map[string]DeploymentInstance, len(previous))
	for _, instance := range previous {
		previousByID[instance.InstanceID] = instance
	}
	for _, instance := range next {
		prior, exists := previousByID[instance.InstanceID]
		if exists && (instance.Generation <= prior.Generation || instance.LineageID != prior.LineageID) {
			return false
		}
	}
	return true
}
