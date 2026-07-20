package controlstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

// DeploymentFleetSnapshot is one immutable controller planning view. Mutations
// still compare the retained deployment revision under the store mutex.
type DeploymentFleetSnapshot struct {
	Deployments []Deployment
	Nodes       []Node
}

type DeploymentCommandTransition struct {
	TenantID             string
	DeploymentID         string
	ExpectedRevision     uint64
	InstanceID           string
	CommandDSSE          []byte
	SchedulingStaleAfter time.Duration
	Placement            *DeploymentPlacementDecision
}

// DeploymentBlockedReason is a stable, machine-readable explanation for why
// the controller cannot advance one deployment instance. Blocked instances
// remain eligible for reconciliation after the operator fixes the condition.
type DeploymentBlockedReason string

const (
	DeploymentBlockedNoEligibleNode          DeploymentBlockedReason = "no_eligible_node"
	DeploymentBlockedAssignedNodeUnavailable DeploymentBlockedReason = "assigned_node_unavailable"
	DeploymentBlockedDelegationExpired       DeploymentBlockedReason = "delegation_expired"
	DeploymentBlockedControllerKeyMismatch   DeploymentBlockedReason = "controller_key_mismatch"
	DeploymentBlockedInvalidAuthority        DeploymentBlockedReason = "invalid_deployment_authority"
	DeploymentBlockedAwaitingLeaseExpiry     DeploymentBlockedReason = "awaiting_lease_expiry"
	DeploymentBlockedStatefulReplacement     DeploymentBlockedReason = "stateful_replacement_unsupported"
	DeploymentBlockedGenerationExhausted     DeploymentBlockedReason = "replacement_generation_exhausted"
	DeploymentBlockedSchedulingUnavailable   DeploymentBlockedReason = "scheduling_observation_unavailable"
	DeploymentBlockedPlacementConstraints    DeploymentBlockedReason = "placement_constraints_unsatisfied"
	DeploymentBlockedWorkloadLimit           DeploymentBlockedReason = "workload_limit_exceeded"
	DeploymentBlockedNodeCapacity            DeploymentBlockedReason = "node_capacity_exhausted"
	DeploymentBlockedTenantCapacity          DeploymentBlockedReason = "tenant_capacity_exhausted"
	DeploymentBlockedDrainDisruptionBudget   DeploymentBlockedReason = "drain_disruption_budget_exhausted"
	DeploymentBlockedRolloutDisruptionBudget DeploymentBlockedReason = "rollout_disruption_budget_exhausted"
	DeploymentBlockedStatefulDrain           DeploymentBlockedReason = "stateful_drain_unsupported"
	deploymentCommandRecordMissing                                   = "deployment_command_record_missing"
)

// RecordDeploymentBlocked retains a stable reason without changing the
// instance phase. Repeated reconciliation of the same condition is a no-op so
// an unavailable fleet cannot create unbounded WAL churn.
func (store *Store) RecordDeploymentBlocked(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	reason DeploymentBlockedReason,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) ||
		!validDeploymentBlockedReason(reason) {
		return Deployment{}, false, invalid("deployment blocked condition is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, exists := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !exists {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.Revision != expectedRevision {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.Phase == DeploymentInstanceFailed || instance.Phase == DeploymentInstanceRemoved {
		return Deployment{}, false, ErrConflict
	}
	if instance.LastError == string(reason) {
		return cloneDeployment(deployment), false, nil
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.LastError = string(reason)
	instance.TransitionedAt = canonicalTimestamp(now)
	deployment.Instances[index] = instance
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(deploymentMutation(deployment)); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

func (store *Store) SnapshotDeploymentFleet() (DeploymentFleetSnapshot, error) {
	if store == nil {
		return DeploymentFleetSnapshot{}, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return DeploymentFleetSnapshot{}, err
	}
	snapshot := DeploymentFleetSnapshot{
		Deployments: make([]Deployment, 0, len(store.current.deployments)),
		Nodes:       make([]Node, 0, len(store.current.nodes)),
	}
	for _, deployment := range store.current.deployments {
		snapshot.Deployments = append(snapshot.Deployments, cloneDeployment(deployment))
	}
	for _, node := range store.current.nodes {
		snapshot.Nodes = append(snapshot.Nodes, cloneNode(node))
	}
	sort.Slice(snapshot.Deployments, func(i, j int) bool {
		if snapshot.Deployments[i].TenantID != snapshot.Deployments[j].TenantID {
			return snapshot.Deployments[i].TenantID < snapshot.Deployments[j].TenantID
		}
		return snapshot.Deployments[i].ID < snapshot.Deployments[j].ID
	})
	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].ID < snapshot.Nodes[j].ID })
	return snapshot, nil
}

// EnqueueDeploymentCommand atomically advances one reconciliation cursor and
// inserts the exact controller-signed command into the existing courier.
func (store *Store) EnqueueDeploymentCommand(
	input DeploymentCommandTransition,
	now time.Time,
) (Deployment, Command, bool, error) {
	if store == nil {
		return Deployment{}, Command{}, false, ErrUnavailable
	}
	if now.IsZero() || input.ExpectedRevision == 0 ||
		!validRecordID(input.TenantID, 128) || !validRecordID(input.DeploymentID, 128) ||
		!validRecordID(input.InstanceID, 256) || len(input.CommandDSSE) == 0 ||
		len(input.CommandDSSE) > store.limits.MaxCommandBytes {
		return Deployment{}, Command{}, false, invalid("deployment command transition is invalid")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, Command{}, false, err
	}
	key := deploymentKey(input.TenantID, input.DeploymentID)
	deployment, exists := store.current.deployments[key]
	if !exists {
		return Deployment{}, Command{}, false, ErrNotFound
	}
	if deployment.Revision != input.ExpectedRevision {
		return Deployment{}, Command{}, false, ErrConflict
	}
	instanceIndex := deploymentInstanceIndex(deployment.Instances, input.InstanceID)
	if instanceIndex < 0 {
		return Deployment{}, Command{}, false, ErrNotFound
	}
	instance := deployment.Instances[instanceIndex]
	capsuleRaw, delegationRaw, err := DeploymentAuthorityForInstance(deployment, instance)
	if err != nil {
		return Deployment{}, Command{}, false, invalidError("select deployment instance authority", err)
	}
	statement, err := admission.VerifyControllerCommand(input.CommandDSSE, delegationRaw, now)
	if err != nil {
		return Deployment{}, Command{}, false, invalidError("verify deployment controller command", err)
	}
	if statement.TenantID != input.TenantID || statement.InstanceID != input.InstanceID {
		return Deployment{}, Command{}, false, invalid("deployment command identity differs from its reconciliation cursor")
	}
	if statement.Kind != "admit" && input.Placement != nil {
		return Deployment{}, Command{}, false, invalid("only admission may retain a placement decision")
	}
	if statement.InstanceGeneration != instance.Generation ||
		!deploymentTransitionAllowed(deployment.DesiredState, instance, statement.Kind) ||
		instance.NodeID != "" && instance.NodeID != statement.NodeID ||
		statement.CommandSequence <= instance.CommandSequence {
		return Deployment{}, Command{}, false, ErrConflict
	}
	node, found := store.current.nodes[statement.NodeID]
	if !found || !node.Active || !tenantMember(node.TenantIDs, input.TenantID) ||
		!containsCapability(node.Capabilities, controlprotocol.ExecutorCapabilityControllerDelegationV1) {
		return Deployment{}, Command{}, false, ErrNotFound
	}
	binding, err := parseCommandBindingForSubmission(input.CommandDSSE)
	if err != nil {
		return Deployment{}, Command{}, false, invalidError("parse deployment command", err)
	}
	commandKeyValue := commandKey(statement.TenantID, statement.NodeID, statement.CommandID)
	if _, exists := store.current.commands[commandKeyValue]; exists {
		return Deployment{}, Command{}, false, ErrConflict
	}
	command := Command{
		TenantID: statement.TenantID, NodeID: statement.NodeID, ID: statement.CommandID,
		DeliveryID: deliveryID(statement.TenantID, statement.NodeID, statement.CommandID),
		Digest:     digestBytes(input.CommandDSSE), CommandDSSE: append([]byte(nil), input.CommandDSSE...),
		CommandKind: binding.Kind, SignedRuntimeRef: binding.RuntimeRef,
		SignedClaimGeneration: binding.ClaimGeneration, SignedInstanceGeneration: binding.InstanceGeneration,
		State: CommandPending, CreatedAt: canonicalTimestamp(now),
	}
	if _, err := deliveryFor(command, 1); err != nil {
		return Deployment{}, Command{}, false, invalidError("deployment command cannot fit one Executor delivery", err)
	}
	if statement.Kind == "admit" {
		intent, err := deploymentAdmitIntent(statement.Payload, capsuleRaw)
		if err != nil {
			return Deployment{}, Command{}, false, invalidError("decode deployment admission intent", err)
		}
		if input.SchedulingStaleAfter <= 0 || input.SchedulingStaleAfter > MaxOperationsThreshold {
			return Deployment{}, Command{}, false, invalid("deployment scheduling freshness is invalid")
		}
		capsule, err := admission.InspectProfileCapsule(capsuleRaw, time.Time{})
		if err != nil {
			return Deployment{}, Command{}, false, invalidError("inspect deployment capsule for scheduling", err)
		}
		delegation, err := admission.InspectCommandDelegation(delegationRaw, time.Time{})
		if err != nil || delegation.Admission == nil {
			return Deployment{}, Command{}, false, invalid("deployment scheduling authority is invalid")
		}
		deployments := make([]Deployment, 0, len(store.current.deployments))
		for _, retained := range store.current.deployments {
			deployments = append(deployments, retained)
		}
		if err := CheckNodeScheduling(
			node, deployments, input.TenantID, intent, capsule,
			delegation.Admission.Placement, now, input.SchedulingStaleAfter,
		); err != nil {
			return Deployment{}, Command{}, false, err
		}
		if input.Placement != nil {
			placement := cloneDeploymentPlacement(input.Placement)
			if placement.NodeID != statement.NodeID || placement.DecidedAt != canonicalTimestamp(now) {
				return Deployment{}, Command{}, false, invalid("deployment placement decision differs from its admission")
			}
			instance.Placement = placement
		}
		instance.Intent = &intent
		instance.Admission = nil
	}
	if statement.Kind == "renew" {
		lease, err := admission.DecodeWorkloadLease(statement.Payload, time.Time{})
		if err != nil {
			return Deployment{}, Command{}, false, invalidError("decode deployment workload lease", err)
		}
		instance.LeaseExpiresAt = lease.ExpiresAt
	}
	if deployment.Revision == math.MaxUint64 || instance.Attempts == math.MaxUint32 {
		return Deployment{}, Command{}, false, ErrCapacityExceeded
	}
	instance.NodeID = statement.NodeID
	if statement.Kind != "renew" {
		instance.Phase = deploymentOperationPhase(statement.Kind)
	}
	instance.CommandID = statement.CommandID
	instance.CommandOperation = statement.Kind
	instance.CommandSequence = statement.CommandSequence
	instance.Attempts++
	instance.LastError = ""
	instance.TransitionedAt = canonicalTimestamp(now)
	deployment.Instances[instanceIndex] = instance
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	deployment.Phase = deploymentAggregatePhase(deployment)
	if err := store.applyMutationsLocked(deploymentMutation(deployment), commandMutation(command)); err != nil {
		return Deployment{}, Command{}, false, err
	}
	return cloneDeployment(deployment), cloneCommand(command), true, nil
}

// ObserveDeploymentCommand advances only known terminal outcomes. Failed and
// outcome-unknown effects become degraded and are never retried automatically.
func (store *Store) ObserveDeploymentCommand(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) {
		return Deployment{}, false, invalid("deployment command observation is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, exists := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !exists {
		return Deployment{}, false, ErrNotFound
	}
	if deployment.Revision != expectedRevision {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if instance.CommandID == "" || instance.NodeID == "" || instance.CommandOperation == "" {
		return cloneDeployment(deployment), false, nil
	}
	if !deploymentCommandInFlight(instance) {
		return cloneDeployment(deployment), false, nil
	}
	command, exists := store.current.commands[commandKey(tenantID, instance.NodeID, instance.CommandID)]
	if !exists {
		if deployment.Revision == math.MaxUint64 {
			return Deployment{}, false, ErrCapacityExceeded
		}
		instance.Phase = DeploymentInstanceFailed
		instance.LastError = deploymentCommandRecordMissing
		failedDrainNode := store.failDeploymentInstanceDrainLocked(&instance, now)
		instance.TransitionedAt = canonicalTimestamp(now)
		deployment.Instances[index] = instance
		deployment.Revision++
		deployment.UpdatedAt = canonicalTimestamp(now)
		deployment.Phase = deploymentAggregatePhase(deployment)
		mutations := []mutation{deploymentMutation(deployment)}
		if failedDrainNode != nil {
			mutations = append(mutations, mutation{Kind: mutationNode, Node: failedDrainNode})
		}
		if err := store.applyMutationsLocked(mutations...); err != nil {
			return Deployment{}, false, err
		}
		return cloneDeployment(deployment), true, nil
	}
	if command.State != CommandTerminal || command.Terminal == nil {
		return cloneDeployment(deployment), false, nil
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	if command.Terminal.Report.Status == controlprotocol.ExecutorStatusDone {
		if instance.CommandOperation != "renew" {
			instance.Phase = deploymentSuccessfulPhase(instance.CommandOperation)
		}
		instance.LastError = ""
		if instance.CommandOperation == "admit" {
			if instance.Intent == nil {
				// An admit enqueued by a pre-projection controller has no intent to
				// authenticate the projection against. Preserve its legacy lifecycle
				// result, but do not make it task-ready by retaining unverified data.
				instance.Admission = nil
			} else if command.Terminal.Admission == nil {
				instance.Phase = DeploymentInstanceFailed
				instance.LastError = "admission_projection_missing"
			} else {
				instance.Admission = cloneAdmissionProjection(command.Terminal.Admission)
			}
		}
		if instance.CommandOperation == "start" && instance.Drain != nil &&
			instance.NodeID != instance.Drain.SourceNodeID {
			instance.Drain = nil
		}
		if instance.CommandOperation == "start" && instance.Rollout != nil &&
			instance.Rollout.Stage == "deploying" {
			instance.Rollout = nil
		}
		if instance.CommandOperation == "destroy" && deployment.DesiredState == DeploymentAbsent {
			instance.Drain = nil
		}
	} else {
		instance.Phase = DeploymentInstanceFailed
		instance.LastError = deploymentCommandError(command)
	}
	failedDrainNode := (*Node)(nil)
	if instance.Phase == DeploymentInstanceFailed {
		failedDrainNode = store.failDeploymentInstanceDrainLocked(&instance, now)
	}
	if instance.CommandOperation == "renew" && instance.Phase != DeploymentInstanceFailed {
		instance.CommandID = ""
		instance.CommandOperation = ""
	}
	instance.TransitionedAt = canonicalTimestamp(now)
	deployment.Instances[index] = instance
	if deployment.Rollout != nil && deploymentRolloutComplete(deployment) {
		deployment.Rollout = nil
	}
	deployment.Revision++
	deployment.UpdatedAt = canonicalTimestamp(now)
	deployment.Phase = deploymentAggregatePhase(deployment)
	mutations := []mutation{deploymentMutation(deployment)}
	if failedDrainNode != nil {
		mutations = append(mutations, mutation{Kind: mutationNode, Node: failedDrainNode})
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

func deploymentRolloutComplete(deployment Deployment) bool {
	if deployment.Rollout == nil {
		return false
	}
	target, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil || len(target.Instances) != len(deployment.Instances) {
		return false
	}
	for _, instance := range deployment.Instances {
		delegated, found := deploymentDelegatedInstance(target.Instances, instance.InstanceID)
		if !found || instance.Generation < delegated.MinInstanceGeneration ||
			instance.Generation > delegated.MaxInstanceGeneration || instance.Phase != DeploymentInstanceRunning ||
			instance.Rollout != nil {
			return false
		}
	}
	return true
}

func deploymentAdmitIntent(raw json.RawMessage, capsule []byte) (admission.InstanceIntent, error) {
	var payload struct {
		Capsule string                   `json:"capsule_dsse_base64"`
		Intent  admission.InstanceIntent `json:"intent"`
	}
	if err := dsse.DecodeStrictInto(raw, len(raw), &payload); err != nil {
		return admission.InstanceIntent{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(payload.Capsule)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != payload.Capsule || !bytes.Equal(decoded, capsule) {
		return admission.InstanceIntent{}, errors.New("admission capsule does not match deployment")
	}
	if err := payload.Intent.Validate(admission.AuthenticatedIdentity{
		TenantID: payload.Intent.TenantID,
		NodeID:   payload.Intent.NodeID,
	}); err != nil {
		return admission.InstanceIntent{}, err
	}
	return payload.Intent, nil
}

// RemovePendingDeploymentInstance completes an absent instance that never
// reached admission, so no node effect or destroy command is necessary.
func (store *Store) RemovePendingDeploymentInstance(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, exists := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !exists {
		return Deployment{}, false, ErrNotFound
	}
	if now.IsZero() || expectedRevision == 0 || deployment.Revision != expectedRevision {
		return Deployment{}, false, ErrConflict
	}
	index := deploymentInstanceIndex(deployment.Instances, instanceID)
	if index < 0 {
		return Deployment{}, false, ErrNotFound
	}
	instance := deployment.Instances[index]
	if deployment.DesiredState != DeploymentAbsent || instance.Phase != DeploymentInstancePending ||
		instance.CommandID != "" || instance.NodeID != "" {
		return Deployment{}, false, ErrConflict
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	instance.Phase = DeploymentInstanceRemoved
	instance.Drain = nil
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

// ReplaceDeploymentInstance advances a stateless instance only after the last
// lease that the old node could have accepted is outside its clock-skew safety
// window. The tenant-signed delegation remains the generation and node ceiling.
func (store *Store) ReplaceDeploymentInstance(
	tenantID, deploymentID, instanceID string,
	expectedRevision uint64,
	now time.Time,
) (Deployment, bool, error) {
	if store == nil {
		return Deployment{}, false, ErrUnavailable
	}
	if now.IsZero() || expectedRevision == 0 || !validRecordID(tenantID, 128) ||
		!validRecordID(deploymentID, 128) || !validRecordID(instanceID, 256) {
		return Deployment{}, false, invalid("deployment replacement input is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Deployment{}, false, err
	}
	deployment, exists := store.current.deployments[deploymentKey(tenantID, deploymentID)]
	if !exists {
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
	if instance.NodeID == "" || instance.LeaseExpiresAt == "" ||
		instance.Phase != DeploymentInstanceStarting && instance.Phase != DeploymentInstanceRunning {
		return Deployment{}, false, ErrConflict
	}
	leaseExpiry, err := time.Parse(time.RFC3339Nano, instance.LeaseExpiresAt)
	if err != nil || now.Before(leaseExpiry.Add(admission.CommandClockSkew)) {
		return Deployment{}, false, ErrConflict
	}
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil || delegation.Admission == nil || delegation.Admission.Capabilities.State {
		return Deployment{}, false, ErrConflict
	}
	delegationExpiry, err := time.Parse(time.RFC3339Nano, delegation.ExpiresAt)
	renewIndex := sort.SearchStrings(delegation.Operations, "renew")
	if err != nil || !delegationExpiry.After(now) || renewIndex >= len(delegation.Operations) ||
		delegation.Operations[renewIndex] != "renew" {
		return Deployment{}, false, ErrConflict
	}
	delegated, found := deploymentDelegatedInstance(delegation.Instances, instance.InstanceID)
	if !found || instance.Generation == math.MaxUint64 || instance.Generation+1 > delegated.MaxInstanceGeneration {
		return Deployment{}, false, ErrCapacityExceeded
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	var abandoned *commandReference
	if instance.CommandID != "" {
		key := commandKey(tenantID, instance.NodeID, instance.CommandID)
		if _, exists := store.current.commands[key]; exists {
			abandoned = &commandReference{
				TenantID: tenantID,
				NodeID:   instance.NodeID,
				ID:       instance.CommandID,
			}
		}
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
	mutations := []mutation{deploymentMutation(deployment)}
	if abandoned != nil {
		mutations = append(mutations, mutation{Kind: mutationCommandDelete, CommandRef: abandoned})
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return Deployment{}, false, err
	}
	return cloneDeployment(deployment), true, nil
}

func deploymentDelegatedInstance(
	instances []admission.CommandDelegationInstance,
	instanceID string,
) (admission.CommandDelegationInstance, bool) {
	index := sort.Search(len(instances), func(index int) bool {
		return instances[index].InstanceID >= instanceID
	})
	if index >= len(instances) || instances[index].InstanceID != instanceID {
		return admission.CommandDelegationInstance{}, false
	}
	return instances[index], true
}

func deploymentTransitionAllowed(desired DeploymentDesiredState, instance DeploymentInstance, operation string) bool {
	phase := instance.Phase
	if desired == DeploymentRunning && instance.Rollout != nil && instance.Rollout.Stage == "draining" {
		return (phase == DeploymentInstanceRunning || phase == DeploymentInstanceStarting) && operation == "stop" ||
			phase == DeploymentInstanceDestroying && operation == "destroy"
	}
	if desired == DeploymentRunning && instance.Drain != nil &&
		instance.NodeID == instance.Drain.SourceNodeID {
		return (phase == DeploymentInstanceRunning || phase == DeploymentInstanceStarting) && operation == "stop" ||
			phase == DeploymentInstanceDestroying && operation == "destroy"
	}
	if desired == DeploymentRunning {
		return phase == DeploymentInstancePending && operation == "admit" ||
			phase == DeploymentInstanceStarting && (operation == "renew" || operation == "start") ||
			phase == DeploymentInstanceRunning && operation == "renew"
	}
	if desired != DeploymentAbsent {
		return false
	}
	return (phase == DeploymentInstanceRunning || phase == DeploymentInstanceStarting) && operation == "stop" ||
		phase == DeploymentInstanceDestroying && operation == "destroy"
}

func deploymentCommandInFlight(instance DeploymentInstance) bool {
	if instance.CommandID == "" || instance.CommandOperation == "" {
		return false
	}
	if instance.CommandOperation == "renew" {
		return instance.Phase == DeploymentInstanceStarting || instance.Phase == DeploymentInstanceRunning
	}
	return instance.Phase == deploymentOperationPhase(instance.CommandOperation)
}

func deploymentOperationPhase(operation string) DeploymentInstancePhase {
	switch operation {
	case "admit":
		return DeploymentInstanceAdmitting
	case "start":
		return DeploymentInstanceStarting
	case "stop":
		return DeploymentInstanceStopping
	case "destroy":
		return DeploymentInstanceDestroying
	default:
		return DeploymentInstanceFailed
	}
}

func deploymentSuccessfulPhase(operation string) DeploymentInstancePhase {
	switch operation {
	case "admit":
		return DeploymentInstanceStarting
	case "start":
		return DeploymentInstanceRunning
	case "stop":
		return DeploymentInstanceDestroying
	case "destroy":
		return DeploymentInstanceRemoved
	default:
		return DeploymentInstanceFailed
	}
}

func deploymentAggregatePhase(deployment Deployment) DeploymentPhase {
	failed, running, removed := false, 0, 0
	for _, instance := range deployment.Instances {
		switch instance.Phase {
		case DeploymentInstanceFailed:
			failed = true
		case DeploymentInstanceRunning:
			running++
		case DeploymentInstanceRemoved:
			removed++
		}
	}
	if failed {
		return DeploymentDegraded
	}
	if deployment.DesiredState == DeploymentRunning {
		if running == len(deployment.Instances) {
			if deployment.Rollout != nil {
				return DeploymentReconciling
			}
			return DeploymentReady
		}
		return DeploymentReconciling
	}
	if removed == len(deployment.Instances) {
		return DeploymentRemoved
	}
	return DeploymentStopping
}

func deploymentInstanceIndex(instances []DeploymentInstance, instanceID string) int {
	index := sort.Search(len(instances), func(index int) bool { return instances[index].InstanceID >= instanceID })
	if index >= len(instances) || instances[index].InstanceID != instanceID {
		return -1
	}
	return index
}

func containsCapability(capabilities []string, wanted string) bool {
	index := sort.SearchStrings(capabilities, wanted)
	return index < len(capabilities) && capabilities[index] == wanted
}

func deploymentCommandError(command Command) string {
	message := string(command.Terminal.Report.Status)
	if command.Terminal.Report.ErrorCode != "" {
		message += ": " + command.Terminal.Report.ErrorCode
	}
	if detail := strings.TrimSpace(command.Terminal.Report.Result.Error); detail != "" {
		message += ": " + detail
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

func validDeploymentBlockedReason(reason DeploymentBlockedReason) bool {
	switch reason {
	case DeploymentBlockedNoEligibleNode, DeploymentBlockedAssignedNodeUnavailable,
		DeploymentBlockedDelegationExpired, DeploymentBlockedControllerKeyMismatch,
		DeploymentBlockedInvalidAuthority, DeploymentBlockedAwaitingLeaseExpiry,
		DeploymentBlockedStatefulReplacement, DeploymentBlockedGenerationExhausted,
		DeploymentBlockedSchedulingUnavailable, DeploymentBlockedPlacementConstraints,
		DeploymentBlockedWorkloadLimit, DeploymentBlockedNodeCapacity, DeploymentBlockedTenantCapacity,
		DeploymentBlockedDrainDisruptionBudget, DeploymentBlockedRolloutDisruptionBudget,
		DeploymentBlockedStatefulDrain:
		return true
	default:
		return false
	}
}
