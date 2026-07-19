package controlstore

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
)

// DeploymentFleetSnapshot is one immutable controller planning view. Mutations
// still compare the retained deployment revision under the store mutex.
type DeploymentFleetSnapshot struct {
	Deployments []Deployment
	Nodes       []Node
}

type DeploymentCommandTransition struct {
	TenantID         string
	DeploymentID     string
	ExpectedRevision uint64
	InstanceID       string
	CommandDSSE      []byte
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
		cloned := node
		cloned.TenantIDs = append([]string(nil), node.TenantIDs...)
		cloned.Capabilities = append([]string(nil), node.Capabilities...)
		cloned.Evidence = cloneEvidenceWitness(node.Evidence)
		snapshot.Nodes = append(snapshot.Nodes, cloned)
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
	statement, err := admission.VerifyControllerCommand(input.CommandDSSE, deployment.DelegationDSSE, now)
	if err != nil {
		return Deployment{}, Command{}, false, invalidError("verify deployment controller command", err)
	}
	if statement.TenantID != input.TenantID || statement.InstanceID != input.InstanceID {
		return Deployment{}, Command{}, false, invalid("deployment command identity differs from its reconciliation cursor")
	}
	instanceIndex := deploymentInstanceIndex(deployment.Instances, input.InstanceID)
	if instanceIndex < 0 {
		return Deployment{}, Command{}, false, ErrNotFound
	}
	instance := deployment.Instances[instanceIndex]
	if statement.InstanceGeneration != instance.Generation ||
		!deploymentTransitionAllowed(deployment.DesiredState, instance.Phase, statement.Kind) ||
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
	if existing, exists := store.current.commands[commandKeyValue]; exists {
		candidate := Command{
			TenantID: statement.TenantID, NodeID: statement.NodeID,
			ID: statement.CommandID, Digest: digestBytes(input.CommandDSSE), CommandDSSE: input.CommandDSSE,
		}
		if !commandsEqual(existing, candidate) {
			return Deployment{}, Command{}, false, ErrConflict
		}
		if instance.CommandID == existing.ID && instance.CommandOperation == statement.Kind &&
			instance.CommandSequence == statement.CommandSequence && instance.NodeID == statement.NodeID {
			return cloneDeployment(deployment), cloneCommand(existing), false, nil
		}
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
	if deployment.Revision == math.MaxUint64 || instance.Attempts == math.MaxUint32 {
		return Deployment{}, Command{}, false, ErrCapacityExceeded
	}
	instance.NodeID = statement.NodeID
	instance.Phase = deploymentOperationPhase(statement.Kind)
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
	if instance.Phase != deploymentOperationPhase(instance.CommandOperation) {
		return cloneDeployment(deployment), false, nil
	}
	command, exists := store.current.commands[commandKey(tenantID, instance.NodeID, instance.CommandID)]
	if !exists {
		return Deployment{}, false, ErrConflict
	}
	if command.State != CommandTerminal || command.Terminal == nil {
		return cloneDeployment(deployment), false, nil
	}
	if deployment.Revision == math.MaxUint64 {
		return Deployment{}, false, ErrCapacityExceeded
	}
	if command.Terminal.Report.Status == controlprotocol.ExecutorStatusDone {
		instance.Phase = deploymentSuccessfulPhase(instance.CommandOperation)
		instance.LastError = ""
	} else {
		instance.Phase = DeploymentInstanceFailed
		instance.LastError = deploymentCommandError(command)
	}
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

func deploymentTransitionAllowed(desired DeploymentDesiredState, phase DeploymentInstancePhase, operation string) bool {
	if desired == DeploymentRunning {
		return phase == DeploymentInstancePending && operation == "admit" ||
			phase == DeploymentInstanceStarting && operation == "start"
	}
	if desired != DeploymentAbsent {
		return false
	}
	return (phase == DeploymentInstanceRunning || phase == DeploymentInstanceStarting) && operation == "stop" ||
		phase == DeploymentInstanceDestroying && operation == "destroy"
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
		DeploymentBlockedInvalidAuthority:
		return true
	default:
		return false
	}
}
