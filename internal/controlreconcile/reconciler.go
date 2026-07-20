// Package controlreconcile converges durable desired deployments through the
// existing signed command courier. It never calls Executor or Docker directly.
package controlreconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

const (
	minInterval              = time.Second
	maxInterval              = time.Hour
	commandLifetime          = 14 * time.Minute
	workloadLeaseDuration    = admission.MaxWorkloadLeaseDuration
	workloadLeaseRenewBefore = 2 * time.Minute
	maxActionsPerPass        = 128
)

type Config struct {
	Store          *controlstore.Store
	KeyID          string
	PrivateKey     ed25519.PrivateKey
	Interval       time.Duration
	NodeStaleAfter time.Duration
	Now            func() time.Time
	Logger         *slog.Logger
}

type Reconciler struct {
	store          *controlstore.Store
	keyID          string
	privateKey     ed25519.PrivateKey
	interval       time.Duration
	nodeStaleAfter time.Duration
	now            func() time.Time
	logger         *slog.Logger
}

type Report struct {
	Deployments     int `json:"deployments"`
	Instances       int `json:"instances"`
	Observed        int `json:"observed"`
	Enqueued        int `json:"enqueued"`
	Removed         int `json:"removed"`
	Replaced        int `json:"replaced"`
	Conflicts       int `json:"conflicts"`
	Blocked         int `json:"blocked"`
	Draining        int `json:"draining"`
	DrainsCompleted int `json:"drains_completed"`
	DrainsFailed    int `json:"drains_failed"`
}

type instanceResult struct {
	changed       bool
	kind          string
	blockedReason controlstore.DeploymentBlockedReason
	conflict      bool
}

func New(config Config) (*Reconciler, error) {
	if config.Store == nil || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		!validKeyID(config.KeyID) || config.Interval < minInterval || config.Interval > maxInterval ||
		config.NodeStaleAfter <= 0 || config.NodeStaleAfter > controlstore.MaxOperationsThreshold {
		return nil, errors.New("controller reconciler requires a store, bounded key ID, Ed25519 private key, interval from 1 second through 1 hour, and node freshness from 1 nanosecond through 365 days")
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{
		store: config.Store, keyID: config.KeyID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...),
		interval:   config.Interval, nodeStaleAfter: config.NodeStaleAfter,
		now: now, logger: logger,
	}, nil
}

func (reconciler *Reconciler) Run(ctx context.Context) error {
	if reconciler == nil || ctx == nil {
		return errors.New("controller reconciler requires a context")
	}
	if _, err := reconciler.Reconcile(ctx); err != nil {
		reconciler.logger.Error("initial desired-state reconciliation failed", "error", err)
	}
	ticker := time.NewTicker(reconciler.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			report, err := reconciler.Reconcile(ctx)
			if err != nil {
				reconciler.logger.Error("desired-state reconciliation failed", "error", err)
				continue
			}
			if report.Enqueued > 0 || report.Observed > 0 || report.Removed > 0 || report.Replaced > 0 ||
				report.Blocked > 0 || report.Draining > 0 || report.DrainsCompleted > 0 || report.DrainsFailed > 0 {
				reconciler.logger.Info("desired-state reconciliation completed",
					"deployments", report.Deployments, "instances", report.Instances,
					"observed", report.Observed, "enqueued", report.Enqueued,
					"removed", report.Removed, "replaced", report.Replaced,
					"conflicts", report.Conflicts, "blocked", report.Blocked,
					"draining", report.Draining, "drains_completed", report.DrainsCompleted,
					"drains_failed", report.DrainsFailed)
			}
		}
	}
}

func (reconciler *Reconciler) Reconcile(ctx context.Context) (Report, error) {
	if reconciler == nil || ctx == nil {
		return Report{}, errors.New("controller reconciler requires a context")
	}
	snapshot, err := reconciler.store.SnapshotDeploymentFleet()
	if err != nil {
		return Report{}, err
	}
	report := Report{Deployments: len(snapshot.Deployments)}
	placements := placementCounts(snapshot.Deployments)
	actions := 0
	for _, deployment := range snapshot.Deployments {
		for _, instance := range deployment.Instances {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			report.Instances++
			if actions >= maxActionsPerPass {
				return report, nil
			}
			result, err := reconciler.reconcileInstance(
				snapshot.Nodes, snapshot.Deployments, placements, deployment, instance,
			)
			if err != nil {
				return report, err
			}
			if result.conflict {
				report.Conflicts++
				break
			}
			if result.blockedReason != "" {
				report.Blocked++
				reconciler.logger.Warn("deployment instance is blocked",
					"tenant_id", deployment.TenantID, "deployment_id", deployment.ID,
					"instance_id", instance.InstanceID, "reason", result.blockedReason)
			}
			if !result.changed {
				continue
			}
			actions++
			switch result.kind {
			case "observed":
				report.Observed++
			case "enqueued":
				report.Enqueued++
			case "removed":
				report.Removed++
			case "replaced":
				report.Replaced++
			case "draining":
				report.Draining++
			}
			break
		}
	}
	completed, failed, err := reconciler.store.CompleteFinishedNodeDrains(reconciler.now().UTC())
	if err != nil {
		return report, err
	}
	report.DrainsCompleted = completed
	report.DrainsFailed = failed
	return report, nil
}

func (reconciler *Reconciler) reconcileInstance(
	nodes []controlstore.Node,
	deployments []controlstore.Deployment,
	placements map[string]int,
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
) (instanceResult, error) {
	now := reconciler.now().UTC()
	if now.IsZero() {
		return instanceResult{}, errors.New("controller clock is invalid")
	}
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedInvalidAuthority), now)
	}
	if instance.Phase == controlstore.DeploymentInstanceFailed ||
		instance.Phase == controlstore.DeploymentInstanceRemoved && instance.Drain == nil {
		return instanceResult{}, nil
	}
	if deployment.DesiredState == controlstore.DeploymentRunning &&
		instance.Phase == controlstore.DeploymentInstanceRemoved && instance.Drain != nil {
		_, changed, err := reconciler.store.ReplaceDrainedDeploymentInstance(
			deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
		)
		if errors.Is(err, controlstore.ErrConflict) {
			return instanceResult{conflict: true}, nil
		}
		if errors.Is(err, controlstore.ErrCapacityExceeded) {
			return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedGenerationExhausted), now)
		}
		return instanceResult{changed: changed, kind: "replaced"}, err
	}
	leaseManaged := containsOperation(delegation.Operations, "renew")
	if instance.NodeID != "" && deployment.DesiredState == controlstore.DeploymentRunning &&
		!assignedNodeEligible(nodes, deployment, instance, delegation, now, reconciler.nodeStaleAfter) {
		return reconciler.recoverUnavailableInstance(deployment, instance, delegation, leaseManaged, now)
	}
	if commandInFlight(instance) {
		_, changed, err := reconciler.store.ObserveDeploymentCommand(
			deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
		)
		if errors.Is(err, controlstore.ErrConflict) {
			return instanceResult{conflict: true}, nil
		}
		return instanceResult{changed: changed, kind: "observed"}, err
	}
	if deployment.DesiredState == controlstore.DeploymentRunning && instance.Drain == nil &&
		instance.Phase == controlstore.DeploymentInstanceRunning {
		if drain, found := activeNodeDrain(nodes, instance.NodeID); found {
			candidate := instance
			candidate.NodeID = ""
			if _, _, err := selectNode(
				nodes, deployments, placements, deployment, candidate, now, reconciler.nodeStaleAfter,
			); err != nil {
				return reconciler.recordBlocked(deployment, instance, err, now)
			}
			_, changed, err := reconciler.store.BeginDeploymentInstanceDrain(
				deployment.TenantID, deployment.ID, instance.InstanceID, instance.NodeID,
				drain.RequestID, deployment.Revision, now,
			)
			if errors.Is(err, controlstore.ErrConflict) {
				return instanceResult{conflict: true}, nil
			}
			switch {
			case errors.Is(err, controlstore.ErrDisruptionBudget):
				return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedDrainDisruptionBudget), now)
			case errors.Is(err, controlstore.ErrStatefulDrain):
				return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedStatefulDrain), now)
			case errors.Is(err, controlstore.ErrCapacityExceeded):
				return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedGenerationExhausted), now)
			}
			return instanceResult{changed: changed, kind: "draining"}, err
		}
	}
	if deployment.DesiredState == controlstore.DeploymentRunning && instance.Drain == nil &&
		instance.Phase == controlstore.DeploymentInstanceRunning &&
		(!leaseManaged || !workloadLeaseNeedsRenewal(instance, now)) {
		return instanceResult{}, nil
	}
	if deployment.DesiredState == controlstore.DeploymentAbsent &&
		instance.Phase == controlstore.DeploymentInstancePending && instance.CommandID == "" && instance.NodeID == "" {
		_, changed, err := reconciler.store.RemovePendingDeploymentInstance(
			deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
		)
		if errors.Is(err, controlstore.ErrConflict) {
			return instanceResult{conflict: true}, nil
		}
		return instanceResult{changed: changed, kind: "removed"}, err
	}
	operation := nextOperation(deployment.DesiredState, instance, leaseManaged, now)
	if operation == "" {
		return instanceResult{}, nil
	}
	nodeID, placement, err := selectNode(
		nodes, deployments, placements, deployment, instance, now, reconciler.nodeStaleAfter,
	)
	if err != nil {
		return reconciler.recordBlocked(deployment, instance, err, now)
	}
	commandRaw, err := reconciler.signCommand(deployment, instance, nodeID, operation, now)
	if err != nil {
		var blocked blockedError
		if errors.As(err, &blocked) {
			return reconciler.recordBlocked(deployment, instance, err, now)
		}
		return instanceResult{}, err
	}
	_, _, changed, err := reconciler.store.EnqueueDeploymentCommand(controlstore.DeploymentCommandTransition{
		TenantID: deployment.TenantID, DeploymentID: deployment.ID,
		ExpectedRevision: deployment.Revision, InstanceID: instance.InstanceID,
		CommandDSSE: commandRaw, SchedulingStaleAfter: reconciler.nodeStaleAfter,
		Placement: placement,
	}, now)
	if errors.Is(err, controlstore.ErrConflict) {
		return instanceResult{conflict: true}, nil
	}
	if reason := schedulingBlockedReason(err); reason != "" {
		return reconciler.recordBlocked(deployment, instance, newBlocked(reason), now)
	}
	if changed && instance.NodeID == "" {
		placements[nodeID]++
	}
	return instanceResult{changed: changed, kind: "enqueued"}, err
}

func (reconciler *Reconciler) recoverUnavailableInstance(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	delegation admission.CommandDelegation,
	leaseManaged bool,
	now time.Time,
) (instanceResult, error) {
	if !leaseManaged || instance.LeaseExpiresAt == "" {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedAssignedNodeUnavailable), now)
	}
	delegationExpiry, err := time.Parse(time.RFC3339Nano, delegation.ExpiresAt)
	if err != nil {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedInvalidAuthority), now)
	}
	if !delegationExpiry.After(now) {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedDelegationExpired), now)
	}
	leaseExpiry, err := time.Parse(time.RFC3339Nano, instance.LeaseExpiresAt)
	if err != nil {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedInvalidAuthority), now)
	}
	if now.Before(leaseExpiry.Add(admission.CommandClockSkew)) {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedAwaitingLeaseExpiry), now)
	}
	if delegation.Admission == nil {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedInvalidAuthority), now)
	}
	if delegation.Admission.Capabilities.State {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedStatefulReplacement), now)
	}
	delegated, found := delegatedInstance(delegation, instance.InstanceID)
	if !found || instance.Generation == ^uint64(0) || instance.Generation+1 > delegated.MaxInstanceGeneration {
		return reconciler.recordBlocked(deployment, instance, newBlocked(controlstore.DeploymentBlockedGenerationExhausted), now)
	}
	_, changed, err := reconciler.store.ReplaceDeploymentInstance(
		deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
	)
	if errors.Is(err, controlstore.ErrConflict) {
		return instanceResult{conflict: true}, nil
	}
	return instanceResult{changed: changed, kind: "replaced"}, err
}

func (reconciler *Reconciler) recordBlocked(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	cause error,
	now time.Time,
) (instanceResult, error) {
	var blocked blockedError
	if !errors.As(cause, &blocked) {
		return instanceResult{}, cause
	}
	_, changed, err := reconciler.store.RecordDeploymentBlocked(
		deployment.TenantID, deployment.ID, instance.InstanceID,
		deployment.Revision, blocked.reason, now,
	)
	if errors.Is(err, controlstore.ErrConflict) {
		return instanceResult{conflict: true}, nil
	}
	return instanceResult{changed: changed, blockedReason: blocked.reason}, err
}

func (reconciler *Reconciler) signCommand(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	nodeID, operation string,
	now time.Time,
) ([]byte, error) {
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		return nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	delegationExpiry, err := time.Parse(time.RFC3339Nano, delegation.ExpiresAt)
	if err != nil {
		return nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	if !delegationExpiry.After(now) {
		return nil, newBlocked(controlstore.DeploymentBlockedDelegationExpired)
	}
	if delegation.ControllerKeyID != reconciler.keyID {
		return nil, newBlocked(controlstore.DeploymentBlockedControllerKeyMismatch)
	}
	public, err := base64.StdEncoding.DecodeString(delegation.ControllerPublicKey)
	if err != nil || !bytes.Equal(public, reconciler.privateKey.Public().(ed25519.PublicKey)) {
		return nil, newBlocked(controlstore.DeploymentBlockedControllerKeyMismatch)
	}
	runtimeRef, err := executoruplink.RuntimeRefV2(deployment.TenantID, nodeID, instance.InstanceID)
	if err != nil {
		return nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	sequence := instance.CommandSequence + 1
	if sequence == 0 {
		return nil, controlstore.ErrCapacityExceeded
	}
	expires := now.Add(commandLifetime)
	if delegationExpiry.Before(expires) {
		expires = delegationExpiry
	}
	payload := []byte(`{}`)
	if operation == "admit" {
		delegated, found := delegatedInstance(delegation, instance.InstanceID)
		if !found || delegation.Admission == nil {
			return nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
		}
		intent := intentFromDelegation(deployment, instance, nodeID, delegated, *delegation.Admission)
		payload, err = json.Marshal(struct {
			Capsule string                   `json:"capsule_dsse_base64"`
			Intent  admission.InstanceIntent `json:"intent"`
		}{Capsule: base64.StdEncoding.EncodeToString(deployment.CapsuleDSSE), Intent: intent})
		if err != nil {
			return nil, err
		}
	}
	if operation == "renew" {
		leaseExpiry := now.Add(workloadLeaseDuration)
		if expires.Before(leaseExpiry) {
			leaseExpiry = expires
		}
		payload, err = json.Marshal(admission.WorkloadLease{
			SchemaVersion: admission.WorkloadLeaseSchemaV1,
			ExpiresAt:     leaseExpiry.Format(time.RFC3339Nano),
		})
		if err != nil {
			return nil, err
		}
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2,
		CommandID:     deploymentCommandID(deployment, instance, operation, sequence),
		TenantID:      deployment.TenantID, NodeID: nodeID, InstanceID: instance.InstanceID,
		RuntimeRef: runtimeRef, Kind: operation,
		ClaimGeneration: delegation.ClaimGeneration, InstanceGeneration: instance.Generation,
		CommandSequence: sequence, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano),
		AuthorizationContextDigest: dsse.Digest(deployment.DelegationDSSE),
		DelegationDSSEBase64:       base64.StdEncoding.EncodeToString(deployment.DelegationDSSE),
		Payload:                    payload,
	}
	if err := statement.Validate(now); err != nil {
		return nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, statementRaw, reconciler.keyID, reconciler.privateKey)
	if err != nil {
		return nil, err
	}
	return dsse.Marshal(envelope)
}

func nextOperation(
	desired controlstore.DeploymentDesiredState,
	instance controlstore.DeploymentInstance,
	leaseManaged bool,
	now time.Time,
) string {
	if desired == controlstore.DeploymentRunning && instance.Drain != nil &&
		instance.NodeID == instance.Drain.SourceNodeID {
		switch instance.Phase {
		case controlstore.DeploymentInstanceRunning, controlstore.DeploymentInstanceStarting:
			return "stop"
		case controlstore.DeploymentInstanceDestroying:
			return "destroy"
		default:
			return ""
		}
	}
	if desired == controlstore.DeploymentRunning {
		switch instance.Phase {
		case controlstore.DeploymentInstancePending:
			return "admit"
		case controlstore.DeploymentInstanceStarting:
			if leaseManaged && workloadLeaseNeedsRenewal(instance, now) {
				return "renew"
			}
			return "start"
		case controlstore.DeploymentInstanceRunning:
			if leaseManaged && workloadLeaseNeedsRenewal(instance, now) {
				return "renew"
			}
		}
		return ""
	}
	switch instance.Phase {
	case controlstore.DeploymentInstanceRunning, controlstore.DeploymentInstanceStarting:
		return "stop"
	case controlstore.DeploymentInstanceDestroying:
		return "destroy"
	default:
		return ""
	}
}

func activeNodeDrain(nodes []controlstore.Node, nodeID string) (controlstore.NodeDrain, bool) {
	for _, node := range nodes {
		if node.ID == nodeID && node.Drain != nil && node.Drain.State == controlstore.NodeDrainActive {
			return *node.Drain, true
		}
	}
	return controlstore.NodeDrain{}, false
}

func commandInFlight(instance controlstore.DeploymentInstance) bool {
	switch instance.CommandOperation {
	case "admit":
		return instance.Phase == controlstore.DeploymentInstanceAdmitting
	case "start":
		return instance.Phase == controlstore.DeploymentInstanceStarting
	case "renew":
		return instance.Phase == controlstore.DeploymentInstanceStarting ||
			instance.Phase == controlstore.DeploymentInstanceRunning
	case "stop":
		return instance.Phase == controlstore.DeploymentInstanceStopping
	case "destroy":
		return instance.Phase == controlstore.DeploymentInstanceDestroying
	default:
		return false
	}
}

func workloadLeaseNeedsRenewal(instance controlstore.DeploymentInstance, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339Nano, instance.LeaseExpiresAt)
	return err != nil || !now.Before(expires.Add(-workloadLeaseRenewBefore))
}

func containsOperation(operations []string, wanted string) bool {
	index := sort.SearchStrings(operations, wanted)
	return index < len(operations) && operations[index] == wanted
}

func assignedNodeEligible(
	nodes []controlstore.Node,
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	delegation admission.CommandDelegation,
	now time.Time,
	staleAfter time.Duration,
) bool {
	allowed := make(map[string]struct{}, len(delegation.NodeIDs))
	for _, nodeID := range delegation.NodeIDs {
		allowed[nodeID] = struct{}{}
	}
	for _, node := range nodes {
		if node.ID == instance.NodeID {
			return nodeAvailableForAssignment(node, deployment.TenantID, allowed, now, staleAfter)
		}
	}
	return false
}

func selectNode(
	nodes []controlstore.Node,
	deployments []controlstore.Deployment,
	placements map[string]int,
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	now time.Time,
	nodeStaleAfter time.Duration,
) (string, *controlstore.DeploymentPlacementDecision, error) {
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		return "", nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	allowed := make(map[string]struct{}, len(delegation.NodeIDs))
	for _, nodeID := range delegation.NodeIDs {
		allowed[nodeID] = struct{}{}
	}
	if instance.NodeID != "" {
		for _, node := range nodes {
			if node.ID == instance.NodeID && nodeAvailableForAssignment(node, deployment.TenantID, allowed, now, nodeStaleAfter) {
				return node.ID, nil, nil
			}
		}
		return "", nil, newBlocked(controlstore.DeploymentBlockedAssignedNodeUnavailable)
	}
	if delegation.Admission == nil {
		return "", nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	capsule, err := admission.InspectProfileCapsule(deployment.CapsuleDSSE, time.Time{})
	if err != nil {
		return "", nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	delegated, found := delegatedInstance(delegation, instance.InstanceID)
	if !found {
		return "", nil, newBlocked(controlstore.DeploymentBlockedInvalidAuthority)
	}
	var selected *placementCandidate
	spreadCounts := deploymentSpreadCounts(nodes, deployment, delegation.Admission.Placement)
	var schedulingUnavailable, placementBlocked, workloadLimit, nodeCapacity, tenantCapacity bool
	for _, node := range nodes {
		if !eligibleNode(node, deployment.TenantID, allowed, now, nodeStaleAfter) {
			continue
		}
		intent := intentFromDelegation(deployment, instance, node.ID, delegated, *delegation.Admission)
		if err := controlstore.CheckNodeScheduling(
			node, deployments, deployment.TenantID, intent, capsule,
			delegation.Admission.Placement, now, nodeStaleAfter,
		); err != nil {
			switch {
			case errors.Is(err, controlstore.ErrNodeSchedulingUnavailable):
				schedulingUnavailable = true
			case errors.Is(err, controlstore.ErrNodePlacementUnavailable):
				placementBlocked = true
			case errors.Is(err, controlstore.ErrNodeSchedulingConstraint):
				placementBlocked = true
			case errors.Is(err, controlstore.ErrTenantCapacityExceeded):
				tenantCapacity = true
			case errors.Is(err, controlstore.ErrWorkloadLimitExceeded):
				workloadLimit = true
			case errors.Is(err, controlstore.ErrNodeCapacityExceeded):
				nodeCapacity = true
			}
			continue
		}
		candidate := rankPlacementCandidate(node, placements[node.ID], delegation.Admission.Placement, spreadCounts)
		if selected == nil || candidate.betterThan(*selected) {
			selected = &candidate
		}
	}
	if selected == nil {
		switch {
		case tenantCapacity:
			return "", nil, newBlocked(controlstore.DeploymentBlockedTenantCapacity)
		case workloadLimit:
			return "", nil, newBlocked(controlstore.DeploymentBlockedWorkloadLimit)
		case nodeCapacity:
			return "", nil, newBlocked(controlstore.DeploymentBlockedNodeCapacity)
		case schedulingUnavailable:
			return "", nil, newBlocked(controlstore.DeploymentBlockedSchedulingUnavailable)
		case placementBlocked:
			return "", nil, newBlocked(controlstore.DeploymentBlockedPlacementConstraints)
		}
		return "", nil, newBlocked(controlstore.DeploymentBlockedNoEligibleNode)
	}
	decision := selected.decision(now)
	return selected.nodeID, &decision, nil
}

type placementCandidate struct {
	nodeID             string
	assignedWorkloads  int
	preferredMatches   []string
	preferredTotal     int
	spreadBy           string
	spreadValue        string
	spreadPresent      bool
	sameInSpreadDomain int
}

func (candidate placementCandidate) betterThan(other placementCandidate) bool {
	if candidate.spreadBy != "" {
		if candidate.spreadPresent != other.spreadPresent {
			return candidate.spreadPresent
		}
		if candidate.sameInSpreadDomain != other.sameInSpreadDomain {
			return candidate.sameInSpreadDomain < other.sameInSpreadDomain
		}
	}
	if len(candidate.preferredMatches) != len(other.preferredMatches) {
		return len(candidate.preferredMatches) > len(other.preferredMatches)
	}
	if candidate.assignedWorkloads != other.assignedWorkloads {
		return candidate.assignedWorkloads < other.assignedWorkloads
	}
	return candidate.nodeID < other.nodeID
}

func (candidate placementCandidate) decision(now time.Time) controlstore.DeploymentPlacementDecision {
	return controlstore.DeploymentPlacementDecision{
		NodeID:                candidate.nodeID,
		PreferredLabelMatches: append([]string{}, candidate.preferredMatches...),
		PreferredLabelCount:   candidate.preferredTotal,
		SpreadBy:              candidate.spreadBy, SpreadValue: candidate.spreadValue,
		SpreadLabelPresent:           candidate.spreadPresent,
		SameDeploymentInSpreadDomain: candidate.sameInSpreadDomain,
		AssignedWorkloads:            candidate.assignedWorkloads,
		DecidedAt:                    now.UTC().Format(time.RFC3339Nano),
	}
}

func rankPlacementCandidate(
	node controlstore.Node,
	assigned int,
	placement *admission.CommandDelegationPlacement,
	spreadCounts map[string]int,
) placementCandidate {
	candidate := placementCandidate{nodeID: node.ID, assignedWorkloads: assigned}
	if placement == nil {
		candidate.preferredMatches = []string{}
		return candidate
	}
	candidate.preferredTotal = len(placement.PreferredLabels)
	candidate.preferredMatches = make([]string, 0, candidate.preferredTotal)
	for _, preferred := range placement.PreferredLabels {
		if value, found := schedulingLabel(node, preferred.Key); found && value == preferred.Value {
			candidate.preferredMatches = append(candidate.preferredMatches, preferred.Key)
		}
	}
	candidate.spreadBy = placement.SpreadBy
	if placement.SpreadBy != "" {
		candidate.spreadValue, candidate.spreadPresent = schedulingLabel(node, placement.SpreadBy)
		candidate.sameInSpreadDomain = spreadCounts[spreadDomainKey(candidate.spreadPresent, candidate.spreadValue)]
	}
	return candidate
}

func deploymentSpreadCounts(
	nodes []controlstore.Node,
	deployment controlstore.Deployment,
	placement *admission.CommandDelegationPlacement,
) map[string]int {
	counts := make(map[string]int)
	if placement == nil || placement.SpreadBy == "" {
		return counts
	}
	nodesByID := make(map[string]controlstore.Node, len(nodes))
	for _, node := range nodes {
		nodesByID[node.ID] = node
	}
	for _, existing := range deployment.Instances {
		if existing.NodeID == "" || existing.Phase == controlstore.DeploymentInstanceRemoved {
			continue
		}
		node, found := nodesByID[existing.NodeID]
		if !found {
			continue
		}
		value, present := schedulingLabel(node, placement.SpreadBy)
		counts[spreadDomainKey(present, value)]++
	}
	return counts
}

func schedulingLabel(node controlstore.Node, key string) (string, bool) {
	if node.Scheduling == nil {
		return "", false
	}
	labels := node.Scheduling.Observation.Labels
	index := sort.Search(len(labels), func(index int) bool { return labels[index].Key >= key })
	if index >= len(labels) || labels[index].Key != key {
		return "", false
	}
	return labels[index].Value, true
}

func spreadDomainKey(present bool, value string) string {
	if !present {
		return "0:"
	}
	return "1:" + value
}

func schedulingBlockedReason(err error) controlstore.DeploymentBlockedReason {
	switch {
	case errors.Is(err, controlstore.ErrNodeSchedulingUnavailable):
		return controlstore.DeploymentBlockedSchedulingUnavailable
	case errors.Is(err, controlstore.ErrNodePlacementUnavailable):
		return controlstore.DeploymentBlockedNoEligibleNode
	case errors.Is(err, controlstore.ErrNodeSchedulingConstraint):
		return controlstore.DeploymentBlockedPlacementConstraints
	case errors.Is(err, controlstore.ErrTenantCapacityExceeded):
		return controlstore.DeploymentBlockedTenantCapacity
	case errors.Is(err, controlstore.ErrWorkloadLimitExceeded):
		return controlstore.DeploymentBlockedWorkloadLimit
	case errors.Is(err, controlstore.ErrNodeCapacityExceeded):
		return controlstore.DeploymentBlockedNodeCapacity
	default:
		return ""
	}
}

func nodeAvailableForAssignment(
	node controlstore.Node,
	tenantID string,
	allowed map[string]struct{},
	now time.Time,
	nodeStaleAfter time.Duration,
) bool {
	if controlstore.EffectiveNodePlacement(node).Mode == controlstore.NodeQuarantined {
		return false
	}
	lastSeen, err := time.Parse(time.RFC3339Nano, node.LastSeenAt)
	if !node.Active || err != nil || !now.Before(lastSeen.Add(nodeStaleAfter)) {
		return false
	}
	if _, ok := allowed[node.ID]; !ok {
		return false
	}
	tenantIndex := sort.SearchStrings(node.TenantIDs, tenantID)
	capabilityIndex := sort.SearchStrings(node.Capabilities, controlprotocol.ExecutorCapabilityControllerDelegationV1)
	return tenantIndex < len(node.TenantIDs) && node.TenantIDs[tenantIndex] == tenantID &&
		capabilityIndex < len(node.Capabilities) &&
		node.Capabilities[capabilityIndex] == controlprotocol.ExecutorCapabilityControllerDelegationV1
}

func eligibleNode(
	node controlstore.Node,
	tenantID string,
	allowed map[string]struct{},
	now time.Time,
	nodeStaleAfter time.Duration,
) bool {
	return controlstore.EffectiveNodePlacement(node).Mode == controlstore.NodeSchedulable &&
		nodeAvailableForAssignment(node, tenantID, allowed, now, nodeStaleAfter)
}

type blockedError struct {
	reason controlstore.DeploymentBlockedReason
}

func (blocked blockedError) Error() string {
	return string(blocked.reason)
}

func newBlocked(reason controlstore.DeploymentBlockedReason) error {
	return blockedError{reason: reason}
}

func placementCounts(deployments []controlstore.Deployment) map[string]int {
	counts := make(map[string]int)
	for _, deployment := range deployments {
		for _, instance := range deployment.Instances {
			if instance.NodeID != "" && instance.Phase != controlstore.DeploymentInstanceRemoved {
				counts[instance.NodeID]++
			}
		}
	}
	return counts
}

func delegatedInstance(
	delegation admission.CommandDelegation,
	instanceID string,
) (admission.CommandDelegationInstance, bool) {
	index := sort.Search(len(delegation.Instances), func(index int) bool {
		return delegation.Instances[index].InstanceID >= instanceID
	})
	if index >= len(delegation.Instances) || delegation.Instances[index].InstanceID != instanceID {
		return admission.CommandDelegationInstance{}, false
	}
	return delegation.Instances[index], true
}

func intentFromDelegation(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	nodeID string,
	delegated admission.CommandDelegationInstance,
	template admission.CommandDelegationAdmissionTemplate,
) admission.InstanceIntent {
	return admission.InstanceIntent{
		TenantID: deployment.TenantID, NodeID: nodeID,
		InstanceID: instance.InstanceID, LineageID: delegated.LineageID,
		Generation: instance.Generation, CapsuleDigest: template.CapsuleDigest,
		Resources: template.Resources, Capabilities: template.Capabilities,
		StateDisposition: template.StateDisposition,
		InferenceRouteID: template.InferenceRouteID, ModelAlias: template.ModelAlias,
		ServiceID:      template.ServiceID,
		EgressRouteIDs: append([]string(nil), template.EgressRouteIDs...),
		ConnectorIDs:   append([]string(nil), template.ConnectorIDs...),
		EffectMode:     template.EffectMode,
	}
}

func deploymentCommandID(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	operation string,
	sequence uint64,
) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "steward-deployment-command-v1\x00%s\x00%s\x00%d\x00%s\x00%d\x00%s\x00%d",
		deployment.TenantID, deployment.ID, deployment.Generation,
		instance.InstanceID, instance.Generation, operation, sequence)
	return "deploy-" + hex.EncodeToString(hash.Sum(nil))
}

func validKeyID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}
