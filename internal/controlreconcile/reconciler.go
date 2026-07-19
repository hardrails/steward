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
	minInterval       = time.Second
	maxInterval       = time.Hour
	commandLifetime   = 14 * time.Minute
	maxActionsPerPass = 128
)

type Config struct {
	Store      *controlstore.Store
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Interval   time.Duration
	Now        func() time.Time
	Logger     *slog.Logger
}

type Reconciler struct {
	store      *controlstore.Store
	keyID      string
	privateKey ed25519.PrivateKey
	interval   time.Duration
	now        func() time.Time
	logger     *slog.Logger
}

type Report struct {
	Deployments int `json:"deployments"`
	Instances   int `json:"instances"`
	Observed    int `json:"observed"`
	Enqueued    int `json:"enqueued"`
	Removed     int `json:"removed"`
	Conflicts   int `json:"conflicts"`
	Blocked     int `json:"blocked"`
}

func New(config Config) (*Reconciler, error) {
	if config.Store == nil || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		!validKeyID(config.KeyID) || config.Interval < minInterval || config.Interval > maxInterval {
		return nil, errors.New("controller reconciler requires a store, bounded key ID, Ed25519 private key, and interval from 1 second through 1 hour")
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
		interval:   config.Interval, now: now, logger: logger,
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
			if report.Enqueued > 0 || report.Observed > 0 || report.Removed > 0 || report.Blocked > 0 {
				reconciler.logger.Info("desired-state reconciliation completed",
					"deployments", report.Deployments, "instances", report.Instances,
					"observed", report.Observed, "enqueued", report.Enqueued,
					"removed", report.Removed, "conflicts", report.Conflicts, "blocked", report.Blocked)
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
			changed, kind, conflict, err := reconciler.reconcileInstance(snapshot.Nodes, placements, deployment, instance)
			if err != nil {
				report.Blocked++
				reconciler.logger.Warn("deployment instance is blocked",
					"tenant_id", deployment.TenantID, "deployment_id", deployment.ID,
					"instance_id", instance.InstanceID, "error", err)
				continue
			}
			if conflict {
				report.Conflicts++
				break
			}
			if !changed {
				continue
			}
			actions++
			switch kind {
			case "observed":
				report.Observed++
			case "enqueued":
				report.Enqueued++
			case "removed":
				report.Removed++
			}
			break
		}
	}
	return report, nil
}

func (reconciler *Reconciler) reconcileInstance(
	nodes []controlstore.Node,
	placements map[string]int,
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
) (changed bool, kind string, conflict bool, result error) {
	now := reconciler.now().UTC()
	if now.IsZero() {
		return false, "", false, errors.New("controller clock is invalid")
	}
	if commandInFlight(instance) {
		_, changed, err := reconciler.store.ObserveDeploymentCommand(
			deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
		)
		if errors.Is(err, controlstore.ErrConflict) {
			return false, "", true, nil
		}
		return changed, "observed", false, err
	}
	if instance.Phase == controlstore.DeploymentInstanceFailed ||
		instance.Phase == controlstore.DeploymentInstanceRemoved ||
		deployment.DesiredState == controlstore.DeploymentRunning && instance.Phase == controlstore.DeploymentInstanceRunning {
		return false, "", false, nil
	}
	if deployment.DesiredState == controlstore.DeploymentAbsent &&
		instance.Phase == controlstore.DeploymentInstancePending && instance.CommandID == "" && instance.NodeID == "" {
		_, changed, err := reconciler.store.RemovePendingDeploymentInstance(
			deployment.TenantID, deployment.ID, instance.InstanceID, deployment.Revision, now,
		)
		if errors.Is(err, controlstore.ErrConflict) {
			return false, "", true, nil
		}
		return changed, "removed", false, err
	}
	operation := nextOperation(deployment.DesiredState, instance)
	if operation == "" {
		return false, "", false, nil
	}
	nodeID, err := selectNode(nodes, placements, deployment, instance)
	if err != nil {
		return false, "", false, err
	}
	commandRaw, err := reconciler.signCommand(deployment, instance, nodeID, operation, now)
	if err != nil {
		return false, "", false, err
	}
	_, _, changed, err = reconciler.store.EnqueueDeploymentCommand(controlstore.DeploymentCommandTransition{
		TenantID: deployment.TenantID, DeploymentID: deployment.ID,
		ExpectedRevision: deployment.Revision, InstanceID: instance.InstanceID,
		CommandDSSE: commandRaw,
	}, now)
	if errors.Is(err, controlstore.ErrConflict) {
		return false, "", true, nil
	}
	if changed && instance.NodeID == "" {
		placements[nodeID]++
	}
	return changed, "enqueued", false, err
}

func (reconciler *Reconciler) signCommand(
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
	nodeID, operation string,
	now time.Time,
) ([]byte, error) {
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, now)
	if err != nil {
		return nil, err
	}
	if delegation.ControllerKeyID != reconciler.keyID {
		return nil, errors.New("deployment delegation names a different controller key")
	}
	public, err := base64.StdEncoding.DecodeString(delegation.ControllerPublicKey)
	if err != nil || !bytes.Equal(public, reconciler.privateKey.Public().(ed25519.PublicKey)) {
		return nil, errors.New("deployment delegation public key does not match this controller")
	}
	runtimeRef, err := executoruplink.RuntimeRefV2(deployment.TenantID, nodeID, instance.InstanceID)
	if err != nil {
		return nil, err
	}
	sequence := instance.CommandSequence + 1
	if sequence == 0 {
		return nil, controlstore.ErrCapacityExceeded
	}
	payload := []byte(`{}`)
	if operation == "admit" {
		delegated, found := delegatedInstance(delegation, instance.InstanceID)
		if !found || delegation.Admission == nil {
			return nil, errors.New("deployment instance is missing from its delegation")
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
	expires := now.Add(commandLifetime)
	delegationExpiry, _ := time.Parse(time.RFC3339Nano, delegation.ExpiresAt)
	if delegationExpiry.Before(expires) {
		expires = delegationExpiry
	}
	if !expires.After(now) {
		return nil, errors.New("deployment delegation expired before command issuance")
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
		return nil, err
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

func nextOperation(desired controlstore.DeploymentDesiredState, instance controlstore.DeploymentInstance) string {
	if desired == controlstore.DeploymentRunning {
		switch instance.Phase {
		case controlstore.DeploymentInstancePending:
			return "admit"
		case controlstore.DeploymentInstanceStarting:
			return "start"
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

func commandInFlight(instance controlstore.DeploymentInstance) bool {
	switch instance.CommandOperation {
	case "admit":
		return instance.Phase == controlstore.DeploymentInstanceAdmitting
	case "start":
		return instance.Phase == controlstore.DeploymentInstanceStarting
	case "stop":
		return instance.Phase == controlstore.DeploymentInstanceStopping
	case "destroy":
		return instance.Phase == controlstore.DeploymentInstanceDestroying
	default:
		return false
	}
}

func selectNode(
	nodes []controlstore.Node,
	placements map[string]int,
	deployment controlstore.Deployment,
	instance controlstore.DeploymentInstance,
) (string, error) {
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		return "", err
	}
	allowed := make(map[string]struct{}, len(delegation.NodeIDs))
	for _, nodeID := range delegation.NodeIDs {
		allowed[nodeID] = struct{}{}
	}
	if instance.NodeID != "" {
		for _, node := range nodes {
			if node.ID == instance.NodeID && eligibleNode(node, deployment.TenantID, allowed) {
				return node.ID, nil
			}
		}
		return "", errors.New("assigned deployment node is no longer eligible")
	}
	selected := ""
	selectedCount := int(^uint(0) >> 1)
	for _, node := range nodes {
		if !eligibleNode(node, deployment.TenantID, allowed) {
			continue
		}
		if count := placements[node.ID]; count < selectedCount || count == selectedCount && node.ID < selected {
			selected, selectedCount = node.ID, count
		}
	}
	if selected == "" {
		return "", errors.New("no active delegated node advertises controller-delegation-v1")
	}
	return selected, nil
}

func eligibleNode(node controlstore.Node, tenantID string, allowed map[string]struct{}) bool {
	if !node.Active {
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
