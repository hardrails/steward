package controlreconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

type reconcileFixture struct {
	store      *controlstore.Store
	auth       *controlauth.Manager
	admin      controlauth.Identity
	node       controlauth.NodeIdentity
	nodeIDs    []string
	now        time.Time
	dir        string
	controller ed25519.PrivateKey
	limits     controlstore.Limits
}

func TestReconcilerConvergesLifecycleWithoutDuplicateEffectAcrossRestart(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 1 {
		t.Fatalf("enqueue admit = (%+v, %v)", report, err)
	}
	deployment := getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentReconciling ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceAdmitting ||
		deployment.Instances[0].CommandOperation != "admit" ||
		deployment.Instances[0].Placement == nil ||
		deployment.Instances[0].Placement.NodeID != "node-1" ||
		deployment.Instances[0].Placement.PreferredLabelMatches == nil ||
		deployment.Instances[0].Placement.DecidedAt != fixture.now.Format(time.RFC3339Nano) {
		t.Fatalf("admit cursor = %+v", deployment)
	}
	firstCommand := deployment.Instances[0].CommandID

	// Restart after durable enqueue but before a node report. The new
	// reconciler observes the same pending command and does not create another.
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlstore.Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	reconciler = fixture.reconciler(t)
	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 0 || report.Observed != 0 {
		t.Fatalf("restart pending reconciliation = (%+v, %v)", report, err)
	}
	if deployment = getControlDeployment(t, fixture); deployment.Instances[0].CommandID != firstCommand ||
		deployment.Instances[0].Attempts != 1 {
		t.Fatalf("restart duplicated command = %+v", deployment.Instances[0])
	}

	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue lease renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe lease renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe start", 1, 0)
	deployment = getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentReady ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceRunning ||
		deployment.Instances[0].Intent == nil || deployment.Instances[0].Admission == nil ||
		deployment.Instances[0].Intent.InstanceID != "research-0" ||
		deployment.Instances[0].Admission.RuntimeRef == "" ||
		deployment.Instances[0].LeaseExpiresAt == "" {
		t.Fatalf("running deployment = %+v", deployment)
	}

	removed, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "research", deployment.Revision,
		controlstore.DeploymentAbsent, fixture.now.Add(20*time.Minute),
	)
	if err != nil || !changed || removed.Phase != controlstore.DeploymentStopping {
		t.Fatalf("set absent = (%+v, %v, %v)", removed, changed, err)
	}
	fixture.now = fixture.now.Add(20 * time.Minute)
	heartbeatControlNode(t, fixture)
	assertReconcileCount(t, reconciler, "enqueue stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe stop", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue destroy", 0, 1)
	completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe destroy", 1, 0)
	deployment = getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentRemoved ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceRemoved ||
		deployment.Instances[0].Attempts != 5 {
		t.Fatalf("removed deployment = %+v", deployment)
	}
	applyControlDeployment(t, fixture, 2)
	recreated := getControlDeployment(t, fixture)
	if recreated.Generation != 2 || recreated.Phase != controlstore.DeploymentPending || recreated.Rollout != nil {
		t.Fatalf("removed deployment was not reusable: %+v", recreated)
	}
}

func TestReconcilerRollsRunningDeploymentAcrossSignedAuthorities(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	assertReconcileCount(t, reconciler, "enqueue source admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source start", 1, 0)

	source := getControlDeployment(t, fixture)
	if source.Phase != controlstore.DeploymentReady {
		t.Fatalf("source deployment is not ready: %+v", source)
	}
	applyControlDeployment(t, fixture, 2)
	target := getControlDeployment(t, fixture)
	if target.Generation != 2 || target.Rollout == nil || target.Rollout.SourceGeneration != 1 ||
		target.Instances[0].Generation != 1 {
		t.Fatalf("rollout did not retain source authority: %+v", target)
	}
	_, selectedSource, err := controlstore.DeploymentAuthorityForInstance(target, target.Instances[0])
	if err != nil || bytes.Equal(selectedSource, target.DelegationDSSE) {
		t.Fatalf("source instance selected target authority before destroy: %v", err)
	}

	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.RollingOut != 1 {
		t.Fatalf("begin rollout = (%+v, %v)", report, err)
	}
	assertReconcileCount(t, reconciler, "enqueue source stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source stop", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source destroy", 0, 1)
	completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source destroy", 1, 0)

	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Replaced != 1 {
		t.Fatalf("advance to target authority = (%+v, %v)", report, err)
	}
	target = getControlDeployment(t, fixture)
	if target.Instances[0].Generation != 2 || target.Instances[0].Phase != controlstore.DeploymentInstancePending ||
		target.Instances[0].Rollout == nil || target.Instances[0].Rollout.Stage != "deploying" {
		t.Fatalf("target cursor was not prepared after destroy: %+v", target)
	}
	_, selectedTarget, err := controlstore.DeploymentAuthorityForInstance(target, target.Instances[0])
	if err != nil || !bytes.Equal(selectedTarget, target.DelegationDSSE) {
		t.Fatalf("target instance retained source authority after destroy: %v", err)
	}

	assertReconcileCount(t, reconciler, "enqueue target admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe target admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue target renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe target renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue target start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe target start", 1, 0)

	completed := getControlDeployment(t, fixture)
	if completed.Phase != controlstore.DeploymentReady || completed.Rollout != nil ||
		completed.Instances[0].Rollout != nil || completed.Instances[0].Generation != 2 ||
		completed.Instances[0].Phase != controlstore.DeploymentInstanceRunning {
		t.Fatalf("rollout did not converge: %+v", completed)
	}
}

func TestReconcilerDoesNotSpendRolloutBudgetAfterSourceDelegationExpires(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue source admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source start", 1, 0)
	applyControlDeployment(t, fixture, 2)

	deployment := getControlDeployment(t, fixture)
	if deployment.Rollout == nil {
		t.Fatal("rollout source authority is missing")
	}
	source, err := admission.InspectCommandDelegation(deployment.Rollout.SourceDelegationDSSE, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339Nano, source.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = expires
	heartbeatControlNode(t, fixture)
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Blocked != 1 {
		t.Fatalf("expired rollout authority reconciliation = (%+v, %v)", report, err)
	}
	blocked := getControlDeployment(t, fixture)
	if blocked.Instances[0].Rollout != nil ||
		blocked.Instances[0].LastError != string(controlstore.DeploymentBlockedDelegationExpired) {
		t.Fatalf("expired source delegation spent rollout budget: %+v", blocked.Instances[0])
	}
}

func TestTopologyPlacementRanksSpreadBeforePreferenceAndLoad(t *testing.T) {
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, time.UTC)
	placement := &admission.CommandDelegationPlacement{
		PreferredLabels: []admission.CommandDelegationLabel{{Key: "disk", Value: "fast"}},
		SpreadBy:        "zone",
	}
	node := func(id string, labels ...controlprotocol.ExecutorSchedulingLabelV1) controlstore.Node {
		return controlstore.Node{ID: id, Scheduling: &controlstore.NodeScheduling{
			Observation: controlprotocol.ExecutorSchedulingObservationV1{Labels: labels},
		}}
	}
	spread := map[string]int{"1:west-a": 2, "1:west-b": 0, "0:": 0}
	busyPreferred := rankPlacementCandidate(node("node-a",
		controlprotocol.ExecutorSchedulingLabelV1{Key: "disk", Value: "fast"},
		controlprotocol.ExecutorSchedulingLabelV1{Key: "zone", Value: "west-a"},
	), 0, placement, spread)
	emptyDomain := rankPlacementCandidate(node("node-b",
		controlprotocol.ExecutorSchedulingLabelV1{Key: "zone", Value: "west-b"},
	), 7, placement, spread)
	missingSpread := rankPlacementCandidate(node("node-c",
		controlprotocol.ExecutorSchedulingLabelV1{Key: "disk", Value: "fast"},
	), 0, placement, spread)
	if !emptyDomain.betterThan(busyPreferred) || !emptyDomain.betterThan(missingSpread) {
		t.Fatalf("spread rank did not dominate preference/load: busy=%+v empty=%+v missing=%+v", busyPreferred, emptyDomain, missingSpread)
	}
	decision := emptyDomain.decision(now)
	if decision.NodeID != "node-b" || decision.SpreadValue != "west-b" ||
		decision.SameDeploymentInSpreadDomain != 0 || decision.PreferredLabelCount != 1 ||
		decision.PreferredLabelMatches == nil || decision.AssignedWorkloads != 7 ||
		decision.DecidedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("placement decision = %+v", decision)
	}
	withoutSpread := rankPlacementCandidate(node("node-d",
		controlprotocol.ExecutorSchedulingLabelV1{Key: "disk", Value: "fast"},
	), 4, &admission.CommandDelegationPlacement{PreferredLabels: placement.PreferredLabels}, nil)
	loaded := rankPlacementCandidate(node("node-e"), 0, &admission.CommandDelegationPlacement{PreferredLabels: placement.PreferredLabels}, nil)
	if !withoutSpread.betterThan(loaded) {
		t.Fatal("preferred label did not outrank node load when no spread key was requested")
	}
}

func TestDeploymentSpreadCountsOnlyLiveKnownAssignments(t *testing.T) {
	nodes := []controlstore.Node{
		{ID: "node-a", Scheduling: &controlstore.NodeScheduling{Observation: controlprotocol.ExecutorSchedulingObservationV1{
			Labels: []controlprotocol.ExecutorSchedulingLabelV1{{Key: "zone", Value: "west"}},
		}}},
		{ID: "node-b", Scheduling: &controlstore.NodeScheduling{Observation: controlprotocol.ExecutorSchedulingObservationV1{
			Labels: []controlprotocol.ExecutorSchedulingLabelV1{},
		}}},
	}
	deployment := controlstore.Deployment{Instances: []controlstore.DeploymentInstance{
		{InstanceID: "empty"},
		{InstanceID: "removed", NodeID: "node-a", Phase: controlstore.DeploymentInstanceRemoved},
		{InstanceID: "unknown", NodeID: "node-missing", Phase: controlstore.DeploymentInstanceRunning},
		{InstanceID: "west", NodeID: "node-a", Phase: controlstore.DeploymentInstanceRunning},
		{InstanceID: "unlabelled", NodeID: "node-b", Phase: controlstore.DeploymentInstanceRunning},
	}}
	if counts := deploymentSpreadCounts(nodes, deployment, nil); len(counts) != 0 {
		t.Fatalf("nil spread counts = %+v", counts)
	}
	if counts := deploymentSpreadCounts(nodes, deployment, &admission.CommandDelegationPlacement{}); len(counts) != 0 {
		t.Fatalf("empty spread counts = %+v", counts)
	}
	counts := deploymentSpreadCounts(nodes, deployment, &admission.CommandDelegationPlacement{SpreadBy: "zone"})
	if len(counts) != 2 || counts["1:west"] != 1 || counts["0:"] != 1 {
		t.Fatalf("live spread counts = %+v", counts)
	}
}

func TestSchedulingBlockedReasonMapsStoreFailures(t *testing.T) {
	tests := []struct {
		err  error
		want controlstore.DeploymentBlockedReason
	}{
		{controlstore.ErrNodeSchedulingUnavailable, controlstore.DeploymentBlockedSchedulingUnavailable},
		{controlstore.ErrNodePlacementUnavailable, controlstore.DeploymentBlockedNoEligibleNode},
		{controlstore.ErrNodeSchedulingConstraint, controlstore.DeploymentBlockedPlacementConstraints},
		{controlstore.ErrTenantCapacityExceeded, controlstore.DeploymentBlockedTenantCapacity},
		{controlstore.ErrWorkloadLimitExceeded, controlstore.DeploymentBlockedWorkloadLimit},
		{controlstore.ErrNodeCapacityExceeded, controlstore.DeploymentBlockedNodeCapacity},
		{errors.New("other"), ""},
	}
	for _, test := range tests {
		if got := schedulingBlockedReason(test.err); got != test.want {
			t.Fatalf("scheduling reason for %v = %q, want %q", test.err, got, test.want)
		}
	}
	if _, found := activeNodeDrain(nil, "node-missing"); found {
		t.Fatal("missing node unexpectedly had an active drain")
	}
	if _, found := schedulingLabel(controlstore.Node{}, "zone"); found {
		t.Fatal("node without a scheduling observation unexpectedly had a label")
	}
}

func TestReconcilerDrainsStatelessInstanceAcrossRestart(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	source := fixture.node
	target := addControlNode(t, fixture, "node-2")
	fixture.node = source
	heartbeatControlNode(t, fixture)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	assertReconcileCount(t, reconciler, "enqueue source admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source start", 1, 0)
	fixture.node = target
	heartbeatControlNode(t, fixture)
	fixture.node = source

	if _, changed, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-1", "kernel upgrade", fixture.now,
	); err != nil || !changed {
		t.Fatalf("start node drain = (%v, %v)", changed, err)
	}
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Draining != 1 {
		t.Fatalf("mark drain = (%+v, %v)", report, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlstore.Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	reconciler = fixture.reconciler(t)

	assertReconcileCount(t, reconciler, "enqueue drain stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe drain stop", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue drain destroy", 0, 1)
	completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe drain destroy", 1, 0)
	fixture.node = target
	heartbeatControlNode(t, fixture)
	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Replaced != 1 {
		t.Fatalf("replace drained instance = (%+v, %v)", report, err)
	}
	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 1 {
		t.Fatalf("enqueue target admit = (%+v, %v)", report, err)
	}
	deployment := getControlDeployment(t, fixture)
	if deployment.Instances[0].NodeID != "node-2" || deployment.Instances[0].Generation != 2 ||
		deployment.Instances[0].Drain == nil {
		t.Fatalf("target placement = %+v", deployment.Instances[0])
	}
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe target admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue target renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe target renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue target start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Observed != 1 || report.DrainsCompleted != 1 {
		t.Fatalf("complete target start and node drain = (%+v, %v)", report, err)
	}
	deployment = getControlDeployment(t, fixture)
	if deployment.Instances[0].Drain != nil || deployment.Instances[0].Phase != controlstore.DeploymentInstanceRunning {
		t.Fatalf("completed replacement = %+v", deployment.Instances[0])
	}
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 2 || nodes[0].Drain == nil ||
		nodes[0].Drain.State != controlstore.NodeDrainCompleted {
		t.Fatalf("completed node drain = (%+v, %v)", nodes, err)
	}
}

func TestReconcilerFailsNodeDrainWithoutRetryingFailedStop(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	source := fixture.node
	target := addControlNode(t, fixture, "node-2")
	fixture.node = source
	heartbeatControlNode(t, fixture)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	assertReconcileCount(t, reconciler, "enqueue source admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source start", 1, 0)
	fixture.node = target
	heartbeatControlNode(t, fixture)
	fixture.node = source

	if _, changed, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-failed-stop", "kernel upgrade", fixture.now,
	); err != nil || !changed {
		t.Fatalf("start node drain = (%v, %v)", changed, err)
	}
	if report, err := reconciler.Reconcile(context.Background()); err != nil || report.Draining != 1 {
		t.Fatalf("mark drain = (%+v, %v)", report, err)
	}
	assertReconcileCount(t, reconciler, "enqueue drain stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusFailed)
	assertReconcileCount(t, reconciler, "observe failed drain stop", 1, 0)

	deployment := getControlDeployment(t, fixture)
	instance := deployment.Instances[0]
	if deployment.Phase != controlstore.DeploymentDegraded ||
		instance.Phase != controlstore.DeploymentInstanceFailed || instance.Drain != nil ||
		!strings.Contains(instance.LastError, controlprotocol.ExecutorStatusFailed) {
		t.Fatalf("failed drain deployment = %+v", deployment)
	}
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 2 || nodes[0].Drain == nil ||
		nodes[0].Drain.State != controlstore.NodeDrainFailed ||
		nodes[0].Drain.FailedInstanceID != instance.InstanceID || nodes[0].Drain.CompletedAt == "" {
		t.Fatalf("failed node drain = (%+v, %v)", nodes, err)
	}
	if _, _, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-after-failure", "retry maintenance", fixture.now.Add(time.Second),
	); !errors.Is(err, controlstore.ErrConflict) {
		t.Fatalf("new drain with unresolved failed assignment = %v", err)
	}
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 0 || report.Observed != 0 ||
		getControlDeployment(t, fixture).Instances[0].Attempts != instance.Attempts {
		t.Fatalf("failed stop retried = (%+v, %v)", report, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlstore.Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	nodes, err = reopened.ListNodes(fixture.admin, "tenant-a")
	if err != nil || nodes[0].Drain == nil || nodes[0].Drain.State != controlstore.NodeDrainFailed ||
		nodes[0].Drain.FailedInstanceID != instance.InstanceID {
		t.Fatalf("reopened failed node drain = (%+v, %v)", nodes, err)
	}
}

func TestReconcilerCompletesDrainWhenRemovedDeploymentBecomesAbsent(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	source := fixture.node
	target := addControlNode(t, fixture, "node-2")
	fixture.node = source
	heartbeatControlNode(t, fixture)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	assertReconcileCount(t, reconciler, "enqueue source admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source renewal", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source renewal", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue source start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe source start", 1, 0)
	fixture.node = target
	heartbeatControlNode(t, fixture)
	fixture.node = source

	if _, changed, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-remove", "kernel upgrade", fixture.now,
	); err != nil || !changed {
		t.Fatalf("start node drain = (%v, %v)", changed, err)
	}
	if report, err := reconciler.Reconcile(context.Background()); err != nil || report.Draining != 1 {
		t.Fatalf("mark drain = (%+v, %v)", report, err)
	}
	assertReconcileCount(t, reconciler, "enqueue drain stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe drain stop", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue drain destroy", 0, 1)
	completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe drain destroy", 1, 0)

	deployment := getControlDeployment(t, fixture)
	if deployment.Instances[0].Phase != controlstore.DeploymentInstanceRemoved ||
		deployment.Instances[0].Drain == nil {
		t.Fatalf("destroyed drain source = %+v", deployment.Instances[0])
	}
	fixture.now = fixture.now.Add(time.Minute)
	if _, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, deployment.TenantID, deployment.ID, deployment.Revision,
		controlstore.DeploymentAbsent, fixture.now,
	); err != nil || !changed {
		t.Fatalf("remove between destroy and replacement = (%v, %v)", changed, err)
	}
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Removed != 1 || report.Replaced != 0 || report.DrainsCompleted != 1 {
		t.Fatalf("complete removed drain = (%+v, %v)", report, err)
	}
	deployment = getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentRemoved || deployment.Instances[0].Drain != nil ||
		deployment.Instances[0].Generation != 1 {
		t.Fatalf("removed drain completion created replacement = %+v", deployment)
	}
	nodes, err := fixture.store.ListNodes(fixture.admin, "tenant-a")
	if err != nil || len(nodes) != 2 || nodes[0].Drain == nil ||
		nodes[0].Drain.State != controlstore.NodeDrainCompleted {
		t.Fatalf("node drain after removal = (%+v, %v)", nodes, err)
	}
}

func TestReconcilerDegradesAmbiguousOutcomeWithoutRetry(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusOutcomeUnknown)
	assertReconcileCount(t, reconciler, "observe unknown", 1, 0)
	deployment := getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentDegraded ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceFailed ||
		!strings.Contains(deployment.Instances[0].LastError, controlprotocol.ExecutorStatusOutcomeUnknown) {
		t.Fatalf("ambiguous deployment = %+v", deployment)
	}
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 0 || report.Observed != 0 ||
		getControlDeployment(t, fixture).Instances[0].Attempts != 1 {
		t.Fatalf("ambiguous outcome retried = (%+v, %v)", report, err)
	}
}

func TestConcurrentReconcilersCannotDoubleEnqueueOrWidenAuthority(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	start := make(chan struct{})
	reports := make(chan Report, 2)
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			report, err := reconciler.Reconcile(context.Background())
			reports <- report
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(reports)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	enqueued := 0
	for report := range reports {
		enqueued += report.Enqueued
	}
	if status, err := fixture.store.Status(); err != nil || enqueued != 1 || status.Commands != 1 ||
		getControlDeployment(t, fixture).Instances[0].Attempts != 1 {
		t.Fatalf("concurrent reconciliation = enqueued %d status %+v err %v", enqueued, status, err)
	}

	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: wrongKey,
		Interval: time.Second, NodeStaleAfter: 2 * time.Minute,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pending command is observed, not re-signed. After admission succeeds,
	// the wrong key cannot produce the next effect.
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, wrong, "observe admit with wrong key", 1, 0)
	report, err := wrong.Reconcile(context.Background())
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 {
		t.Fatalf("wrong controller key widened authority = (%+v, %v)", report, err)
	}
	if deployment := getControlDeployment(t, fixture); deployment.Instances[0].LastError !=
		string(controlstore.DeploymentBlockedControllerKeyMismatch) {
		t.Fatalf("wrong controller key reason = %+v", deployment.Instances[0])
	}
}

func TestReconcilerAtomicallyRechecksCapacityAcrossOneFleetSnapshot(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	observation := testSchedulingObservation("node-1")
	observation.Policy.Host.Workloads = 1
	observation.Policy.Tenant.Workloads = 1
	if _, applied, err := fixture.store.ObserveNodeScheduling(fixture.node, observation, fixture.now); err != nil || !applied {
		t.Fatalf("tighten scheduling capacity = (%v, %v)", applied, err)
	}
	applyControlDeploymentNamed(t, fixture, "alpha", "alpha-0", "alpha-lineage-0", 1)
	applyControlDeploymentNamed(t, fixture, "beta", "beta-0", "beta-lineage-0", 1)
	report, err := fixture.reconciler(t).Reconcile(context.Background())
	if err != nil || report.Enqueued != 1 || report.Blocked != 1 {
		t.Fatalf("capacity reconciliation = (%+v, %v)", report, err)
	}
	snapshot, err := fixture.store.SnapshotDeploymentFleet()
	if err != nil {
		t.Fatal(err)
	}
	admitting, blocked := 0, 0
	for _, deployment := range snapshot.Deployments {
		instance := deployment.Instances[0]
		if instance.Phase == controlstore.DeploymentInstanceAdmitting {
			admitting++
		}
		if instance.Phase == controlstore.DeploymentInstancePending &&
			instance.LastError == string(controlstore.DeploymentBlockedNodeCapacity) {
			blocked++
		}
	}
	status, err := fixture.store.Status()
	if err != nil || admitting != 1 || blocked != 1 || status.Commands != 1 {
		t.Fatalf("atomic reservation result = admitting %d blocked %d status %+v err %v", admitting, blocked, status, err)
	}
}

func TestReconcilerPersistsStableNodeBlockAndRecoversAfterHeartbeat(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	fixture.now = fixture.now.Add(2 * time.Minute)

	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 {
		t.Fatalf("stale node block = (%+v, %v)", report, err)
	}
	blocked := getControlDeployment(t, fixture)
	if blocked.Instances[0].LastError != string(controlstore.DeploymentBlockedNoEligibleNode) ||
		blocked.Instances[0].Phase != controlstore.DeploymentInstancePending ||
		blocked.Instances[0].Attempts != 0 {
		t.Fatalf("stale node deployment = %+v", blocked)
	}
	report, err = reconciler.Reconcile(context.Background())
	stable := getControlDeployment(t, fixture)
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 || stable.Revision != blocked.Revision {
		t.Fatalf("repeated node block = report %+v deployment %+v err %v", report, stable, err)
	}

	heartbeatControlNode(t, fixture)
	report, err = reconciler.Reconcile(context.Background())
	recovered := getControlDeployment(t, fixture)
	if err != nil || report.Enqueued != 1 || report.Blocked != 0 ||
		recovered.Instances[0].LastError != "" || recovered.Instances[0].Attempts != 1 {
		t.Fatalf("heartbeat recovery = report %+v deployment %+v err %v", report, recovered, err)
	}
}

func TestReconcilerDoesNotReplaceStaleAssignedNode(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	fixture.now = fixture.now.Add(2 * time.Minute)

	report, err := reconciler.Reconcile(context.Background())
	deployment := getControlDeployment(t, fixture)
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 ||
		deployment.Instances[0].NodeID != "node-1" || deployment.Instances[0].Attempts != 1 ||
		deployment.Instances[0].LastError != string(controlstore.DeploymentBlockedAssignedNodeUnavailable) {
		t.Fatalf("stale assigned node = report %+v deployment %+v err %v", report, deployment, err)
	}
}

func TestReconcilerIgnoresTerminalInstancesBeforeStaleNodeRecovery(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	fixture.now = fixture.now.Add(2 * time.Minute)
	snapshot, err := fixture.store.SnapshotDeploymentFleet()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Deployments) != 1 || len(snapshot.Deployments[0].Instances) != 1 {
		t.Fatalf("unexpected fleet snapshot = %+v", snapshot)
	}
	deployment := snapshot.Deployments[0]
	for _, phase := range []controlstore.DeploymentInstancePhase{
		controlstore.DeploymentInstanceFailed,
		controlstore.DeploymentInstanceRemoved,
	} {
		t.Run(string(phase), func(t *testing.T) {
			instance := deployment.Instances[0]
			instance.NodeID = "node-1"
			instance.Phase = phase
			result, err := reconciler.reconcileInstance(
				snapshot.Nodes, snapshot.Deployments, nil, deployment, instance,
			)
			if err != nil || result != (instanceResult{}) {
				t.Fatalf("terminal instance entered stale-node recovery = (%+v, %v)", result, err)
			}
		})
	}
}

func TestReconcilerReplacesStatelessInstanceOnlyAfterLeaseSafetyWindow(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: fixture.controller,
		Interval: time.Second, NodeStaleAfter: 30 * time.Second,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeatControlNode(t, fixture)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue renew", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe renew", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe start", 1, 0)

	running := getControlDeployment(t, fixture)
	leaseExpiry, err := time.Parse(time.RFC3339Nano, running.Instances[0].LeaseExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = leaseExpiry.Add(admission.CommandClockSkew - time.Nanosecond)
	report, err := reconciler.Reconcile(context.Background())
	waiting := getControlDeployment(t, fixture)
	if err != nil || report.Blocked != 1 || report.Replaced != 0 ||
		waiting.Instances[0].LastError != string(controlstore.DeploymentBlockedAwaitingLeaseExpiry) {
		t.Fatalf("pre-fence replacement = report %+v deployment %+v err %v", report, waiting, err)
	}

	fixture.now = leaseExpiry.Add(admission.CommandClockSkew)
	report, err = reconciler.Reconcile(context.Background())
	replaced := getControlDeployment(t, fixture)
	if err != nil || report.Replaced != 1 || report.Enqueued != 0 ||
		replaced.Instances[0].Generation != 2 || replaced.Instances[0].NodeID != "" ||
		replaced.Instances[0].Phase != controlstore.DeploymentInstancePending ||
		replaced.Instances[0].LeaseExpiresAt != "" {
		t.Fatalf("replacement = report %+v deployment %+v err %v", report, replaced, err)
	}
	heartbeatControlNode(t, fixture)
	report, err = reconciler.Reconcile(context.Background())
	reassigned := getControlDeployment(t, fixture)
	if err != nil || report.Enqueued != 1 || reassigned.Instances[0].Generation != 2 ||
		reassigned.Instances[0].NodeID != "node-1" || reassigned.Instances[0].CommandOperation != "admit" {
		t.Fatalf("replacement admission = report %+v deployment %+v err %v", report, reassigned, err)
	}
}

func TestReconcilerReportsInvalidAuthorityWhenReplacementTemplateIsMissing(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue renew", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe renew", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe start", 1, 0)

	deployment := getControlDeployment(t, fixture)
	instance := deployment.Instances[0]
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	delegation.Admission = nil
	leaseExpiry, err := time.Parse(time.RFC3339Nano, instance.LeaseExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = leaseExpiry.Add(admission.CommandClockSkew)
	result, err := reconciler.recoverUnavailableInstance(deployment, instance, delegation, true, fixture.now)
	blocked := getControlDeployment(t, fixture)
	if err != nil || result.blockedReason != controlstore.DeploymentBlockedInvalidAuthority || !result.changed ||
		blocked.Instances[0].LastError != string(controlstore.DeploymentBlockedInvalidAuthority) {
		t.Fatalf("missing replacement template = result %+v deployment %+v err %v", result, blocked, err)
	}
}

func TestReconcilerDoesNotReplaceAfterDelegationExpires(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue renew", 0, 1)
	completeDeploymentCommand(t, fixture, "renew", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe renew", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe start", 1, 0)

	fixture.now = fixture.now.Add(24 * time.Hour)
	report, err := reconciler.Reconcile(context.Background())
	deployment := getControlDeployment(t, fixture)
	if err != nil || report.Blocked != 1 || report.Replaced != 0 ||
		deployment.Instances[0].Generation != 1 ||
		deployment.Instances[0].LastError != string(controlstore.DeploymentBlockedDelegationExpired) {
		t.Fatalf("expired delegation replacement = report %+v deployment %+v err %v", report, deployment, err)
	}
}

func TestReconcilerReportsExpiredDelegation(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	fixture.now = fixture.now.Add(24 * time.Hour)
	heartbeatControlNode(t, fixture)

	report, err := reconciler.Reconcile(context.Background())
	deployment := getControlDeployment(t, fixture)
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 ||
		deployment.Instances[0].LastError != string(controlstore.DeploymentBlockedDelegationExpired) {
		t.Fatalf("expired delegation = report %+v deployment %+v err %v", report, deployment, err)
	}
}

func TestLeaseManagedLifecycleOperationPlan(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(workloadLeaseRenewBefore + time.Minute).Format(time.RFC3339Nano)
	due := now.Add(workloadLeaseRenewBefore).Format(time.RFC3339Nano)
	for _, test := range []struct {
		name         string
		desired      controlstore.DeploymentDesiredState
		phase        controlstore.DeploymentInstancePhase
		leaseManaged bool
		leaseExpiry  string
		want         string
	}{
		{name: "admit pending", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstancePending, want: "admit"},
		{name: "renew before first start", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceStarting, leaseManaged: true, want: "renew"},
		{name: "start with lease", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceStarting, leaseManaged: true, leaseExpiry: fresh, want: "start"},
		{name: "renew due before first start", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceStarting, leaseManaged: true, leaseExpiry: due, want: "renew"},
		{name: "renew due running", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceRunning, leaseManaged: true, leaseExpiry: due, want: "renew"},
		{name: "renew malformed running", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceRunning, leaseManaged: true, leaseExpiry: "invalid", want: "renew"},
		{name: "keep fresh running", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceRunning, leaseManaged: true, leaseExpiry: fresh},
		{name: "keep legacy running", desired: controlstore.DeploymentRunning, phase: controlstore.DeploymentInstanceRunning},
		{name: "stop running", desired: controlstore.DeploymentAbsent, phase: controlstore.DeploymentInstanceRunning, want: "stop"},
		{name: "stop starting", desired: controlstore.DeploymentAbsent, phase: controlstore.DeploymentInstanceStarting, want: "stop"},
		{name: "destroy stopped", desired: controlstore.DeploymentAbsent, phase: controlstore.DeploymentInstanceDestroying, want: "destroy"},
		{name: "ignore pending removal", desired: controlstore.DeploymentAbsent, phase: controlstore.DeploymentInstancePending},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance := controlstore.DeploymentInstance{Phase: test.phase, LeaseExpiresAt: test.leaseExpiry}
			if got := nextOperation(test.desired, instance, test.leaseManaged, now); got != test.want {
				t.Fatalf("next operation=%q want=%q", got, test.want)
			}
		})
	}
}

func TestReconcilerRemovesPendingDeploymentWithoutNodeEffect(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	deployment := getControlDeployment(t, fixture)
	removed, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "research", deployment.Revision,
		controlstore.DeploymentAbsent, fixture.now.Add(time.Second),
	)
	if err != nil || !changed {
		t.Fatalf("set absent = (%+v, %v, %v)", removed, changed, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	reconciler := fixture.reconciler(t)
	report, err := reconciler.Reconcile(context.Background())
	deployment = getControlDeployment(t, fixture)
	if err != nil || report.Removed != 1 || report.Enqueued != 0 ||
		deployment.Phase != controlstore.DeploymentRemoved ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceRemoved ||
		deployment.Instances[0].NodeID != "" || deployment.Instances[0].Attempts != 0 {
		t.Fatalf("remove pending = report %+v deployment %+v err %v", report, deployment, err)
	}
}

func TestReconcilerRejectsInvalidConfigurationAndStopsWithContext(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	if _, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: fixture.controller,
		Interval: time.Second,
	}); err == nil {
		t.Fatal("reconciler accepted missing node freshness threshold")
	}
	reconciler := fixture.reconciler(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reconciler.Run(ctx); err != nil {
		t.Fatalf("canceled reconciler run = %v", err)
	}
	if _, err := (*Reconciler)(nil).Reconcile(context.Background()); err == nil {
		t.Fatal("nil reconciler accepted reconciliation")
	}
}

func TestReconcilerClassifiesMalformedAuthorityAndBoundaries(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	deployment := getControlDeployment(t, fixture)
	instance := deployment.Instances[0]
	if reason := (blockedError{reason: controlstore.DeploymentBlockedNoEligibleNode}).Error(); reason != string(controlstore.DeploymentBlockedNoEligibleNode) {
		t.Fatalf("blocked error reason = %q", reason)
	}

	if _, err := reconciler.signCommand(controlstore.Deployment{}, instance, "node-1", "admit", fixture.now); err == nil ||
		err.Error() != string(controlstore.DeploymentBlockedInvalidAuthority) {
		t.Fatalf("malformed authority error = %v", err)
	}
	missing := instance
	missing.InstanceID = "not-delegated"
	if _, err := reconciler.signCommand(deployment, missing, "node-1", "admit", fixture.now); err == nil ||
		err.Error() != string(controlstore.DeploymentBlockedInvalidAuthority) {
		t.Fatalf("missing instance authority error = %v", err)
	}
	overflow := instance
	overflow.CommandSequence = ^uint64(0)
	if _, err := reconciler.signCommand(deployment, overflow, "node-1", "start", fixture.now); !errors.Is(err, controlstore.ErrCapacityExceeded) {
		t.Fatalf("command sequence overflow error = %v", err)
	}
	if _, _, err := selectNode(nil, nil, nil, controlstore.Deployment{}, instance, fixture.now, time.Minute); err == nil {
		t.Fatal("malformed placement authority was accepted")
	}
	if eligibleNode(controlstore.Node{Active: true, LastSeenAt: "bad"}, "tenant-a", map[string]struct{}{}, fixture.now, time.Minute) {
		t.Fatal("node with malformed observation time was eligible")
	}
	allowed := map[string]struct{}{"node-1": {}}
	maintenanceNode := controlstore.Node{
		ID: "node-1", Active: true, CreatedAt: fixture.now.Format(time.RFC3339Nano),
		LastSeenAt: fixture.now.Format(time.RFC3339Nano), TenantIDs: []string{"tenant-a"},
		Capabilities: []string{controlprotocol.ExecutorCapabilityControllerDelegationV1},
		Placement: &controlstore.NodePlacement{
			Mode: controlstore.NodeCordoned, Reason: "maintenance", ChangedAt: fixture.now.Format(time.RFC3339Nano),
		},
	}
	if eligibleNode(maintenanceNode, "tenant-a", allowed, fixture.now, time.Minute) ||
		!nodeAvailableForAssignment(maintenanceNode, "tenant-a", allowed, fixture.now, time.Minute) {
		t.Fatal("cordon did not exclude only new placement")
	}
	maintenanceNode.Placement.Mode = controlstore.NodeQuarantined
	if eligibleNode(maintenanceNode, "tenant-a", allowed, fixture.now, time.Minute) ||
		nodeAvailableForAssignment(maintenanceNode, "tenant-a", allowed, fixture.now, time.Minute) {
		t.Fatal("quarantine left node available for placement or assignment")
	}
	if err := (*Reconciler)(nil).Run(context.Background()); err == nil {
		t.Fatal("nil reconciler accepted run")
	}
	for _, keyID := range []string{"", "-leading", "bad space", strings.Repeat("a", 257)} {
		if validKeyID(keyID) {
			t.Fatalf("invalid key ID accepted: %q", keyID)
		}
	}
}

func newControlReconcileFixture(t *testing.T) *reconcileFixture {
	t.Helper()
	limits := controlstore.DefaultLimits()
	dir := filepath.Join(t.TempDir(), "control")
	store, err := controlstore.Initialize(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := controlauth.New(bytes.Repeat([]byte{0x44}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	adminRaw, _, _, err := store.BootstrapSiteAdmin(auth, now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AuthenticateOperator(auth, adminRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateTenant(admin, "tenant-a", now); err != nil {
		t.Fatal(err)
	}
	enrollmentRaw, enrollment, _, err := store.CreateEnrollment(
		admin, auth, "node-1", []string{"tenant-a"}, now.Add(time.Hour), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	public, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		auth.InstanceID(), enrollment.ID, "node-1", "node-1", 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.ExchangeEnrollment(auth, enrollmentRaw, "enroll-node-1", proof, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.AuthenticateNode(auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	if deliveries, err := store.PollV4(node, capabilities, now.Add(2*time.Minute), time.Minute, 1); err != nil || len(deliveries) != 0 {
		t.Fatalf("prime node capabilities = (%+v, %v)", deliveries, err)
	}
	if _, _, err := store.ObserveNodeScheduling(node, testSchedulingObservation("node-1"), now.Add(2*time.Minute)); err != nil {
		t.Fatalf("prime node scheduling = %v", err)
	}
	_, controller, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &reconcileFixture{
		store: store, auth: auth, admin: admin, node: node, now: now.Add(3 * time.Minute),
		nodeIDs: []string{"node-1"}, dir: dir, controller: controller, limits: limits,
	}
}

func addControlNode(t *testing.T, fixture *reconcileFixture, nodeID string) controlauth.NodeIdentity {
	t.Helper()
	enrollmentRaw, enrollment, _, err := fixture.store.CreateEnrollment(
		fixture.admin, fixture.auth, nodeID, []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	public, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		fixture.auth.InstanceID(), enrollment.ID, nodeID, nodeID, 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := fixture.store.ExchangeEnrollment(
		fixture.auth, enrollmentRaw, "enroll-"+nodeID, proof, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.store.AuthenticateNode(fixture.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	fixture.now = fixture.now.Add(2 * time.Minute)
	if deliveries, err := fixture.store.PollV4(node, capabilities, fixture.now, time.Minute, 1); err != nil || len(deliveries) != 0 {
		t.Fatalf("prime %s capabilities = (%+v, %v)", nodeID, deliveries, err)
	}
	if _, _, err := fixture.store.ObserveNodeScheduling(node, testSchedulingObservation(nodeID), fixture.now); err != nil {
		t.Fatalf("prime %s scheduling = %v", nodeID, err)
	}
	fixture.nodeIDs = append(fixture.nodeIDs, nodeID)
	return node
}

func (fixture *reconcileFixture) reconciler(t *testing.T) *Reconciler {
	t.Helper()
	reconciler, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: fixture.controller,
		Interval: time.Second, NodeStaleAfter: 2 * time.Minute,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func applyControlDeployment(t *testing.T, fixture *reconcileFixture, generation uint64) {
	applyControlDeploymentNamed(t, fixture, "research", "research-0", "research-lineage-0", generation)
}

func applyControlDeploymentNamed(
	t *testing.T,
	fixture *reconcileFixture,
	deploymentID, instanceID, lineageID string,
	generation uint64,
) {
	t.Helper()
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: deploymentID + "-capsule", PublisherKeyID: "publisher-a",
		Profile: admission.ProfileRef{ID: "generic-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository: "registry.example/" + deploymentID, ManifestDigest: "sha256:" + strings.Repeat("c", 64),
			ConfigDigest: "sha256:" + strings.Repeat("d", 64),
			Platform:     admission.Platform{OS: "linux", Architecture: "amd64"},
		},
		Command:   []string{"/agent", "serve"},
		Resources: admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		State:     admission.StateShape{SchemaVersion: "v1", Path: "/state"},
	}
	capsulePayload, err := json.Marshal(capsule)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Sign(
		admission.CapsulePayloadType, capsulePayload, "publisher-a", publisherPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, err := dsse.Marshal(capsuleEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  deploymentID + "-authority", TenantID: "tenant-a",
		ControllerKeyID:     "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(fixture.controller.Public().(ed25519.PublicKey)),
		Operations:          []string{"admit", "destroy", "renew", "start", "stop"}, NodeIDs: append([]string(nil), fixture.nodeIDs...),
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: instanceID, LineageID: lineageID,
			MinInstanceGeneration: generation, MaxInstanceGeneration: generation + 4,
		}},
		ClaimGeneration: generation,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest:    dsse.Digest(capsuleRaw),
			Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
			StateDisposition: "none",
		},
		IssuedAt:  fixture.now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: fixture.now.Add(23 * time.Hour).Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	_, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandDelegationPayloadType, payload, "tenant-command-a", tenantPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	expectedRevision := uint64(0)
	if existing, found, err := fixture.store.GetDeployment(fixture.admin, "tenant-a", deploymentID); err != nil {
		t.Fatal(err)
	} else if found {
		expectedRevision = existing.Revision
	}
	if _, changed, err := fixture.store.ApplyDeployment(fixture.admin, controlstore.DeploymentApply{
		TenantID: "tenant-a", ID: deploymentID, Generation: generation,
		ExpectedRevision: expectedRevision,
		AgentName:        deploymentID + "-agent", BundleDigest: "sha256:" + strings.Repeat("a", 64),
		CapsuleDSSE: capsuleRaw, DelegationDSSE: delegationRaw,
	}, fixture.now); err != nil || !changed {
		t.Fatalf("apply deployment = (%v, %v)", changed, err)
	}
}

func completeDeploymentCommand(t *testing.T, fixture *reconcileFixture, operation, status string) {
	t.Helper()
	fixture.now = fixture.now.Add(time.Minute)
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	deliveries, err := fixture.store.PollV4(fixture.node, capabilities, fixture.now, time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll %s = (%+v, %v)", operation, deliveries, err)
	}
	observeControlNodeScheduling(t, fixture)
	deployment := getControlDeployment(t, fixture)
	instance := deployment.Instances[0]
	if instance.CommandOperation != operation || instance.CommandID != deliveries[0].CommandID {
		t.Fatalf("%s delivery differs from cursor: delivery=%+v instance=%+v", operation, deliveries[0], instance)
	}
	commandRaw, err := base64.StdEncoding.DecodeString(deliveries[0].CommandDSSEBase64)
	if err != nil {
		t.Fatalf("decode %s command: %v", operation, err)
	}
	capsuleRaw, delegationRaw, err := controlstore.DeploymentAuthorityForInstance(deployment, instance)
	if err != nil {
		t.Fatalf("select %s authority: %v", operation, err)
	}
	statement, err := admission.VerifyControllerCommand(commandRaw, delegationRaw, fixture.now)
	if err != nil {
		t.Fatalf("verify %s command: %v", operation, err)
	}
	runtimeDigest := sha256.Sum256([]byte(deployment.TenantID + "\x00" + instance.InstanceID))
	runtimeRef := "executor-" + hex.EncodeToString(runtimeDigest[:])
	reported := "stopped"
	if operation == "start" {
		reported = "running"
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		CommandID: deliveries[0].CommandID, CommandDigest: deliveries[0].CommandDigest,
		Status: status, ReportedStatus: reported, ClaimGeneration: statement.ClaimGeneration,
		Result: controlprotocol.ExecutorReportResultV4{RuntimeRef: runtimeRef},
	}
	if status == controlprotocol.ExecutorStatusDone && operation == "admit" {
		report.Result.Admission = &controlprotocol.ExecutorAdmissionProjectionV1{
			SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
			RuntimeRef:    runtimeRef, Status: "created",
			CapsuleDigest: dsse.Digest(capsuleRaw),
			PolicyDigest:  "sha256:" + strings.Repeat("b", 64),
			Generation:    instance.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		}
	}
	if status == controlprotocol.ExecutorStatusOutcomeUnknown {
		report.ReportedStatus = "failed"
		report.ErrorCode = "local_outcome_unknown"
		report.Result.Error = "executor response was lost after dispatch"
	}
	if operation == "destroy" && status == controlprotocol.ExecutorStatusDone {
		report.Result.Absent = true
	}
	if applied, err := fixture.store.ApplyReportV4(fixture.node, report, fixture.now.Add(time.Second)); err != nil || !applied {
		t.Fatalf("report %s = (%v, %v)", operation, applied, err)
	}
	fixture.now = fixture.now.Add(2 * time.Second)
}

func heartbeatControlNode(t *testing.T, fixture *reconcileFixture) {
	t.Helper()
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	if deliveries, err := fixture.store.PollV4(
		fixture.node, capabilities, fixture.now, time.Minute, 1,
	); err != nil || len(deliveries) != 0 {
		t.Fatalf("heartbeat node = (%+v, %v)", deliveries, err)
	}
	observeControlNodeScheduling(t, fixture)
}

func observeControlNodeScheduling(t *testing.T, fixture *reconcileFixture) {
	t.Helper()
	if _, _, err := fixture.store.ObserveNodeScheduling(
		fixture.node, testSchedulingObservation(fixture.node.NodeID), fixture.now,
	); err != nil {
		t.Fatalf("observe node scheduling = %v", err)
	}
}

func testSchedulingObservation(nodeID string) controlprotocol.ExecutorSchedulingObservationV1 {
	return controlprotocol.ExecutorSchedulingObservationV1{
		SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
		NodeID:        nodeID, CredentialScope: "node", OS: "linux", Architecture: "amd64",
		Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor,
		Labels:    []controlprotocol.ExecutorSchedulingLabelV1{}, Taints: []string{},
		Policy: controlprotocol.ExecutorSchedulingPolicyV1{
			PerWorkload: controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 256, Workloads: 1,
			},
			Host: controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: 8 << 30, CPUMillis: 8000, PIDs: 2048, Workloads: 32,
			},
			Tenant: controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: 2 << 30, CPUMillis: 2000, PIDs: 512, Workloads: 4,
			},
			RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{
				MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
			},
		},
	}
}

func assertReconcileCount(t *testing.T, reconciler *Reconciler, label string, observed, enqueued int) {
	t.Helper()
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Observed != observed || report.Enqueued != enqueued {
		t.Fatalf("%s = (%+v, %v)", label, report, err)
	}
}

func getControlDeployment(t *testing.T, fixture *reconcileFixture) controlstore.Deployment {
	t.Helper()
	deployment, found, err := fixture.store.GetDeployment(fixture.admin, "tenant-a", "research")
	if err != nil || !found {
		t.Fatalf("get deployment = (%+v, %v, %v)", deployment, found, err)
	}
	return deployment
}
