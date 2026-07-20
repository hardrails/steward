package controlstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestDeploymentApplyIsBoundedIdempotentRevisionedAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	if deliveries, err := fixture.store.PollV4(
		nodeIdentity,
		[]string{controlprotocol.ExecutorCapabilityControllerDelegationV1},
		fixture.now.Add(2*time.Minute), time.Minute, 1,
	); err != nil || len(deliveries) != 0 {
		t.Fatalf("prime node capability = (%+v, %v)", deliveries, err)
	}
	input := deploymentApplyFixture(t, fixture.now, "deployment-a", 1)

	created, changed, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(2*time.Minute))
	if err != nil || !changed || created.Revision != 1 || created.Phase != DeploymentPending ||
		created.DesiredState != DeploymentRunning || len(created.Instances) != 2 ||
		created.Instances[0].Phase != DeploymentInstancePending {
		t.Fatalf("create deployment = (%+v, %v, %v)", created, changed, err)
	}
	retry, changed, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(3*time.Minute))
	if err != nil || changed || !reflect.DeepEqual(retry, created) {
		t.Fatalf("retry deployment = (%+v, %v, %v)", retry, changed, err)
	}

	rollout := deploymentApplyFixture(t, fixture.now.Add(3*time.Minute), "deployment-a", 2)
	rollout.ExpectedRevision = 99
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, rollout, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale deployment revision error = %v", err)
	}
	rollout.ExpectedRevision = created.Revision
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, rollout, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("live deployment rollout error = %v", err)
	}
	removed := created
	for index := range removed.Instances {
		removed.Instances[index].Phase = DeploymentInstanceRemoved
	}
	removed.DesiredState = DeploymentAbsent
	removed.Phase = DeploymentRemoved
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = removed
	fixture.store.mu.Unlock()
	updated, changed, err := fixture.store.ApplyDeployment(fixture.admin, rollout, fixture.now.Add(4*time.Minute))
	if err != nil || !changed || updated.Generation != 2 || updated.Revision != 2 ||
		updated.CreatedAt != created.CreatedAt || updated.UpdatedAt == created.UpdatedAt {
		t.Fatalf("rollout deployment = (%+v, %v, %v)", updated, changed, err)
	}
	scaleDown := deploymentApplyFixtureWithInstanceCount(t, fixture.now.Add(4*time.Minute), "deployment-a", 3, 1)
	scaleDown.ExpectedRevision = updated.Revision
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, scaleDown, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollout omitted live instance error = %v", err)
	}
	absent, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", updated.Revision,
		DeploymentAbsent, fixture.now.Add(6*time.Minute),
	)
	if err != nil || !changed || absent.Revision != 3 || absent.Phase != DeploymentStopping {
		t.Fatalf("remove deployment = (%+v, %v, %v)", absent, changed, err)
	}
	if _, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", 1,
		DeploymentAbsent, fixture.now.Add(6*time.Minute),
	); err != nil || changed {
		t.Fatalf("idempotent desired-state retry = (%v, %v)", changed, err)
	}

	status, err := fixture.store.Status()
	if err != nil || status.Deployments != 1 {
		t.Fatalf("deployment status = (%+v, %v)", status, err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen deployment state: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, found, err := reopened.GetDeployment(fixture.admin, "tenant-a", "deployment-a")
	if err != nil || !found || !reflect.DeepEqual(loaded, absent) {
		t.Fatalf("recovered deployment = (%+v, %v, %v)", loaded, found, err)
	}
}

func TestDeploymentUpdateCannotForgetAuthorityForAFormerRuntime(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	next := deploymentApplyFixture(t, fixture.now.Add(time.Minute), "deployment-a", 2)
	next.ExpectedRevision = created.Revision
	for _, phase := range []DeploymentInstancePhase{
		DeploymentInstancePending, DeploymentInstanceAdmitting, DeploymentInstanceStarting,
		DeploymentInstanceRunning, DeploymentInstanceStopping, DeploymentInstanceDestroying,
		DeploymentInstanceFailed,
	} {
		t.Run(string(phase), func(t *testing.T) {
			current := created
			current.Instances = append([]DeploymentInstance(nil), created.Instances...)
			current.Instances[0].Phase = phase
			fixture.store.mu.Lock()
			fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = current
			fixture.store.mu.Unlock()
			if _, _, err := fixture.store.ApplyDeployment(fixture.admin, next, fixture.now.Add(2*time.Minute)); !errors.Is(err, ErrConflict) {
				t.Fatalf("phase %s update error = %v", phase, err)
			}
		})
	}
}

func TestDeploymentRolloutRetainsSourceAuthorityAndSpendsBudgetAtomically(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	if deliveries, err := fixture.store.PollV4(
		nodeIdentity,
		[]string{controlprotocol.ExecutorCapabilityControllerDelegationV1},
		fixture.now.Add(2*time.Minute), time.Minute, 1,
	); err != nil || len(deliveries) != 0 {
		t.Fatalf("prime rollout node capability = (%+v, %v)", deliveries, err)
	}
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	ready := fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")]
	for index := range ready.Instances {
		ready.Instances[index].NodeID = "node-1"
		ready.Instances[index].Phase = DeploymentInstanceRunning
	}
	ready.Phase = DeploymentReady
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = ready
	fixture.store.mu.Unlock()

	targetInput := deploymentApplyFixture(t, fixture.now.Add(time.Minute), "deployment-a", 2)
	targetInput.ExpectedRevision = created.Revision
	target, changed, err := fixture.store.ApplyDeployment(fixture.admin, targetInput, fixture.now.Add(time.Minute))
	if err != nil || !changed || target.Rollout == nil || target.Rollout.SourceGeneration != 1 ||
		target.Generation != 2 || target.Phase != DeploymentReconciling {
		t.Fatalf("apply rollout = (%+v, %v, %v)", target, changed, err)
	}
	for _, instance := range target.Instances {
		_, selected, selectErr := DeploymentAuthorityForInstance(target, instance)
		if selectErr != nil || bytes.Equal(selected, target.DelegationDSSE) {
			t.Fatalf("source authority was discarded before destroy: %v", selectErr)
		}
	}
	if _, _, err := fixture.store.StartNodeDrain(
		fixture.admin, "node-1", "maintenance-during-rollout", "kernel maintenance", fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("node drain raced active rollout: %v", err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", "missing-instance", target.Revision, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout instance error = %v", err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, target.Revision+1, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rollout revision error = %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout(
		"tenant-a", "deployment-a", "missing-instance", target.Revision, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout advance instance error = %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, target.Revision, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("unstarted rollout advance error = %v", err)
	}
	fixture.store.mu.Lock()
	node := fixture.store.current.nodes["node-1"]
	delete(fixture.store.current.nodes, "node-1")
	fixture.store.mu.Unlock()
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, target.Revision, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("rollout on inactive node error = %v", err)
	}
	fixture.store.mu.Lock()
	fixture.store.current.nodes["node-1"] = node
	fixture.store.mu.Unlock()
	fixture.store.mu.Lock()
	maxRevisionDeployment := fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")]
	maxRevisionDeployment.Revision = ^uint64(0)
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = maxRevisionDeployment
	fixture.store.mu.Unlock()
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, ^uint64(0), fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("rollout revision overflow error = %v", err)
	}
	fixture.store.mu.Lock()
	maxRevisionDeployment.Revision = target.Revision
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = maxRevisionDeployment
	fixture.store.mu.Unlock()

	rolling, changed, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, target.Revision, fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed || rolling.Instances[0].Rollout == nil ||
		rolling.Instances[0].Rollout.Stage != "draining" {
		t.Fatalf("begin first instance = (%+v, %v, %v)", rolling, changed, err)
	}
	if same, changed, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, rolling.Revision, fixture.now.Add(2*time.Minute),
	); err != nil || changed || same.Revision != rolling.Revision {
		t.Fatalf("idempotent rollout begin = (%+v, %v, %v)", same, changed, err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[1].InstanceID, rolling.Revision, fixture.now.Add(2*time.Minute),
	); !errors.Is(err, ErrDisruptionBudget) {
		t.Fatalf("second instance exceeded disruption budget: %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout(
		"tenant-a", "deployment-a", target.Instances[0].InstanceID, rolling.Revision, fixture.now.Add(3*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("instance advanced without a proven destroy: %v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatalf("reopen rollout state: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	recovered, found, err := reopened.GetDeployment(fixture.admin, "tenant-a", "deployment-a")
	if err != nil || !found || recovered.Rollout == nil || recovered.Instances[0].Rollout == nil {
		t.Fatalf("recover rollout = (%+v, %v, %v)", recovered, found, err)
	}
	_, selected, err := DeploymentAuthorityForInstance(recovered, recovered.Instances[0])
	if err != nil || bytes.Equal(selected, recovered.DelegationDSSE) {
		t.Fatalf("restart discarded source authority: %v", err)
	}
	missingAuthorityInstance := recovered.Instances[0]
	missingAuthorityInstance.InstanceID = "missing-instance"
	if _, _, err := DeploymentAuthorityForInstance(recovered, missingAuthorityInstance); err == nil {
		t.Fatal("rollout selected authority for an undelegated instance")
	}
	malformedAuthority := cloneDeployment(recovered)
	malformedAuthority.DelegationDSSE = []byte(`{}`)
	if _, _, err := DeploymentAuthorityForInstance(malformedAuthority, malformedAuthority.Instances[0]); err == nil {
		t.Fatal("rollout selected malformed target authority")
	}
	unknownStage := recovered.Instances[0]
	unknownStage.Rollout = cloneDeploymentInstanceRollout(unknownStage.Rollout)
	unknownStage.Rollout.Stage = "unknown"
	if _, _, err := DeploymentAuthorityForInstance(recovered, unknownStage); err == nil {
		t.Fatal("rollout selected authority for an unknown stage")
	}
	if !deploymentUsesRolloutFormat(Deployment{
		Instances: []DeploymentInstance{{Rollout: &DeploymentInstanceRollout{Stage: "draining"}}},
	}) {
		t.Fatal("instance rollout cursor did not require the rollout store format")
	}
	if err := validateDeployment(recovered, fixture.limits); err != nil {
		t.Fatalf("recovered rollout validation: %v", err)
	}
	invalidRollout := cloneDeployment(recovered)
	invalidRollout.Rollout.StartedAt = "not-a-time"
	if err := validateDeployment(invalidRollout, fixture.limits); err == nil {
		t.Fatal("rollout with malformed start time was accepted")
	}
	invalidRollout = cloneDeployment(recovered)
	invalidRollout.Rollout.SourceDelegationDSSE = []byte(`{}`)
	if err := validateDeployment(invalidRollout, fixture.limits); err == nil {
		t.Fatal("rollout with malformed source authority was accepted")
	}
	invalidRollout = cloneDeployment(recovered)
	invalidRollout.Rollout.SourceDelegationDSSE = rewriteDeploymentDelegation(
		t, invalidRollout.Rollout.SourceDelegationDSSE,
		func(value *admission.CommandDelegation) { value.Instances[0].LineageID = "other-lineage" },
	)
	if err := validateDeployment(invalidRollout, fixture.limits); err == nil {
		t.Fatal("rollout whose source changes lineage identity was accepted")
	}
	invalidRollout = cloneDeployment(recovered)
	sourceCapsuleEnvelope, err := dsse.Parse(invalidRollout.Rollout.SourceCapsuleDSSE)
	if err != nil {
		t.Fatal(err)
	}
	sourceCapsuleEnvelope.PayloadType = "application/vnd.steward.invalid"
	invalidRollout.Rollout.SourceCapsuleDSSE, err = dsse.Marshal(sourceCapsuleEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	invalidRollout.Rollout.SourceDelegationDSSE = rewriteDeploymentDelegation(
		t, invalidRollout.Rollout.SourceDelegationDSSE,
		func(value *admission.CommandDelegation) {
			value.Admission.CapsuleDigest = dsse.Digest(invalidRollout.Rollout.SourceCapsuleDSSE)
		},
	)
	if err := validateDeployment(invalidRollout, fixture.limits); err == nil {
		t.Fatal("rollout with a non-capsule source envelope was accepted")
	}
	invalidRollout = cloneDeployment(recovered)
	invalidRollout.Instances[0].Rollout.StartedAt = "not-a-time"
	if err := validateDeployment(invalidRollout, fixture.limits); err == nil {
		t.Fatal("rollout with malformed instance cursor was accepted")
	}
	reopened.mu.Lock()
	current := reopened.current.clone()
	reopened.mu.Unlock()
	snapshotRaw, err := encodeState(current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var legacy snapshotState
	if err := json.Unmarshal(snapshotRaw, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.Version = stateFormatRolloutVersion - 1
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(legacyRaw, fixture.limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled rollout state")
	}
	if _, err := applyTransaction(current, transaction{
		Version:   transactionRolloutVersion - 1,
		Mutations: []mutation{deploymentMutation(recovered)},
	}); err == nil {
		t.Fatal("legacy transaction smuggled rollout state")
	}
}

func rewriteDeploymentDelegation(
	t *testing.T,
	raw []byte,
	mutate func(*admission.CommandDelegation),
) []byte {
	t.Helper()
	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var delegation admission.CommandDelegation
	if err := json.Unmarshal(payload, &delegation); err != nil {
		t.Fatal(err)
	}
	mutate(&delegation)
	payload, err = json.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	rewritten, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return rewritten
}

func TestDeploymentRolloutTransitionsRejectUnavailableAndInvalidInputs(t *testing.T) {
	var unavailable *Store
	now := time.Date(2026, 7, 20, 20, 0, 0, 0, time.UTC)
	if _, _, err := unavailable.BeginDeploymentInstanceRollout("tenant", "deployment", "instance", 1, now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil rollout store error = %v", err)
	}
	if _, _, err := unavailable.AdvanceDeploymentInstanceRollout("tenant", "deployment", "instance", 1, now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil rollout advance store error = %v", err)
	}
	fixture := newRecordsFixture(t, DefaultLimits())
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout("", "", "", 0, time.Time{}); err == nil {
		t.Fatal("invalid rollout input was accepted")
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout("", "", "", 0, time.Time{}); err == nil {
		t.Fatal("invalid rollout advance input was accepted")
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout("tenant", "deployment", "instance", 1, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout deployment error = %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout("tenant", "deployment", "instance", 1, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rollout advance deployment error = %v", err)
	}
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment", 1), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment", created.Instances[0].InstanceID, created.Revision, now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("deployment without rollout begin error = %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout(
		"tenant-a", "deployment", created.Instances[0].InstanceID, created.Revision, now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("deployment without rollout advance error = %v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.BeginDeploymentInstanceRollout(
		"tenant-a", "deployment", created.Instances[0].InstanceID, created.Revision, now,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed rollout store error = %v", err)
	}
	if _, _, err := fixture.store.AdvanceDeploymentInstanceRollout(
		"tenant-a", "deployment", created.Instances[0].InstanceID, created.Revision, now,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed rollout advance store error = %v", err)
	}
}

func TestDeploymentMissingCommandFailsClosedAndActiveCommandIsRetained(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}

	instance := created.Instances[0]
	instance.NodeID = "node-1"
	instance.Phase = DeploymentInstanceStarting
	instance.CommandID = "deployment-command"
	instance.CommandOperation = "start"
	instance.CommandSequence = 1
	instance.TransitionedAt = canonicalTimestamp(fixture.now.Add(time.Minute))
	created.Instances[0] = instance
	created.Revision++
	created.UpdatedAt = instance.TransitionedAt
	command := Command{
		TenantID: "tenant-a", NodeID: "node-1", ID: instance.CommandID,
		State: CommandTerminal,
		Terminal: &TerminalReport{
			Report:      controlprotocol.ExecutorReportV3{Status: controlprotocol.ExecutorStatusDone},
			CompletedAt: canonicalTimestamp(fixture.now.Add(-48 * time.Hour)),
		},
	}

	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = created
	fixture.store.current.commands[commandKey("tenant-a", "node-1", command.ID)] = command
	prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now)
	delete(fixture.store.current.commands, commandKey("tenant-a", "node-1", command.ID))
	fixture.store.mu.Unlock()
	if len(prunable) != 0 {
		t.Fatalf("active deployment command became prunable: %+v", prunable)
	}

	failed, changed, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instance.InstanceID, created.Revision, fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed || failed.Phase != DeploymentDegraded ||
		failed.Instances[0].Phase != DeploymentInstanceFailed ||
		failed.Instances[0].LastError != deploymentCommandRecordMissing {
		t.Fatalf("missing command observation = (%+v, %v, %v)", failed, changed, err)
	}
}

func TestDeploymentLegacyInflightAdmitCompletesWithoutTaskReadyProjection(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	instance := created.Instances[0]
	instance.NodeID = "node-1"
	instance.Phase = DeploymentInstanceAdmitting
	instance.CommandID = "legacy-admit"
	instance.CommandOperation = "admit"
	instance.CommandSequence = 1
	instance.Intent = nil
	instance.Admission = nil
	instance.TransitionedAt = canonicalTimestamp(fixture.now.Add(time.Minute))
	created.Instances[0] = instance
	created.Revision++
	created.UpdatedAt = instance.TransitionedAt
	statement := baseV4CommandStatement(instance.CommandID, "tenant-a", "node-1", "admit", 1, instance.Generation)
	statement.InstanceID = instance.InstanceID
	raw := signV4CommandStatement(t, statement)
	if _, submitted, err := fixture.store.SubmitCommand(
		fixture.admin, "tenant-a", "node-1", raw, fixture.now.Add(2*time.Minute),
	); err != nil || !submitted {
		t.Fatalf("submit legacy admit = (%v, %v)", submitted, err)
	}
	deliveries, err := fixture.store.Poll(node, []string{}, fixture.now.Add(3*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll legacy admit = (%+v, %v)", deliveries, err)
	}
	if applied, err := fixture.store.ApplyReport(
		node, reportFor(deliveries[0], controlprotocol.ExecutorStatusDone), fixture.now.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply legacy admit report = (%v, %v)", applied, err)
	}

	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = created
	fixture.store.mu.Unlock()

	observed, changed, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instance.InstanceID, created.Revision, fixture.now.Add(5*time.Minute),
	)
	if err != nil || !changed || observed.Instances[0].Phase != DeploymentInstanceStarting ||
		observed.Instances[0].LastError != "" || observed.Instances[0].Intent != nil ||
		observed.Instances[0].Admission != nil {
		t.Fatalf("legacy admit observation = (%+v, %v, %v)", observed, changed, err)
	}

	withIntent := observed
	current := withIntent.Instances[0]
	current.Phase = DeploymentInstanceAdmitting
	current.Intent = &admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-1", InstanceID: current.InstanceID, LineageID: current.LineageID,
		Generation: current.Generation, CapsuleDigest: dsse.Digest(withIntent.CapsuleDSSE),
		Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		StateDisposition: "none",
	}
	withIntent.Instances[0] = current
	withIntent.Revision++
	withIntent.UpdatedAt = canonicalTimestamp(fixture.now.Add(6 * time.Minute))
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = withIntent
	fixture.store.mu.Unlock()
	failed, changed, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", current.InstanceID, withIntent.Revision, fixture.now.Add(7*time.Minute),
	)
	if err != nil || !changed || failed.Instances[0].Phase != DeploymentInstanceFailed ||
		failed.Instances[0].LastError != "admission_projection_missing" {
		t.Fatalf("current admit without projection = (%+v, %v, %v)", failed, changed, err)
	}
}

func TestDeploymentScopeIsolationCapacityAndLegacyFormat(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDeployments = 1
	limits.MaxDeploymentsPerTenant = 1
	fixture := newRecordsFixture(t, limits)
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	fixture.createNode(t, "tenant-a", "tenant-b")
	input := deploymentApplyFixture(t, fixture.now, "deployment-a", 1)
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	tenantRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "deployment-operator-b", controlauth.RoleTenantOperator,
		"tenant-b", fixture.now.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := fixture.store.AuthenticateOperator(fixture.auth, tenantRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := fixture.store.GetDeployment(tenantB, "tenant-a", "deployment-a"); err != nil || found {
		t.Fatalf("cross-tenant deployment lookup = (%v, %v)", found, err)
	}
	if deployments, err := fixture.store.ListDeployments(tenantB, ""); err != nil || len(deployments) != 0 {
		t.Fatalf("tenant deployment projection = (%+v, %v)", deployments, err)
	}
	second := deploymentApplyFixture(t, fixture.now, "deployment-b", 1)
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, second, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("deployment capacity error = %v", err)
	}

	fixture.store.mu.Lock()
	current := fixture.store.current.clone()
	fixture.store.mu.Unlock()
	raw, err := encodeState(current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	legacy := snapshot
	legacy.Version = stateFormatCaptureVersion
	legacy.Deployments = nil
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyRaw, fixture.limits.MaxStateBytes)
	if err != nil || migrated.deployments == nil || len(migrated.deployments) != 0 {
		t.Fatalf("legacy deployment migration = (%+v, %v)", migrated.deployments, err)
	}
	snapshot.Version = stateFormatCaptureVersion
	if smuggled, err := json.Marshal(snapshot); err != nil {
		t.Fatal(err)
	} else if _, err := decodeState(smuggled, fixture.limits.MaxStateBytes); err == nil {
		t.Fatal("format-4 snapshot smuggled deployment state")
	}
	change := deploymentMutation(current.deployments[deploymentKey("tenant-a", "deployment-a")])
	if _, err := applyTransaction(current, transaction{
		Version: transactionCaptureVersion, Mutations: []mutation{change},
	}); err == nil {
		t.Fatal("format-4 transaction smuggled deployment state")
	}
}

func TestDeploymentBlockedReasonIsDurableBoundedAndIdempotent(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin, deploymentApplyFixture(t, fixture.now, "deployment-a", 1),
		fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	instanceID := created.Instances[0].InstanceID
	blocked, changed, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", instanceID, created.Revision,
		DeploymentBlockedNoEligibleNode, fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed || blocked.Revision != created.Revision+1 ||
		blocked.Instances[0].Phase != DeploymentInstancePending ||
		blocked.Instances[0].LastError != string(DeploymentBlockedNoEligibleNode) {
		t.Fatalf("record blocked reason = (%+v, %v, %v)", blocked, changed, err)
	}
	retry, changed, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", instanceID, blocked.Revision,
		DeploymentBlockedNoEligibleNode, fixture.now.Add(3*time.Minute),
	)
	if err != nil || changed || !reflect.DeepEqual(retry, blocked) {
		t.Fatalf("repeat blocked reason = (%+v, %v, %v)", retry, changed, err)
	}
	if _, _, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", instanceID, blocked.Revision,
		DeploymentBlockedReason("free-form detail"), fixture.now.Add(4*time.Minute),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded blocked reason error = %v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, found, err := reopened.GetDeployment(fixture.admin, "tenant-a", "deployment-a")
	if err != nil || !found || loaded.Instances[0].LastError != string(DeploymentBlockedNoEligibleNode) {
		t.Fatalf("recovered blocked reason = (%+v, %v, %v)", loaded, found, err)
	}
}

func TestDeploymentReplacementWaitsForLeaseFenceAndAdvancesGeneration(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	created, _, err := fixture.store.ApplyDeployment(
		fixture.admin,
		deploymentApplyFixture(t, fixture.now, "deployment-a", 1),
		fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaseExpiry := fixture.now.Add(2 * time.Minute).UTC()
	fixture.store.mu.Lock()
	deployment := fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")]
	instance := deployment.Instances[0]
	instance.NodeID = "node-1"
	instance.Phase = DeploymentInstanceRunning
	instance.LeaseExpiresAt = leaseExpiry.Format(time.RFC3339Nano)
	instance.CommandID = "renew-command"
	instance.CommandOperation = "renew"
	instance.CommandSequence = 7
	instance.Attempts = 3
	instance.TransitionedAt = canonicalTimestamp(fixture.now)
	deployment.Instances[0] = instance
	deployment.Phase = DeploymentReady
	fixture.store.current.deployments[deploymentKey("tenant-a", "deployment-a")] = deployment
	fixture.store.current.commands[commandKey("tenant-a", "node-1", instance.CommandID)] = Command{
		TenantID: "tenant-a", NodeID: "node-1", ID: instance.CommandID, State: CommandPending,
	}
	fixture.store.mu.Unlock()

	if _, _, err := fixture.store.ReplaceDeploymentInstance(
		"tenant-a", "deployment-a", instance.InstanceID, created.Revision,
		leaseExpiry.Add(admission.CommandClockSkew-time.Nanosecond),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement before safety bound error = %v", err)
	}
	if _, _, err := fixture.store.ReplaceDeploymentInstance(
		"tenant-a", "deployment-a", instance.InstanceID, created.Revision,
		fixture.now.Add(2*time.Hour),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement after delegation expiry error = %v", err)
	}
	replaced, changed, err := fixture.store.ReplaceDeploymentInstance(
		"tenant-a", "deployment-a", instance.InstanceID, created.Revision,
		leaseExpiry.Add(admission.CommandClockSkew),
	)
	if err != nil || !changed {
		t.Fatalf("replace = (%+v, %v, %v)", replaced, changed, err)
	}
	got := replaced.Instances[0]
	if got.Generation != 2 || got.NodeID != "" || got.Phase != DeploymentInstancePending ||
		got.LeaseExpiresAt != "" || got.Intent != nil || got.Admission != nil ||
		got.CommandID != "" || got.CommandOperation != "" || got.CommandSequence != 7 || got.Attempts != 3 {
		t.Fatalf("replacement cursor = %+v", got)
	}
	if status, statusErr := fixture.store.Status(); statusErr != nil || status.Commands != 0 {
		t.Fatalf("replacement retained abandoned command = (%+v, %v)", status, statusErr)
	}
}

func TestDeploymentStoreRejectsInvalidAndStaleTransitions(t *testing.T) {
	var unavailable *Store
	if _, _, err := unavailable.ApplyDeployment(controlauth.Identity{}, DeploymentApply{}, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil apply error = %v", err)
	}
	if _, _, err := unavailable.SetDeploymentDesiredState(controlauth.Identity{}, "a", "b", 1, DeploymentAbsent, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil desired state error = %v", err)
	}
	if _, _, err := unavailable.GetDeployment(controlauth.Identity{}, "a", "b"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil get error = %v", err)
	}
	if _, err := unavailable.ListDeployments(controlauth.Identity{}, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil list error = %v", err)
	}
	if _, err := unavailable.SnapshotDeploymentFleet(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil snapshot error = %v", err)
	}
	if _, _, _, err := unavailable.EnqueueDeploymentCommand(DeploymentCommandTransition{}, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil enqueue error = %v", err)
	}
	if _, _, err := unavailable.ObserveDeploymentCommand("a", "b", "c", 1, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil observe error = %v", err)
	}
	if _, _, err := unavailable.RemovePendingDeploymentInstance("a", "b", "c", 1, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil remove pending error = %v", err)
	}
	if _, _, err := unavailable.RecordDeploymentBlocked(
		"a", "b", "c", 1, DeploymentBlockedNoEligibleNode, time.Now(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil block error = %v", err)
	}

	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	input := deploymentApplyFixture(t, fixture.now, "deployment-a", 1)
	if _, _, err := fixture.store.ApplyDeployment(controlauth.Identity{}, input, fixture.now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized apply error = %v", err)
	}
	invalid := input
	invalid.Generation = 0
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, invalid, fixture.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid apply error = %v", err)
	}
	created, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	invalidCursor := cloneDeployment(created)
	invalidCursor.Instances[0].CommandID = "read-command"
	invalidCursor.Instances[0].CommandOperation = "read"
	invalidCursor.Instances[0].CommandSequence = 1
	if err := validateDeployment(invalidCursor, fixture.limits); err == nil {
		t.Fatal("deployment accepted a command operation the reconciler cannot advance")
	}
	instanceID := created.Instances[0].InstanceID
	overlapping := input
	overlapping.ID = "deployment-overlap"
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, overlapping, fixture.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("overlapping deployment identity error = %v", err)
	}

	if _, _, err := fixture.store.SetDeploymentDesiredState(
		controlauth.Identity{}, "tenant-a", "deployment-a", created.Revision,
		DeploymentAbsent, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized desired state error = %v", err)
	}
	if _, _, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", 0, DeploymentAbsent, fixture.now,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid desired state error = %v", err)
	}
	if _, _, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "missing", created.Revision, DeploymentAbsent, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing desired state error = %v", err)
	}
	if _, _, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", created.Revision+1, DeploymentAbsent, fixture.now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale desired state error = %v", err)
	}
	if _, _, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", instanceID, created.Revision+1,
		DeploymentBlockedNoEligibleNode, fixture.now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale block error = %v", err)
	}
	if _, _, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", "missing", created.Revision,
		DeploymentBlockedNoEligibleNode, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing block instance error = %v", err)
	}
	if _, _, err := fixture.store.RecordDeploymentBlocked(
		"tenant-a", "missing", instanceID, created.Revision,
		DeploymentBlockedNoEligibleNode, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing block deployment error = %v", err)
	}
	if _, _, _, err := fixture.store.EnqueueDeploymentCommand(DeploymentCommandTransition{}, fixture.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid enqueue error = %v", err)
	}
	if _, _, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instanceID, 0, fixture.now,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid observe error = %v", err)
	}
	if _, _, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "missing", instanceID, created.Revision, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing observe error = %v", err)
	}
	if _, _, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instanceID, created.Revision+1, fixture.now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale observe error = %v", err)
	}
	if _, _, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", "missing", created.Revision, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing observe instance error = %v", err)
	}
	if deployment, changed, err := fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instanceID, created.Revision, fixture.now,
	); err != nil || changed || deployment.Revision != created.Revision {
		t.Fatalf("idle observe = (%+v, %v, %v)", deployment, changed, err)
	}
	if _, _, err := fixture.store.RemovePendingDeploymentInstance(
		"tenant-a", "deployment-a", instanceID, created.Revision, fixture.now,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("running desired remove error = %v", err)
	}
	if _, _, err := fixture.store.RemovePendingDeploymentInstance(
		"tenant-a", "missing", instanceID, created.Revision, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pending deployment error = %v", err)
	}
	if _, _, err := fixture.store.RemovePendingDeploymentInstance(
		"tenant-a", "deployment-a", "missing", created.Revision, fixture.now,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing pending instance error = %v", err)
	}
	absent, _, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", created.Revision,
		DeploymentAbsent, fixture.now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	running, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", absent.Revision,
		DeploymentRunning, fixture.now.Add(2*time.Second),
	)
	if err != nil || !changed || running.Phase != DeploymentPending {
		t.Fatalf("restore running = (%+v, %v, %v)", running, changed, err)
	}
	if _, found, err := fixture.store.GetDeployment(fixture.admin, "tenant-a", "bad id"); err != nil || found {
		t.Fatalf("invalid get = (%v, %v)", found, err)
	}
}

func TestDeploymentRollForwardMayOmitOnlyRemovedInstances(t *testing.T) {
	previous := []DeploymentInstance{
		{InstanceID: "removed", Phase: DeploymentInstanceRemoved},
		{InstanceID: "live", LineageID: "lineage", Generation: 1, Phase: DeploymentInstanceRunning},
	}
	next := []DeploymentInstance{{InstanceID: "live", LineageID: "lineage", Generation: 2}}
	if !deploymentInstancesRollForward(previous, next) {
		t.Fatal("roll-forward rejected omission of a fully removed instance")
	}
	if deploymentInstancesRollForward(previous, nil) {
		t.Fatal("roll-forward accepted omission of a live instance")
	}
}

func TestDeploymentStoreOperationsStopAfterClose(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	input := deploymentApplyFixture(t, fixture.now, "deployment-a", 1)
	created, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	instanceID := created.Instances[0].InstanceID
	checks := []error{}
	_, err = fixture.store.SnapshotDeploymentFleet()
	checks = append(checks, err)
	_, _, err = fixture.store.GetDeployment(fixture.admin, "tenant-a", "deployment-a")
	checks = append(checks, err)
	_, err = fixture.store.ListDeployments(fixture.admin, "tenant-a")
	checks = append(checks, err)
	_, _, err = fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", created.Revision, DeploymentAbsent, fixture.now,
	)
	checks = append(checks, err)
	_, _, err = fixture.store.RecordDeploymentBlocked(
		"tenant-a", "deployment-a", instanceID, created.Revision,
		DeploymentBlockedNoEligibleNode, fixture.now,
	)
	checks = append(checks, err)
	_, _, err = fixture.store.ObserveDeploymentCommand(
		"tenant-a", "deployment-a", instanceID, created.Revision, fixture.now,
	)
	checks = append(checks, err)
	_, _, err = fixture.store.RemovePendingDeploymentInstance(
		"tenant-a", "deployment-a", instanceID, created.Revision, fixture.now,
	)
	checks = append(checks, err)
	for index, err := range checks {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("closed operation %d error = %v", index, err)
		}
	}
}

func deploymentApplyFixture(t *testing.T, now time.Time, deploymentID string, generation uint64) DeploymentApply {
	return deploymentApplyFixtureWithInstanceCount(t, now, deploymentID, generation, 2)
}

func deploymentApplyFixtureWithInstanceCount(
	t *testing.T,
	now time.Time,
	deploymentID string,
	generation uint64,
	instanceCount int,
) DeploymentApply {
	t.Helper()
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Sign(admission.CapsulePayloadType, []byte(`{"schema_version":"steward.capsule.v1"}`), "publisher-a", publisherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, err := dsse.Marshal(capsuleEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instances := make([]admission.CommandDelegationInstance, instanceCount)
	for index := range instances {
		instances[index] = admission.CommandDelegationInstance{
			InstanceID:            deploymentID + "-" + string(rune('0'+index)),
			LineageID:             deploymentID + "-lineage-" + string(rune('0'+index)),
			MinInstanceGeneration: generation, MaxInstanceGeneration: generation + 2,
		}
	}
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  deploymentID + "-authority-" + string(rune('a'+generation-1)), TenantID: "tenant-a",
		ControllerKeyID:     "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "destroy", "renew", "start", "stop"}, NodeIDs: []string{"node-1"},
		Instances:       instances,
		ClaimGeneration: generation,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest:    dsse.Digest(capsuleRaw),
			Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
			StateDisposition: "none",
		},
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}
	delegationPayload, err := json.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	_, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := dsse.Sign(
		admission.CommandDelegationPayloadType, delegationPayload, "tenant-command-a", tenantPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := dsse.Marshal(delegationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	return DeploymentApply{
		TenantID: "tenant-a", ID: deploymentID, Generation: generation,
		AgentName: "agent-a", BundleDigest: digestBytes([]byte("bundle-" + deploymentID)),
		CapsuleDSSE: capsuleRaw, DelegationDSSE: delegationRaw,
	}
}
