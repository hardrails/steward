package controlstore

import (
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
	"github.com/hardrails/steward/internal/dsse"
)

func TestDeploymentApplyIsBoundedIdempotentRevisionedAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
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
	updated, changed, err := fixture.store.ApplyDeployment(fixture.admin, rollout, fixture.now.Add(4*time.Minute))
	if err != nil || !changed || updated.Generation != 2 || updated.Revision != 2 ||
		updated.CreatedAt != created.CreatedAt || updated.UpdatedAt == created.UpdatedAt {
		t.Fatalf("rollout deployment = (%+v, %v, %v)", updated, changed, err)
	}
	absent, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "deployment-a", updated.Revision,
		DeploymentAbsent, fixture.now.Add(5*time.Minute),
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
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  deploymentID + "-authority-" + string(rune('a'+generation-1)), TenantID: "tenant-a",
		ControllerKeyID:     "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "destroy", "start", "stop"}, NodeIDs: []string{"node-1"},
		Instances: []admission.CommandDelegationInstance{
			{InstanceID: deploymentID + "-0", LineageID: deploymentID + "-lineage-0", MinInstanceGeneration: generation, MaxInstanceGeneration: generation + 2},
			{InstanceID: deploymentID + "-1", LineageID: deploymentID + "-lineage-1", MinInstanceGeneration: generation, MaxInstanceGeneration: generation + 2},
		},
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
