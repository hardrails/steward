package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestSnapshotQuarantineIsScopedOptimisticAndDurable(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createTenant(t, "tenant-b")
	fixture.createNode(t, "tenant-a")
	tenantA := operationalFreezeTenantOperator(t, fixture, "tenant-a", "snapshot-operator-a")
	tenantB := operationalFreezeTenantOperator(t, fixture, "tenant-b", "snapshot-operator-b")

	status, err := fixture.store.InspectSnapshotQuarantine(tenantA, "tenant-a", "node-1", "snapshot-a")
	if err != nil || status.Record != nil || status.Blocked {
		t.Fatalf("initial snapshot quarantine = (%+v, %v)", status, err)
	}
	if _, err := fixture.store.InspectSnapshotQuarantine(tenantB, "tenant-a", "node-1", "snapshot-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant snapshot inspection error = %v", err)
	}
	status, changed, err := fixture.store.ChangeSnapshotQuarantine(
		tenantA, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionSet, 0,
		"suspected authority contamination", fixture.now.Add(2*time.Minute),
	)
	if err != nil || !changed || !status.Blocked || status.Record == nil || status.Record.Revision != 1 {
		t.Fatalf("snapshot quarantine = (%+v, %v, %v)", status, changed, err)
	}
	if _, changed, err := fixture.store.ChangeSnapshotQuarantine(
		tenantA, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionSet, 1,
		"suspected authority contamination", fixture.now.Add(3*time.Minute),
	); err != nil || changed {
		t.Fatalf("idempotent snapshot quarantine = (%v, %v)", changed, err)
	}
	if _, _, err := fixture.store.ChangeSnapshotQuarantine(
		tenantA, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionClear, 0, "",
		fixture.now.Add(3*time.Minute),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale snapshot unquarantine error = %v", err)
	}
	status, changed, err = fixture.store.ChangeSnapshotQuarantine(
		tenantA, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionClear, 1, "",
		fixture.now.Add(4*time.Minute),
	)
	if err != nil || !changed || status.Blocked || status.Record == nil || status.Record.Revision != 2 {
		t.Fatalf("snapshot unquarantine = (%+v, %v, %v)", status, changed, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	status, err = reopened.InspectSnapshotQuarantine(fixture.admin, "tenant-a", "node-1", "snapshot-a")
	if err != nil || status.Record == nil || status.Record.Revision != 2 || status.Blocked {
		t.Fatalf("reopened snapshot quarantine = (%+v, %v)", status, err)
	}
}

func TestSnapshotQuarantineBlocksOnlyNewForkAdmission(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, nodeIdentity := fixture.createNode(t, "tenant-a")
	if _, err := fixture.store.PollV4(nodeIdentity, []string{
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
		controlprotocol.ExecutorCapabilityStateSnapshotsV1,
	}, fixture.now.Add(time.Minute), time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	input := snapshotQuarantineForkApplyFixture(t, fixture.now)
	if _, _, err := fixture.store.ChangeSnapshotQuarantine(
		fixture.admin, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionSet,
		0, "suspected contamination", fixture.now.Add(2*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(3*time.Minute)); !errors.Is(err, ErrSnapshotQuarantined) {
		t.Fatalf("quarantined fork apply error = %v", err)
	}
	if _, _, err := fixture.store.ChangeSnapshotQuarantine(
		fixture.admin, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionClear,
		1, "", fixture.now.Add(4*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	created, changed, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(5*time.Minute))
	if err != nil || !changed || created.Fork == nil || created.Fork.SnapshotID != "snapshot-a" {
		t.Fatalf("cleared fork apply = (%+v, %v, %v)", created, changed, err)
	}
	if _, _, err := fixture.store.ChangeSnapshotQuarantine(
		fixture.admin, "tenant-a", "node-1", "snapshot-a", SnapshotQuarantineActionSet,
		2, "new finding", fixture.now.Add(6*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	retry, changed, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now.Add(7*time.Minute))
	if err != nil || changed || retry.ID != created.ID {
		t.Fatalf("retained fork retry during quarantine = (%+v, %v, %v)", retry, changed, err)
	}
}

func snapshotQuarantineForkApplyFixture(t *testing.T, now time.Time) DeploymentApply {
	t.Helper()
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Sign(
		admission.CapsulePayloadType, []byte(`{"schema_version":"steward.capsule.v1"}`),
		"publisher-a", publisherPrivate,
	)
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
		SchemaVersion:       admission.CommandDelegationSchemaV1,
		DelegationID:        "fork-authority-a",
		TenantID:            "tenant-a",
		ControllerKeyID:     "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "clone-state", "destroy", "purge", "renew", "start", "stop"},
		NodeIDs:             []string{"node-1"},
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: "fork-a-0", LineageID: "fork-lineage-a",
			MinInstanceGeneration: 1, MaxInstanceGeneration: 1,
		}},
		ClaimGeneration: 1,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest: dsse.Digest(capsuleRaw),
			Resources: admission.ResourceLimits{
				MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32,
			},
			Capabilities: admission.Capabilities{State: true}, StateDisposition: "resume",
		},
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(6 * time.Hour).UTC().Format(time.RFC3339Nano),
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
		TenantID: "tenant-a", ID: "fork-a", Generation: 1, AgentName: "agent-a",
		BundleDigest: digestBytes([]byte("fork-bundle")), CapsuleDSSE: capsuleRaw, DelegationDSSE: delegationRaw,
		Fork: &DeploymentFork{
			SnapshotID: "snapshot-a", SourceLineageID: "source-lineage-a", SourceNodeID: "node-1",
			ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339Nano),
		},
	}
}

func TestSnapshotQuarantineFormatRejectsLegacySmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	record := SnapshotQuarantine{
		TenantID: "tenant-a", NodeID: "node-1", SnapshotID: "snapshot-a", Quarantined: true,
		Revision: 1, Reason: "format test", ChangedAt: firstTenant(current).CreatedAt,
	}
	current.quarantines[snapshotQuarantineKey(record.TenantID, record.NodeID, record.SnapshotID)] = record
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeState(raw, limits.MaxStateBytes)
	if err != nil || len(decoded.quarantines) != 1 {
		t.Fatalf("snapshot quarantine round trip = (%+v, %v)", decoded.quarantines, err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Version = stateFormatForkLifecycleVersion
	smuggled, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot accepted snapshot quarantine state")
	}
	snapshot.Quarantines = nil
	legacy, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacy, limits.MaxStateBytes)
	if err != nil || migrated.quarantines == nil || len(migrated.quarantines) != 0 {
		t.Fatalf("legacy snapshot quarantine migration = (%+v, %v)", migrated.quarantines, err)
	}
	if _, err := applyTransaction(current, transaction{
		Version:   transactionForkLifecycleVersion,
		Mutations: []mutation{{Kind: mutationSnapshotQuarantine, Quarantine: &record}},
	}); err == nil {
		t.Fatal("legacy transaction accepted snapshot quarantine state")
	}
}

func TestSnapshotQuarantineStateRejectsPerTenantCapacityOverflow(t *testing.T) {
	current, limits := populatedControlState(t)
	changedAt := firstTenant(current).CreatedAt
	for index := 0; index <= MaxSnapshotQuarantinesPerTenant; index++ {
		snapshotID := "snapshot-" + strconv.Itoa(index)
		record := SnapshotQuarantine{
			TenantID: "tenant-a", NodeID: "node-1", SnapshotID: snapshotID,
			Quarantined: true, Revision: 1, Reason: "capacity test", ChangedAt: changedAt,
		}
		current.quarantines[snapshotQuarantineKey(record.TenantID, record.NodeID, record.SnapshotID)] = record
	}
	if err := validateState(current, limits); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("snapshot quarantine capacity error = %v", err)
	}
}
