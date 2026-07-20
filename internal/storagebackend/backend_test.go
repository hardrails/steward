package storagebackend

import (
	"errors"
	"strings"
	"testing"
)

func TestProductionCapabilitiesRequireEveryEnforcementProperty(t *testing.T) {
	capabilities := Capabilities{
		SchemaVersion: SchemaVersion, BackendID: "zfs-local", HardByteQuota: true,
		HardObjectQuota: true, ColdSnapshots: true, ImmutableSnapshots: true,
		CopyOnWriteClones: true, CrashSafeMetadata: true, DockerVolumeHandles: true,
	}
	if err := capabilities.Validate(); err != nil || !capabilities.ProductionQualified() {
		t.Fatalf("qualified capabilities = (%+v, %v)", capabilities, err)
	}
	checks := []func(*Capabilities){
		func(value *Capabilities) { value.HardByteQuota = false },
		func(value *Capabilities) { value.HardObjectQuota = false },
		func(value *Capabilities) { value.ColdSnapshots = false },
		func(value *Capabilities) { value.ImmutableSnapshots = false },
		func(value *Capabilities) { value.CopyOnWriteClones = false },
		func(value *Capabilities) { value.CrashSafeMetadata = false },
		func(value *Capabilities) { value.DockerVolumeHandles = false },
	}
	for _, mutate := range checks {
		candidate := capabilities
		mutate(&candidate)
		if candidate.ProductionQualified() {
			t.Fatalf("incomplete backend qualified: %+v", candidate)
		}
	}
}

func TestStorageObjectsRejectPathsScopeDriftAndInvalidLimits(t *testing.T) {
	validSpec := VolumeSpec{
		VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a",
		Generation: 1, ByteLimit: 1 << 30, ObjectLimit: 100_000,
	}
	if err := validSpec.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*VolumeSpec){
		func(value *VolumeSpec) { value.VolumeID = "../escape" },
		func(value *VolumeSpec) { value.TenantID = " tenant/a" },
		func(value *VolumeSpec) { value.LineageID = "" },
		func(value *VolumeSpec) { value.Generation = 0 },
		func(value *VolumeSpec) { value.ByteLimit = 0 },
		func(value *VolumeSpec) { value.ObjectLimit = -1 },
		func(value *VolumeSpec) { value.ParentSnapshotID = "snapshot/a" },
	} {
		candidate := validSpec
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid spec accepted: %+v error=%v", candidate, err)
		}
	}

	volume := Volume{
		Spec: validSpec, State: StateReady, BackendRef: "dataset-0123",
		DockerVolumeHandle: "steward-state-0123", CreatedAt: "2026-07-20T12:00:00Z",
	}
	if err := volume.Validate(); err != nil {
		t.Fatal(err)
	}
	volume.BackendRef = "/tank/tenant-a"
	if err := volume.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("host path backend reference accepted: %v", err)
	}
}

func TestSnapshotAndCloneRequireImmutableExactParentIdentity(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	snapshot := Snapshot{
		SnapshotID: "snapshot-a", TenantID: "tenant-a", SourceVolumeID: "volume-a",
		SourceLineageID: "lineage-a", Generation: 1, State: StateReady,
		BackendRef: "snapshot-0123", ContentDigest: digest, RetainedBytes: 4096,
		ObjectCount: 12, CreatedAt: "2026-07-20T12:00:00Z",
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := CloneVolumeRequest{
		RequestID: "clone-request-a", Snapshot: snapshot.Scope(),
		Volume: VolumeSpec{
			VolumeID: "volume-fork", TenantID: "tenant-a", LineageID: "lineage-fork",
			Generation: 1, ByteLimit: 1 << 30, ObjectLimit: 100_000,
			ParentSnapshotID: snapshot.SnapshotID,
		},
	}
	if err := clone.Validate(); err != nil {
		t.Fatal(err)
	}
	clone.Volume.ParentSnapshotID = "snapshot-other"
	if err := clone.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clone with different parent accepted: %v", err)
	}
	clone.Volume.ParentSnapshotID = snapshot.SnapshotID
	clone.Volume.TenantID = "tenant-b"
	if err := clone.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-tenant clone accepted: %v", err)
	}
}

func TestStorageMutationContractsRejectIncompleteLifecycleIdentity(t *testing.T) {
	spec := VolumeSpec{
		VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a",
		Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
	}
	volume := Volume{
		Spec: spec, State: StateReady, BackendRef: "backend-a", DockerVolumeHandle: "handle-a",
		CreatedAt: "2026-07-20T12:00:00Z",
	}
	for _, mutate := range []func(*Volume){
		func(value *Volume) { value.State = "other" },
		func(value *Volume) { value.UsedBytes = -1 },
		func(value *Volume) { value.State, value.DeletedAt = StateDeleted, "" },
		func(value *Volume) { value.State, value.DeletedAt = StateReady, "2026-07-20T12:01:00Z" },
	} {
		candidate := volume
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid volume accepted: %+v error=%v", candidate, err)
		}
	}
	snapshot := Snapshot{
		SnapshotID: "snapshot-a", TenantID: "tenant-a", SourceVolumeID: spec.VolumeID,
		SourceLineageID: spec.LineageID, Generation: 1, State: StateReady, BackendRef: "snapshot-a",
		ContentDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: "2026-07-20T12:00:00Z",
	}
	for _, mutate := range []func(*Snapshot){
		func(value *Snapshot) { value.ContentDigest = "bad" },
		func(value *Snapshot) { value.RetainedBytes = -1 },
		func(value *Snapshot) { value.State, value.DeletedAt = StateDeleted, "" },
		func(value *Snapshot) { value.State, value.DeletedAt = StateReady, "2026-07-20T12:01:00Z" },
	} {
		candidate := snapshot
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid snapshot accepted: %+v error=%v", candidate, err)
		}
	}
	for name, validate := range map[string]func() error{
		"create volume": func() error { return (CreateVolumeRequest{Volume: spec}).Validate() },
		"delete volume": func() error { return (DeleteVolumeRequest{Volume: spec.Scope()}).Validate() },
		"create snapshot": func() error {
			return (CreateSnapshotRequest{SnapshotID: "snapshot-a", Source: spec.Scope()}).Validate()
		},
		"delete snapshot": func() error { return (DeleteSnapshotRequest{Snapshot: snapshot.Scope()}).Validate() },
	} {
		if err := validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s without request identity error=%v", name, err)
		}
	}
}
