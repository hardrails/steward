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
		func(value *VolumeSpec) { value.TenantID = "tenant/a" },
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
