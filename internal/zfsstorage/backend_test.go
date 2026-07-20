package zfsstorage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/storagebackend"
)

func TestBackendLifecycleIsScopedDurableAndIdempotent(t *testing.T) {
	runner := newFakeZFS("tank/steward")
	binder := &fakeBinder{bindings: make(map[string]Binding)}
	backend, err := New(Config{
		DatasetRoot: "tank/steward", MountRoot: "/var/lib/steward-state",
		Runner: runner, Binder: binder,
		Now: func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	capabilities, err := backend.Capabilities(ctx)
	if err != nil || !capabilities.ProductionQualified() {
		t.Fatalf("capabilities = (%+v, %v)", capabilities, err)
	}

	parentRequest := storagebackend.CreateVolumeRequest{RequestID: "create-parent", Volume: storagebackend.VolumeSpec{
		VolumeID: "parent", TenantID: "tenant-a", LineageID: "lineage-parent", Generation: 1,
		ByteLimit: 1 << 20, ObjectLimit: 100,
	}}
	plan, err := backend.PlanVolume(ctx, parentRequest.Volume)
	if err != nil || plan.Spec != parentRequest.Volume || !strings.HasPrefix(plan.DockerVolumeHandle, "steward-zfs-") {
		t.Fatalf("plan parent = (%+v, %v)", plan, err)
	}
	parent, changed, err := backend.CreateVolume(ctx, parentRequest)
	if err != nil || !changed || parent.State != storagebackend.StateReady {
		t.Fatalf("create parent = (%+v, %v, %v)", parent, changed, err)
	}
	if !strings.HasPrefix(parent.DockerVolumeHandle, "steward-zfs-") || parent.UsedBytes != 0 || parent.UsedObjects != 0 {
		t.Fatalf("unexpected parent projection: %+v", parent)
	}
	replayed, changed, err := backend.CreateVolume(ctx, parentRequest)
	if err != nil || changed || replayed != parent {
		t.Fatalf("replay create = (%+v, %v, %v), want unchanged", replayed, changed, err)
	}
	conflicting := parentRequest
	conflicting.RequestID = "different-create"
	if _, _, err := backend.CreateVolume(ctx, conflicting); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("different request ID error = %v, want conflict", err)
	}
	foreignScope := parent.Scope()
	foreignScope.TenantID = "tenant-b"
	if _, err := backend.InspectVolume(ctx, foreignScope); !errors.Is(err, storagebackend.ErrNotFound) {
		t.Fatalf("foreign tenant inspect error = %v, want not found", err)
	}

	snapshotRequest := storagebackend.CreateSnapshotRequest{
		RequestID: "snapshot-parent", SnapshotID: "snapshot-parent", Source: parent.Scope(),
	}
	snapshot, changed, err := backend.CreateSnapshot(ctx, snapshotRequest)
	if err != nil || !changed || snapshot.State != storagebackend.StateReady || snapshot.ContentDigest == "" {
		t.Fatalf("create snapshot = (%+v, %v, %v)", snapshot, changed, err)
	}
	replayedSnapshot, changed, err := backend.CreateSnapshot(ctx, snapshotRequest)
	if err != nil || changed || replayedSnapshot != snapshot {
		t.Fatalf("replay snapshot = (%+v, %v, %v)", replayedSnapshot, changed, err)
	}
	inspectedSnapshot, err := backend.InspectSnapshot(ctx, snapshot.Scope())
	if err != nil || inspectedSnapshot != snapshot {
		t.Fatalf("inspect snapshot = (%+v, %v)", inspectedSnapshot, err)
	}

	cloneRequest := storagebackend.CloneVolumeRequest{
		RequestID: "clone-child", Snapshot: snapshot.Scope(),
		Volume: storagebackend.VolumeSpec{
			VolumeID: "child", TenantID: "tenant-a", LineageID: "lineage-child", Generation: 1,
			ByteLimit: 2 << 20, ObjectLimit: 200, ParentSnapshotID: snapshot.SnapshotID,
		},
	}
	child, changed, err := backend.CloneVolume(ctx, cloneRequest)
	if err != nil || !changed || child.Spec.ParentSnapshotID != snapshot.SnapshotID {
		t.Fatalf("clone = (%+v, %v, %v)", child, changed, err)
	}
	if _, _, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{
		RequestID: "delete-parent-too-soon", Snapshot: snapshot.Scope(),
	}); !errors.Is(err, storagebackend.ErrInUse) {
		t.Fatalf("delete referenced snapshot error = %v, want in use", err)
	}

	deletedChild, changed, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-child", Volume: child.Scope()})
	if err != nil || !changed || deletedChild.State != storagebackend.StateDeleted {
		t.Fatalf("delete child = (%+v, %v, %v)", deletedChild, changed, err)
	}
	replayedDelete, changed, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-child", Volume: child.Scope()})
	if err != nil || changed || replayedDelete.State != storagebackend.StateDeleted {
		t.Fatalf("replay delete child = (%+v, %v, %v)", replayedDelete, changed, err)
	}

	deletedSnapshot, changed, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{RequestID: "delete-snapshot", Snapshot: snapshot.Scope()})
	if err != nil || !changed || deletedSnapshot.State != storagebackend.StateDeleted {
		t.Fatalf("delete snapshot = (%+v, %v, %v)", deletedSnapshot, changed, err)
	}
	deletedParent, changed, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-parent", Volume: parent.Scope()})
	if err != nil || !changed || deletedParent.State != storagebackend.StateDeleted {
		t.Fatalf("delete parent = (%+v, %v, %v)", deletedParent, changed, err)
	}
	if len(binder.bindings) != 0 {
		t.Fatalf("bindings after delete = %+v", binder.bindings)
	}
}

func TestBackendConformanceExercisesQualifiedLifecycle(t *testing.T) {
	runner := newFakeZFS("tank/steward")
	binder := &fakeBinder{bindings: make(map[string]Binding)}
	probe := &recordingQuotaProbe{}
	backend, err := New(Config{
		DatasetRoot: "tank/steward", MountRoot: "/var/lib/steward-state",
		Runner: runner, Binder: binder, QuotaProbe: probe,
		Now: func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := backend.VerifyConformance(ctx); err != nil {
		t.Fatal(err)
	}
	if probe.calls != 1 || probe.byteLimit != conformanceByteLimit || probe.objectLimit != conformanceObjectLimit ||
		!strings.HasPrefix(probe.mountpoint, "/var/lib/steward-state/v-") {
		t.Fatalf("quota probe = %+v", probe)
	}
	if len(binder.bindings) != 0 {
		t.Fatalf("conformance leaked Docker bindings: %+v", binder.bindings)
	}
}

func TestFilesystemQuotaProbeRejectsAnUnquotaedDirectory(t *testing.T) {
	directory := t.TempDir()
	err := (FilesystemQuotaProbe{}).Verify(context.Background(), directory, 2<<20, 16)
	if err == nil || !strings.Contains(err.Error(), "object quota did not stop") {
		t.Fatalf("unquotaed probe error = %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("probe cleanup entries=%v err=%v", entries, readErr)
	}
}

type recordingQuotaProbe struct {
	calls       int
	mountpoint  string
	byteLimit   int64
	objectLimit int64
}

func (probe *recordingQuotaProbe) Verify(_ context.Context, mountpoint string, byteLimit, objectLimit int64) error {
	probe.calls++
	probe.mountpoint, probe.byteLimit, probe.objectLimit = mountpoint, byteLimit, objectLimit
	return nil
}

func TestBackendQuarantinesMissingOrReboundDockerVolume(t *testing.T) {
	backend, _, binder := newBackendFixture(t)
	request := storagebackend.CreateVolumeRequest{RequestID: "create", Volume: storagebackend.VolumeSpec{
		VolumeID: "volume", TenantID: "tenant", LineageID: "lineage", Generation: 1,
		ByteLimit: 4096, ObjectLimit: 10,
	}}
	volume, _, err := backend.CreateVolume(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	delete(binder.bindings, volume.DockerVolumeHandle)
	observed, err := backend.InspectVolume(context.Background(), volume.Scope())
	if err != nil || observed.State != storagebackend.StateQuarantined {
		t.Fatalf("missing binding inspect = (%+v, %v)", observed, err)
	}
	if _, changed, err := backend.CreateVolume(context.Background(), request); err != nil || changed {
		t.Fatalf("same request should repair binding idempotently: changed=%v err=%v", changed, err)
	}
	binding := binder.bindings[volume.DockerVolumeHandle]
	binding.Source = "/host/attacker"
	binder.bindings[volume.DockerVolumeHandle] = binding
	observed, err = backend.InspectVolume(context.Background(), volume.Scope())
	if err != nil || observed.State != storagebackend.StateQuarantined {
		t.Fatalf("rebound binding inspect = (%+v, %v)", observed, err)
	}
}

func TestBackendRejectsUnsafeConfigurationAndScopeCollisions(t *testing.T) {
	runner := newFakeZFS("tank/steward")
	binder := &fakeBinder{bindings: make(map[string]Binding)}
	for _, config := range []Config{
		{DatasetRoot: "tank/steward@bad", MountRoot: "/state", Runner: runner, Binder: binder},
		{DatasetRoot: "tank/steward", MountRoot: "relative", Runner: runner, Binder: binder},
		{DatasetRoot: "tank/steward", MountRoot: "/", Runner: runner, Binder: binder},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("unsafe config accepted: %+v", config)
		}
	}
	backend, err := New(Config{DatasetRoot: "tank/steward", MountRoot: "/state", Runner: runner, Binder: binder})
	if err != nil {
		t.Fatal(err)
	}
	left := storagebackend.VolumeScope{VolumeID: "ab", TenantID: "c", LineageID: "d", Generation: 1}
	right := storagebackend.VolumeScope{VolumeID: "a", TenantID: "bc", LineageID: "d", Generation: 1}
	if backend.volumeDataset(left) == backend.volumeDataset(right) {
		t.Fatal("length-framed scope digest collided")
	}
}

func TestBoundedBufferDetectsOnlyActualOverflow(t *testing.T) {
	buffer := &boundedBuffer{remaining: 8}
	if _, err := buffer.Write([]byte("12345")); err != nil || buffer.overflow {
		t.Fatalf("short write = (%q, overflow=%v, %v)", buffer.String(), buffer.overflow, err)
	}
	if _, err := buffer.Write([]byte("6789")); err != nil || !buffer.overflow || buffer.String() != "12345678" {
		t.Fatalf("overflow write = (%q, overflow=%v, %v)", buffer.String(), buffer.overflow, err)
	}
}

func TestBackendErrorClassificationAndInputGuards(t *testing.T) {
	commandFailure := func(stderr string) error {
		return &CommandError{Args: []string{"test"}, Stderr: stderr, Err: errors.New("exit status 1")}
	}
	for _, test := range []struct {
		stderr string
		want   error
	}{
		{"dataset is busy", storagebackend.ErrInUse},
		{"has dependent clones", storagebackend.ErrInUse},
		{"snapshot is held", storagebackend.ErrInUse},
		{"out of space", storagebackend.ErrCapacity},
		{"quota exceeded", storagebackend.ErrCapacity},
		{"no space left", storagebackend.ErrCapacity},
		{"dataset already exists", storagebackend.ErrConflict},
		{"unexpected localized failure", storagebackend.ErrUnavailable},
	} {
		if err := mapCommandError(commandFailure(test.stderr)); !errors.Is(err, test.want) {
			t.Fatalf("command error %q = %v, want %v", test.stderr, err, test.want)
		}
	}
	for input, want := range map[error]error{
		nil:                 nil,
		ErrBindingInUse:     storagebackend.ErrInUse,
		ErrBindingConflict:  storagebackend.ErrConflict,
		ErrBindingNotFound:  storagebackend.ErrNotFound,
		errors.New("other"): storagebackend.ErrUnavailable,
	} {
		if err := mapBindingError(input); !errors.Is(err, want) {
			t.Fatalf("binding error %v = %v, want %v", input, err, want)
		}
	}
	for _, value := range []string{"-1", "not-a-number"} {
		if _, err := parseNonnegative(value); !errors.Is(err, storagebackend.ErrConflict) {
			t.Fatalf("parse %q error = %v", value, err)
		}
	}
	if value, err := parseNonnegative("42"); err != nil || value != 42 {
		t.Fatalf("parse nonnegative = (%d, %v)", value, err)
	}

	backend, _, _ := newBackendFixture(t)
	badVolume := storagebackend.VolumeScope{VolumeID: "bad id", TenantID: "tenant", LineageID: "lineage", Generation: 1}
	if _, err := backend.InspectVolume(context.Background(), badVolume); err == nil {
		t.Fatal("invalid volume scope was inspected")
	}
	badSnapshot := storagebackend.SnapshotScope{SnapshotID: "bad id", TenantID: "tenant", SourceVolumeID: "source", SourceLineageID: "lineage", Generation: 1}
	if _, err := backend.InspectSnapshot(context.Background(), badSnapshot); err == nil {
		t.Fatal("invalid snapshot scope was inspected")
	}
	if _, err := backend.InspectSnapshot(context.Background(), storagebackend.SnapshotScope{
		SnapshotID: "missing", TenantID: "tenant", SourceVolumeID: "source", SourceLineageID: "lineage", Generation: 1,
	}); !errors.Is(err, storagebackend.ErrNotFound) {
		t.Fatalf("missing snapshot error = %v", err)
	}
}

func TestConformanceAndQuotaProbeInputFailures(t *testing.T) {
	backend, _, _ := newBackendFixture(t)
	if err := backend.VerifyConformance(nil); err == nil {
		t.Fatal("nil conformance context was accepted")
	}
	if err := conformanceError(nil); err == nil {
		t.Fatal("unexpected conformance projection produced no error")
	}
	sentinel := errors.New("sentinel")
	if !errors.Is(conformanceError(sentinel), sentinel) {
		t.Fatal("conformance error did not preserve cause")
	}
	for _, test := range []struct {
		ctx         context.Context
		mount       string
		bytes, objs int64
	}{
		{nil, "/state", 1, 1},
		{context.Background(), "relative", 1, 1},
		{context.Background(), "/state", 0, 1},
		{context.Background(), "/state", 1, 0},
		{context.Background(), "/state", 1 << 31, 1},
		{context.Background(), "/state", 1, 4097},
	} {
		if err := (FilesystemQuotaProbe{}).Verify(test.ctx, test.mount, test.bytes, test.objs); err == nil {
			t.Fatalf("invalid quota probe accepted: %+v", test)
		}
	}
	if err := (FilesystemQuotaProbe{}).Verify(context.Background(), filepath.Join(t.TempDir(), "missing"), 1, 1); err == nil {
		t.Fatal("missing quota mountpoint was accepted")
	}
	if !quotaError(syscall.EDQUOT) || !quotaError(syscall.ENOSPC) || quotaError(errors.New("other")) {
		t.Fatal("quota errors were misclassified")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (FilesystemQuotaProbe{}).Verify(cancelled, t.TempDir(), 1, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled quota probe error = %v", err)
	}
	if err := (FilesystemQuotaProbe{}).Verify(context.Background(), t.TempDir(), 1, 1); err == nil ||
		!strings.Contains(err.Error(), "object quota") {
		t.Fatalf("unquotaed filesystem probe error = %v", err)
	}
}

func TestBackendQuarantinesOrRejectsCorruptPhysicalState(t *testing.T) {
	backend, runner, binder := newBackendFixture(t)
	ctx := context.Background()
	spec := storagebackend.VolumeSpec{
		VolumeID: "volume-corrupt", TenantID: "tenant-a", LineageID: "lineage-corrupt",
		Generation: 1, ByteLimit: 1 << 20, ObjectLimit: 100,
	}
	volume, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create-corrupt", Volume: spec})
	if err != nil {
		t.Fatal(err)
	}
	dataset := backend.volumeDataset(spec.Scope())
	properties := runner.datasets[dataset].properties

	originalMount := properties["mountpoint"]
	properties["mountpoint"] = "/wrong"
	if _, err := backend.InspectVolume(ctx, spec.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("wrong mountpoint error = %v", err)
	}
	properties["mountpoint"] = originalMount
	project := strconv.FormatUint(uint64(projectID(spec.Scope())), 10)
	properties["projectused@"+project] = "-1"
	if _, err := backend.InspectVolume(ctx, spec.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("negative byte usage error = %v", err)
	}
	properties["projectused@"+project] = "0"
	delete(binder.bindings, volume.DockerVolumeHandle)
	quarantined, err := backend.InspectVolume(ctx, spec.Scope())
	if err != nil || quarantined.State != storagebackend.StateQuarantined {
		t.Fatalf("missing binding projection = (%+v, %v)", quarantined, err)
	}
	_, _ = binder.Ensure(ctx, backend.binding(persistedRecord{Volume: spec, DockerHandle: volume.DockerVolumeHandle, BackendRef: volume.BackendRef}))

	snapshot, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{
		RequestID: "snapshot-corrupt", SnapshotID: "snapshot-corrupt", Source: spec.Scope(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshotDataset := backend.snapshotDataset(snapshot.Scope())
	snapshotProperties := runner.datasets[snapshotDataset].properties
	for property, value := range map[string]string{"referenced": "-1", "projectobjused@" + project: "-1", "guid": "-"} {
		original := snapshotProperties[property]
		snapshotProperties[property] = value
		if _, err := backend.InspectSnapshot(ctx, snapshot.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
			t.Fatalf("corrupt snapshot %s error = %v", property, err)
		}
		snapshotProperties[property] = original
	}
	originalRecord := properties[recordProperty]
	properties[recordProperty] = "not-base64"
	if _, err := backend.InspectVolume(ctx, spec.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("corrupt record error = %v", err)
	}
	properties[recordProperty] = originalRecord
}

func TestPersistedRecordValidationRejectsIncompleteObjects(t *testing.T) {
	valid := persistedRecord{
		Version: recordVersion, Kind: "volume", State: storagebackend.StateReady,
		CreateRequestID: "create", Volume: storagebackend.VolumeSpec{
			VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a",
			Generation: 1, ByteLimit: 1, ObjectLimit: 1,
		},
		ProjectID: 1, DockerHandle: "handle-a", BackendRef: "backend-a", CreatedAt: "2026-07-20T12:00:00Z",
	}
	for name, mutate := range map[string]func(*persistedRecord){
		"version":  func(record *persistedRecord) { record.Version = 0 },
		"kind":     func(record *persistedRecord) { record.Kind = "other" },
		"volume":   func(record *persistedRecord) { record.DockerHandle = "" },
		"state":    func(record *persistedRecord) { record.State = "other" },
		"deleted":  func(record *persistedRecord) { record.State = storagebackend.StateDeleted },
		"snapshot": func(record *persistedRecord) { record.Kind, record.Volume = "snapshot", storagebackend.VolumeSpec{} },
	} {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := record.validate(); err == nil {
				t.Fatalf("invalid record accepted: %+v", record)
			}
			if _, err := encodeRecord(record); err == nil {
				t.Fatal("invalid record encoded")
			}
		})
	}
}

func TestBackendPublicOperationsRejectInvalidOrMissingState(t *testing.T) {
	backend, _, _ := newBackendFixture(t)
	ctx := context.Background()
	if _, err := backend.PlanVolume(ctx, storagebackend.VolumeSpec{}); err == nil {
		t.Fatal("invalid volume plan accepted")
	}
	if _, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{}); err == nil {
		t.Fatal("invalid volume creation accepted")
	}
	if _, _, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{}); err == nil {
		t.Fatal("invalid volume deletion accepted")
	}
	if _, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{}); err == nil {
		t.Fatal("invalid snapshot creation accepted")
	}
	if _, _, err := backend.CloneVolume(ctx, storagebackend.CloneVolumeRequest{}); err == nil {
		t.Fatal("invalid clone accepted")
	}
	if _, _, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{}); err == nil {
		t.Fatal("invalid snapshot deletion accepted")
	}
	missingVolume := storagebackend.VolumeScope{VolumeID: "missing", TenantID: "tenant-a", LineageID: "missing", Generation: 1}
	if _, _, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-missing", Volume: missingVolume}); !errors.Is(err, storagebackend.ErrNotFound) {
		t.Fatalf("missing volume deletion error = %v", err)
	}
	missingSnapshot := storagebackend.SnapshotScope{
		SnapshotID: "missing", TenantID: "tenant-a", SourceVolumeID: "missing",
		SourceLineageID: "missing", Generation: 1,
	}
	if _, _, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{RequestID: "delete-missing", Snapshot: missingSnapshot}); !errors.Is(err, storagebackend.ErrNotFound) {
		t.Fatalf("missing snapshot deletion error = %v", err)
	}
}

func TestBackendPropertyReaderRejectsAmbiguousZFSOutput(t *testing.T) {
	for name, output := range map[string]string{
		"malformed": "property-without-tab\n",
		"missing":   "other\tvalue\n",
	} {
		t.Run(name, func(t *testing.T) {
			backend, err := New(Config{
				DatasetRoot: "tank/steward", MountRoot: "/state",
				Runner: runnerFunc(func(context.Context, ...string) ([]byte, error) { return []byte(output), nil }),
				Binder: &fakeBinder{bindings: make(map[string]Binding)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := backend.get(context.Background(), "tank/steward", "type"); !errors.Is(err, storagebackend.ErrConflict) {
				t.Fatalf("ambiguous output error = %v", err)
			}
		})
	}
	for name, failure := range map[string]error{
		"missing": &CommandError{Stderr: "dataset does not exist", Err: errors.New("exit 1")},
		"failure": &CommandError{Stderr: "I/O failure", Err: errors.New("exit 1")},
	} {
		t.Run(name, func(t *testing.T) {
			backend, err := New(Config{
				DatasetRoot: "tank/steward", MountRoot: "/state",
				Runner: runnerFunc(func(context.Context, ...string) ([]byte, error) { return nil, failure }),
				Binder: &fakeBinder{bindings: make(map[string]Binding)},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, found, err := backend.get(context.Background(), "tank/steward", "type")
			if name == "missing" && (err != nil || found) {
				t.Fatalf("missing dataset = (%v, %v)", found, err)
			}
			if name == "failure" && !errors.Is(err, storagebackend.ErrUnavailable) {
				t.Fatalf("ZFS failure error = %v", err)
			}
		})
	}
}

func TestBackendCommandFailuresAbortMutationsWithoutSuccessProjection(t *testing.T) {
	t.Run("create dataset", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		backend.runner = &failingRunner{base: runner, command: "create"}
		_, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{
			RequestID: "create-dataset-failure", Volume: storagebackend.VolumeSpec{
				VolumeID: "volume-create-failure", TenantID: "tenant-a", LineageID: "lineage-create-failure",
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
			},
		})
		if !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("dataset creation error = %v", err)
		}
	})

	t.Run("create project assignment", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		backend.runner = &failingRunner{base: runner, command: "project"}
		_, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{
			RequestID: "create-failure", Volume: storagebackend.VolumeSpec{
				VolumeID: "volume-failure", TenantID: "tenant-a", LineageID: "lineage-failure",
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
			},
		})
		if !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("project assignment error = %v", err)
		}
	})

	for _, command := range []string{"snapshot", "hold"} {
		t.Run("snapshot "+command, func(t *testing.T) {
			backend, runner, _ := newBackendFixture(t)
			spec := storagebackend.VolumeSpec{
				VolumeID: "volume-snapshot", TenantID: "tenant-a", LineageID: "lineage-snapshot",
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
			}
			if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
				t.Fatal(err)
			}
			backend.runner = &failingRunner{base: runner, command: command}
			if _, _, err := backend.CreateSnapshot(context.Background(), storagebackend.CreateSnapshotRequest{
				RequestID: "snapshot", SnapshotID: "snapshot-failure", Source: spec.Scope(),
			}); !errors.Is(err, storagebackend.ErrUnavailable) {
				t.Fatalf("%s failure error = %v", command, err)
			}
		})
	}

	t.Run("clone", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		spec := storagebackend.VolumeSpec{
			VolumeID: "volume-parent", TenantID: "tenant-a", LineageID: "lineage-parent",
			Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
		}
		if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
			t.Fatal(err)
		}
		snapshot, _, err := backend.CreateSnapshot(context.Background(), storagebackend.CreateSnapshotRequest{
			RequestID: "snapshot", SnapshotID: "snapshot-clone", Source: spec.Scope(),
		})
		if err != nil {
			t.Fatal(err)
		}
		backend.runner = &failingRunner{base: runner, command: "clone"}
		_, _, err = backend.CloneVolume(context.Background(), storagebackend.CloneVolumeRequest{
			RequestID: "clone", Snapshot: snapshot.Scope(), Volume: storagebackend.VolumeSpec{
				VolumeID: "volume-child", TenantID: "tenant-a", LineageID: "lineage-child",
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10, ParentSnapshotID: snapshot.SnapshotID,
			},
		})
		if !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("clone failure error = %v", err)
		}
	})

	t.Run("delete volume", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		spec := storagebackend.VolumeSpec{
			VolumeID: "volume-delete", TenantID: "tenant-a", LineageID: "lineage-delete",
			Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
		}
		if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
			t.Fatal(err)
		}
		backend.runner = &failingRunner{base: runner, command: "destroy"}
		if _, _, err := backend.DeleteVolume(context.Background(), storagebackend.DeleteVolumeRequest{
			RequestID: "delete", Volume: spec.Scope(),
		}); !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("volume destroy failure error = %v", err)
		}
	})

	for _, command := range []string{"create", "set"} {
		t.Run("delete volume "+command, func(t *testing.T) {
			backend, runner, _ := newBackendFixture(t)
			spec := storagebackend.VolumeSpec{
				VolumeID: "volume-delete-" + command, TenantID: "tenant-a", LineageID: "lineage-delete-" + command,
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
			}
			if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
				t.Fatal(err)
			}
			backend.runner = &failingRunner{base: runner, command: command}
			if _, _, err := backend.DeleteVolume(context.Background(), storagebackend.DeleteVolumeRequest{
				RequestID: "delete", Volume: spec.Scope(),
			}); !errors.Is(err, storagebackend.ErrUnavailable) {
				t.Fatalf("volume delete %s failure error = %v", command, err)
			}
		})
	}

	t.Run("delete snapshot", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		spec := storagebackend.VolumeSpec{
			VolumeID: "volume-delete-snapshot", TenantID: "tenant-a", LineageID: "lineage-delete-snapshot",
			Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
		}
		if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
			t.Fatal(err)
		}
		snapshot, _, err := backend.CreateSnapshot(context.Background(), storagebackend.CreateSnapshotRequest{
			RequestID: "snapshot", SnapshotID: "snapshot-delete", Source: spec.Scope(),
		})
		if err != nil {
			t.Fatal(err)
		}
		backend.runner = &failingRunner{base: runner, command: "release"}
		if _, _, err := backend.DeleteSnapshot(context.Background(), storagebackend.DeleteSnapshotRequest{
			RequestID: "delete", Snapshot: snapshot.Scope(),
		}); !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("snapshot release failure error = %v", err)
		}
	})

	t.Run("delete snapshot record", func(t *testing.T) {
		backend, runner, _ := newBackendFixture(t)
		spec := storagebackend.VolumeSpec{
			VolumeID: "volume-snapshot-record", TenantID: "tenant-a", LineageID: "lineage-snapshot-record",
			Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
		}
		if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
			t.Fatal(err)
		}
		snapshot, _, err := backend.CreateSnapshot(context.Background(), storagebackend.CreateSnapshotRequest{
			RequestID: "snapshot", SnapshotID: "snapshot-record", Source: spec.Scope(),
		})
		if err != nil {
			t.Fatal(err)
		}
		backend.runner = &failingRunner{base: runner, command: "set"}
		if _, _, err := backend.DeleteSnapshot(context.Background(), storagebackend.DeleteSnapshotRequest{
			RequestID: "delete", Snapshot: snapshot.Scope(),
		}); !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("snapshot record failure error = %v", err)
		}
	})
}

func TestBackendRetainedIdentitiesRejectDifferentIdempotencyKeys(t *testing.T) {
	backend, _, _ := newBackendFixture(t)
	ctx := context.Background()
	spec := storagebackend.VolumeSpec{
		VolumeID: "volume-replay", TenantID: "tenant-a", LineageID: "lineage-replay",
		Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
	}
	if _, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create-a", Volume: spec}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create-b", Volume: spec}); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("different volume create identity error = %v", err)
	}
	snapshot, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{
		RequestID: "snapshot-a", SnapshotID: "snapshot-replay", Source: spec.Scope(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{
		RequestID: "snapshot-b", SnapshotID: snapshot.SnapshotID, Source: spec.Scope(),
	}); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("different snapshot create identity error = %v", err)
	}
	if _, _, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{RequestID: "delete-snapshot-a", Snapshot: snapshot.Scope()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{RequestID: "delete-snapshot-b", Snapshot: snapshot.Scope()}); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("different snapshot delete identity error = %v", err)
	}
	if _, _, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-volume-a", Volume: spec.Scope()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{RequestID: "delete-volume-b", Volume: spec.Scope()}); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("different volume delete identity error = %v", err)
	}
	record, location, found, err := backend.findVolumeRecord(ctx, spec.Scope())
	if err != nil || !found {
		t.Fatalf("retained volume record = (%+v, %q, %v, %v)", record, location, found, err)
	}
	if err := backend.createTombstone(ctx, location, record); err != nil {
		t.Fatalf("idempotent tombstone = %v", err)
	}
	record.DeleteRequestID = "different"
	if err := backend.createTombstone(ctx, location, record); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("conflicting tombstone error = %v", err)
	}
}

func TestBackendInitializationRejectsConflictingRootDataset(t *testing.T) {
	runner := newFakeZFS("tank/steward")
	runner.datasets["tank/steward/volumes"] = &fakeDataset{properties: map[string]string{
		"type": "volume", "canmount": "off", "mountpoint": "none",
	}}
	backend, err := New(Config{
		DatasetRoot: "tank/steward", MountRoot: "/state", Runner: runner,
		Binder: &fakeBinder{bindings: make(map[string]Binding)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Initialize(context.Background()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("conflicting root error = %v", err)
	}
	if equalLabels(map[string]string{"a": "b"}, map[string]string{}) ||
		equalLabels(map[string]string{"a": "b"}, map[string]string{"a": "c"}) {
		t.Fatal("unequal labels matched")
	}
}

func TestBackendPropagatesDockerBindingFailures(t *testing.T) {
	t.Run("ensure", func(t *testing.T) {
		backend, _, binder := newBackendFixture(t)
		binder.ensureErr = errors.New("Docker unavailable")
		_, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{
			RequestID: "create-binding", Volume: storagebackend.VolumeSpec{
				VolumeID: "volume-binding", TenantID: "tenant-a", LineageID: "lineage-binding",
				Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
			},
		})
		if !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("binding ensure error = %v", err)
		}
	})
	t.Run("inspect and delete", func(t *testing.T) {
		backend, _, binder := newBackendFixture(t)
		spec := storagebackend.VolumeSpec{
			VolumeID: "volume-binding-live", TenantID: "tenant-a", LineageID: "lineage-binding-live",
			Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
		}
		if _, _, err := backend.CreateVolume(context.Background(), storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
			t.Fatal(err)
		}
		binder.inspectErr = errors.New("Docker unavailable")
		if _, err := backend.InspectVolume(context.Background(), spec.Scope()); !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("binding inspect error = %v", err)
		}
		binder.inspectErr = nil
		binder.deleteErr = errors.New("Docker unavailable")
		if _, _, err := backend.DeleteVolume(context.Background(), storagebackend.DeleteVolumeRequest{
			RequestID: "delete", Volume: spec.Scope(),
		}); !errors.Is(err, storagebackend.ErrUnavailable) {
			t.Fatalf("binding delete error = %v", err)
		}
	})
}

func TestBackendRejectsAdditionalCorruptMetadataAndHelperFailures(t *testing.T) {
	backend, runner, _ := newBackendFixture(t)
	ctx := context.Background()
	spec := storagebackend.VolumeSpec{
		VolumeID: "volume-helper", TenantID: "tenant-a", LineageID: "lineage-helper",
		Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
	}
	if _, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); err != nil {
		t.Fatal(err)
	}
	project := strconv.FormatUint(uint64(projectID(spec.Scope())), 10)
	volumeProperties := runner.datasets[backend.volumeDataset(spec.Scope())].properties
	volumeProperties["projectobjused@"+project] = "-1"
	if _, err := backend.InspectVolume(ctx, spec.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("negative object usage error = %v", err)
	}
	volumeProperties["projectobjused@"+project] = "0"
	snapshot, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{
		RequestID: "snapshot", SnapshotID: "snapshot-helper", Source: spec.Scope(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshotProperties := runner.datasets[backend.snapshotDataset(snapshot.Scope())].properties
	snapshotProperties["projectobjused@"+project] = "-1"
	if _, err := backend.InspectSnapshot(ctx, snapshot.Scope()); !errors.Is(err, storagebackend.ErrConflict) {
		t.Fatalf("negative snapshot object usage error = %v", err)
	}
	if _, err := backend.listSnapshots(ctx, "tank/steward/missing"); !errors.Is(err, storagebackend.ErrUnavailable) {
		t.Fatalf("missing snapshot list error = %v", err)
	}
	if err := backend.setRecord(ctx, "tank/steward/invalid", persistedRecord{}); err == nil {
		t.Fatal("invalid record was persisted")
	}
	for _, dataset := range []string{"tank//bad", "tank/$bad", "tank/.."} {
		if validDataset(dataset) {
			t.Fatalf("invalid dataset accepted: %q", dataset)
		}
	}

	base := newFakeZFS("tank/steward")
	failing := &failingRunner{base: base, command: "create"}
	uninitialized, err := New(Config{
		DatasetRoot: "tank/steward", MountRoot: "/state", Runner: failing,
		Binder: &fakeBinder{bindings: make(map[string]Binding)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := uninitialized.Initialize(ctx); !errors.Is(err, storagebackend.ErrUnavailable) {
		t.Fatalf("namespace creation error = %v", err)
	}
}

type failingRunner struct {
	base    Runner
	command string
	failed  bool
}

func (runner *failingRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == runner.command && !runner.failed {
		runner.failed = true
		return nil, &CommandError{Args: append([]string(nil), args...), Stderr: "I/O failure", Err: errors.New("exit 1")}
	}
	return runner.base.Run(ctx, args...)
}

type runnerFunc func(context.Context, ...string) ([]byte, error)

func (function runnerFunc) Run(ctx context.Context, args ...string) ([]byte, error) {
	return function(ctx, args...)
}

func newBackendFixture(t *testing.T) (*Backend, *fakeZFS, *fakeBinder) {
	t.Helper()
	runner := newFakeZFS("tank/steward")
	binder := &fakeBinder{bindings: make(map[string]Binding)}
	backend, err := New(Config{DatasetRoot: "tank/steward", MountRoot: "/state", Runner: runner, Binder: binder,
		Now: func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return backend, runner, binder
}

type fakeBinder struct {
	mu         sync.Mutex
	bindings   map[string]Binding
	ensureErr  error
	inspectErr error
	deleteErr  error
}

func (binder *fakeBinder) Ensure(_ context.Context, binding Binding) (bool, error) {
	if binder.ensureErr != nil {
		return false, binder.ensureErr
	}
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if existing, ok := binder.bindings[binding.Handle]; ok {
		if existing.Source != binding.Source || !equalLabels(existing.Labels, binding.Labels) {
			return false, ErrBindingConflict
		}
		return false, nil
	}
	binding.Labels = cloneLabels(binding.Labels)
	binder.bindings[binding.Handle] = binding
	return true, nil
}

func (binder *fakeBinder) Inspect(_ context.Context, handle string) (Binding, error) {
	if binder.inspectErr != nil {
		return Binding{}, binder.inspectErr
	}
	binder.mu.Lock()
	defer binder.mu.Unlock()
	binding, ok := binder.bindings[handle]
	if !ok {
		return Binding{}, ErrBindingNotFound
	}
	binding.Labels = cloneLabels(binding.Labels)
	return binding, nil
}

func (binder *fakeBinder) Delete(_ context.Context, handle string) (bool, error) {
	if binder.deleteErr != nil {
		return false, binder.deleteErr
	}
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if _, ok := binder.bindings[handle]; !ok {
		return false, ErrBindingNotFound
	}
	delete(binder.bindings, handle)
	return true, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

type fakeDataset struct {
	properties map[string]string
	origin     string
	held       bool
}

type fakeZFS struct {
	mu       sync.Mutex
	datasets map[string]*fakeDataset
	nextGUID uint64
}

func newFakeZFS(root string) *fakeZFS {
	return &fakeZFS{datasets: map[string]*fakeDataset{root: {properties: map[string]string{
		"type": "filesystem", "canmount": "on", "mountpoint": "/tank/steward",
	}}}, nextGUID: 100}
}

func (zfs *fakeZFS) Run(_ context.Context, args ...string) ([]byte, error) {
	zfs.mu.Lock()
	defer zfs.mu.Unlock()
	if len(args) == 0 {
		return nil, zfsError(args, "missing command")
	}
	switch args[0] {
	case "get":
		return zfs.get(args)
	case "create":
		return nil, zfs.create(args, "")
	case "clone":
		if len(args) < 3 {
			return nil, zfsError(args, "invalid clone")
		}
		origin := args[len(args)-2]
		if _, ok := zfs.datasets[origin]; !ok {
			return nil, zfsError(args, "dataset does not exist")
		}
		target := args[len(args)-1]
		createArgs := append([]string{"create"}, args[1:len(args)-2]...)
		createArgs = append(createArgs, target)
		return nil, zfs.create(createArgs, origin, target)
	case "snapshot":
		return nil, zfs.createSnapshot(args)
	case "project":
		return nil, nil
	case "hold":
		dataset := zfs.datasets[args[len(args)-1]]
		if dataset == nil {
			return nil, zfsError(args, "dataset does not exist")
		}
		if dataset.held {
			return nil, zfsError(args, "tag already exists")
		}
		dataset.held = true
		return nil, nil
	case "release":
		dataset := zfs.datasets[args[len(args)-1]]
		if dataset == nil {
			return nil, zfsError(args, "dataset does not exist")
		}
		if !dataset.held {
			return nil, zfsError(args, "no such tag")
		}
		dataset.held = false
		return nil, nil
	case "destroy":
		return nil, zfs.destroy(args)
	case "set":
		if len(args) != 3 {
			return nil, zfsError(args, "invalid set")
		}
		dataset := zfs.datasets[args[2]]
		if dataset == nil {
			return nil, zfsError(args, "dataset does not exist")
		}
		key, value, ok := strings.Cut(args[1], "=")
		if !ok {
			return nil, zfsError(args, "invalid set")
		}
		dataset.properties[key] = value
		return nil, nil
	case "list":
		return zfs.list(args)
	default:
		return nil, zfsError(args, "unsupported fake command")
	}
}

func (zfs *fakeZFS) get(args []string) ([]byte, error) {
	if len(args) != 6 {
		return nil, zfsError(args, "invalid get")
	}
	target := args[5]
	dataset := zfs.datasets[target]
	if dataset == nil {
		return nil, zfsError(args, "dataset does not exist")
	}
	var lines []string
	for _, property := range strings.Split(args[4], ",") {
		value, ok := dataset.properties[property]
		if !ok && (strings.HasPrefix(property, "projectused@") || strings.HasPrefix(property, "projectobjused@")) {
			value, ok = "0", true
		}
		if property == "clones" {
			var clones []string
			for name, candidate := range zfs.datasets {
				if candidate.origin == target {
					clones = append(clones, name)
				}
			}
			slices.Sort(clones)
			if len(clones) == 0 {
				value = "-"
			} else {
				value = strings.Join(clones, ",")
			}
			ok = true
		}
		if !ok {
			value = "-"
		}
		lines = append(lines, property+"\t"+value)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func (zfs *fakeZFS) create(args []string, extras ...string) error {
	target := args[len(args)-1]
	origin := ""
	if len(extras) == 2 {
		origin, target = extras[0], extras[1]
	}
	if _, exists := zfs.datasets[target]; exists {
		return zfsError(args, "dataset already exists")
	}
	properties := map[string]string{"type": "filesystem", "canmount": "on", "mountpoint": "/" + target}
	for index := 1; index < len(args)-1; index++ {
		if args[index] != "-o" || index+1 >= len(args)-1 {
			continue
		}
		key, value, ok := strings.Cut(args[index+1], "=")
		if ok {
			properties[key] = value
		}
		index++
	}
	zfs.datasets[target] = &fakeDataset{properties: properties, origin: origin}
	return nil
}

func (zfs *fakeZFS) createSnapshot(args []string) error {
	target := args[len(args)-1]
	if _, exists := zfs.datasets[target]; exists {
		return zfsError(args, "dataset already exists")
	}
	source, _, ok := strings.Cut(target, "@")
	if !ok || zfs.datasets[source] == nil {
		return zfsError(args, "dataset does not exist")
	}
	zfs.nextGUID++
	properties := map[string]string{"type": "snapshot", "referenced": "0", "guid": strconv.FormatUint(zfs.nextGUID, 10)}
	for index := 1; index < len(args)-1; index++ {
		if args[index] == "-o" && index+1 < len(args)-1 {
			key, value, _ := strings.Cut(args[index+1], "=")
			properties[key] = value
			index++
		}
	}
	zfs.datasets[target] = &fakeDataset{properties: properties}
	return nil
}

func (zfs *fakeZFS) destroy(args []string) error {
	target := args[len(args)-1]
	dataset := zfs.datasets[target]
	if dataset == nil {
		return zfsError(args, "dataset does not exist")
	}
	if dataset.held {
		return zfsError(args, "snapshot is held")
	}
	if !strings.Contains(target, "@") {
		for name := range zfs.datasets {
			if strings.HasPrefix(name, target+"@") {
				return zfsError(args, "dataset is busy")
			}
		}
	}
	if strings.Contains(target, "@") {
		for _, candidate := range zfs.datasets {
			if candidate.origin == target {
				return zfsError(args, "has dependent clones")
			}
		}
	}
	delete(zfs.datasets, target)
	return nil
}

func (zfs *fakeZFS) list(args []string) ([]byte, error) {
	target := args[len(args)-1]
	if zfs.datasets[target] == nil {
		return nil, zfsError(args, "dataset does not exist")
	}
	values := []string{target}
	for name := range zfs.datasets {
		if strings.HasPrefix(name, target+"@") {
			values = append(values, name)
		}
	}
	slices.Sort(values)
	return []byte(strings.Join(values, "\n") + "\n"), nil
}

func zfsError(args []string, stderr string) error {
	return &CommandError{Args: append([]string(nil), args...), Stderr: stderr, Err: fmt.Errorf("exit status 1")}
}
