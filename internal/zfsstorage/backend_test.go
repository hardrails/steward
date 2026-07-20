package zfsstorage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	mu       sync.Mutex
	bindings map[string]Binding
}

func (binder *fakeBinder) Ensure(_ context.Context, binding Binding) (bool, error) {
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
