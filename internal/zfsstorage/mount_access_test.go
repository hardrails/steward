package zfsstorage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

type fakeMountAccess struct {
	prepared              []string
	prepareErr, verifyErr error
}

func (access *fakeMountAccess) Prepare(path string) error {
	access.prepared = append(access.prepared, path)
	return access.prepareErr
}

func (access *fakeMountAccess) Verify(string) error { return access.verifyErr }

func newTestBackend(config Config) (*Backend, error) {
	if config.MountAccess == nil {
		config.MountAccess = &fakeMountAccess{}
	}
	return New(config)
}

func TestMountAccessFailurePreventsReadyVolumeAndCleansBinding(t *testing.T) {
	for _, phase := range []string{"prepare", "verify"} {
		t.Run(phase, func(t *testing.T) {
			runner := newFakeZFS("tank/steward")
			binder := &fakeBinder{bindings: make(map[string]Binding)}
			sentinel := errors.New("mount boundary failed")
			access := &fakeMountAccess{}
			if phase == "prepare" {
				access.prepareErr = sentinel
			} else {
				access.verifyErr = sentinel
			}
			backend, err := New(Config{DatasetRoot: "tank/steward", MountRoot: "/state",
				Runner: runner, Binder: binder, MountAccess: access})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := backend.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			spec := storagebackend.VolumeSpec{VolumeID: "volume", TenantID: "tenant", LineageID: "lineage",
				Generation: 1, ByteLimit: 16 << 20, ObjectLimit: 256}
			if _, ready, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec}); ready || !errors.Is(err, sentinel) {
				t.Fatalf("ready=%v error=%v", ready, err)
			}
			if len(binder.bindings) != 0 {
				t.Fatal("failed mount retained a Docker binding")
			}
			if _, exists := runner.datasets[backend.volumeDataset(spec.Scope())]; exists {
				t.Fatal("failed mount retained its dataset")
			}
		})
	}
}

func TestMountInspectionDoesNotRepairChangedPermissions(t *testing.T) {
	runner := newFakeZFS("tank/steward")
	access := &fakeMountAccess{}
	backend, err := New(Config{DatasetRoot: "tank/steward", MountRoot: "/state", Runner: runner,
		Binder: &fakeBinder{bindings: make(map[string]Binding)}, MountAccess: access})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	request := storagebackend.CreateVolumeRequest{RequestID: "create", Volume: storagebackend.VolumeSpec{
		VolumeID: "volume", TenantID: "tenant", LineageID: "lineage", Generation: 1, ByteLimit: 16 << 20, ObjectLimit: 256}}
	if _, _, err := backend.CreateVolume(ctx, request); err != nil {
		t.Fatal(err)
	}
	access.verifyErr = errors.New("mount permissions changed")
	if _, err := backend.InspectVolume(ctx, request.Volume.Scope()); !errors.Is(err, access.verifyErr) {
		t.Fatalf("inspect = %v", err)
	}
	if _, _, err := backend.CreateVolume(ctx, request); !errors.Is(err, access.verifyErr) {
		t.Fatalf("replay = %v", err)
	}
	if len(access.prepared) != 1 {
		t.Fatal("inspection or replay repaired permissions")
	}
}

func TestFilesystemMountAccessRejectsUnquotaedAndSymlinkDirectories(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ordinary")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, link, "/", "relative", filepath.Join(root, "absent")} {
		if err := (FilesystemMountAccess{}).Prepare(candidate); err == nil {
			t.Fatalf("prepared unsafe path %q", candidate)
		}
		if err := (FilesystemMountAccess{}).Verify(candidate); err == nil {
			t.Fatalf("verified unsafe path %q", candidate)
		}
		if err := (FilesystemMountAccess{}).MigrateLegacy(candidate); err == nil {
			t.Fatalf("migrated unsafe path %q", candidate)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("changed permissions of unquotaed directory")
	}
}
