package zfsstorage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/storagebackend"
)

// Uses only a random child dataset and explicitly named disposable containers.
// Existing services, pools, volumes and credentials are never modified.
func TestOfflineVolumeMigrationOnRealZFS(t *testing.T) {
	parent := os.Getenv("STEWARD_STORAGE_TEST_DATASET_PARENT")
	if parent == "" {
		t.Skip("requires explicit ZFS parent, Docker and root")
	}
	if os.Geteuid() != 0 || !validDataset(parent) || len(parent) > 100 {
		t.Fatal("invalid live migration test parent or identity")
	}
	binary, err := filepath.EvalSymlinks(os.Getenv("STEWARD_STORAGE_TEST_BINARY"))
	if err != nil || !filepath.IsAbs(binary) {
		t.Fatal("requires an absolute compiled storage worker binary")
	}
	image := os.Getenv("STEWARD_STORAGE_TEST_CONTAINER_IMAGE")
	if image == "" {
		t.Fatal("requires an explicitly selected local image with /bin/sh and sleep; no image is pulled")
	}
	command := func(args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		raw, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		return strings.TrimSpace(string(raw)), err
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := command(args...)
		if err != nil {
			t.Fatalf("%s failed: %v: %s", args[0], err, out)
		}
		return out
	}
	if run("zfs", "list", "-H", "-o", "type", parent) != "filesystem" {
		t.Fatal("parent must be a filesystem")
	}
	run("docker", "image", "inspect", image)
	fixture, err := os.MkdirTemp("/var/lib", "steward-migration-")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(fixture)
	dataset := parent + "/" + name
	created := false
	handle := ""
	container := false
	t.Cleanup(func() {
		if container {
			if out, err := command("docker", "rm", "-f", name); err != nil {
				t.Errorf("fixture container cleanup: %v %s", err, out)
				return
			}
		}
		if handle != "" {
			if out, err := command("docker", "volume", "rm", handle); err != nil {
				t.Errorf("fixture binding cleanup: %v %s", err, out)
				return
			}
		}
		if created {
			if out, err := command("zfs", "destroy", "-r", dataset); err != nil {
				t.Errorf("fixture dataset cleanup: %v %s", err, out)
				return
			}
		}
		if err := os.RemoveAll(fixture); err != nil {
			t.Error(err)
		}
	})
	run("zfs", "create", "-o", "canmount=off", "-o", "mountpoint=none", "-o", "quota=64M", dataset)
	created = true
	binder, err := NewDockerBinder("/var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := New(Config{DatasetRoot: dataset, MountRoot: filepath.Join(fixture, "state"), Runner: ExecRunner{Path: "/usr/sbin/zfs"}, Binder: binder})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	spec := storagebackend.VolumeSpec{VolumeID: "retained", TenantID: "migration-fixture", LineageID: "retained", Generation: 1, ByteLimit: 16 << 20, ObjectLimit: 1000}
	volume, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: "create", Volume: spec})
	if err != nil {
		t.Fatal(err)
	}
	handle = volume.DockerVolumeHandle
	mount := backend.volumeMountpoint(spec.Scope())
	dataPath := filepath.Join(mount, "retained.txt")
	if err := os.WriteFile(dataPath, []byte("retained customer bytes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{RequestID: "snapshot", SnapshotID: "before", Source: spec.Scope()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err := command("zfs", "release", holdTag, backend.snapshotDataset(snapshot.Scope()))
		if err != nil {
			t.Error(err)
		}
	}()
	// Record/quota/snapshot identity snapshots are separate from root permissions.
	project := strconv.FormatUint(uint64(projectID(spec.Scope())), 10)
	properties := recordProperty + ",refquota,projectquota@" + project + ",projectobjquota@" + project
	before := run("zfs", "get", "-Hp", "-o", "property,value", properties, backend.volumeDataset(spec.Scope()))
	fileBefore, err := os.Stat(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(mount, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mount, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(fixture, "token")
	if err := os.WriteFile(token, []byte("isolated-fixture-only-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath, scopePath := filepath.Join(fixture, "config.json"), filepath.Join(fixture, "scope.json")
	socket := filepath.Join(fixture, "storage.sock")
	writeJSON(configPath, map[string]string{"schema": "steward.storage-zfs.config.v1", "socket": socket, "token_file": token,
		"dataset_root": dataset, "mount_root": backend.mountRoot, "docker_socket": "/var/run/docker.sock", "zfs_binary": "/usr/sbin/zfs"})
	writeJSON(scopePath, spec.Scope())
	args := []string{binary, "-config", configPath, "-migrate-volume-access", scopePath}
	refuse := func(label string) {
		t.Helper()
		if out, err := command(args...); err == nil {
			t.Fatalf("%s accepted: %s", label, out)
		}
		info, err := os.Stat(mount)
		if err != nil || info.Mode().Perm() != 0o755 || info.Sys().(*syscall.Stat_t).Gid != 0 {
			t.Fatalf("%s changed root permissions: %v", label, err)
		}
		t.Log(label + " refused without changing retained root")
	}
	lock, err := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	refuse("active worker lifetime lock")
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	run("docker", "create", "--pull=never", "--name", name, "--network=none", "--read-only", "--user=65532:65532", "--mount", "type=volume,src="+handle+",dst=/state", image, "/bin/sh", "-c", "sleep 120")
	container = true
	refuse("stopped container reference")
	run("docker", "start", name)
	if run("docker", "inspect", "--format", "{{.State.Running}}", name) != "true" {
		t.Fatal("fixture container did not run")
	}
	refuse("running container reference")
	run("docker", "rm", "-f", name)
	container = false
	run(args...)
	run(args...)
	if err := (FilesystemMountAccess{}).Verify(mount); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dataPath)
	if err != nil || string(raw) != "retained customer bytes\n" {
		t.Fatalf("retained content changed: %v", err)
	}
	fileAfter, err := os.Stat(dataPath)
	if err != nil || fileAfter.Mode() != fileBefore.Mode() || fileAfter.Sys().(*syscall.Stat_t).Uid != fileBefore.Sys().(*syscall.Stat_t).Uid || fileAfter.Sys().(*syscall.Stat_t).Gid != fileBefore.Sys().(*syscall.Stat_t).Gid {
		t.Fatal("migration recursively changed retained file ownership/mode")
	}
	if after := run("zfs", "get", "-Hp", "-o", "property,value", properties, backend.volumeDataset(spec.Scope())); after != before {
		t.Fatal("record/quota changed")
	}
	if after, err := backend.InspectVolume(ctx, spec.Scope()); err != nil || after.DockerVolumeHandle != handle || after.State != storagebackend.StateReady {
		t.Fatalf("reattachment inspection failed: %+v %v", after, err)
	}
	if after, err := backend.InspectSnapshot(ctx, snapshot.Scope()); err != nil || after != snapshot {
		t.Fatalf("snapshot changed: %+v %v", after, err)
	}
	t.Log("CLI migration and replay preserve retained contents, file modes, identity, quota, binding and snapshot; new inspection permits reattachment")
}
