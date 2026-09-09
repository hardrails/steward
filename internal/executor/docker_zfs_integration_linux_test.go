package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/storagebackend"
	"github.com/hardrails/steward/internal/zfsstorage"
)

// Uses only a random child of an explicitly selected parent. The loaded Hermes
// image must contain its normal /opt/data seed directory: the copy-up negative
// control proves that image content would otherwise replace the backend root.
func TestDockerZFSStateRootIntegration(t *testing.T) {
	parent := os.Getenv("STEWARD_DOCKER_ZFS_TEST_PARENT")
	socket := os.Getenv("STEWARD_DOCKER_INTEGRATION_SOCKET")
	image := os.Getenv("STEWARD_DOCKER_INTEGRATION_IMAGE")
	if parent == "" || socket == "" || image == "" {
		t.Skip("requires explicit ZFS parent, Docker socket and loaded Hermes image")
	}
	if os.Geteuid() != 0 || len(parent) > 100 || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*$`).MatchString(parent) {
		t.Fatal("requires root and a bounded ZFS parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	runner := zfsstorage.ExecRunner{Path: "/usr/sbin/zfs"}
	name := fmt.Sprintf("steward-copy-proof-%d", time.Now().UnixNano())
	dataset := parent + "/" + name
	mountRoot, err := os.MkdirTemp("/var/lib", name+"-")
	if err != nil {
		t.Fatal(err)
	}
	created := false
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if created {
			if _, err := runner.Run(cleanup, "destroy", "-r", dataset); err != nil {
				t.Errorf("remove owned dataset: %v", err)
				return
			}
		}
		if err := os.RemoveAll(mountRoot); err != nil {
			t.Error(err)
		}
	})
	if _, err := runner.Run(ctx, "create", "-o", "canmount=off", "-o", "mountpoint=none", "-o", "quota=134217728", dataset); err != nil {
		t.Fatal(err)
	}
	created = true
	binder, err := zfsstorage.NewDockerBinder(socket)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := zfsstorage.New(zfsstorage.Config{DatasetRoot: dataset, MountRoot: filepath.Join(mountRoot, "state"), Runner: runner, Binder: binder})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	for _, noCopy := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-copy=%t", noCopy), func(t *testing.T) {
			instance := fmt.Sprintf("%s-%t", name, noCopy)
			spec := storagebackend.VolumeSpec{VolumeID: instance, TenantID: "copy-proof", LineageID: instance, Generation: 1, ByteLimit: 32 << 20, ObjectLimit: 1000}
			plan, err := backend.PlanVolume(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				if _, err := binder.Delete(cleanup, plan.DockerVolumeHandle); err != nil {
					t.Errorf("remove owned binding: %v", err)
				}
			})
			volume, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{RequestID: instance, Volume: spec})
			if err != nil {
				t.Fatal(err)
			}
			docker := NewDockerHTTP(socket)
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				if err := docker.Remove(cleanup, instance); err != nil {
					t.Errorf("remove owned container: %v", err)
				}
			})
			w := Workload{TenantID: "copy-proof", InstanceID: instance, ProfileID: "hermes-v1@v1", Image: image, Command: []string{"true"}, Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32}, State: &StateMount{VolumeName: volume.DockerVolumeHandle, Path: "/opt/data", NoCopy: noCopy}}
			if err := docker.Create(ctx, instance, w); err != nil {
				t.Fatal(err)
			}
			observed, err := docker.Inspect(ctx, instance)
			if err != nil || !observed.Hardened {
				t.Fatalf("Docker create/inspect: hardened=%t error=%v", observed.Hardened, err)
			}
			_, err = backend.InspectVolume(ctx, spec.Scope())
			if noCopy && err != nil {
				t.Fatalf("Docker replaced qualified storage root: %v", err)
			}
			if !noCopy && err == nil {
				t.Fatal("negative control did not reproduce image copy-up; use the normal Hermes image")
			}
		})
	}
}
