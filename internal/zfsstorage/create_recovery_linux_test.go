package zfsstorage

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

// This opt-in proof creates only a random child dataset and one named Docker
// volume. No container, existing service, retained volume or credential changes.
func TestUncertainCreateRetainsRealZFSData(t *testing.T) {
	parent := os.Getenv("STEWARD_STORAGE_TEST_DATASET_PARENT")
	if parent == "" {
		t.Skip("requires an explicit ZFS parent, Docker and root")
	}
	if os.Geteuid() != 0 || !validDataset(parent) || len(parent) > 100 {
		t.Fatal("invalid live storage test parent or identity")
	}
	ctx := context.Background()
	runner := ExecRunner{Path: "/usr/sbin/zfs"}
	if raw, err := runner.Run(ctx, "list", "-H", "-o", "type", parent); err != nil || strings.TrimSpace(string(raw)) != "filesystem" {
		t.Fatalf("invalid parent filesystem: %v", err)
	}
	fixture, err := os.MkdirTemp("/var/lib", "steward-create-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	dataset := parent + "/" + filepath.Base(fixture)
	binder, err := NewDockerBinder("/var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	created := false
	handle := ""
	t.Cleanup(func() {
		if handle != "" {
			if _, err := binder.Delete(ctx, handle); err != nil && !errors.Is(err, ErrBindingNotFound) {
				t.Errorf("fixture binding cleanup: %v", err)
				return
			}
		}
		if created {
			if _, err := runner.Run(ctx, "destroy", "-r", dataset); err != nil {
				t.Errorf("fixture dataset cleanup: %v", err)
				return
			}
		}
		if err := os.RemoveAll(fixture); err != nil {
			t.Error(err)
		}
	})
	if _, err := runner.Run(ctx, "create", "-o", "canmount=off", "-o", "mountpoint=none", "-o", "quota=64M", dataset); err != nil {
		t.Fatal(err)
	}
	created = true
	config := Config{DatasetRoot: dataset, MountRoot: filepath.Join(fixture, "state"), Runner: runner, Binder: binder}
	backend, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	request := storagebackend.CreateVolumeRequest{RequestID: "create", Volume: storagebackend.VolumeSpec{
		VolumeID: "retained", TenantID: "recovery-fixture", LineageID: "retained", Generation: 1, ByteLimit: 16 << 20, ObjectLimit: 1000,
	}}
	handle = backend.dockerHandle(request.Volume.Scope())
	dataPath := filepath.Join(backend.volumeMountpoint(request.Volume.Scope()), "retained.txt")
	transport := binder.client.Transport
	faulted := false
	backend.binder = newDockerBinder(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		if err == nil && !faulted && r.Method == http.MethodPost && response.StatusCode == http.StatusCreated {
			faulted = true
			_ = response.Body.Close()
			if err := os.WriteFile(dataPath, []byte("retained despite lost acknowledgement\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			return nil, errors.New("injected lost Docker create acknowledgement")
		}
		return response, err
	}), Timeout: binder.client.Timeout})
	if _, changed, err := backend.CreateVolume(ctx, request); !faulted || changed || err == nil {
		t.Fatalf("uncertain create: fault=%v changed=%v error=%v", faulted, changed, err)
	}
	before, err := os.Stat(dataPath)
	if err != nil {
		t.Fatalf("uncertain create removed retained data: %v", err)
	}
	restarted, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	volume, changed, err := restarted.CreateVolume(ctx, request)
	if err != nil || changed || volume.State != storagebackend.StateReady || volume.Spec != request.Volume {
		t.Fatalf("recovered create: %+v, %v, %v", volume, changed, err)
	}
	raw, err := os.ReadFile(dataPath)
	if err != nil || string(raw) != "retained despite lost acknowledgement\n" {
		t.Fatalf("recovered bytes changed: %v", err)
	}
	after, err := os.Stat(dataPath)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatalf("recovery replaced retained file: %v", err)
	}
	if err := (FilesystemMountAccess{}).Verify(filepath.Dir(dataPath)); err != nil {
		t.Fatal(err)
	}
	t.Log("lost Docker acknowledgement preserves real ZFS data; a new backend replays the exact request without replacing the file")
}
