package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// Exercise Docker's actual create/inspect normalization, not a hand-written
// inspect fixture. The container is never started; cleanup uses its unique name.
func TestDockerCreateInspectIntegration(t *testing.T) {
	socket := os.Getenv("STEWARD_DOCKER_INTEGRATION_SOCKET")
	image := os.Getenv("STEWARD_DOCKER_INTEGRATION_IMAGE")
	if socket == "" || image == "" {
		t.Skip("set Docker integration socket and an already-loaded image")
	}
	for _, prefix := range []string{"", "steward-state-", "steward-zfs-"} {
		t.Run("volume-prefix="+prefix, func(t *testing.T) {
			proveDockerCreateInspect(t, socket, image, prefix)
		})
	}
}

func proveDockerCreateInspect(t *testing.T, socket, image, volumePrefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docker := NewDockerHTTP(socket)
	name := fmt.Sprintf("steward-inspect-proof-%d", time.Now().UnixNano())
	w := Workload{
		TenantID: "inspect-proof", InstanceID: name, ProfileID: "generic-v1@v1",
		Image: image, Command: []string{"true"},
		Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32},
	}
	if volumePrefix != "" {
		volume := StateVolumeSpec{Name: volumePrefix + name, TenantID: w.TenantID, LineageID: name}
		if err := docker.CreateStateVolume(ctx, volume); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := docker.RemoveStateVolume(cleanup, volume.Name); err != nil {
				t.Errorf("remove owned proof volume: %v", err)
			}
		})
		w.State = &StateMount{VolumeName: volume.Name, Path: profileLayoutFor(w.ProfileID).StatePath}
	}
	if err := docker.Create(ctx, name, w); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := docker.Remove(cleanup, name); err != nil {
			t.Errorf("remove owned proof container: %v", err)
		}
	})
	observed, err := docker.Inspect(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Managed || !observed.Hardened || observed.Fingerprint != workloadFingerprint(w) {
		// Limit diagnostics to non-secret Docker isolation configuration.
		request, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://docker/v1.41/containers/"+pathEscape(name)+"/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := docker.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var diagnostic struct {
			HostConfig      json.RawMessage
			Mounts          json.RawMessage
			NetworkSettings json.RawMessage
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&diagnostic); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("created container rejected: managed=%t hardened=%t host=%s mounts=%s network=%s",
			observed.Managed, observed.Hardened, diagnostic.HostConfig, diagnostic.Mounts, diagnostic.NetworkSettings)
	}
}
