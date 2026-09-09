package zfsstorage

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

func TestCreateRetainsPreparedStateAcrossUncertainDockerOutcome(t *testing.T) {
	for _, phase := range []string{"post_commit", "verify", "rebound", "projection"} {
		t.Run(phase, func(t *testing.T) {
			backend, runner, _ := newBackendFixture(t)
			ctx := context.Background()
			request := storagebackend.CreateVolumeRequest{RequestID: "create-recoverable", Volume: storagebackend.VolumeSpec{
				VolumeID: "recoverable", TenantID: "tenant", LineageID: "lineage", Generation: 1,
				ByteLimit: 1 << 20, ObjectLimit: 256,
			}}
			dataset := backend.volumeDataset(request.Volume.Scope())
			handle := backend.dockerHandle(request.Volume.Scope())
			engine := &fakeDockerVolumes{volumes: make(map[string]dockerVolume)}
			created, deleted, reads := 0, 0, 0
			faulted := false
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet && created > 0 {
					reads++
					if !faulted && (phase == "verify" && reads == 1 || phase == "projection" && reads == 2) {
						faulted = true
						return nil, errors.New("Docker verification unavailable")
					}
				}
				response, err := engine.RoundTrip(r)
				if r.Method == http.MethodDelete {
					deleted++
				}
				if r.Method == http.MethodPost && err == nil {
					created++
					if !faulted && phase == "post_commit" {
						faulted = true
						_ = response.Body.Close()
						return nil, errors.New("Docker create acknowledgement lost")
					}
					if !faulted && phase == "rebound" {
						faulted = true
						engine.volumes[handle].Options["device"] = "/foreign"
					}
				}
				return response, err
			})})
			backend.binder = binder
			_, changed, err := backend.CreateVolume(ctx, request)
			if !faulted || changed || err == nil {
				t.Fatalf("uncertain creation: fault=%v changed=%v error=%v", faulted, changed, err)
			}
			retained, exists := runner.datasets[dataset]
			if !exists || len(engine.volumes) != 1 || deleted != 0 {
				t.Fatal("uncertain creation destroyed its dataset or binding")
			}
			properties := maps.Clone(retained.properties)
			// A new Backend reuses only persisted state, not an in-memory creation flag.
			restarted, err := newTestBackend(Config{DatasetRoot: backend.root, MountRoot: backend.mountRoot,
				Runner: runner, Binder: binder})
			if err != nil {
				t.Fatal(err)
			}
			conflicting := request
			conflicting.RequestID = "different-request"
			if _, _, err := restarted.CreateVolume(ctx, conflicting); !errors.Is(err, storagebackend.ErrConflict) {
				t.Fatalf("changed request was adopted: %v", err)
			}
			if phase == "rebound" {
				if _, _, err := restarted.CreateVolume(ctx, request); !errors.Is(err, storagebackend.ErrConflict) {
					t.Fatalf("foreign binding was adopted: %v", err)
				}
				if engine.volumes[handle].Options["device"] != "/foreign" || deleted != 0 {
					t.Fatal("replay repaired or deleted a foreign binding")
				}
				// Only the operator can reconcile the foreign binding to the exact source.
				engine.volumes[handle].Options["device"] = backend.volumeMountpoint(request.Volume.Scope())
			}
			volume, changed, err := restarted.CreateVolume(ctx, request)
			if err != nil || changed || volume.State != storagebackend.StateReady || volume.Spec != request.Volume {
				t.Fatalf("retained replay: volume=%+v changed=%v error=%v", volume, changed, err)
			}
			if runner.datasets[dataset] != retained || !maps.Equal(properties, retained.properties) || created != 1 || deleted != 0 {
				t.Fatal("replay replaced prepared state or repeated Docker creation")
			}
			removed, changed, err := restarted.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{
				RequestID: "delete-recovered", Volume: request.Volume.Scope(),
			})
			if err != nil || !changed || removed.State != storagebackend.StateDeleted || len(engine.volumes) != 0 {
				t.Fatalf("explicit cleanup after recovery: %+v, %v, %v", removed, changed, err)
			}
		})
	}
}
