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
				if _, _, err := restarted.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{
					RequestID: "delete-conflicting", Volume: request.Volume.Scope(),
				}); !errors.Is(err, storagebackend.ErrConflict) {
					t.Fatalf("foreign binding deletion was accepted: %v", err)
				}
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

func TestCreatePreexistingConflictDoesNotRetainDeletionAuthority(t *testing.T) {
	for _, phase := range []string{"foreign_source", "foreign_labels", "invalid_driver", "unavailable"} {
		t.Run(phase, func(t *testing.T) {
			backend, runner, _ := newBackendFixture(t)
			ctx := context.Background()
			request := storagebackend.CreateVolumeRequest{RequestID: "create-conflicting", Volume: storagebackend.VolumeSpec{
				VolumeID: "conflicting", TenantID: "tenant", LineageID: "lineage", Generation: 1,
				ByteLimit: 1 << 20, ObjectLimit: 256,
			}}
			handle := backend.dockerHandle(request.Volume.Scope())
			foreign := dockerVolume{Name: handle, Driver: "local", Options: map[string]string{
				"type": "none", "o": "bind", "device": backend.volumeMountpoint(request.Volume.Scope()),
			}, Labels: map[string]string{
				"io.hardrails.steward.managed": "true", "io.hardrails.steward.backend-ref": backend.volumeRef(request.Volume.Scope()),
			}}
			switch phase {
			case "foreign_source":
				foreign.Options["device"] = "/foreign"
			case "foreign_labels":
				foreign.Labels["io.hardrails.steward.backend-ref"] = "foreign"
			case "invalid_driver":
				foreign.Driver = "foreign"
			}
			engine := &fakeDockerVolumes{volumes: map[string]dockerVolume{handle: foreign}}
			mutations := 0
			binder := newDockerBinder(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					mutations++
				}
				if phase == "unavailable" {
					return nil, errors.New("Docker unavailable before create")
				}
				return engine.RoundTrip(r)
			})})
			backend.binder = binder
			for attempt := 0; attempt < 2; attempt++ {
				if _, changed, err := backend.CreateVolume(ctx, request); err == nil || changed {
					t.Fatalf("conflict accepted: changed=%v error=%v", changed, err)
				}
				if _, exists := runner.datasets[backend.volumeDataset(request.Volume.Scope())]; exists {
					t.Fatal("pre-create failure retained a new Steward dataset/record")
				}
				// Restart must not turn a failed create into authority over a foreign handle.
				var err error
				backend, err = newTestBackend(Config{DatasetRoot: backend.root, MountRoot: backend.mountRoot, Runner: runner, Binder: binder})
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{
					RequestID: "delete-conflicting", Volume: request.Volume.Scope(),
				}); !errors.Is(err, storagebackend.ErrNotFound) {
					t.Fatalf("failed create retained deletion authority: %v", err)
				}
			}
			if mutations != 0 || len(engine.volumes) != 1 || !maps.Equal(engine.volumes[handle].Options, foreign.Options) ||
				!maps.Equal(engine.volumes[handle].Labels, foreign.Labels) || engine.volumes[handle].Driver != foreign.Driver {
				t.Fatal("pre-existing foreign binding was mutated")
			}
		})
	}
}

func TestDeleteRequiresCurrentBindingIdentityAndReplaysMissingBinding(t *testing.T) {
	for _, phase := range []string{"foreign_labels", "unavailable", "missing", "lost_delete_ack"} {
		t.Run(phase, func(t *testing.T) {
			backend, runner, _ := newBackendFixture(t)
			ctx := context.Background()
			request := storagebackend.CreateVolumeRequest{RequestID: "create-owned", Volume: storagebackend.VolumeSpec{
				VolumeID: "owned", TenantID: "tenant", LineageID: "lineage", Generation: 1,
				ByteLimit: 1 << 20, ObjectLimit: 256,
			}}
			engine := &fakeDockerVolumes{volumes: make(map[string]dockerVolume)}
			backend.binder = newDockerBinder(&http.Client{Transport: engine})
			volume, _, err := backend.CreateVolume(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			handle := volume.DockerVolumeHandle
			original := engine.volumes[handle]
			original.Labels = maps.Clone(original.Labels)
			if phase == "foreign_labels" {
				engine.volumes[handle].Labels["io.hardrails.steward.backend-ref"] = "foreign"
			} else if phase == "missing" {
				delete(engine.volumes, handle)
			}
			deletes := 0
			backend.binder = newDockerBinder(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodDelete {
					deletes++
				}
				if phase == "unavailable" {
					return nil, errors.New("cannot verify binding ownership")
				}
				response, err := engine.RoundTrip(r)
				if phase == "lost_delete_ack" && r.Method == http.MethodDelete && err == nil {
					_ = response.Body.Close()
					return nil, errors.New("delete acknowledgement lost")
				}
				return response, err
			})})
			deletion := storagebackend.DeleteVolumeRequest{RequestID: "delete-owned", Volume: request.Volume.Scope()}
			_, changed, err := backend.DeleteVolume(ctx, deletion)
			if phase == "missing" {
				if err != nil || !changed || deletes != 0 {
					t.Fatalf("missing binding cleanup: changed=%v deletes=%d error=%v", changed, deletes, err)
				}
			} else {
				if err == nil || changed || runner.datasets[backend.volumeDataset(request.Volume.Scope())] == nil {
					t.Fatal("unverified deletion changed retained state")
				}
				if phase != "lost_delete_ack" && (deletes != 0 || len(engine.volumes) != 1) {
					t.Fatal("unverified binding was deleted")
				}
			}
			if phase == "foreign_labels" {
				// Explicit fixture-owner reconciliation, not a backend repair.
				engine.volumes[handle] = original
			}
			restarted, err := newTestBackend(Config{DatasetRoot: backend.root, MountRoot: backend.mountRoot,
				Runner: runner, Binder: newDockerBinder(&http.Client{Transport: engine})})
			if err != nil {
				t.Fatal(err)
			}
			removed, _, err := restarted.DeleteVolume(ctx, deletion)
			if err != nil || removed.State != storagebackend.StateDeleted || len(engine.volumes) != 0 {
				t.Fatalf("verified deletion replay failed: %+v %v", removed, err)
			}
		})
	}
}
