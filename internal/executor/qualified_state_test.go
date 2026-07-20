package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

func TestQualifiedStateBackendCreatesReconcilesAndPurgesLineage(t *testing.T) {
	docker := &secureDocker{}
	backend := newQualifiedStateBackend()
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	config.AllowUnquotaedStateOnDedicatedHost = false
	config.StateBackend = backend
	config.StateVolumeByteLimit = 8 << 30
	config.StateVolumeObjectLimit = 250_000
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	response := submitSecureAdmission(t, server, capsule, intent)
	if response.Code != http.StatusCreated || docker.observed == nil || docker.observed.Workload.State == nil || docker.volume != nil {
		t.Fatalf("admit status=%d docker=%+v body=%s", response.Code, docker, response.Body.String())
	}
	spec := server.qualifiedStateSpec(intent.TenantID, intent.LineageID)
	if spec.ByteLimit != config.StateVolumeByteLimit || spec.ObjectLimit != config.StateVolumeObjectLimit {
		t.Fatalf("state spec = %+v", spec)
	}
	volume, err := backend.InspectVolume(context.Background(), spec.Scope())
	if err != nil || volume.State != storagebackend.StateReady || volume.DockerVolumeHandle != docker.observed.Workload.State.VolumeName {
		t.Fatalf("backend volume = (%+v, %v)", volume, err)
	}
	report, err := server.Reconcile(context.Background())
	if err != nil || !report.Ready {
		t.Fatalf("reconcile = (%+v, %v)", report, err)
	}

	ref := RuntimeRef(intent.TenantID, intent.InstanceID)
	destroy := httptest.NewRequest(http.MethodDelete, "/v1/workloads/"+ref, nil)
	destroy.Header.Set("Authorization", "Bearer secret")
	destroyResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(destroyResponse, destroy)
	if destroyResponse.Code != http.StatusNoContent {
		t.Fatalf("destroy status=%d body=%s", destroyResponse.Code, destroyResponse.Body.String())
	}
	purgeRaw, _ := json.Marshal(purgeStateRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation,
	})
	for attempt := 0; attempt < 2; attempt++ {
		purge := httptest.NewRequest(http.MethodPost, "/v1/state/purge", strings.NewReader(string(purgeRaw)))
		purge.Header.Set("Authorization", "Bearer secret")
		purgeResponse := httptest.NewRecorder()
		server.Handler().ServeHTTP(purgeResponse, purge)
		if purgeResponse.Code != http.StatusNoContent {
			t.Fatalf("purge attempt %d status=%d body=%s", attempt, purgeResponse.Code, purgeResponse.Body.String())
		}
	}
	volume, err = backend.InspectVolume(context.Background(), spec.Scope())
	if err != nil || volume.State != storagebackend.StateDeleted {
		t.Fatalf("deleted backend volume = (%+v, %v)", volume, err)
	}
}

func TestQualifiedStateBackendRequiresExistingResumeAndQualifiedCapabilities(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "resume"
	config.AllowUnquotaedStateOnDedicatedHost = false
	backend := newQualifiedStateBackend()
	config.StateBackend = backend
	config.StateVolumeByteLimit = 4096
	config.StateVolumeObjectLimit = 10
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	response := submitSecureAdmission(t, server, capsule, intent)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"state_missing"`) || len(docker.created) != 0 {
		t.Fatalf("resume status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
	}

	server, _ = NewServer(&secureDocker{}, "secret", nil)
	_, _, config = secureAdmissionFixture(t)
	backend.capabilities.HardObjectQuota = false
	config.AllowUnquotaedStateOnDedicatedHost = false
	config.StateBackend = backend
	config.StateVolumeByteLimit = 4096
	config.StateVolumeObjectLimit = 10
	if err := server.EnableSecureAdmission(config); err == nil || !strings.Contains(err.Error(), "not production-qualified") {
		t.Fatalf("unqualified backend error = %v", err)
	}
}

type qualifiedStateBackend struct {
	mu           sync.Mutex
	capabilities storagebackend.Capabilities
	volumes      map[storagebackend.VolumeScope]storagebackend.Volume
}

func newQualifiedStateBackend() *qualifiedStateBackend {
	return &qualifiedStateBackend{
		capabilities: storagebackend.Capabilities{
			SchemaVersion: storagebackend.SchemaVersion, BackendID: "qualified-test",
			HardByteQuota: true, HardObjectQuota: true, ColdSnapshots: true, ImmutableSnapshots: true,
			CopyOnWriteClones: true, CrashSafeMetadata: true, DockerVolumeHandles: true,
		},
		volumes: make(map[storagebackend.VolumeScope]storagebackend.Volume),
	}
}

func (backend *qualifiedStateBackend) Capabilities(context.Context) (storagebackend.Capabilities, error) {
	return backend.capabilities, nil
}

func (backend *qualifiedStateBackend) PlanVolume(_ context.Context, spec storagebackend.VolumeSpec) (storagebackend.VolumePlan, error) {
	if err := spec.Validate(); err != nil {
		return storagebackend.VolumePlan{}, err
	}
	return storagebackend.VolumePlan{
		Spec: spec, BackendRef: "test-" + spec.VolumeID, DockerVolumeHandle: "test-" + spec.VolumeID,
	}, nil
}

func (backend *qualifiedStateBackend) InspectVolume(_ context.Context, scope storagebackend.VolumeScope) (storagebackend.Volume, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volume, ok := backend.volumes[scope]
	if !ok {
		return storagebackend.Volume{}, storagebackend.ErrNotFound
	}
	return volume, nil
}

func (backend *qualifiedStateBackend) CreateVolume(_ context.Context, request storagebackend.CreateVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if existing, ok := backend.volumes[request.Volume.Scope()]; ok {
		return existing, false, nil
	}
	volume := storagebackend.Volume{
		Spec: request.Volume, State: storagebackend.StateReady,
		BackendRef: "test-" + request.Volume.VolumeID, DockerVolumeHandle: "test-" + request.Volume.VolumeID,
		CreatedAt: "2026-07-20T12:00:00Z",
	}
	backend.volumes[request.Volume.Scope()] = volume
	return volume, true, nil
}

func (backend *qualifiedStateBackend) DeleteVolume(_ context.Context, request storagebackend.DeleteVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volume, ok := backend.volumes[request.Volume]
	if !ok {
		return storagebackend.Volume{}, false, storagebackend.ErrNotFound
	}
	if volume.State == storagebackend.StateDeleted {
		return volume, false, nil
	}
	volume.State, volume.DeletedAt = storagebackend.StateDeleted, "2026-07-20T12:01:00Z"
	backend.volumes[request.Volume] = volume
	return volume, true, nil
}

func (*qualifiedStateBackend) InspectSnapshot(context.Context, storagebackend.SnapshotScope) (storagebackend.Snapshot, error) {
	return storagebackend.Snapshot{}, storagebackend.ErrUnsupported
}
func (*qualifiedStateBackend) CreateSnapshot(context.Context, storagebackend.CreateSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	return storagebackend.Snapshot{}, false, storagebackend.ErrUnsupported
}
func (*qualifiedStateBackend) CloneVolume(context.Context, storagebackend.CloneVolumeRequest) (storagebackend.Volume, bool, error) {
	return storagebackend.Volume{}, false, storagebackend.ErrUnsupported
}
func (*qualifiedStateBackend) DeleteSnapshot(context.Context, storagebackend.DeleteSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	return storagebackend.Snapshot{}, false, storagebackend.ErrUnsupported
}

var _ storagebackend.Backend = (*qualifiedStateBackend)(nil)
