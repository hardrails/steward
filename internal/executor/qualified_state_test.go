package executor

import (
	"context"
	"encoding/json"
	"errors"
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

func TestQualifiedStateSnapshotCloneAndResumeWorkflow(t *testing.T) {
	docker := &secureDocker{}
	backend := newQualifiedStateBackend()
	server, _ := NewServer(docker, "secret", nil)
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
	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
		t.Fatalf("source admission status=%d body=%s", response.Code, response.Body.String())
	}
	ref := RuntimeRef(intent.TenantID, intent.InstanceID)
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+ref, context.Background(), http.StatusNoContent)

	snapshotRequest := stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "checkpoint-a",
	}
	snapshot := postStateMutation(t, server, "/v1/state/snapshots", snapshotRequest)
	if snapshot.Code != http.StatusCreated {
		t.Fatalf("snapshot status=%d body=%s", snapshot.Code, snapshot.Body.String())
	}
	if replay := postStateMutation(t, server, "/v1/state/snapshots", snapshotRequest); replay.Code != http.StatusOK {
		t.Fatalf("snapshot replay status=%d body=%s", replay.Code, replay.Body.String())
	}

	cloneRequest := stateCloneRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "agent-fork",
		LineageID: "lineage-fork", Generation: 1, SnapshotID: "checkpoint-a",
		SourceLineageID: intent.LineageID,
	}
	clone := postStateMutation(t, server, "/v1/state/clones", cloneRequest)
	if clone.Code != http.StatusCreated {
		t.Fatalf("clone status=%d body=%s", clone.Code, clone.Body.String())
	}
	if replay := postStateMutation(t, server, "/v1/state/clones", cloneRequest); replay.Code != http.StatusOK {
		t.Fatalf("clone replay status=%d body=%s", replay.Code, replay.Body.String())
	}

	intent.InstanceID = cloneRequest.InstanceID
	intent.LineageID = cloneRequest.LineageID
	intent.Generation = cloneRequest.Generation
	intent.StateDisposition = "resume"
	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
		t.Fatalf("fork admission status=%d body=%s", response.Code, response.Body.String())
	}
	forkSpec := server.qualifiedStateSpec(intent.TenantID, intent.LineageID)
	fork, err := backend.InspectVolume(context.Background(), forkSpec.Scope())
	if err != nil || fork.Spec.ParentSnapshotID != snapshotRequest.SnapshotID || docker.observed.Workload.State.VolumeName != fork.DockerVolumeHandle {
		t.Fatalf("fork volume=%+v err=%v workload=%+v", fork, err, docker.observed.Workload)
	}
}

func TestQualifiedStateSnapshotFailsClosedWhileLineageIsPresent(t *testing.T) {
	docker := &secureDocker{}
	backend := newQualifiedStateBackend()
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	config.AllowUnquotaedStateOnDedicatedHost = false
	config.StateBackend = backend
	config.StateVolumeByteLimit, config.StateVolumeObjectLimit = 4096, 10
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
		t.Fatalf("source admission status=%d body=%s", response.Code, response.Body.String())
	}
	response := postStateMutation(t, server, "/v1/state/snapshots", stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "live",
	})
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"state_in_use"`) {
		t.Fatalf("snapshot status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestQualifiedStateSnapshotDistinguishesDefinitiveAndAmbiguousBackendFailure(t *testing.T) {
	for _, test := range []struct {
		name        string
		backendErr  error
		wantStatus  int
		wantPending int
	}{
		{name: "definitive conflict", backendErr: storagebackend.ErrConflict, wantStatus: http.StatusConflict},
		{name: "lost response", backendErr: errors.New("storage transport closed"), wantStatus: http.StatusServiceUnavailable, wantPending: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := &secureDocker{}
			backend := newQualifiedStateBackend()
			server, _ := NewServer(docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			intent.Capabilities.State, intent.StateDisposition = true, "new"
			config.AllowUnquotaedStateOnDedicatedHost = false
			config.StateBackend = backend
			config.StateVolumeByteLimit, config.StateVolumeObjectLimit = 4096, 10
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
				t.Fatalf("source admission status=%d body=%s", response.Code, response.Body.String())
			}
			assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+RuntimeRef(intent.TenantID, intent.InstanceID), context.Background(), http.StatusNoContent)
			backend.snapshotErr = test.backendErr
			response := postStateMutation(t, server, "/v1/state/snapshots", stateSnapshotRequest{
				TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
				LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "failure",
			})
			if response.Code != test.wantStatus || len(config.Journal.Pending()) != test.wantPending {
				t.Fatalf("status=%d pending=%d body=%s", response.Code, len(config.Journal.Pending()), response.Body.String())
			}
		})
	}
}

func postStateMutation(t *testing.T, server *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type qualifiedStateBackend struct {
	mu           sync.Mutex
	capabilities storagebackend.Capabilities
	volumes      map[storagebackend.VolumeScope]storagebackend.Volume
	snapshots    map[storagebackend.SnapshotScope]storagebackend.Snapshot
	snapshotErr  error
	cloneErr     error
}

func newQualifiedStateBackend() *qualifiedStateBackend {
	return &qualifiedStateBackend{
		capabilities: storagebackend.Capabilities{
			SchemaVersion: storagebackend.SchemaVersion, BackendID: "qualified-test",
			HardByteQuota: true, HardObjectQuota: true, ColdSnapshots: true, ImmutableSnapshots: true,
			CopyOnWriteClones: true, CrashSafeMetadata: true, DockerVolumeHandles: true,
		},
		volumes:   make(map[storagebackend.VolumeScope]storagebackend.Volume),
		snapshots: make(map[storagebackend.SnapshotScope]storagebackend.Snapshot),
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

func (backend *qualifiedStateBackend) InspectSnapshot(_ context.Context, scope storagebackend.SnapshotScope) (storagebackend.Snapshot, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshot, ok := backend.snapshots[scope]
	if !ok {
		return storagebackend.Snapshot{}, storagebackend.ErrNotFound
	}
	return snapshot, nil
}
func (backend *qualifiedStateBackend) CreateSnapshot(_ context.Context, request storagebackend.CreateSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	if backend.snapshotErr != nil {
		return storagebackend.Snapshot{}, false, backend.snapshotErr
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	scope := storagebackend.SnapshotScope{
		SnapshotID: request.SnapshotID, TenantID: request.Source.TenantID,
		SourceVolumeID: request.Source.VolumeID, SourceLineageID: request.Source.LineageID,
		Generation: request.Source.Generation,
	}
	if existing, ok := backend.snapshots[scope]; ok {
		return existing, false, nil
	}
	volume, ok := backend.volumes[request.Source]
	if !ok || volume.State != storagebackend.StateReady {
		return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
	}
	snapshot := storagebackend.Snapshot{
		SnapshotID: scope.SnapshotID, TenantID: scope.TenantID,
		SourceVolumeID: scope.SourceVolumeID, SourceLineageID: scope.SourceLineageID,
		Generation: scope.Generation, State: storagebackend.StateReady,
		BackendRef:    "snapshot-" + scope.SnapshotID,
		ContentDigest: "sha256:" + strings.Repeat("d", 64), CreatedAt: "2026-07-20T12:02:00Z",
	}
	backend.snapshots[scope] = snapshot
	return snapshot, true, nil
}
func (backend *qualifiedStateBackend) CloneVolume(_ context.Context, request storagebackend.CloneVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	if backend.cloneErr != nil {
		return storagebackend.Volume{}, false, backend.cloneErr
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if snapshot, ok := backend.snapshots[request.Snapshot]; !ok || snapshot.State != storagebackend.StateReady {
		return storagebackend.Volume{}, false, storagebackend.ErrNotFound
	}
	if existing, ok := backend.volumes[request.Volume.Scope()]; ok {
		return existing, false, nil
	}
	volume := storagebackend.Volume{
		Spec: request.Volume, State: storagebackend.StateReady,
		BackendRef: "test-" + request.Volume.VolumeID, DockerVolumeHandle: "test-" + request.Volume.VolumeID,
		CreatedAt: "2026-07-20T12:03:00Z",
	}
	backend.volumes[request.Volume.Scope()] = volume
	return volume, true, nil
}
func (backend *qualifiedStateBackend) DeleteSnapshot(_ context.Context, request storagebackend.DeleteSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshot, ok := backend.snapshots[request.Snapshot]
	if !ok {
		return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
	}
	if snapshot.State == storagebackend.StateDeleted {
		return snapshot, false, nil
	}
	snapshot.State, snapshot.DeletedAt = storagebackend.StateDeleted, "2026-07-20T12:04:00Z"
	backend.snapshots[request.Snapshot] = snapshot
	return snapshot, true, nil
}

var _ storagebackend.Backend = (*qualifiedStateBackend)(nil)
