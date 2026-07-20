package storagebackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientAndHandlerPreserveScopedIdempotentStorageLifecycle(t *testing.T) {
	backend := newMemoryBackend()
	handler, err := NewHandler(backend, "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newClient(server.URL, "storage-secret", server.Client())
	ctx := context.Background()

	capabilities, err := client.Capabilities(ctx)
	if err != nil || !capabilities.ProductionQualified() {
		t.Fatalf("capabilities = (%+v, %v)", capabilities, err)
	}
	create := CreateVolumeRequest{RequestID: "create-parent", Volume: VolumeSpec{
		VolumeID: "volume-parent", TenantID: "tenant-a", LineageID: "lineage-parent",
		Generation: 1, ByteLimit: 1 << 30, ObjectLimit: 100_000,
	}}
	parent, changed, err := client.CreateVolume(ctx, create)
	if err != nil || !changed || parent.Scope() != create.Volume.Scope() {
		t.Fatalf("create parent = (%+v, %v, %v)", parent, changed, err)
	}
	retry, changed, err := client.CreateVolume(ctx, create)
	if err != nil || changed || retry != parent {
		t.Fatalf("retry parent = (%+v, %v, %v)", retry, changed, err)
	}
	wrongScope := parent.Scope()
	wrongScope.TenantID = "tenant-b"
	if _, err := client.InspectVolume(ctx, wrongScope); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant inspect error = %v", err)
	}

	snapshotRequest := CreateSnapshotRequest{
		RequestID: "snapshot-parent", SnapshotID: "snapshot-parent", Source: parent.Scope(),
	}
	snapshot, changed, err := client.CreateSnapshot(ctx, snapshotRequest)
	if err != nil || !changed || snapshot.TenantID != parent.Spec.TenantID || snapshot.SourceLineageID != parent.Spec.LineageID {
		t.Fatalf("create snapshot = (%+v, %v, %v)", snapshot, changed, err)
	}
	cloneRequest := CloneVolumeRequest{
		RequestID: "clone-child", Snapshot: snapshot.Scope(),
		Volume: VolumeSpec{
			VolumeID: "volume-child", TenantID: "tenant-a", LineageID: "lineage-child",
			Generation: 1, ByteLimit: 512 << 20, ObjectLimit: 50_000,
			ParentSnapshotID: snapshot.SnapshotID,
		},
	}
	child, changed, err := client.CloneVolume(ctx, cloneRequest)
	if err != nil || !changed || child.Spec.ParentSnapshotID != snapshot.SnapshotID {
		t.Fatalf("clone child = (%+v, %v, %v)", child, changed, err)
	}
	if _, _, err := client.DeleteSnapshot(ctx, DeleteSnapshotRequest{
		RequestID: "delete-live-parent", Snapshot: snapshot.Scope(),
	}); !errors.Is(err, ErrInUse) {
		t.Fatalf("referenced snapshot deletion error = %v", err)
	}
	deletedChild, changed, err := client.DeleteVolume(ctx, DeleteVolumeRequest{
		RequestID: "delete-child", Volume: child.Scope(),
	})
	if err != nil || !changed || deletedChild.State != StateDeleted {
		t.Fatalf("delete child = (%+v, %v, %v)", deletedChild, changed, err)
	}
	deletedSnapshot, changed, err := client.DeleteSnapshot(ctx, DeleteSnapshotRequest{
		RequestID: "delete-snapshot", Snapshot: snapshot.Scope(),
	})
	if err != nil || !changed || deletedSnapshot.State != StateDeleted {
		t.Fatalf("delete snapshot = (%+v, %v, %v)", deletedSnapshot, changed, err)
	}
}

func TestHandlerBoundsAndAuthenticatesEveryRequest(t *testing.T) {
	handler, err := NewHandler(newMemoryBackend(), "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("unauthorized response = %d %s", recorder.Code, recorder.Body.String())
	}

	for name, body := range map[string]string{
		"unknown":   `{"volume_id":"volume-a","tenant_id":"tenant-a","lineage_id":"lineage-a","generation":1,"extra":true}`,
		"duplicate": `{"volume_id":"volume-a","volume_id":"volume-b","tenant_id":"tenant-a","lineage_id":"lineage-a","generation":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/volumes/inspect", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer storage-secret")
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"error":"invalid_request"`) {
				t.Fatalf("strict response = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/volumes/inspect", bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxWireBytes+1)))
	request.Header.Set("Authorization", "Bearer storage-secret")
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestClientRejectsRedirectsAndOutOfScopeResponses(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Fatal("storage bearer reached redirect target")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer redirectTarget.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	client := newClient(redirector.URL, "storage-secret", &http.Client{
		Transport: redirector.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("storage backend redirects are disabled")
		},
	})
	if _, err := client.Capabilities(context.Background()); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error = %v", err)
	}

	outOfScope := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = jsonResponse(writer, readyVolume(VolumeSpec{
			VolumeID: "volume-a", TenantID: "tenant-b", LineageID: "lineage-a",
			Generation: 1, ByteLimit: 1 << 20, ObjectLimit: 100,
		}))
	}))
	defer outOfScope.Close()
	client = newClient(outOfScope.URL, "storage-secret", outOfScope.Client())
	if _, err := client.InspectVolume(context.Background(), VolumeScope{
		VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a", Generation: 1,
	}); err == nil || !strings.Contains(err.Error(), "out of scope") {
		t.Fatalf("out-of-scope response error = %v", err)
	}
}

func jsonResponse(writer http.ResponseWriter, value any) error {
	return json.NewEncoder(writer).Encode(value)
}

type memoryBackend struct {
	mu        sync.Mutex
	volumes   map[string]Volume
	snapshots map[string]Snapshot
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{volumes: make(map[string]Volume), snapshots: make(map[string]Snapshot)}
}

func (backend *memoryBackend) Capabilities(context.Context) (Capabilities, error) {
	return Capabilities{
		SchemaVersion: SchemaVersion, BackendID: "memory-conformance", HardByteQuota: true,
		HardObjectQuota: true, ColdSnapshots: true, ImmutableSnapshots: true,
		CopyOnWriteClones: true, CrashSafeMetadata: true, DockerVolumeHandles: true,
	}, nil
}

func (backend *memoryBackend) InspectVolume(_ context.Context, scope VolumeScope) (Volume, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volume, ok := backend.volumes[scope.VolumeID]
	if !ok || volume.Scope() != scope {
		return Volume{}, ErrNotFound
	}
	return volume, nil
}

func (backend *memoryBackend) CreateVolume(_ context.Context, request CreateVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if existing, ok := backend.volumes[request.Volume.VolumeID]; ok {
		if existing.Spec != request.Volume || existing.State == StateDeleted {
			return Volume{}, false, ErrConflict
		}
		return existing, false, nil
	}
	volume := readyVolume(request.Volume)
	backend.volumes[request.Volume.VolumeID] = volume
	return volume, true, nil
}

func (backend *memoryBackend) DeleteVolume(_ context.Context, request DeleteVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volume, ok := backend.volumes[request.Volume.VolumeID]
	if !ok || volume.Scope() != request.Volume {
		return Volume{}, false, ErrNotFound
	}
	if volume.State == StateDeleted {
		return volume, false, nil
	}
	volume.State, volume.DeletedAt = StateDeleted, "2026-07-20T12:02:00Z"
	backend.volumes[volume.Spec.VolumeID] = volume
	return volume, true, nil
}

func (backend *memoryBackend) InspectSnapshot(_ context.Context, scope SnapshotScope) (Snapshot, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshot, ok := backend.snapshots[scope.SnapshotID]
	if !ok || snapshot.Scope() != scope {
		return Snapshot{}, ErrNotFound
	}
	return snapshot, nil
}

func (backend *memoryBackend) CreateSnapshot(_ context.Context, request CreateSnapshotRequest) (Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return Snapshot{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volume, ok := backend.volumes[request.Source.VolumeID]
	if !ok || volume.Scope() != request.Source || volume.State != StateReady {
		return Snapshot{}, false, ErrNotFound
	}
	if existing, ok := backend.snapshots[request.SnapshotID]; ok {
		if existing.TenantID != volume.Spec.TenantID || existing.SourceVolumeID != volume.Spec.VolumeID ||
			existing.SourceLineageID != volume.Spec.LineageID || existing.State == StateDeleted {
			return Snapshot{}, false, ErrConflict
		}
		return existing, false, nil
	}
	digest := sha256.Sum256([]byte(volume.Spec.TenantID + "\x00" + volume.Spec.LineageID + "\x00" + request.SnapshotID))
	snapshot := Snapshot{
		SnapshotID: request.SnapshotID, TenantID: volume.Spec.TenantID, SourceVolumeID: volume.Spec.VolumeID,
		SourceLineageID: volume.Spec.LineageID, Generation: 1, State: StateReady,
		BackendRef: "snap-" + request.SnapshotID, ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
		RetainedBytes: volume.UsedBytes, ObjectCount: volume.UsedObjects, CreatedAt: "2026-07-20T12:01:00Z",
	}
	backend.snapshots[snapshot.SnapshotID] = snapshot
	return snapshot, true, nil
}

func (backend *memoryBackend) CloneVolume(_ context.Context, request CloneVolumeRequest) (Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshot, ok := backend.snapshots[request.Snapshot.SnapshotID]
	if !ok || snapshot.Scope() != request.Snapshot || snapshot.State != StateReady {
		return Volume{}, false, ErrNotFound
	}
	if snapshot.TenantID != request.Volume.TenantID {
		return Volume{}, false, ErrNotFound
	}
	if existing, ok := backend.volumes[request.Volume.VolumeID]; ok {
		if existing.Spec != request.Volume || existing.State == StateDeleted {
			return Volume{}, false, ErrConflict
		}
		return existing, false, nil
	}
	volume := readyVolume(request.Volume)
	volume.UsedBytes, volume.UsedObjects = snapshot.RetainedBytes, snapshot.ObjectCount
	backend.volumes[volume.Spec.VolumeID] = volume
	return volume, true, nil
}

func (backend *memoryBackend) DeleteSnapshot(_ context.Context, request DeleteSnapshotRequest) (Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return Snapshot{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshot, ok := backend.snapshots[request.Snapshot.SnapshotID]
	if !ok || snapshot.Scope() != request.Snapshot {
		return Snapshot{}, false, ErrNotFound
	}
	if snapshot.State == StateDeleted {
		return snapshot, false, nil
	}
	for _, volume := range backend.volumes {
		if volume.State != StateDeleted && volume.Spec.ParentSnapshotID == snapshot.SnapshotID {
			return Snapshot{}, false, ErrInUse
		}
	}
	snapshot.State, snapshot.DeletedAt = StateDeleted, "2026-07-20T12:03:00Z"
	backend.snapshots[snapshot.SnapshotID] = snapshot
	return snapshot, true, nil
}

func readyVolume(spec VolumeSpec) Volume {
	return Volume{
		Spec: spec, State: StateReady, BackendRef: "dataset-" + spec.VolumeID,
		DockerVolumeHandle: "steward-state-" + spec.VolumeID,
		CreatedAt:          time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
}
