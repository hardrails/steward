package storagebackend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	plan, err := client.PlanVolume(ctx, create.Volume)
	if err != nil || plan.Spec != create.Volume || plan.DockerVolumeHandle != "memory-volume-parent" {
		t.Fatalf("plan parent = (%+v, %v)", plan, err)
	}
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
	inspectedSnapshot, err := client.InspectSnapshot(ctx, snapshot.Scope())
	if err != nil || inspectedSnapshot != snapshot {
		t.Fatalf("inspect snapshot = (%+v, %v)", inspectedSnapshot, err)
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

func TestUnixClientAndAPIErrorClassification(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-storage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "storage.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(newMemoryBackend(), "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	go func() { _ = server.Serve(listener) }()
	client, err := NewUnixClient(socket, "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	if capabilities, err := client.Capabilities(context.Background()); err != nil || !capabilities.ProductionQualified() {
		t.Fatalf("unix capabilities = (%+v, %v)", capabilities, err)
	}
	for _, input := range [][2]string{{"relative", "token"}, {socket, ""}, {"/", "token"}} {
		if _, err := NewUnixClient(input[0], input[1]); err == nil {
			t.Fatalf("invalid unix client accepted: %q %q", input[0], input[1])
		}
	}
	for code, target := range map[string]error{
		"invalid_request": ErrInvalid, "not_found": ErrNotFound, "conflict": ErrConflict,
		"in_use": ErrInUse, "capacity_exceeded": ErrCapacity, "unsupported": ErrUnsupported,
		"unavailable": ErrUnavailable,
	} {
		failure := &APIError{Status: http.StatusConflict, Code: code, Message: "classified"}
		if !errors.Is(failure, target) || failure.Error() == "" {
			t.Fatalf("API error %q was not classified as %v", code, target)
		}
	}
	if errors.Is(&APIError{Code: "unknown"}, ErrUnavailable) {
		t.Fatal("unknown API error was classified")
	}
}

func TestClientFailsClosedOnMalformedTransportResponses(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"wrong media type": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte(`{}`))
		},
		"oversized": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(bytes.Repeat([]byte{'x'}, MaxWireBytes+1))
		},
		"invalid error": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusConflict)
			_, _ = writer.Write([]byte(`{"error":"conflict"}`))
		},
		"valid error": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusConflict)
			_, _ = writer.Write([]byte(`{"error":"conflict","message":"retained identity differs"}`))
		},
		"invalid success": func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"unknown":true}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			_, err := newClient(server.URL, "storage-secret", server.Client()).Capabilities(context.Background())
			if err == nil {
				t.Fatal("malformed transport response was accepted")
			}
			if name == "valid error" && !errors.Is(err, ErrConflict) {
				t.Fatalf("valid wire error = %v", err)
			}
		})
	}

	client := newClient("http://127.0.0.1", "storage-secret", http.DefaultClient)
	ctx := context.Background()
	if _, err := client.PlanVolume(ctx, VolumeSpec{}); err == nil {
		t.Fatal("invalid plan scope was sent")
	}
	if _, err := client.InspectVolume(ctx, VolumeScope{}); err == nil {
		t.Fatal("invalid volume scope was sent")
	}
	if _, _, err := client.CreateVolume(ctx, CreateVolumeRequest{}); err == nil {
		t.Fatal("invalid volume creation was sent")
	}
	if _, _, err := client.DeleteVolume(ctx, DeleteVolumeRequest{}); err == nil {
		t.Fatal("invalid volume deletion was sent")
	}
	if _, err := client.InspectSnapshot(ctx, SnapshotScope{}); err == nil {
		t.Fatal("invalid snapshot scope was sent")
	}
	if _, _, err := client.CreateSnapshot(ctx, CreateSnapshotRequest{}); err == nil {
		t.Fatal("invalid snapshot creation was sent")
	}
	if _, _, err := client.CloneVolume(ctx, CloneVolumeRequest{}); err == nil {
		t.Fatal("invalid clone was sent")
	}
	if _, _, err := client.DeleteSnapshot(ctx, DeleteSnapshotRequest{}); err == nil {
		t.Fatal("invalid snapshot deletion was sent")
	}
}

func TestClientRejectsValidButOutOfScopeStorageProjections(t *testing.T) {
	spec := VolumeSpec{
		VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a",
		Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
	}
	snapshot := Snapshot{
		SnapshotID: "snapshot-a", TenantID: "tenant-b", SourceVolumeID: spec.VolumeID,
		SourceLineageID: spec.LineageID, Generation: 1, State: StateReady, BackendRef: "snapshot-a",
		ContentDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: "2026-07-20T12:00:00Z",
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/capabilities":
			_ = json.NewEncoder(writer).Encode(Capabilities{SchemaVersion: "other", BackendID: "backend-a"})
		case "/v1/volumes/plan":
			other := spec
			other.VolumeID = "volume-other"
			_ = json.NewEncoder(writer).Encode(VolumePlan{Spec: other, BackendRef: "backend-other", DockerVolumeHandle: "handle-other"})
		case "/v1/volumes/create":
			_ = json.NewEncoder(writer).Encode(mutationResponse{Changed: true})
		case "/v1/snapshots/inspect":
			_ = json.NewEncoder(writer).Encode(snapshot)
		case "/v1/snapshots/create", "/v1/snapshots/delete":
			_ = json.NewEncoder(writer).Encode(mutationResponse{Snapshot: &snapshot, Changed: true})
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	client := newClient(server.URL, "storage-secret", server.Client())
	ctx := context.Background()
	if _, err := client.Capabilities(ctx); err == nil {
		t.Fatal("invalid capabilities projection accepted")
	}
	if _, err := client.PlanVolume(ctx, spec); err == nil {
		t.Fatal("out-of-scope plan accepted")
	}
	if _, _, err := client.CreateVolume(ctx, CreateVolumeRequest{RequestID: "create", Volume: spec}); err == nil {
		t.Fatal("empty volume mutation accepted")
	}
	wantSnapshot := snapshot.Scope()
	wantSnapshot.TenantID = spec.TenantID
	if _, err := client.InspectSnapshot(ctx, wantSnapshot); err == nil {
		t.Fatal("out-of-scope snapshot accepted")
	}
	if _, _, err := client.CreateSnapshot(ctx, CreateSnapshotRequest{
		RequestID: "snapshot", SnapshotID: snapshot.SnapshotID, Source: spec.Scope(),
	}); err == nil {
		t.Fatal("out-of-scope snapshot mutation accepted")
	}
	if _, _, err := client.DeleteSnapshot(ctx, DeleteSnapshotRequest{RequestID: "delete", Snapshot: wantSnapshot}); err == nil {
		t.Fatal("out-of-scope snapshot deletion accepted")
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

func TestBackendErrorContractMapsEveryFailureClass(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{ErrInvalid, http.StatusBadRequest, "invalid_request"},
		{ErrNotFound, http.StatusNotFound, "not_found"},
		{ErrConflict, http.StatusConflict, "conflict"},
		{ErrInUse, http.StatusConflict, "in_use"},
		{ErrCapacity, http.StatusInsufficientStorage, "capacity_exceeded"},
		{ErrUnsupported, http.StatusNotImplemented, "unsupported"},
		{ErrUnavailable, http.StatusServiceUnavailable, "unavailable"},
		{errors.New("unexpected"), http.StatusInternalServerError, "backend_error"},
	} {
		recorder := httptest.NewRecorder()
		writeMappedBackendError(recorder, test.err)
		if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), `"error":"`+test.code+`"`) {
			t.Fatalf("error %v response=%d %s", test.err, recorder.Code, recorder.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", strings.NewReader("x"))
	request.Header.Set("Authorization", "Bearer storage-secret")
	recorder := httptest.NewRecorder()
	handler, err := NewHandler(newMemoryBackend(), "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("capabilities body status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	scope := VolumeScope{VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a", Generation: 1}
	raw, _ := json.Marshal(scope)
	request = httptest.NewRequest(http.MethodPost, "/v1/volumes/inspect", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	serveBackendOperation(recorder, request, func(context.Context, VolumeScope) (Volume, error) {
		return Volume{}, nil
	})
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("invalid operation projection status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/volumes/inspect", bytes.NewReader(raw))
	recorder = httptest.NewRecorder()
	serveBackendOperation(recorder, request, func(context.Context, VolumeScope) (Volume, error) {
		return Volume{}, nil
	})
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing media type status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	spec := VolumeSpec{
		VolumeID: "volume-a", TenantID: "tenant-a", LineageID: "lineage-a",
		Generation: 1, ByteLimit: 1024, ObjectLimit: 10,
	}
	create := CreateVolumeRequest{RequestID: "create-a", Volume: spec}
	raw, _ = json.Marshal(create)
	request = httptest.NewRequest(http.MethodPost, "/v1/volumes/create", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	serveBackendMutation(recorder, request, func(context.Context, CreateVolumeRequest) (Volume, bool, error) {
		return readyVolume(spec), true, nil
	}, "snapshot")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("mutation type mismatch status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/volumes/create", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	serveBackendMutation(recorder, request, func(context.Context, CreateVolumeRequest) (Volume, bool, error) {
		return Volume{}, true, nil
	}, "volume")
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("invalid mutation projection status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	snapshot := Snapshot{
		SnapshotID: "snapshot-a", TenantID: spec.TenantID, SourceVolumeID: spec.VolumeID,
		SourceLineageID: spec.LineageID, Generation: 1, State: StateReady, BackendRef: "snapshot-a",
		ContentDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: "2026-07-20T12:00:00Z",
	}
	snapshotRequest := CreateSnapshotRequest{RequestID: "snapshot-a", SnapshotID: snapshot.SnapshotID, Source: spec.Scope()}
	raw, _ = json.Marshal(snapshotRequest)
	request = httptest.NewRequest(http.MethodPost, "/v1/snapshots/create", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	serveBackendMutation(recorder, request, func(context.Context, CreateSnapshotRequest) (Snapshot, bool, error) {
		return snapshot, true, nil
	}, "volume")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("snapshot mutation type mismatch status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/capabilities?unexpected=true", nil)
	request.Header.Set("Authorization", "Bearer storage-secret")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("query parameter status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCapabilitiesRejectBackendFailureAndInvalidProjection(t *testing.T) {
	for name, backend := range map[string]Backend{
		"failure": &capabilitiesBackend{memoryBackend: newMemoryBackend(), err: ErrUnavailable},
		"invalid": &capabilitiesBackend{memoryBackend: newMemoryBackend(), capabilities: Capabilities{}},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewHandler(backend, "storage-secret")
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
			request.Header.Set("Authorization", "Bearer storage-secret")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code < http.StatusBadRequest {
				t.Fatalf("invalid capabilities status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestStorageHandlerRecoversBackendPanicAsJSON(t *testing.T) {
	handler, err := NewHandler(&capabilitiesBackend{memoryBackend: newMemoryBackend(), panic: true}, "storage-secret")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	request.Header.Set("Authorization", "Bearer storage-secret")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), `"error":"internal_error"`) {
		t.Fatalf("panic response=%d %s", recorder.Code, recorder.Body.String())
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

type capabilitiesBackend struct {
	*memoryBackend
	capabilities Capabilities
	err          error
	panic        bool
}

func (backend *capabilitiesBackend) Capabilities(context.Context) (Capabilities, error) {
	if backend.panic {
		panic("backend panic")
	}
	return backend.capabilities, backend.err
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

func (backend *memoryBackend) PlanVolume(_ context.Context, spec VolumeSpec) (VolumePlan, error) {
	if err := spec.Validate(); err != nil {
		return VolumePlan{}, err
	}
	return VolumePlan{Spec: spec, BackendRef: "memory-" + spec.VolumeID, DockerVolumeHandle: "memory-" + spec.VolumeID}, nil
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
