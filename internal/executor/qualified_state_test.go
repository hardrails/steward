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

	"github.com/hardrails/steward/internal/admission"
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
	backend.cloneErr = errors.New("storage transport closed")
	clone := postStateMutation(t, server, "/v1/state/clones", cloneRequest)
	if clone.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 {
		t.Fatalf("ambiguous clone status=%d pending=%d body=%s", clone.Code, len(config.Journal.Pending()), clone.Body.String())
	}
	backend.cloneErr = nil
	clone = postStateMutation(t, server, "/v1/state/clones", cloneRequest)
	if clone.Code != http.StatusCreated || len(config.Journal.Pending()) != 0 {
		t.Fatalf("recovered clone status=%d pending=%d body=%s", clone.Code, len(config.Journal.Pending()), clone.Body.String())
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
	deleteSnapshot := stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "agent-1",
		LineageID: "lineage-a", Generation: 1, SnapshotID: snapshotRequest.SnapshotID,
	}
	if response := postStateMutation(t, server, "/v1/state/snapshots/delete", deleteSnapshot); response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), `"error":"state_in_use"`) {
		t.Fatalf("in-use snapshot delete status=%d body=%s", response.Code, response.Body.String())
	}
	forkRef := RuntimeRef(intent.TenantID, intent.InstanceID)
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+forkRef, context.Background(), http.StatusNoContent)
	assertStatePurge(t, server, purgeStateRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation,
	}, context.Background(), http.StatusNoContent)
	for attempt := 0; attempt < 2; attempt++ {
		if response := postStateMutation(t, server, "/v1/state/snapshots/delete", deleteSnapshot); response.Code != http.StatusNoContent {
			t.Fatalf("snapshot delete attempt=%d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}
	assertStatePurge(t, server, purgeStateRequest{
		TenantID: deleteSnapshot.TenantID, NodeID: deleteSnapshot.NodeID,
		LineageID: deleteSnapshot.LineageID, Generation: deleteSnapshot.Generation,
	}, context.Background(), http.StatusNoContent)
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
			if test.wantPending == 0 {
				return
			}
			if report, err := server.Reconcile(context.Background()); !errors.Is(err, ErrReconciliationIncomplete) || report.Ready {
				t.Fatalf("pending reconcile report=%+v err=%v", report, err)
			}
			mismatch := postStateMutation(t, server, "/v1/state/snapshots", stateSnapshotRequest{
				TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
				LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "different",
			})
			if mismatch.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 {
				t.Fatalf("mismatched recovery status=%d pending=%d body=%s", mismatch.Code, len(config.Journal.Pending()), mismatch.Body.String())
			}
			backend.snapshotErr = nil
			recovered := postStateMutation(t, server, "/v1/state/snapshots", stateSnapshotRequest{
				TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
				LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "failure",
			})
			if recovered.Code != http.StatusCreated || len(config.Journal.Pending()) != 0 {
				t.Fatalf("recovery status=%d pending=%d body=%s", recovered.Code, len(config.Journal.Pending()), recovered.Body.String())
			}
			if report, err := server.Reconcile(context.Background()); err != nil || !report.Ready {
				t.Fatalf("recovered reconcile report=%+v err=%v", report, err)
			}
		})
	}
}

func TestStateSnapshotEndpointGuardsAndHelpers(t *testing.T) {
	paths := []string{"/v1/state/snapshots", "/v1/state/clones", "/v1/state/snapshots/delete"}
	server, err := NewServer(&secureDocker{}, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if response := postStateMutation(t, server, path, map[string]string{}); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("unconfigured %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	_, _, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if response := postStateMutation(t, server, path, map[string]string{}); response.Code != http.StatusNotImplemented {
			t.Fatalf("backend-free %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	server, err = NewServer(&secureDocker{}, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, config = secureAdmissionFixture(t)
	config.StateBackend = newQualifiedStateBackend()
	config.AllowUnquotaedStateOnDedicatedHost = false
	config.StateVolumeByteLimit, config.StateVolumeObjectLimit = 4096, 10
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if response := postStateMutation(t, server, path, map[string]string{}); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	snapshotRequest := stateSnapshotRequest{
		TenantID: "tenant-a", NodeID: "other-node", InstanceID: "agent-1",
		LineageID: "lineage-a", Generation: 1, SnapshotID: "snapshot-a",
	}
	if response := postStateMutation(t, server, paths[0], snapshotRequest); response.Code != http.StatusForbidden {
		t.Fatalf("wrong-node snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	wrongNodeClone := stateCloneRequest{
		TenantID: "tenant-a", NodeID: "other-node", InstanceID: "agent-fork", LineageID: "lineage-fork",
		Generation: 1, SnapshotID: "snapshot-a", SourceLineageID: "lineage-a",
	}
	if response := postStateMutation(t, server, paths[1], wrongNodeClone); response.Code != http.StatusForbidden {
		t.Fatalf("wrong-node clone status=%d body=%s", response.Code, response.Body.String())
	}
	if response := postStateMutation(t, server, paths[2], snapshotRequest); response.Code != http.StatusForbidden {
		t.Fatalf("wrong-node deletion status=%d body=%s", response.Code, response.Body.String())
	}
	snapshotRequest.NodeID = "node-a"
	if response := postStateMutation(t, server, paths[0], snapshotRequest); response.Code != http.StatusNotFound {
		t.Fatalf("unknown snapshot lineage status=%d body=%s", response.Code, response.Body.String())
	}
	if response := postStateMutation(t, server, paths[2], snapshotRequest); response.Code != http.StatusNotFound {
		t.Fatalf("unknown deletion lineage status=%d body=%s", response.Code, response.Body.String())
	}
	cloneRequest := stateCloneRequest{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-fork", LineageID: "lineage-fork",
		Generation: 1, SnapshotID: "snapshot-a", SourceLineageID: "lineage-a",
	}
	if response := postStateMutation(t, server, paths[1], cloneRequest); response.Code != http.StatusNotFound {
		t.Fatalf("unknown clone source status=%d body=%s", response.Code, response.Body.String())
	}

	for _, backendErr := range []error{
		storagebackend.ErrInvalid, storagebackend.ErrNotFound, storagebackend.ErrConflict,
		storagebackend.ErrInUse, storagebackend.ErrCapacity, storagebackend.ErrUnsupported,
		storagebackend.ErrUnavailable,
	} {
		if !definitiveStateBackendError(backendErr) {
			t.Fatalf("definitive backend error not recognized: %v", backendErr)
		}
	}
	if definitiveStateBackendError(errors.New("transport closed")) {
		t.Fatal("ambiguous transport error was treated as definitive")
	}
	if target := stateMutationTarget("snapshot", "snapshot-a", "tenant-a", "lineage-a", 1); !strings.HasPrefix(target, "snapshot:") {
		t.Fatalf("mutation target = %q", target)
	}
	if validStateSnapshotRequest(stateSnapshotRequest{}) || validStateCloneRequest(stateCloneRequest{}) {
		t.Fatal("empty state mutation request was valid")
	}
	if validStateCloneRequest(stateCloneRequest{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-1", LineageID: "same",
		SourceLineageID: "same", SnapshotID: "snapshot-a", Generation: 1,
	}) {
		t.Fatal("self-clone request was valid")
	}
	snapshot := storagebackend.Snapshot{
		SnapshotID: "snapshot-a", TenantID: "tenant-a", SourceLineageID: "lineage-a",
		ContentDigest: "sha256:" + strings.Repeat("a", 64), RetainedBytes: 10, ObjectCount: 2,
		CreatedAt: "2026-07-20T12:00:00Z",
	}
	if response := snapshotResponse(snapshot); response.SnapshotID != snapshot.SnapshotID || response.Status != "stopped" {
		t.Fatalf("snapshot response = %+v", response)
	}
	if response := cloneResponse(cloneRequest); response.LineageID != cloneRequest.LineageID || response.Status != "stopped" {
		t.Fatalf("clone response = %+v", response)
	}
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{storagebackend.ErrInvalid, http.StatusBadRequest, "invalid_state"},
		{storagebackend.ErrNotFound, http.StatusNotFound, "state_not_found"},
		{storagebackend.ErrConflict, http.StatusConflict, "state_drift"},
		{storagebackend.ErrInUse, http.StatusConflict, "state_in_use"},
		{storagebackend.ErrCapacity, http.StatusInsufficientStorage, "state_capacity_exceeded"},
		{storagebackend.ErrUnsupported, http.StatusNotImplemented, "capability_unavailable"},
		{errors.New("transport"), http.StatusServiceUnavailable, "state_backend_unavailable"},
	} {
		recorder := httptest.NewRecorder()
		writeStateBackendError(recorder, test.err)
		if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), `"error":"`+test.code+`"`) {
			t.Fatalf("backend error %v response=%d %s", test.err, recorder.Code, recorder.Body.String())
		}
	}
}

func TestStateSnapshotLifecycleFailsClosedOnBackendDrift(t *testing.T) {
	server, backend, intent := stoppedQualifiedStateLineage(t)
	request := stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "checkpoint-drift",
	}
	backend.inspectVolumeErr = storagebackend.ErrUnavailable
	assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "state_backend_unavailable")
	backend.inspectVolumeErr = nil
	spec := server.qualifiedStateSpec(intent.TenantID, intent.LineageID)
	volume := backend.volumes[spec.Scope()]
	volume.State = storagebackend.StateDeleted
	backend.volumes[spec.Scope()] = volume
	assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusConflict, "state_drift")
	volume.State = storagebackend.StateReady
	backend.volumes[spec.Scope()] = volume
	backend.inspectSnapshotErr = storagebackend.ErrUnavailable
	assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "state_backend_unavailable")
	backend.inspectSnapshotErr = nil
	scope := storagebackend.SnapshotScope{
		SnapshotID: request.SnapshotID, TenantID: request.TenantID, SourceVolumeID: spec.VolumeID,
		SourceLineageID: request.LineageID, Generation: 1,
	}
	backend.snapshots[scope] = storagebackend.Snapshot{
		SnapshotID: scope.SnapshotID, TenantID: scope.TenantID, SourceVolumeID: scope.SourceVolumeID,
		SourceLineageID: scope.SourceLineageID, Generation: scope.Generation, State: storagebackend.StateDeleted,
		BackendRef: "snapshot-" + scope.SnapshotID, ContentDigest: "sha256:" + strings.Repeat("d", 64),
		CreatedAt: "2026-07-20T12:02:00Z", DeletedAt: "2026-07-20T12:03:00Z",
	}
	assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusConflict, "state_drift")
	delete(backend.snapshots, scope)
	backend.invalidSnapshot = true
	assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "reconciliation_required")
}

func TestStateCloneAndDeleteFailClosedOnBackendDrift(t *testing.T) {
	t.Run("clone", func(t *testing.T) {
		server, backend, intent := stoppedQualifiedStateLineage(t)
		snapshotRequest := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "checkpoint-clone",
		}
		if response := postStateMutation(t, server, "/v1/state/snapshots", snapshotRequest); response.Code != http.StatusCreated {
			t.Fatalf("snapshot status=%d body=%s", response.Code, response.Body.String())
		}
		request := stateCloneRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-a", LineageID: "lineage-fork-a",
			Generation: 1, SnapshotID: snapshotRequest.SnapshotID, SourceLineageID: intent.LineageID,
		}
		conflict := request
		conflict.InstanceID = intent.InstanceID
		assertStateMutationStatus(t, server, "/v1/state/clones", conflict, http.StatusConflict, "state_exists")
		scope := storagebackend.SnapshotScope{
			SnapshotID: request.SnapshotID, TenantID: request.TenantID,
			SourceVolumeID:  stateBackendVolumeID(request.TenantID, request.SourceLineageID),
			SourceLineageID: request.SourceLineageID, Generation: 1,
		}
		snapshot := backend.snapshots[scope]
		snapshot.State = storagebackend.StateDeleted
		backend.snapshots[scope] = snapshot
		assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusConflict, "state_drift")
		snapshot.State = storagebackend.StateReady
		backend.snapshots[scope] = snapshot
		backend.planErr = storagebackend.ErrCapacity
		assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusInsufficientStorage, "state_capacity_exceeded")
	})

	t.Run("clone target drift", func(t *testing.T) {
		server, backend, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "checkpoint-target-drift")
		request := stateCloneRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-drift", LineageID: "lineage-fork-drift",
			Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
		}
		spec := server.qualifiedStateSpec(request.TenantID, request.LineageID)
		spec.ParentSnapshotID = snapshotID
		backend.volumes[spec.Scope()] = storagebackend.Volume{
			Spec: spec, State: storagebackend.StateReady, BackendRef: "wrong",
			DockerVolumeHandle: "wrong", CreatedAt: "2026-07-20T12:00:00Z",
		}
		assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusConflict, "state_drift")
	})

	for _, test := range []struct {
		name string
		set  func(*qualifiedStateBackend)
		code string
	}{
		{name: "clone mutation", set: func(backend *qualifiedStateBackend) { backend.cloneErr = storagebackend.ErrConflict }, code: "state_drift"},
		{name: "clone projection", set: func(backend *qualifiedStateBackend) { backend.invalidClone = true }, code: "reconciliation_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, backend, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "checkpoint-"+strings.ReplaceAll(test.name, " ", "-"))
			test.set(backend)
			request := stateCloneRequest{
				TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-b", LineageID: "lineage-fork-b",
				Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
			}
			status := http.StatusConflict
			if test.code == "reconciliation_required" {
				status = http.StatusServiceUnavailable
			}
			assertStateMutationStatus(t, server, "/v1/state/clones", request, status, test.code)
		})
	}

	t.Run("delete", func(t *testing.T) {
		server, backend, intent := stoppedQualifiedStateLineage(t)
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "checkpoint-delete",
		}
		if response := postStateMutation(t, server, "/v1/state/snapshots", request); response.Code != http.StatusCreated {
			t.Fatalf("snapshot status=%d body=%s", response.Code, response.Body.String())
		}
		backend.deleteSnapshotErr = storagebackend.ErrInUse
		assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusConflict, "state_in_use")
		backend.deleteSnapshotErr = nil
		backend.invalidDelete = true
		assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "reconciliation_required")
	})
}

func TestStateSnapshotMutationsBlockBehindUnrelatedPreparedWork(t *testing.T) {
	server, _, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "checkpoint-pending")
	if _, err := server.secure.journal.Prepare("unrelated-operation", "unrelated-target", 1); err != nil {
		t.Fatal(err)
	}
	snapshot := stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
	}
	clone := stateCloneRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-pending", LineageID: "lineage-fork-pending",
		Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
	}
	for path, request := range map[string]any{
		"/v1/state/snapshots":        snapshot,
		"/v1/state/clones":           clone,
		"/v1/state/snapshots/delete": snapshot,
	} {
		assertStateMutationStatus(t, server, path, request, http.StatusServiceUnavailable, "reconciliation_required")
	}
}

func TestStateCloneAndDeleteSurfaceBackendInspectionFailure(t *testing.T) {
	t.Run("clone", func(t *testing.T) {
		server, backend, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "checkpoint-inspect-clone")
		backend.inspectSnapshotErr = storagebackend.ErrUnavailable
		request := stateCloneRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-inspect", LineageID: "lineage-fork-inspect",
			Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
		}
		assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusServiceUnavailable, "state_backend_unavailable")
	})
	t.Run("delete", func(t *testing.T) {
		server, backend, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "checkpoint-inspect-delete")
		backend.inspectSnapshotErr = storagebackend.ErrUnavailable
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
		}
		assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "state_backend_unavailable")
	})
}

func TestStateSnapshotMutationsRequireDurableJournalAndEvidence(t *testing.T) {
	t.Run("snapshot journal", func(t *testing.T) {
		server, _, intent := stoppedQualifiedStateLineage(t)
		if err := server.secure.journal.Close(); err != nil {
			t.Fatal(err)
		}
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "snapshot-journal",
		}
		assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "journal_unavailable")
	})
	t.Run("snapshot evidence", func(t *testing.T) {
		server, _, intent := stoppedQualifiedStateLineage(t)
		if err := server.secure.evidence.Close(); err != nil {
			t.Fatal(err)
		}
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "snapshot-evidence",
		}
		assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "evidence_unavailable")
	})
	for _, action := range []string{"clone", "delete"} {
		t.Run(action+" evidence", func(t *testing.T) {
			server, _, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "snapshot-"+action+"-evidence")
			if err := server.secure.evidence.Close(); err != nil {
				t.Fatal(err)
			}
			if action == "clone" {
				request := stateCloneRequest{
					TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-evidence", LineageID: "lineage-fork-evidence",
					Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
				}
				assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusServiceUnavailable, "evidence_unavailable")
				return
			}
			request := stateSnapshotRequest{
				TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
				LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
			}
			assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "evidence_unavailable")
		})
	}
}

func TestStateSnapshotDeletionRetainsAmbiguousOrUnprovenWork(t *testing.T) {
	t.Run("already absent", func(t *testing.T) {
		server, _, intent := stoppedQualifiedStateLineage(t)
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "snapshot-already-absent",
		}
		if response := postStateMutation(t, server, "/v1/state/snapshots/delete", request); response.Code != http.StatusNoContent {
			t.Fatalf("absent deletion status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("ambiguous backend result", func(t *testing.T) {
		server, backend, intent, snapshotID := stoppedQualifiedStateSnapshot(t, "snapshot-delete-ambiguous")
		backend.deleteSnapshotErr = errors.New("storage transport closed")
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
		}
		assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "reconciliation_required")
		if len(server.secure.journal.Pending()) != 1 {
			t.Fatal("ambiguous deletion did not remain prepared")
		}
	})
	t.Run("missing recovery target", func(t *testing.T) {
		server, _, intent := stoppedQualifiedStateLineage(t)
		request := stateSnapshotRequest{
			TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
			LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: "snapshot-missing-recovery",
		}
		target := stateMutationTarget("delete-snapshot", request.SnapshotID, request.TenantID, request.LineageID, request.Generation)
		if _, err := server.secure.journal.Prepare("delete-recovery", target, request.Generation); err != nil {
			t.Fatal(err)
		}
		assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "reconciliation_required")
	})
}

func TestStateMutationDoesNotAcknowledgeWithoutCommitReceipt(t *testing.T) {
	for _, durable := range []string{"evidence", "journal"} {
		for _, action := range []string{"snapshot", "clone", "delete"} {
			t.Run(action+" "+durable, func(t *testing.T) {
				server, backend, intent := stoppedQualifiedStateLineage(t)
				snapshotID := "snapshot-commit-" + action + "-" + durable
				if action != "snapshot" {
					request := stateSnapshotRequest{
						TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
						LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
					}
					if response := postStateMutation(t, server, "/v1/state/snapshots", request); response.Code != http.StatusCreated {
						t.Fatalf("prepare snapshot status=%d body=%s", response.Code, response.Body.String())
					}
				}
				closeReceiptStore := func() {
					if durable == "evidence" {
						_ = server.secure.evidence.Close()
					} else {
						_ = server.secure.journal.Close()
					}
				}
				switch action {
				case "snapshot":
					backend.snapshotHook = closeReceiptStore
					request := stateSnapshotRequest{
						TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
						LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
					}
					assertStateMutationStatus(t, server, "/v1/state/snapshots", request, http.StatusServiceUnavailable, "reconciliation_required")
				case "clone":
					backend.cloneHook = closeReceiptStore
					request := stateCloneRequest{
						TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: "fork-commit", LineageID: "lineage-fork-commit",
						Generation: 1, SnapshotID: snapshotID, SourceLineageID: intent.LineageID,
					}
					assertStateMutationStatus(t, server, "/v1/state/clones", request, http.StatusServiceUnavailable, "reconciliation_required")
				case "delete":
					backend.deleteHook = closeReceiptStore
					request := stateSnapshotRequest{
						TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
						LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
					}
					assertStateMutationStatus(t, server, "/v1/state/snapshots/delete", request, http.StatusServiceUnavailable, "reconciliation_required")
				}
			})
		}
	}
}

func stoppedQualifiedStateLineage(t *testing.T) (*Server, *qualifiedStateBackend, admission.InstanceIntent) {
	t.Helper()
	backend := newQualifiedStateBackend()
	server, err := NewServer(&secureDocker{}, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State, intent.StateDisposition = true, "new"
	config.StateBackend = backend
	config.AllowUnquotaedStateOnDedicatedHost = false
	config.StateVolumeByteLimit, config.StateVolumeObjectLimit = 4096, 10
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	if response := submitSecureAdmission(t, server, capsule, intent); response.Code != http.StatusCreated {
		t.Fatalf("admission status=%d body=%s", response.Code, response.Body.String())
	}
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+RuntimeRef(intent.TenantID, intent.InstanceID), context.Background(), http.StatusNoContent)
	return server, backend, intent
}

func stoppedQualifiedStateSnapshot(t *testing.T, snapshotID string) (*Server, *qualifiedStateBackend, admission.InstanceIntent, string) {
	t.Helper()
	server, backend, intent := stoppedQualifiedStateLineage(t)
	request := stateSnapshotRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, InstanceID: intent.InstanceID,
		LineageID: intent.LineageID, Generation: intent.Generation, SnapshotID: snapshotID,
	}
	if response := postStateMutation(t, server, "/v1/state/snapshots", request); response.Code != http.StatusCreated {
		t.Fatalf("snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	return server, backend, intent, snapshotID
}

func assertStateMutationStatus(t *testing.T, server *Server, path string, request any, status int, code string) {
	t.Helper()
	response := postStateMutation(t, server, path, request)
	if response.Code != status || !strings.Contains(response.Body.String(), `"error":"`+code+`"`) {
		t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
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
	mu                 sync.Mutex
	capabilities       storagebackend.Capabilities
	volumes            map[storagebackend.VolumeScope]storagebackend.Volume
	snapshots          map[storagebackend.SnapshotScope]storagebackend.Snapshot
	snapshotErr        error
	cloneErr           error
	inspectVolumeErr   error
	inspectSnapshotErr error
	planErr            error
	deleteSnapshotErr  error
	invalidSnapshot    bool
	invalidClone       bool
	invalidDelete      bool
	snapshotHook       func()
	cloneHook          func()
	deleteHook         func()
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
	if backend.planErr != nil {
		return storagebackend.VolumePlan{}, backend.planErr
	}
	if err := spec.Validate(); err != nil {
		return storagebackend.VolumePlan{}, err
	}
	return storagebackend.VolumePlan{
		Spec: spec, BackendRef: "test-" + spec.VolumeID, DockerVolumeHandle: "test-" + spec.VolumeID,
	}, nil
}

func (backend *qualifiedStateBackend) InspectVolume(_ context.Context, scope storagebackend.VolumeScope) (storagebackend.Volume, error) {
	if backend.inspectVolumeErr != nil {
		return storagebackend.Volume{}, backend.inspectVolumeErr
	}
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
	if backend.inspectSnapshotErr != nil {
		return storagebackend.Snapshot{}, backend.inspectSnapshotErr
	}
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
	if backend.invalidSnapshot {
		snapshot.State = storagebackend.StateDeleted
		snapshot.DeletedAt = "2026-07-20T12:02:01Z"
	}
	backend.snapshots[scope] = snapshot
	if backend.snapshotHook != nil {
		backend.snapshotHook()
	}
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
	if backend.invalidClone {
		volume.DockerVolumeHandle = "wrong-handle"
	}
	backend.volumes[request.Volume.Scope()] = volume
	if backend.cloneHook != nil {
		backend.cloneHook()
	}
	return volume, true, nil
}
func (backend *qualifiedStateBackend) DeleteSnapshot(_ context.Context, request storagebackend.DeleteSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	if backend.deleteSnapshotErr != nil {
		return storagebackend.Snapshot{}, false, backend.deleteSnapshotErr
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
	for _, volume := range backend.volumes {
		if volume.State == storagebackend.StateReady && volume.Spec.ParentSnapshotID == request.Snapshot.SnapshotID {
			return storagebackend.Snapshot{}, false, storagebackend.ErrInUse
		}
	}
	snapshot.State, snapshot.DeletedAt = storagebackend.StateDeleted, "2026-07-20T12:04:00Z"
	if backend.invalidDelete {
		snapshot.State, snapshot.DeletedAt = storagebackend.StateReady, ""
	}
	backend.snapshots[request.Snapshot] = snapshot
	if backend.deleteHook != nil {
		backend.deleteHook()
	}
	return snapshot, true, nil
}

var _ storagebackend.Backend = (*qualifiedStateBackend)(nil)
