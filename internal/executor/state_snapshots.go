package executor

import (
	"errors"
	"io"
	"net/http"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/storagebackend"
)

type stateSnapshotRequest struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	InstanceID string `json:"instance_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
	SnapshotID string `json:"snapshot_id"`
}

type stateCloneRequest struct {
	TenantID        string `json:"tenant_id"`
	NodeID          string `json:"node_id"`
	InstanceID      string `json:"instance_id"`
	LineageID       string `json:"lineage_id"`
	Generation      uint64 `json:"generation"`
	SnapshotID      string `json:"snapshot_id"`
	SourceLineageID string `json:"source_lineage_id"`
}

type stateSnapshotResponse struct {
	Status          string `json:"status"`
	SnapshotID      string `json:"snapshot_id"`
	TenantID        string `json:"tenant_id"`
	SourceLineageID string `json:"source_lineage_id"`
	ContentDigest   string `json:"content_digest"`
	RetainedBytes   int64  `json:"retained_bytes"`
	ObjectCount     int64  `json:"object_count"`
	CreatedAt       string `json:"created_at"`
}

type stateCloneResponse struct {
	Status     string `json:"status"`
	TenantID   string `json:"tenant_id"`
	InstanceID string `json:"instance_id"`
	LineageID  string `json:"lineage_id"`
	SnapshotID string `json:"snapshot_id"`
}

func (s *Server) createStateSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	if s.secure.stateBackend == nil {
		writeError(w, http.StatusNotImplemented, "capability_unavailable", "cold snapshots require a qualified persistent state backend")
		return
	}
	var request stateSnapshotRequest
	if !decodeStateMutation(w, r, &request) || !validStateSnapshotRequest(request) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded state snapshot object")
		return
	}
	if !s.authorizeStateMutation(r, request.TenantID, request.NodeID, request.Generation) {
		writeError(w, http.StatusForbidden, "admission_denied", "state snapshot does not match the authenticated command")
		return
	}

	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	target := stateMutationTarget("snapshot", request.SnapshotID, request.TenantID, request.LineageID, request.Generation)
	opID, recovering, blocked := s.stateMutationRecovery(target, request.Generation)
	if blocked {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	record, found, active := s.coldLineageRecord(request.TenantID, request.InstanceID, request.LineageID, request.Generation)
	if active {
		writeError(w, http.StatusConflict, "state_in_use", "state must be stopped and destroyed before it can be snapshotted")
		return
	}
	if !found || !s.principalAuthorizesRecord(r.Context(), record) {
		writeError(w, http.StatusNotFound, "state_not_found", "the signed state lineage is not known on this node")
		return
	}

	volumeSpec := s.qualifiedStateSpec(request.TenantID, request.LineageID)
	volume, err := s.secure.stateBackend.InspectVolume(r.Context(), volumeSpec.Scope())
	if err != nil {
		writeStateBackendError(w, err)
		return
	}
	if !qualifiedStateSpecMatches(volume.Spec, volumeSpec) || volume.State != storagebackend.StateReady {
		writeError(w, http.StatusConflict, "state_drift", "state volume does not match the signed tenant lineage and fixed host quota")
		return
	}
	scope := storagebackend.SnapshotScope{
		SnapshotID: request.SnapshotID, TenantID: request.TenantID,
		SourceVolumeID: volume.Spec.VolumeID, SourceLineageID: request.LineageID,
		Generation: volume.Spec.Generation,
	}
	if existing, inspectErr := s.secure.stateBackend.InspectSnapshot(r.Context(), scope); inspectErr == nil && existing.State != storagebackend.StateReady {
		writeError(w, http.StatusConflict, "state_drift", "snapshot is not ready")
		return
	} else if inspectErr != nil && !errors.Is(inspectErr, storagebackend.ErrNotFound) {
		writeStateBackendError(w, inspectErr)
		return
	}

	prepared := stateMutationEvidence(record, request.SnapshotID, "state-snapshot", evidence.JournalPrepare, evidence.Allowed)
	if !recovering {
		opID, err = newOperationID("snapshot-"+request.SnapshotID, request.Generation)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "create state snapshot operation identity")
			return
		}
		if _, err := s.secure.journal.Prepare(opID, target, request.Generation); err != nil {
			writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
			return
		}
		if _, err := s.secure.evidence.Append(prepared); err != nil {
			_ = s.secure.journal.Compensate(opID)
			writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
			return
		}
	}
	snapshot, changed, mutationErr := s.secure.stateBackend.CreateSnapshot(r.Context(), storagebackend.CreateSnapshotRequest{
		RequestID:  stateBackendRequestID("snapshot-"+request.SnapshotID, request.TenantID, request.LineageID, request.Generation),
		SnapshotID: request.SnapshotID, Source: volume.Spec.Scope(),
	})
	if mutationErr != nil {
		if definitiveStateBackendError(mutationErr) {
			s.recordCompensation(opID, prepared, "state_snapshot")
			writeStateBackendError(w, mutationErr)
		} else {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state snapshot result is ambiguous; operation remains prepared")
		}
		return
	}
	if snapshot.Scope() != scope || snapshot.State != storagebackend.StateReady {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state snapshot returned an invalid projection; operation remains prepared")
		return
	}
	committed := prepared
	committed.Type, committed.Outcome, committed.MetadataHash = evidence.JournalCommit, evidence.Committed, snapshot.ContentDigest
	if _, err := s.secure.evidence.Append(committed); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "snapshot exists but its receipt could not be persisted")
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	status := http.StatusCreated
	if !changed {
		status = http.StatusOK
	}
	writeJSON(w, status, snapshotResponse(snapshot))
}

func (s *Server) cloneStateSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	if s.secure.stateBackend == nil {
		writeError(w, http.StatusNotImplemented, "capability_unavailable", "copy-on-write clones require a qualified persistent state backend")
		return
	}
	var request stateCloneRequest
	if !decodeStateMutation(w, r, &request) || !validStateCloneRequest(request) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded state clone object")
		return
	}
	if !s.authorizeStateMutation(r, request.TenantID, request.NodeID, request.Generation) {
		writeError(w, http.StatusForbidden, "admission_denied", "state clone does not match the authenticated command")
		return
	}

	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	target := stateMutationTarget("clone", request.SnapshotID, request.TenantID, request.LineageID, request.Generation)
	opID, recovering, blocked := s.stateMutationRecovery(target, request.Generation)
	if blocked {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	for _, record := range s.secure.fences.Records() {
		if record.TenantID == request.TenantID && (record.InstanceID == request.InstanceID || record.LineageID == request.LineageID) {
			writeError(w, http.StatusConflict, "state_exists", "clone target identity already has retained signed lifecycle state")
			return
		}
	}
	sourceRecord, sourceFound := s.latestLineageRecord(request.TenantID, request.SourceLineageID)
	if !sourceFound {
		writeError(w, http.StatusNotFound, "state_not_found", "source snapshot has no retained signed lineage on this node")
		return
	}
	snapshotScope := storagebackend.SnapshotScope{
		SnapshotID: request.SnapshotID, TenantID: request.TenantID,
		SourceVolumeID:  stateBackendVolumeID(request.TenantID, request.SourceLineageID),
		SourceLineageID: request.SourceLineageID, Generation: 1,
	}
	snapshot, err := s.secure.stateBackend.InspectSnapshot(r.Context(), snapshotScope)
	if err != nil {
		writeStateBackendError(w, err)
		return
	}
	if snapshot.State != storagebackend.StateReady {
		writeError(w, http.StatusConflict, "state_drift", "source snapshot is not ready")
		return
	}
	volumeSpec := s.qualifiedStateSpec(request.TenantID, request.LineageID)
	volumeSpec.ParentSnapshotID = request.SnapshotID
	plan, err := s.secure.stateBackend.PlanVolume(r.Context(), volumeSpec)
	if err != nil {
		writeStateBackendError(w, err)
		return
	}
	if existing, inspectErr := s.secure.stateBackend.InspectVolume(r.Context(), volumeSpec.Scope()); inspectErr == nil {
		if existing.Spec != volumeSpec || existing.State != storagebackend.StateReady || existing.DockerVolumeHandle != plan.DockerVolumeHandle {
			writeError(w, http.StatusConflict, "state_drift", "clone target conflicts with retained backend identity")
			return
		}
	} else if !errors.Is(inspectErr, storagebackend.ErrNotFound) {
		writeStateBackendError(w, inspectErr)
		return
	}

	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: request.TenantID, RuntimeRef: plan.DockerVolumeHandle,
		CapsuleDigest: sourceRecord.CapsuleDigest, PolicyDigest: sourceRecord.PolicyDigest,
		Generation: request.Generation, GrantID: "state-clone", Outcome: evidence.Allowed,
	}
	if !recovering {
		opID, err = newOperationID("clone-"+request.InstanceID, request.Generation)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "create state clone operation identity")
			return
		}
		if _, err := s.secure.journal.Prepare(opID, target, request.Generation); err != nil {
			writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
			return
		}
		if _, err := s.secure.evidence.Append(prepared); err != nil {
			_ = s.secure.journal.Compensate(opID)
			writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
			return
		}
	}
	volume, changed, mutationErr := s.secure.stateBackend.CloneVolume(r.Context(), storagebackend.CloneVolumeRequest{
		RequestID: stateBackendRequestID("clone-"+request.SnapshotID, request.TenantID, request.LineageID, request.Generation),
		Snapshot:  snapshotScope, Volume: volumeSpec,
	})
	if mutationErr != nil {
		if definitiveStateBackendError(mutationErr) {
			s.recordCompensation(opID, prepared, "state_clone")
			writeStateBackendError(w, mutationErr)
		} else {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state clone result is ambiguous; operation remains prepared")
		}
		return
	}
	if volume.Spec != volumeSpec || volume.State != storagebackend.StateReady || volume.DockerVolumeHandle != plan.DockerVolumeHandle {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state clone returned an invalid projection; operation remains prepared")
		return
	}
	committed := prepared
	committed.Type, committed.Outcome, committed.MetadataHash = evidence.JournalCommit, evidence.Committed, snapshot.ContentDigest
	if _, err := s.secure.evidence.Append(committed); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "clone exists but its receipt could not be persisted")
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	status := http.StatusCreated
	if !changed {
		status = http.StatusOK
	}
	writeJSON(w, status, cloneResponse(request))
}

func decodeStateMutation(w http.ResponseWriter, r *http.Request, output any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	return dsse.DecodeStrictInto(raw, maxBodyBytes, output) == nil
}

func definitiveStateBackendError(err error) bool {
	return errors.Is(err, storagebackend.ErrInvalid) || errors.Is(err, storagebackend.ErrNotFound) ||
		errors.Is(err, storagebackend.ErrConflict) || errors.Is(err, storagebackend.ErrInUse) ||
		errors.Is(err, storagebackend.ErrCapacity) || errors.Is(err, storagebackend.ErrUnsupported) ||
		errors.Is(err, storagebackend.ErrUnavailable)
}

func stateMutationTarget(action, snapshotID, tenantID, lineageID string, generation uint64) string {
	return action + ":" + stateBackendRequestID(action+"-"+snapshotID, tenantID, lineageID, generation)
}

// stateMutationRecovery permits only an exact retry to resolve its own durable
// prepared operation. This is narrower than general degraded-mode mutation:
// unrelated or multiple pending operations still fail closed.
func (s *Server) stateMutationRecovery(target string, generation uint64) (string, bool, bool) {
	pending := s.secure.journal.Pending()
	if len(pending) != 0 {
		if len(pending) == 1 && pending[0].Target == target && pending[0].Generation == generation {
			return pending[0].ID, true, false
		}
		return "", false, true
	}
	s.reconcileMu.RLock()
	degraded := s.reconcileAttempted && !s.reconcileReport.Ready
	s.reconcileMu.RUnlock()
	return "", false, degraded
}

func validStateSnapshotRequest(value stateSnapshotRequest) bool {
	return boundedRuntimeText(value.TenantID, 128) && boundedRuntimeText(value.NodeID, 128) &&
		boundedRuntimeText(value.InstanceID, 256) && boundedRuntimeText(value.LineageID, 256) &&
		boundedRuntimeText(value.SnapshotID, storagebackend.MaxIdentifierBytes) && value.Generation > 0
}

func validStateCloneRequest(value stateCloneRequest) bool {
	return boundedRuntimeText(value.TenantID, 128) && boundedRuntimeText(value.NodeID, 128) &&
		boundedRuntimeText(value.InstanceID, 256) && boundedRuntimeText(value.LineageID, 256) &&
		boundedRuntimeText(value.SourceLineageID, 256) && value.LineageID != value.SourceLineageID &&
		boundedRuntimeText(value.SnapshotID, storagebackend.MaxIdentifierBytes) && value.Generation > 0
}

func (s *Server) authorizeStateMutation(r *http.Request, tenantID, nodeID string, generation uint64) bool {
	if nodeID != s.secure.nodeID {
		return false
	}
	principal, ok := r.Context().Value(admissionPrincipalKey{}).(admissionPrincipal)
	if !ok {
		return s.secure.allowHostAdmin
	}
	return principal.tenantID == tenantID && principal.nodeID == nodeID && principal.generation == generation
}

func (s *Server) coldLineageRecord(tenantID, instanceID, lineageID string, generation uint64) (admission.FenceRecord, bool, bool) {
	var found admission.FenceRecord
	active := false
	for _, record := range s.secure.fences.Records() {
		if record.TenantID != tenantID || record.LineageID != lineageID {
			continue
		}
		active = active || record.Present
		if record.InstanceID == instanceID && record.Generation == generation {
			found = record
		}
	}
	return found, found.Generation != 0, active
}

func (s *Server) latestLineageRecord(tenantID, lineageID string) (admission.FenceRecord, bool) {
	var latest admission.FenceRecord
	for _, record := range s.secure.fences.Records() {
		if record.TenantID == tenantID && record.LineageID == lineageID && record.Generation > latest.Generation {
			latest = record
		}
	}
	return latest, latest.Generation != 0
}

func stateMutationEvidence(record admission.FenceRecord, runtimeRef, grant string, kind evidence.EventType, outcome evidence.Outcome) evidence.Event {
	return evidence.Event{
		Type: kind, TenantID: record.TenantID, RuntimeRef: runtimeRef,
		CapsuleDigest: record.CapsuleDigest, PolicyDigest: record.PolicyDigest,
		Generation: record.Generation, GrantID: grant, Outcome: outcome,
	}
}

func snapshotResponse(snapshot storagebackend.Snapshot) stateSnapshotResponse {
	return stateSnapshotResponse{
		Status:     "stopped",
		SnapshotID: snapshot.SnapshotID, TenantID: snapshot.TenantID,
		SourceLineageID: snapshot.SourceLineageID, ContentDigest: snapshot.ContentDigest,
		RetainedBytes: snapshot.RetainedBytes, ObjectCount: snapshot.ObjectCount, CreatedAt: snapshot.CreatedAt,
	}
}

func cloneResponse(request stateCloneRequest) stateCloneResponse {
	return stateCloneResponse{
		Status:   "stopped",
		TenantID: request.TenantID, InstanceID: request.InstanceID, LineageID: request.LineageID,
		SnapshotID: request.SnapshotID,
	}
}
