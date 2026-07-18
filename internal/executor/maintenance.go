package executor

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

const maintenanceStatusSchema = "steward.executor-maintenance.v1"

type maintenanceEnterRequest struct {
	Reason string `json:"reason"`
}

type maintenanceStatusResponse struct {
	SchemaVersion     string   `json:"schema_version"`
	Enabled           bool     `json:"enabled"`
	EnteredAt         string   `json:"entered_at,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	ActiveRuntimeRefs []string `json:"active_runtime_refs"`
	PendingOperations int      `json:"pending_operations"`
}

func (s *Server) maintenanceStatus(w http.ResponseWriter, _ *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	writeJSON(w, http.StatusOK, s.maintenanceStatusLocked())
}

func (s *Server) maintenanceEnter(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the maintenance limit")
		return
	}
	var request maintenanceEnterRequest
	if err := dsse.DecodeStrictInto(raw, maxBodyBytes, &request); err != nil || !admission.ValidMaintenanceReason(request.Reason) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain one bounded maintenance reason")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	current := s.secure.fences.Maintenance()
	if current.Enabled && current.Reason != request.Reason {
		writeError(w, http.StatusConflict, "maintenance_conflict", "node maintenance is already enabled with a different reason")
		return
	}
	if err := s.secure.fences.SetMaintenance(true, request.Reason, time.Now()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "maintenance_unavailable", "maintenance state could not be persisted")
		return
	}
	writeJSON(w, http.StatusOK, s.maintenanceStatusLocked())
}

func (s *Server) maintenanceExit(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the maintenance limit")
		return
	}
	if len(strings.TrimSpace(string(raw))) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "maintenance exit does not accept a request body")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	s.reconcileMu.RLock()
	reconciled := s.reconcileAttempted && s.reconcileReport.Ready
	s.reconcileMu.RUnlock()
	if len(s.secure.journal.Pending()) != 0 || !reconciled {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; maintenance cannot exit until reconciliation succeeds")
		return
	}
	if err := s.secure.fences.SetMaintenance(false, "", time.Time{}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "maintenance_unavailable", "maintenance state could not be persisted")
		return
	}
	writeJSON(w, http.StatusOK, s.maintenanceStatusLocked())
}

func (s *Server) maintenanceStatusLocked() maintenanceStatusResponse {
	state := s.secure.fences.Maintenance()
	refs := make([]string, 0, s.secure.fences.Count())
	for _, record := range s.secure.fences.Records() {
		if record.Present {
			refs = append(refs, RuntimeRef(record.TenantID, record.InstanceID))
		}
	}
	slices.Sort(refs)
	return maintenanceStatusResponse{
		SchemaVersion: maintenanceStatusSchema,
		Enabled:       state.Enabled, EnteredAt: state.EnteredAt, Reason: state.Reason,
		ActiveRuntimeRefs: refs, PendingOperations: len(s.secure.journal.Pending()),
	}
}
