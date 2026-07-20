package controlplane

import (
	"net/http"

	"github.com/hardrails/steward/internal/controlstore"
)

type snapshotQuarantineChangeResponse struct {
	Status  controlstore.SnapshotQuarantineStatus `json:"status"`
	Changed bool                                  `json:"changed"`
}

func (server *Server) snapshotQuarantine(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPut {
		methodNotAllowed(writer, http.MethodGet, http.MethodPut)
		return
	}
	if !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenantID := request.PathValue("tenant_id")
	nodeID := request.PathValue("node_id")
	snapshotID := request.PathValue("snapshot_id")
	if request.Method == http.MethodGet {
		status, err := server.store.InspectSnapshotQuarantine(identity, tenantID, nodeID, snapshotID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		writeJSON(writer, http.StatusOK, status)
		return
	}
	var input struct {
		Action           controlstore.SnapshotQuarantineAction `json:"action"`
		ExpectedRevision uint64                                `json:"expected_revision"`
		Reason           string                                `json:"reason,omitempty"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	status, changed, err := server.store.ChangeSnapshotQuarantine(
		identity, tenantID, nodeID, snapshotID,
		input.Action, input.ExpectedRevision, input.Reason, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	writeJSON(writer, http.StatusOK, snapshotQuarantineChangeResponse{Status: status, Changed: changed})
}
