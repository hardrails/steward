package controlplane

import (
	"net/http"

	"github.com/hardrails/steward/internal/controlstore"
)

type operationalFreezeChangeResponse struct {
	Status  controlstore.OperationalFreezeStatus `json:"status"`
	Changed bool                                 `json:"changed"`
}

func (server *Server) siteOperationalFreeze(writer http.ResponseWriter, request *http.Request) {
	server.operationalFreeze(writer, request, "")
}

func (server *Server) tenantOperationalFreeze(writer http.ResponseWriter, request *http.Request) {
	server.operationalFreeze(writer, request, request.PathValue("tenant_id"))
}

func (server *Server) operationalFreeze(writer http.ResponseWriter, request *http.Request, tenantID string) {
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
	if request.Method == http.MethodGet {
		status, err := server.store.InspectOperationalFreeze(identity, tenantID)
		if err != nil {
			server.storeError(writer, err, tenantID != "")
			return
		}
		writeJSON(writer, http.StatusOK, status)
		return
	}
	var input struct {
		Action           controlstore.OperationalFreezeAction `json:"action"`
		ExpectedRevision uint64                               `json:"expected_revision"`
		Reason           string                               `json:"reason,omitempty"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	status, changed, err := server.store.ChangeOperationalFreeze(
		identity, tenantID, input.Action, input.ExpectedRevision, input.Reason, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, tenantID != "")
		return
	}
	writeJSON(writer, http.StatusOK, operationalFreezeChangeResponse{Status: status, Changed: changed})
}
