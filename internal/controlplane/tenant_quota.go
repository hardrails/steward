package controlplane

import (
	"net/http"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

type tenantResourceQuotaChangeResponse struct {
	Status  controlstore.TenantResourceQuotaStatus `json:"status"`
	Changed bool                                   `json:"changed"`
}

func (server *Server) tenantResourceQuota(writer http.ResponseWriter, request *http.Request) {
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
	if request.Method == http.MethodGet {
		status, err := server.store.InspectTenantResourceQuota(identity, tenantID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		writeJSON(writer, http.StatusOK, status)
		return
	}
	var input struct {
		Action           controlstore.TenantQuotaAction                `json:"action"`
		ExpectedRevision uint64                                        `json:"expected_revision"`
		Resources        controlprotocol.ExecutorSchedulingResourcesV1 `json:"resources"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	status, changed, err := server.store.ChangeTenantResourceQuota(
		identity, tenantID, input.Action, input.ExpectedRevision, input.Resources, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, tenantResourceQuotaChangeResponse{Status: status, Changed: changed})
}
