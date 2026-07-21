package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

type deploymentApplyRequest struct {
	Generation           uint64                                   `json:"generation"`
	ExpectedRevision     uint64                                   `json:"expected_revision,omitempty"`
	AgentName            string                                   `json:"agent_name"`
	BundleDigest         string                                   `json:"bundle_digest"`
	CapsuleDSSEBase64    string                                   `json:"capsule_dsse_base64"`
	DelegationDSSEBase64 string                                   `json:"delegation_dsse_base64"`
	DisruptionBudget     *controlstore.DeploymentDisruptionBudget `json:"disruption_budget,omitempty"`
	Fork                 *controlstore.DeploymentFork             `json:"fork,omitempty"`
}

type deploymentDeleteRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type deploymentRolloutControlRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	Paused           bool   `json:"paused"`
}

type deploymentResponse struct {
	TenantID            string                                  `json:"tenant_id"`
	DeploymentID        string                                  `json:"deployment_id"`
	Generation          uint64                                  `json:"generation"`
	Revision            uint64                                  `json:"revision"`
	AgentName           string                                  `json:"agent_name"`
	BundleDigest        string                                  `json:"bundle_digest"`
	CapsuleDigest       string                                  `json:"capsule_digest"`
	DelegationDigest    string                                  `json:"delegation_digest"`
	DelegationID        string                                  `json:"delegation_id"`
	ControllerKeyID     string                                  `json:"controller_key_id"`
	ClaimGeneration     uint64                                  `json:"claim_generation"`
	AllowedNodeIDs      []string                                `json:"allowed_node_ids"`
	DelegationExpiresAt string                                  `json:"delegation_expires_at"`
	DesiredState        controlstore.DeploymentDesiredState     `json:"desired_state"`
	DisruptionBudget    controlstore.DeploymentDisruptionBudget `json:"disruption_budget"`
	Phase               controlstore.DeploymentPhase            `json:"phase"`
	Instances           []controlstore.DeploymentInstance       `json:"instances"`
	Rollout             *deploymentRolloutResponse              `json:"rollout,omitempty"`
	Fork                *controlstore.DeploymentFork            `json:"fork,omitempty"`
	CreatedAt           string                                  `json:"created_at"`
	UpdatedAt           string                                  `json:"updated_at"`
}

type deploymentRolloutResponse struct {
	SourceGeneration       uint64 `json:"source_generation"`
	SourceAgentName        string `json:"source_agent_name"`
	SourceBundleDigest     string `json:"source_bundle_digest"`
	SourceCapsuleDigest    string `json:"source_capsule_digest"`
	SourceDelegationDigest string `json:"source_delegation_digest"`
	StartedAt              string `json:"started_at"`
	PausedAt               string `json:"paused_at,omitempty"`
}

type deploymentListResponse struct {
	Deployments []deploymentResponse `json:"deployments"`
	NextAfter   string               `json:"next_after,omitempty"`
}

func (server *Server) deployments(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	values, err := server.store.ListDeployments(identity, request.PathValue("tenant_id"))
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	views, next, err := pageDeploymentViews(values, page)
	if err != nil {
		server.logger.Error("control deployment page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded deployment page")
		return
	}
	writeJSON(writer, http.StatusOK, deploymentListResponse{Deployments: views, NextAfter: next})
}

func (server *Server) deployment(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPut && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodGet, http.MethodPut, http.MethodDelete)
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
	deploymentID := request.PathValue("deployment_id")
	switch request.Method {
	case http.MethodGet:
		value, found, err := server.store.GetDeployment(identity, tenantID, deploymentID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		if !found {
			writeError(writer, http.StatusNotFound, "not_found", "deployment was not found")
			return
		}
		view, err := deploymentView(value)
		if err != nil {
			server.logger.Error("retained deployment projection is invalid", "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not project retained deployment state")
			return
		}
		writeJSON(writer, http.StatusOK, view)
	case http.MethodPut:
		var input deploymentApplyRequest
		if !server.decode(writer, request, &input) {
			return
		}
		capsule, ok := decodeDeploymentBase64(writer, "capsule_dsse_base64", input.CapsuleDSSEBase64)
		if !ok {
			return
		}
		delegation, ok := decodeDeploymentBase64(writer, "delegation_dsse_base64", input.DelegationDSSEBase64)
		if !ok {
			return
		}
		value, created, err := server.store.ApplyDeployment(identity, controlstore.DeploymentApply{
			TenantID: tenantID, ID: deploymentID, Generation: input.Generation,
			ExpectedRevision: input.ExpectedRevision, AgentName: input.AgentName,
			BundleDigest: input.BundleDigest, CapsuleDSSE: capsule, DelegationDSSE: delegation,
			DisruptionBudget: input.DisruptionBudget,
			Fork:             input.Fork,
		}, server.now())
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		view, err := deploymentView(value)
		if err != nil {
			server.logger.Error("new deployment projection is invalid", "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not project deployment state")
			return
		}
		status := http.StatusOK
		if created && value.Revision == 1 {
			status = http.StatusCreated
		}
		writeJSON(writer, status, view)
	case http.MethodDelete:
		var input deploymentDeleteRequest
		if !server.decode(writer, request, &input) {
			return
		}
		value, _, err := server.store.SetDeploymentDesiredState(
			identity, tenantID, deploymentID, input.ExpectedRevision,
			controlstore.DeploymentAbsent, server.now(),
		)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		view, err := deploymentView(value)
		if err != nil {
			server.logger.Error("removed deployment projection is invalid", "error", err)
			writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not project deployment state")
			return
		}
		writeJSON(writer, http.StatusAccepted, view)
	}
}

func (server *Server) deploymentRollout(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPut) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input deploymentRolloutControlRequest
	if !server.decode(writer, request, &input) {
		return
	}
	value, _, err := server.store.SetDeploymentRolloutPaused(
		identity, request.PathValue("tenant_id"), request.PathValue("deployment_id"),
		input.ExpectedRevision, input.Paused, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	view, err := deploymentView(value)
	if err != nil {
		server.logger.Error("controlled deployment rollout projection is invalid", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not project deployment state")
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

func deploymentView(value controlstore.Deployment) (deploymentResponse, error) {
	delegation, err := admission.InspectCommandDelegation(value.DelegationDSSE, time.Time{})
	if err != nil {
		return deploymentResponse{}, err
	}
	view := deploymentResponse{
		TenantID: value.TenantID, DeploymentID: value.ID,
		Generation: value.Generation, Revision: value.Revision,
		AgentName: value.AgentName, BundleDigest: value.BundleDigest,
		CapsuleDigest: dsse.Digest(value.CapsuleDSSE), DelegationDigest: dsse.Digest(value.DelegationDSSE),
		DelegationID: delegation.DelegationID, ControllerKeyID: delegation.ControllerKeyID,
		ClaimGeneration:     delegation.ClaimGeneration,
		AllowedNodeIDs:      append([]string(nil), delegation.NodeIDs...),
		DelegationExpiresAt: delegation.ExpiresAt,
		DesiredState:        value.DesiredState, Phase: value.Phase,
		DisruptionBudget: value.DisruptionBudget,
		Instances:        append([]controlstore.DeploymentInstance(nil), value.Instances...),
		Fork:             value.Fork,
		CreatedAt:        value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
	if value.Rollout != nil {
		view.Rollout = &deploymentRolloutResponse{
			SourceGeneration: value.Rollout.SourceGeneration, SourceAgentName: value.Rollout.SourceAgentName,
			SourceBundleDigest:     value.Rollout.SourceBundleDigest,
			SourceCapsuleDigest:    dsse.Digest(value.Rollout.SourceCapsuleDSSE),
			SourceDelegationDigest: dsse.Digest(value.Rollout.SourceDelegationDSSE),
			StartedAt:              value.Rollout.StartedAt,
			PausedAt:               value.Rollout.PausedAt,
		}
	}
	return view, nil
}

func pageDeploymentViews(values []controlstore.Deployment, page pageRequest) ([]deploymentResponse, string, error) {
	start := sort.Search(len(values), func(index int) bool { return values[index].ID > page.after })
	views := make([]deploymentResponse, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(views) < page.limit; index++ {
		view, err := deploymentView(values[index])
		if err != nil {
			return nil, "", err
		}
		candidate := append(append([]deploymentResponse(nil), views...), view)
		next := ""
		if index+1 < len(values) {
			next = values[index].ID
		}
		raw, err := json.Marshal(deploymentListResponse{Deployments: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(views) == 0 {
				return nil, "", errors.New("one valid deployment cannot fit the response limit")
			}
			break
		}
		views = candidate
	}
	next := ""
	if start+len(views) < len(values) {
		next = values[start+len(views)-1].ID
	}
	return views, next, nil
}

func decodeDeploymentBase64(writer http.ResponseWriter, field, encoded string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		writeError(writer, http.StatusBadRequest, "invalid_request", field+" must be canonical base64")
		return nil, false
	}
	return raw, true
}
