package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/hardrails/steward/internal/controlstore"
)

type workroomProjectApplyRequest struct {
	ExpectedRevision uint64                                 `json:"expected_revision"`
	Name             string                                 `json:"name"`
	Description      string                                 `json:"description,omitempty"`
	AgentRef         string                                 `json:"agent_ref,omitempty"`
	Skills           []string                               `json:"skills,omitempty"`
	Sessions         []controlstore.WorkroomSession         `json:"sessions"`
	Artifacts        []controlstore.WorkroomArtifact        `json:"artifacts"`
	MemoryRefs       []controlstore.WorkroomMemoryReference `json:"memory_refs"`
}

type workroomProjectDeleteRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type workroomProjectPage struct {
	Projects  []controlstore.WorkroomProject `json:"projects"`
	NextAfter string                         `json:"next_after,omitempty"`
}

func (server *Server) workroomProjects(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	projects, err := server.store.ListWorkroomProjects(identity, request.PathValue("tenant_id"))
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	selected, next, err := pageWorkroomProjects(projects, page)
	if err != nil {
		server.logger.Error("control workroom project page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded project page")
		return
	}
	writeJSON(writer, http.StatusOK, workroomProjectPage{Projects: selected, NextAfter: next})
}

func (server *Server) workroomProject(writer http.ResponseWriter, request *http.Request) {
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
	tenantID, projectID := request.PathValue("tenant_id"), request.PathValue("project_id")
	switch request.Method {
	case http.MethodGet:
		project, err := server.store.GetWorkroomProject(identity, tenantID, projectID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		writeJSON(writer, http.StatusOK, project)
	case http.MethodPut:
		var input workroomProjectApplyRequest
		if !server.decode(writer, request, &input) {
			return
		}
		project, changed, err := server.store.ApplyWorkroomProject(identity, controlstore.WorkroomProject{
			TenantID: tenantID, ID: projectID, Name: input.Name, Description: input.Description,
			AgentRef: input.AgentRef, Skills: input.Skills, Sessions: input.Sessions,
			Artifacts: input.Artifacts, MemoryRefs: input.MemoryRefs,
		}, input.ExpectedRevision, server.now())
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		status := http.StatusOK
		if changed && project.Revision == 1 {
			status = http.StatusCreated
		}
		writeJSON(writer, status, project)
	case http.MethodDelete:
		var input workroomProjectDeleteRequest
		if !server.decode(writer, request, &input) {
			return
		}
		if err := server.store.DeleteWorkroomProject(identity, tenantID, projectID, input.ExpectedRevision); err != nil {
			server.storeError(writer, err, true)
			return
		}
		writeNoContent(writer)
	}
}

func pageWorkroomProjects(
	values []controlstore.WorkroomProject,
	page pageRequest,
) ([]controlstore.WorkroomProject, string, error) {
	start := sort.Search(len(values), func(index int) bool { return values[index].ID > page.after })
	selected := make([]controlstore.WorkroomProject, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(selected) < page.limit; index++ {
		candidate := append(append([]controlstore.WorkroomProject(nil), selected...), values[index])
		next := ""
		if index+1 < len(values) {
			next = values[index].ID
		}
		raw, err := json.Marshal(workroomProjectPage{Projects: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(selected) == 0 {
				return nil, "", errors.New("one valid workroom project cannot fit the response limit")
			}
			break
		}
		selected = candidate
	}
	next := ""
	if start+len(selected) < len(values) {
		next = selected[len(selected)-1].ID
	}
	return selected, next, nil
}
