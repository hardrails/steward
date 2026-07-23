package controlplane

import (
	"net/http"
	"strings"
	"testing"
)

func TestWorkroomProjectHTTPContractIsAuthenticatedBoundedAndOptimistic(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(
		t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`,
	), http.StatusCreated)

	body := `{"expected_revision":0,"name":"Research desk","description":"Primary-source research","agent_ref":"hermes-research","skills":["analysis","web-research"],"sessions":[{"id":"launch","title":"Launch research","state":"active","task_ids":[]}],"artifacts":[],"memory_refs":[]}`
	response := fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/projects/research", fixture.adminToken, body,
	)
	requireStatus(t, response, http.StatusCreated)
	if !strings.Contains(response.Body.String(), `"revision":1`) ||
		!strings.Contains(response.Body.String(), `"created_at"`) {
		t.Fatalf("project create response=%s", response.Body.String())
	}

	response = fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/projects?limit=10", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(response.Body.String(), `"id":"research"`) {
		t.Fatalf("project list response=%s", response.Body.String())
	}
	requireStatus(t, fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/projects/research", fixture.adminToken, "",
	), http.StatusOK)
	requireError(t, fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/projects/research", fixture.adminToken, body,
	), http.StatusConflict, "conflict")
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/projects", "", "",
	), http.StatusUnauthorized, "unauthorized")
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/projects?limit=0", fixture.adminToken, "",
	), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(
		t, http.MethodPost, "/v1/tenants/tenant-a/projects/research", fixture.adminToken, `{}`,
	), http.StatusMethodNotAllowed, "method_not_allowed")
	requireError(t, fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/projects/research", fixture.adminToken,
		`{"expected_revision":1,"name":"Research","sessions":[],"artifacts":[],"memory_refs":[],"unknown":true}`,
	), http.StatusBadRequest, "invalid_request")

	requireStatus(t, fixture.request(
		t, http.MethodDelete, "/v1/tenants/tenant-a/projects/research", fixture.adminToken,
		`{"expected_revision":1}`,
	), http.StatusNoContent)
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/projects/research", fixture.adminToken, "",
	), http.StatusNotFound, "not_found")
}
