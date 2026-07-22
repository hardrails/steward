package controlplane

import (
	"net/http"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestNodePoolAPIExposesProviderNeutralCapacityAndOptimisticChanges(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)

	response := fixture.request(t, http.MethodGet, "/v1/node-pools?limit=1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var page nodePoolListResponse
	decodeResponse(t, response, &page)
	if page.NodePools == nil || len(page.NodePools) != 0 || page.NextAfter != "" {
		t.Fatalf("empty pools=%+v", page)
	}

	response = fixture.request(t, http.MethodPut, "/v1/node-pools/research-amd64", fixture.adminToken,
		`{"expected_revision":0,"tenant_ids":["tenant-a"],"architecture":"amd64","min_nodes":1,"desired_nodes":2,"max_nodes":4}`)
	requireStatus(t, response, http.StatusCreated)
	var status controlstore.NodePoolStatus
	decodeResponse(t, response, &status)
	if status.Pool.ID != "research-amd64" || status.Pool.Revision != 1 || status.RegisteredNodes != 0 ||
		status.ScaleOutNeeded != 2 || len(status.Conditions) != 1 || status.Conditions[0] != controlstore.NodePoolConditionCapacityShortfall {
		t.Fatalf("created status=%+v", status)
	}

	response = fixture.request(t, http.MethodGet, "/v1/node-pools/research-amd64", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &status)
	if status.Pool.Revision != 1 || status.ObservedAt == "" {
		t.Fatalf("get status=%+v", status)
	}

	response = fixture.request(t, http.MethodPut, "/v1/node-pools/research-amd64", fixture.adminToken,
		`{"expected_revision":1,"tenant_ids":["tenant-a"],"architecture":"amd64","min_nodes":1,"desired_nodes":1,"max_nodes":4}`)
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &status)
	if status.Pool.Revision != 2 || status.ScaleOutNeeded != 1 {
		t.Fatalf("updated status=%+v", status)
	}
	requireError(t, fixture.request(t, http.MethodPut, "/v1/node-pools/research-amd64", fixture.adminToken,
		`{"expected_revision":1,"tenant_ids":["tenant-a"],"architecture":"amd64","min_nodes":1,"desired_nodes":3,"max_nodes":4}`),
		http.StatusConflict, "conflict")

	response = fixture.request(t, http.MethodDelete, "/v1/node-pools/research-amd64", fixture.adminToken,
		`{"expected_revision":2}`)
	requireStatus(t, response, http.StatusNoContent)
	requireError(t, fixture.request(t, http.MethodGet, "/v1/node-pools/research-amd64", fixture.adminToken, ""),
		http.StatusNotFound, "not_found")
}

func TestNodePoolAPIRejectsUnsafeMethodsQueriesAndBodies(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	tests := []struct {
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{http.MethodPost, "/v1/node-pools", `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/v1/node-pools/pool-a?unexpected=true", "", http.StatusBadRequest, "invalid_request"},
		{http.MethodPatch, "/v1/node-pools/pool-a", `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPut, "/v1/node-pools/pool-a", `{"expected_revision":0,"tenant_ids":["tenant-a"],"min_nodes":2,"desired_nodes":1,"max_nodes":2}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPut, "/v1/node-pools/pool-a", `{"expected_revision":0,"tenant_ids":["tenant-a"],"min_nodes":0,"desired_nodes":1,"max_nodes":2,"unknown":true}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/node-pools/pool-a", `{"expected_revision":0}`, http.StatusBadRequest, "invalid_request"},
	}
	for _, test := range tests {
		requireError(t, fixture.request(t, test.method, test.path, fixture.adminToken, test.body), test.status, test.code)
	}
}

func TestNodePoolListPaginatesByStablePoolIdentity(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	for _, poolID := range []string{"pool-a", "pool-b"} {
		requireStatus(t, fixture.request(t, http.MethodPut, "/v1/node-pools/"+poolID, fixture.adminToken,
			`{"expected_revision":0,"tenant_ids":["tenant-a"],"min_nodes":0,"desired_nodes":0,"max_nodes":2}`), http.StatusCreated)
	}
	response := fixture.request(t, http.MethodGet, "/v1/node-pools?limit=1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var first nodePoolListResponse
	decodeResponse(t, response, &first)
	if len(first.NodePools) != 1 || first.NodePools[0].Pool.ID != "pool-a" || first.NextAfter != "pool-a" {
		t.Fatalf("first page=%+v", first)
	}
	response = fixture.request(t, http.MethodGet, "/v1/node-pools?limit=1&after=pool-a", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var second nodePoolListResponse
	decodeResponse(t, response, &second)
	if len(second.NodePools) != 1 || second.NodePools[0].Pool.ID != "pool-b" || second.NextAfter != "" {
		t.Fatalf("second page=%+v", second)
	}
}
