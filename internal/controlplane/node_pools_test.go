package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/poolmembership"
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

func TestExecutorBindsIndependentlySignedPoolMembership(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	credential := enrollNodeThroughAPI(t, fixture, fixture.adminToken, "pool-node-enrollment", "node-a", []string{"tenant-a"})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poolBody := mustJSON(t, map[string]any{
		"expected_revision": 0, "tenant_ids": []string{"tenant-a"}, "architecture": "amd64",
		"min_nodes": 0, "desired_nodes": 1, "max_nodes": 2, "membership_key_id": "pool-authority-1",
		"membership_public_key_base64": base64.StdEncoding.EncodeToString(public),
	})
	requireStatus(t, fixture.request(t, http.MethodPut, "/v1/node-pools/pool-a", fixture.adminToken, poolBody), http.StatusCreated)
	now := fixture.now
	raw, err := poolmembership.Sign(poolmembership.Statement{
		SchemaVersion: 1, ControllerInstanceID: fixture.server.auth.InstanceID(), PoolID: "pool-a", PoolMembershipGeneration: 1,
		PoolCreatedAt: now.Format(time.RFC3339Nano),
		NodeID:        "node-a", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		BootIdentitySHA256:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchedulingPolicySHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:               now.Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano),
	}, "pool-authority-1", private)
	if err != nil {
		t.Fatal(err)
	}
	body := mustJSON(t, struct {
		Membership json.RawMessage `json:"membership"`
	}{Membership: raw})
	response := fixture.request(t, http.MethodPut, "/executor-uplink/pool-membership", credential.Credential, body)
	requireStatus(t, response, http.StatusOK)
	var binding struct {
		NodeID     string                           `json:"node_id"`
		Membership *controlstore.NodePoolMembership `json:"membership"`
	}
	decodeResponse(t, response, &binding)
	if binding.NodeID != "node-a" || binding.Membership == nil || binding.Membership.PoolID != "pool-a" {
		t.Fatalf("binding=%+v", binding)
	}
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/pool-membership", credential.Credential, body),
		http.StatusMethodNotAllowed, "method_not_allowed")
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
