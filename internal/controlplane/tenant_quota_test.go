package controlplane

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestTenantResourceQuotaAPIEnforcesAuthorityAndOptimisticChanges(t *testing.T) {
	fixture := newServerFixture(t)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
			mustJSON(t, map[string]string{"tenant_id": tenantID})), http.StatusCreated)
	}
	operatorA := issueOperatorThroughAPI(t, fixture, "quota-operator-a", "tenant-a")
	operatorB := issueOperatorThroughAPI(t, fixture, "quota-operator-b", "tenant-b")

	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants/tenant-a/quota", fixture.adminToken, `{}`),
		http.StatusMethodNotAllowed, "method_not_allowed")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/quota?unexpected=1", operatorA, ""),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/quota", fixture.adminToken, `{`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/quota", operatorB, ""),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/quota", operatorA,
		quotaSetBody(0)), http.StatusForbidden, "forbidden")

	response := fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/quota", fixture.adminToken,
		quotaSetBody(0))
	requireStatus(t, response, http.StatusOK)
	var changed tenantResourceQuotaChangeResponse
	decodeResponse(t, response, &changed)
	if !changed.Changed || changed.Status.TenantID != "tenant-a" || changed.Status.Quota == nil ||
		!changed.Status.Quota.Enabled || changed.Status.Quota.Revision != 1 || changed.Status.OverQuota {
		t.Fatalf("quota set response = %+v", changed)
	}

	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/quota", operatorA, "")
	requireStatus(t, response, http.StatusOK)
	var status controlstore.TenantResourceQuotaStatus
	decodeResponse(t, response, &status)
	if status.Quota == nil || status.Quota.Resources.MemoryBytes != 4<<30 || status.Usage.Workloads != 0 {
		t.Fatalf("tenant quota status = %+v", status)
	}

	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/quota", fixture.adminToken,
		`{"action":"clear","expected_revision":0,"resources":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0}}`),
		http.StatusConflict, "conflict")
	response = fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/quota", fixture.adminToken,
		`{"action":"clear","expected_revision":1,"resources":{"memory_bytes":0,"cpu_millis":0,"pids":0,"workloads":0}}`)
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &changed)
	if !changed.Changed || changed.Status.Quota == nil || changed.Status.Quota.Enabled ||
		changed.Status.Quota.Revision != 2 {
		t.Fatalf("quota clear response = %+v", changed)
	}
}

func quotaSetBody(revision uint64) string {
	return mustJSONString(map[string]any{
		"action": "set", "expected_revision": revision,
		"resources": map[string]int64{
			"memory_bytes": 4 << 30, "cpu_millis": 4000, "pids": 1024, "workloads": 8,
		},
	})
}

func mustJSONString(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
