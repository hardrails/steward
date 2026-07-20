package controlplane

import (
	"net/http"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestSnapshotQuarantineAPIIsTenantScopedOptimisticAndBounded(t *testing.T) {
	fixture := newServerFixture(t)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
			mustJSON(t, map[string]string{"tenant_id": tenantID})), http.StatusCreated)
	}
	enrollNodeThroughAPI(t, fixture, fixture.adminToken, "snapshot-enrollment", "node-a", []string{"tenant-a"})
	operatorA := issueOperatorThroughAPI(t, fixture, "snapshot-operator-a", "tenant-a")
	operatorB := issueOperatorThroughAPI(t, fixture, "snapshot-operator-b", "tenant-b")
	path := "/v1/tenants/tenant-a/nodes/node-a/snapshots/snapshot-a/quarantine"

	requireError(t, fixture.request(t, http.MethodGet, path+"?unexpected=1", operatorA, ""),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, path, operatorA, `{}`),
		http.StatusMethodNotAllowed, "method_not_allowed")
	requireError(t, fixture.request(t, http.MethodGet, path, operatorB, ""),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodPut, path, operatorA, `{`),
		http.StatusBadRequest, "invalid_request")

	response := fixture.request(t, http.MethodGet, path, operatorA, "")
	requireStatus(t, response, http.StatusOK)
	var status controlstore.SnapshotQuarantineStatus
	decodeResponse(t, response, &status)
	if status.Record != nil || status.Blocked || status.SnapshotID != "snapshot-a" {
		t.Fatalf("initial snapshot quarantine = %+v", status)
	}

	response = fixture.request(t, http.MethodPut, path, operatorA,
		`{"action":"quarantine","expected_revision":0,"reason":"suspected contamination"}`)
	requireStatus(t, response, http.StatusOK)
	var changed snapshotQuarantineChangeResponse
	decodeResponse(t, response, &changed)
	if !changed.Changed || !changed.Status.Blocked || changed.Status.Record == nil ||
		changed.Status.Record.Revision != 1 {
		t.Fatalf("snapshot quarantine response = %+v", changed)
	}

	requireError(t, fixture.request(t, http.MethodPut, path, operatorA,
		`{"action":"clear","expected_revision":0}`), http.StatusConflict, "conflict")
	response = fixture.request(t, http.MethodPut, path, operatorA,
		`{"action":"clear","expected_revision":1}`)
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &changed)
	if !changed.Changed || changed.Status.Blocked || changed.Status.Record == nil ||
		changed.Status.Record.Revision != 2 {
		t.Fatalf("snapshot unquarantine response = %+v", changed)
	}
}
