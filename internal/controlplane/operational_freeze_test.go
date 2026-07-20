package controlplane

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestOperationalFreezeAPIEnforcesScopeAndCommandGate(t *testing.T) {
	fixture := newServerFixture(t)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
			mustJSON(t, map[string]string{"tenant_id": tenantID})), http.StatusCreated)
	}
	operatorA := issueOperatorThroughAPI(t, fixture, "freeze-operator-a", "tenant-a")
	operatorB := issueOperatorThroughAPI(t, fixture, "freeze-operator-b", "tenant-b")
	enrollNodeThroughAPI(t, fixture, fixture.adminToken, "freeze-node", "node-1", []string{"tenant-a"})

	requireError(t, fixture.request(t, http.MethodPost, "/v1/operations/freeze", "", `{}`),
		http.StatusMethodNotAllowed, "method_not_allowed")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/operations/freeze?unexpected=1", fixture.adminToken, ""),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/freeze", operatorA, `{`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/operations/freeze", operatorA, ""),
		http.StatusForbidden, "forbidden")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/freeze", operatorB, ""),
		http.StatusNotFound, "not_found")

	response := fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/freeze", operatorA,
		`{"action":"freeze","expected_revision":0,"reason":"credential investigation"}`)
	requireStatus(t, response, http.StatusOK)
	var changed operationalFreezeChangeResponse
	decodeResponse(t, response, &changed)
	if !changed.Changed || changed.Status.Tenant == nil || changed.Status.Tenant.Revision != 1 ||
		changed.Status.Effective == nil || changed.Status.Effective.Scope != controlstore.OperationalFreezeTenant {
		t.Fatalf("tenant freeze response = %+v", changed)
	}

	commandRaw := signedCommand(t, fixture.now, "frozen-command", "tenant-a", "node-1")
	requireError(t, fixture.request(
		t, http.MethodPost, "/v1/tenants/tenant-a/nodes/node-1/commands", operatorA,
		mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(commandRaw)}),
	), http.StatusLocked, "operationally_frozen")

	response = fixture.request(t, http.MethodPut, "/v1/operations/freeze", fixture.adminToken,
		`{"action":"freeze","expected_revision":0,"reason":"site containment"}`)
	requireStatus(t, response, http.StatusOK)
	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/freeze", operatorA, "")
	requireStatus(t, response, http.StatusOK)
	var status controlstore.OperationalFreezeStatus
	decodeResponse(t, response, &status)
	if status.Site == nil || status.Tenant == nil || status.Effective == nil ||
		status.Effective.Scope != controlstore.OperationalFreezeSite {
		t.Fatalf("effective site freeze = %+v", status)
	}

	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/freeze", operatorA,
		`{"action":"unfreeze","expected_revision":0}`), http.StatusConflict, "conflict")
	response = fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/freeze", operatorA,
		`{"action":"unfreeze","expected_revision":1}`)
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &changed)
	if !changed.Changed || changed.Status.Tenant == nil || changed.Status.Tenant.Frozen ||
		changed.Status.Effective == nil || changed.Status.Effective.Scope != controlstore.OperationalFreezeSite {
		t.Fatalf("tenant unfreeze under site freeze = %+v", changed)
	}
}
