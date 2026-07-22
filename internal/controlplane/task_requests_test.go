package controlplane

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestAsyncTaskHTTPRoutesAreBoundedAuthenticatedAndNodeScoped(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(
		t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`,
	), http.StatusCreated)
	credential := enrollNodeThroughAPI(
		t, fixture, fixture.adminToken, "task-enrollment", "node-1", []string{"tenant-a"},
	)

	response := fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/task-requests?limit=10", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	if got := strings.TrimSpace(response.Body.String()); got != `{"tasks":[]}` {
		t.Fatalf("empty task page=%s", got)
	}

	poll := controlprotocol.ExecutorTaskPollRequestV1{
		SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, NodeID: "node-1", Limit: 8,
	}
	response = fixture.request(
		t, http.MethodPost, "/executor-uplink/tasks/poll", credential.Credential, mustJSON(t, poll),
	)
	requireStatus(t, response, http.StatusOK)
	if got := strings.TrimSpace(response.Body.String()); got != `{"schema_version":"steward.executor-task-poll.v1","deliveries":[]}` {
		t.Fatalf("empty task poll=%s", got)
	}

	report := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    "task-delivery", DeliveryGeneration: 1,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "missing-task",
		Status:       controlprotocol.ExecutorTaskReportUncertain,
		PermitDigest: "sha256:" + strings.Repeat("a", 64), ErrorCode: "task_not_found",
	}
	requireError(t, fixture.request(
		t, http.MethodPost, "/executor-uplink/tasks/report", credential.Credential, mustJSON(t, report),
	), http.StatusNotFound, "not_found")

	for _, test := range []struct {
		method string
		path   string
		token  string
		body   string
		status int
		code   string
	}{
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests", "", "", http.StatusUnauthorized, "unauthorized"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests?limit=101", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests?unexpected=1", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests", fixture.adminToken, `{`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests", fixture.adminToken, `{"task_permit":"bad","request_base64":"!!!!"}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests", fixture.adminToken, `{"task_permit":"bad","request_base64":"cmVxdWVzdA=="}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPut, "/v1/tenants/tenant-a/task-requests", fixture.adminToken, `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests?limit=0", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing?unexpected=1", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/tenants/tenant-a/task-requests/missing", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/tenants/tenant-a/task-requests/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodPost, "/v1/tenants/tenant-a/task-requests/missing", fixture.adminToken, "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing/result", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing/result", "", "", http.StatusUnauthorized, "unauthorized"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing/result?unexpected=1", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/v1/tenants/tenant-a/task-requests/missing/result", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/tenants/tenant-a/task-requests/missing/result", fixture.adminToken, "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/executor-uplink/tasks/poll", fixture.adminToken, mustJSON(t, poll), http.StatusUnauthorized, "unauthorized"},
		{http.MethodPost, "/executor-uplink/tasks/poll?unexpected=1", credential.Credential, mustJSON(t, poll), http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/executor-uplink/tasks/poll", credential.Credential, mustJSON(t, controlprotocol.ExecutorTaskPollRequestV1{SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, NodeID: "node-2", Limit: 1}), http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/executor-uplink/tasks/poll", credential.Credential, "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/executor-uplink/tasks/poll", credential.Credential, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/executor-uplink/tasks/report?unexpected=1", credential.Credential, mustJSON(t, report), http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/executor-uplink/tasks/report", credential.Credential, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/executor-uplink/tasks/report", credential.Credential, "", http.StatusMethodNotAllowed, "method_not_allowed"},
	} {
		requireError(t, fixture.request(t, test.method, test.path, test.token, test.body), test.status, test.code)
	}
}

func TestPageTaskRequestsUsesExclusiveStableCursorAndWireLimit(t *testing.T) {
	values := []controlstore.TaskRequest{{TaskID: "task-c"}, {TaskID: "task-b"}, {TaskID: "task-a"}}
	selected, next, err := pageTaskRequests(values, pageRequest{limit: 1})
	if err != nil || len(selected) != 1 || selected[0].TaskID != "task-c" || next != "task-c" {
		t.Fatalf("first page=(%+v, %q, %v)", selected, next, err)
	}
	selected, next, err = pageTaskRequests(values, pageRequest{after: "task-c", limit: 5})
	if err != nil || len(selected) != 2 || selected[0].TaskID != "task-b" || next != "" {
		t.Fatalf("second page=(%+v, %q, %v)", selected, next, err)
	}
	selected, next, err = pageTaskRequests(values, pageRequest{after: "task-a", limit: 1})
	if err != nil || len(selected) != 0 || next != "" {
		t.Fatalf("terminal cursor=(%+v, %q, %v)", selected, next, err)
	}
	if _, _, err := pageTaskRequests(values, pageRequest{after: "missing", limit: 1}); err == nil {
		t.Fatal("missing task cursor was accepted")
	}
	if _, _, err := pageTaskRequests(
		[]controlstore.TaskRequest{{TaskID: strings.Repeat("x", maxResponseBytes)}}, pageRequest{limit: 1},
	); err == nil {
		t.Fatal("task larger than response bound was accepted")
	}
	selected, next, err = pageTaskRequests([]controlstore.TaskRequest{
		{TaskID: "small"}, {TaskID: strings.Repeat("x", maxResponseBytes)},
	}, pageRequest{limit: 2})
	if err != nil || len(selected) != 1 || selected[0].TaskID != "small" || next != "small" {
		t.Fatalf("wire-truncated page=(%+v, %q, %v)", selected, next, err)
	}
}
