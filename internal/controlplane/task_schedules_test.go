package controlplane

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/schedulepermit"
)

func TestTaskScheduleHTTPRoutesAreBoundedAndAuthenticated(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(
		t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`,
	), http.StatusCreated)

	response := fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/schedules?limit=10", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	if got := strings.TrimSpace(response.Body.String()); got != `{"schedules":[]}` {
		t.Fatalf("empty schedule page=%s", got)
	}
	for _, test := range []struct {
		method string
		path   string
		token  string
		body   string
		status int
		code   string
	}{
		{http.MethodGet, "/v1/tenants/tenant-a/schedules", "", "", http.StatusUnauthorized, "unauthorized"},
		{http.MethodGet, "/v1/tenants/tenant-a/schedules?limit=101", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/v1/tenants/tenant-a/schedules?after=missing", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/schedules", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/schedules", fixture.adminToken, `{"schedule_permit_base64":"!!!!","request_base64":"cmVxdWVzdA=="}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/schedules?unexpected=1", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPut, "/v1/tenants/tenant-a/schedules", fixture.adminToken, `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/v1/tenants/tenant-a/schedules/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/tenants/tenant-a/schedules/missing?unexpected=1", fixture.adminToken, "", http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/tenants/tenant-a/schedules/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodDelete, "/v1/tenants/tenant-a/schedules/missing", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/tenants/tenant-a/schedules/missing", fixture.adminToken, "", http.StatusMethodNotAllowed, "method_not_allowed"},
	} {
		requireError(t, fixture.request(t, test.method, test.path, test.token, test.body), test.status, test.code)
	}
}

func TestPageTaskSchedulesUsesExclusiveStableCursorAndWireLimit(t *testing.T) {
	values := []controlstore.TaskSchedule{
		{Statement: scheduleStatementID("schedule-c")},
		{Statement: scheduleStatementID("schedule-b")},
		{Statement: scheduleStatementID("schedule-a")},
	}
	selected, next, err := pageTaskSchedules(values, pageRequest{limit: 1})
	if err != nil || len(selected) != 1 || selected[0].Statement.ScheduleID != "schedule-c" || next != "schedule-c" {
		t.Fatalf("first page=(%+v, %q, %v)", selected, next, err)
	}
	selected, next, err = pageTaskSchedules(values, pageRequest{after: "schedule-c", limit: 5})
	if err != nil || len(selected) != 2 || selected[0].Statement.ScheduleID != "schedule-b" || next != "" {
		t.Fatalf("second page=(%+v, %q, %v)", selected, next, err)
	}
	if _, _, err := pageTaskSchedules(values, pageRequest{after: "missing", limit: 1}); err == nil {
		t.Fatal("missing schedule cursor was accepted")
	}
	huge := controlstore.TaskSchedule{Statement: scheduleStatementID(strings.Repeat("x", maxResponseBytes))}
	if _, _, err := pageTaskSchedules([]controlstore.TaskSchedule{huge}, pageRequest{limit: 1}); err == nil {
		t.Fatal("schedule larger than response bound was accepted")
	}
}

func scheduleStatementID(id string) schedulepermit.Statement {
	return schedulepermit.Statement{ScheduleID: id}
}
