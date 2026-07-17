package controlplane

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestEvidenceCaptureAdministrationIsBoundedAndSiteAdminOnly(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(
		t,
		http.MethodPost,
		"/v1/tenants",
		fixture.adminToken,
		`{"tenant_id":"tenant-a"}`,
	), http.StatusCreated)
	credential := enrollNodeThroughAPI(
		t,
		fixture,
		fixture.adminToken,
		"capture-enrollment",
		"node-capture",
		[]string{"tenant-a"},
	)
	if credential.NodeID != "node-capture" {
		t.Fatalf("credential = %#v", credential)
	}
	operatorResponse := fixture.request(
		t,
		http.MethodPost,
		"/v1/operators",
		fixture.adminToken,
		`{"request_id":"capture-operator","role":"tenant_operator","tenant_id":"tenant-a"}`,
	)
	requireStatus(t, operatorResponse, http.StatusCreated)
	var operator struct {
		Token string `json:"token"`
	}
	decodeResponse(t, operatorResponse, &operator)

	path := "/v1/nodes/node-capture/evidence/captures"
	body := `{"capture_id":"capture-1","request_id":"request-1","tenant_id":"tenant-a","runtime_ref":"executor-` +
		strings.Repeat("a", 64) +
		`","generation":7,"activation_id":"activation-1","activation_begin_digest":"sha256:` +
		strings.Repeat("1", 64) + `","ttl_seconds":60}`
	requireError(
		t,
		fixture.request(t, http.MethodPost, path, operator.Token, body),
		http.StatusForbidden,
		"forbidden",
	)
	response := fixture.request(t, http.MethodPost, path, fixture.adminToken, body)
	requireStatus(t, response, http.StatusCreated)
	var capture controlstore.EvidenceCapture
	decodeResponse(t, response, &capture)
	if err := capture.Validate(); err != nil ||
		capture.CaptureID != "capture-1" ||
		capture.NodeID != "node-capture" ||
		capture.State != controlstore.EvidenceCaptureArmed ||
		capture.ExpiresAt != fixture.now.Add(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("capture = %#v, %v", capture, err)
	}

	// An exact request retry returns the same absolute expiry; it does not
	// silently refresh the capture lease.
	fixture.now = fixture.now.Add(time.Second)
	response = fixture.request(t, http.MethodPost, path, fixture.adminToken, body)
	requireStatus(t, response, http.StatusOK)
	var retry controlstore.EvidenceCapture
	decodeResponse(t, response, &retry)
	if retry != capture {
		t.Fatalf("retry changed capture: got %#v want %#v", retry, capture)
	}
	requireError(
		t,
		fixture.request(
			t,
			http.MethodPost,
			path,
			fixture.adminToken,
			strings.Replace(body, `"ttl_seconds":60`, `"ttl_seconds":61`, 1),
		),
		http.StatusConflict,
		"conflict",
	)

	item := path + "/capture-1"
	response = fixture.request(t, http.MethodGet, item, fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var inspected controlstore.EvidenceCapture
	decodeResponse(t, response, &inspected)
	if inspected != capture {
		t.Fatalf("inspection = %#v, want %#v", inspected, capture)
	}
	requireError(
		t,
		fixture.request(
			t,
			http.MethodGet,
			"/v1/nodes/node-other/evidence/captures/capture-1",
			fixture.adminToken,
			"",
		),
		http.StatusNotFound,
		"not_found",
	)
	requireError(
		t,
		fixture.request(
			t,
			http.MethodPost,
			item+"/seal",
			fixture.adminToken,
			`{"canary_command_id":"canary-1"}`,
		),
		http.StatusConflict,
		"conflict",
	)
	requireError(
		t,
		fixture.request(t, http.MethodGet, item+"/export", fixture.adminToken, ""),
		http.StatusConflict,
		"conflict",
	)
	requireError(
		t,
		fixture.request(
			t,
			http.MethodPost,
			path,
			fixture.adminToken,
			strings.Replace(body, `"ttl_seconds":60`, `"ttl_seconds":0`, 1),
		),
		http.StatusBadRequest,
		"invalid_request",
	)
	requireError(
		t,
		fixture.request(
			t,
			http.MethodPost,
			path,
			fixture.adminToken,
			strings.TrimSuffix(body, "}")+`,"unknown":true}`,
		),
		http.StatusBadRequest,
		"invalid_request",
	)
	requireError(
		t,
		fixture.request(t, http.MethodPut, item, "", `{}`),
		http.StatusMethodNotAllowed,
		"method_not_allowed",
	)

	response = fixture.request(t, http.MethodDelete, item, fixture.adminToken, "")
	requireStatus(t, response, http.StatusNoContent)
	if response.Body.Len() != 0 {
		t.Fatalf("delete response body = %q", response.Body.String())
	}
	requireError(
		t,
		fixture.request(t, http.MethodGet, item, fixture.adminToken, ""),
		http.StatusNotFound,
		"not_found",
	)
}
