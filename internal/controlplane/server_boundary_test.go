package controlplane

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

type gatedRequestBody struct {
	raw     []byte
	started chan struct{}
	release chan struct{}
	once    sync.Once
	offset  int
}

func newGatedRequestBody(raw string) *gatedRequestBody {
	return &gatedRequestBody{raw: []byte(raw), started: make(chan struct{}), release: make(chan struct{})}
}

func (body *gatedRequestBody) Read(destination []byte) (int, error) {
	body.once.Do(func() { close(body.started) })
	<-body.release
	if body.offset == len(body.raw) {
		return 0, io.EOF
	}
	written := copy(destination, body.raw[body.offset:])
	body.offset += written
	return written, nil
}

func TestRevocationFencesRequestsAuthenticatedBeforeTheirBodiesArrive(t *testing.T) {
	fixture := newServerFixture(t)
	admin, err := fixture.store.AuthenticateOperator(fixture.server.auth, fixture.adminToken)
	if err != nil {
		t.Fatal(err)
	}
	backupRaw, _, _, err := fixture.store.IssueOperator(
		admin, fixture.server.auth, "revocation-race-backup", controlauth.RoleSiteAdmin, "", fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := fixture.store.AuthenticateOperator(fixture.server.auth, backupRaw)
	if err != nil {
		t.Fatal(err)
	}

	body := newGatedRequestBody(`{"request_id":"revocation-race-mint","role":"site_admin"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/operators", body)
	request.Header.Set("Authorization", "Bearer "+fixture.adminToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fixture.server.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-body.started:
	case <-time.After(5 * time.Second):
		t.Fatal("operator request did not reach its gated body")
	}
	if revoked, err := fixture.store.RevokeOperator(backup, admin.CredentialID, fixture.now.Add(time.Minute)); err != nil || !revoked {
		t.Fatalf("revoke authenticated operator = (%v, %v)", revoked, err)
	}
	close(body.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked operator request did not finish")
	}
	requireError(t, response, http.StatusUnauthorized, "unauthorized")
	status, err := fixture.store.Status()
	if err != nil || status.Credentials != 2 {
		t.Fatalf("revoked in-flight request minted a credential: status=%+v err=%v", status, err)
	}
}

func TestNodeAdministrationFencesEveryCredentialAndTenantView(t *testing.T) {
	fixture := newServerFixture(t)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
			mustJSON(t, map[string]string{"tenant_id": tenantID})), http.StatusCreated)
	}
	operatorA := issueOperatorThroughAPI(t, fixture, "operator-a", "tenant-a")
	operatorB := issueOperatorThroughAPI(t, fixture, "operator-b", "tenant-b")

	first := enrollNodeThroughAPI(t, fixture, fixture.adminToken, "enrollment-1", "node-1", []string{"tenant-a", "tenant-b"})
	second := enrollNodeThroughAPI(t, fixture, fixture.adminToken, "enrollment-2", "node-1", []string{"tenant-a", "tenant-b"})

	response := fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes?limit=1", operatorA, "")
	requireStatus(t, response, http.StatusOK)
	var listing nodeListResponse
	decodeResponse(t, response, &listing)
	if len(listing.Nodes) != 1 || listing.Nodes[0].NodeID != "node-1" ||
		len(listing.Nodes[0].TenantIDs) != 1 || listing.Nodes[0].TenantIDs[0] != "tenant-a" {
		t.Fatalf("tenant-scoped node projection = %+v", listing)
	}

	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var node nodeResponse
	decodeResponse(t, response, &node)
	if len(node.TenantIDs) != 2 || node.State != "active" {
		t.Fatalf("site-admin node projection = %+v", node)
	}

	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-b/nodes", operatorA, ""),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-b/nodes/node-1", operatorA, ""),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/nodes/node-1", operatorB, ""),
		http.StatusForbidden, "forbidden")

	response = fixture.request(t, http.MethodDelete, "/v1/nodes/node-1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var revoked struct {
		NodeID             string `json:"node_id"`
		RevokedCredentials int    `json:"revoked_credentials"`
	}
	decodeResponse(t, response, &revoked)
	if revoked.NodeID != "node-1" || revoked.RevokedCredentials != 2 {
		t.Fatalf("node revocation = %+v", revoked)
	}

	response = fixture.request(t, http.MethodDelete, "/v1/nodes/node-1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &revoked)
	if revoked.RevokedCredentials != 0 {
		t.Fatalf("idempotent node revocation = %+v", revoked)
	}
	for _, credential := range []controlauth.NodeCredentialFile{first, second} {
		requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/poll", credential.Credential,
			`{"protocol_version":3,"node_id":"node-1","credential_scope":"node","capabilities":[]}`),
			http.StatusUnauthorized, "unauthorized")
	}

	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1", operatorA, "")
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &node)
	if node.State != "revoked" || node.RevokedAt == "" {
		t.Fatalf("revoked node remains auditable = %+v", node)
	}
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/nodes/missing", fixture.adminToken, ""),
		http.StatusNotFound, "not_found")
}

func TestControlPlaneRejectsProtocolAndPaginationAmbiguity(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-a"}`), http.StatusCreated)
	operator := issueOperatorThroughAPI(t, fixture, "operator-a", "tenant-a")
	node := enrollNodeThroughAPI(t, fixture, operator, "enrollment-1", "node-1", []string{"tenant-a"})
	requireStatus(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a", operator, ""), http.StatusOK)
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants?unexpected=1", fixture.adminToken, `{}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"bad id"}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/enroll", "", `{"enrollment_token":"invalid","request_id":"request"}`),
		http.StatusUnauthorized, "unauthorized")

	for _, request := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/tenants", ""},
		{http.MethodGet, "/v1/tenants/tenant-a", ""},
		{http.MethodPost, "/v1/operators", `{}`},
		{http.MethodDelete, "/v1/operators/missing", ""},
		{http.MethodPost, "/v1/enrollments", `{}`},
		{http.MethodDelete, "/v1/node-credentials/missing", ""},
		{http.MethodDelete, "/v1/nodes/node-1", ""},
		{http.MethodGet, "/v1/tenants/tenant-a/nodes", ""},
		{http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1", ""},
		{http.MethodPost, "/v1/tenants/tenant-a/nodes/node-1/commands", `{}`},
		{http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1/commands/missing", ""},
		{http.MethodPost, "/executor-uplink/poll", `{}`},
		{http.MethodPost, "/executor-uplink/report", `{}`},
	} {
		requireError(t, fixture.request(t, request.method, request.path, "", request.body),
			http.StatusUnauthorized, "unauthorized")
	}

	for _, request := range []struct {
		path  string
		token string
	}{
		{"/v1/operators", fixture.adminToken},
		{"/v1/enrollments", operator},
		{"/v1/enroll", ""},
		{"/v1/tenants/tenant-a/nodes/node-1/commands", operator},
		{"/executor-uplink/poll", node.Credential},
		{"/executor-uplink/report", node.Credential},
	} {
		requireError(t, fixture.request(t, http.MethodPost, request.path, request.token, `{`),
			http.StatusBadRequest, "invalid_request")
	}

	for _, path := range []string{
		"/v1/tenants?unknown=1",
		"/v1/tenants?limit=0",
		"/v1/tenants?limit=501",
		"/v1/tenants?limit=not-a-number",
		"/v1/tenants?limit=1&limit=2",
		"/v1/tenants?after=" + strings.Repeat("a", 129),
		"/v1/tenants/tenant-a/nodes?after=x&after=y",
	} {
		requireError(t, fixture.request(t, http.MethodGet, path, fixture.adminToken, ""),
			http.StatusBadRequest, "invalid_request")
	}
	for _, path := range []string{
		"/v1/healthz?unexpected=1",
		"/v1/readiness?unexpected=1",
		"/v1/tenants/tenant-a?unexpected=1",
		"/v1/tenants/tenant-a/nodes/node-1?unexpected=1",
	} {
		requireError(t, fixture.request(t, http.MethodGet, path, fixture.adminToken, ""),
			http.StatusBadRequest, "invalid_request")
	}
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/nodes/node-1?unexpected=1", fixture.adminToken, ""),
		http.StatusBadRequest, "invalid_request")

	requireError(t, fixture.request(t, http.MethodPost, "/v1/enrollments", operator,
		`{"request_id":"bad-ttl","node_id":"node-2","tenant_ids":["tenant-a"],"ttl_seconds":0}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/enrollments", operator,
		`{"request_id":"bad-ttl","node_id":"node-2","tenant_ids":["tenant-a"],"ttl_seconds":86401}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/enroll", "", `{}`),
		http.StatusBadRequest, "invalid_request")

	for _, body := range []string{
		`{"protocol_version":2,"node_id":"node-1","credential_scope":"node","capabilities":[]}`,
		`{"protocol_version":3,"node_id":"another-node","credential_scope":"node","capabilities":[]}`,
		`{"protocol_version":3,"node_id":"node-1","credential_scope":"operator","capabilities":[]}`,
	} {
		requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/poll", node.Credential, body),
			http.StatusBadRequest, "invalid_request")
	}
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/poll", node.Credential,
		`{"protocol_version":3,"node_id":"node-1","credential_scope":"node","capabilities":["duplicate","duplicate"]}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/report", node.Credential, `{}`),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants/tenant-a/nodes/node-1/commands", operator,
		`{"command_dsse_base64":"not-base64"}`), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1/commands/missing", operator, ""),
		http.StatusNotFound, "not_found")

	request := httptest.NewRequest(http.MethodPost, "/v1/tenants", strings.NewReader(`{"tenant_id":"tenant-b"}`))
	request.Header.Set("Authorization", "Bearer "+fixture.adminToken)
	recorder := httptest.NewRecorder()
	fixture.server.ServeHTTP(recorder, request)
	requireError(t, recorder, http.StatusUnsupportedMediaType, "unsupported_media_type")

	request = httptest.NewRequest(http.MethodPost, "/v1/tenants", errorReader{})
	request.Header.Set("Authorization", "Bearer "+fixture.adminToken)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	fixture.server.ServeHTTP(recorder, request)
	requireError(t, recorder, http.StatusBadRequest, "invalid_request")

	for _, authorization := range []string{
		"Basic abc", "Bearer", "Bearer ", "Bearer  padded", "Bearer bad token", "Bearer " + strings.Repeat("x", 4097),
	} {
		request = httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
		request.Header.Set("Authorization", authorization)
		recorder = httptest.NewRecorder()
		fixture.server.ServeHTTP(recorder, request)
		requireError(t, recorder, http.StatusUnauthorized, "unauthorized")
	}
}

func TestControlPlaneFailsClosedOnPanicsUnavailableStateAndEncodingBounds(t *testing.T) {
	fixture := newServerFixture(t)
	fixture.server.mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) { panic("test panic") })
	requireError(t, fixture.request(t, http.MethodGet, "/panic", "", ""),
		http.StatusInternalServerError, "internal_error")

	for _, test := range []struct {
		err    error
		status int
		code   string
		hide   bool
	}{
		{controlauth.ErrUnauthorized, http.StatusUnauthorized, "unauthorized", false},
		{controlauth.ErrEnrollmentConsumed, http.StatusConflict, "conflict", false},
		{controlauth.ErrEnrollmentExpired, http.StatusGone, "enrollment_expired", false},
		{controlstore.ErrForbidden, http.StatusForbidden, "forbidden", false},
		{controlstore.ErrForbidden, http.StatusNotFound, "not_found", true},
		{controlstore.ErrNotFound, http.StatusNotFound, "not_found", false},
		{controlstore.ErrInvalid, http.StatusBadRequest, "invalid_request", false},
		{controlstore.ErrCapacityExceeded, http.StatusServiceUnavailable, "capacity_exceeded", false},
		{controlstore.ErrUnavailable, http.StatusServiceUnavailable, "not_ready", false},
		{errors.New("unexpected"), http.StatusInternalServerError, "internal_error", false},
	} {
		recorder := httptest.NewRecorder()
		fixture.server.storeError(recorder, test.err, test.hide)
		requireError(t, recorder, test.status, test.code)
	}

	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, make(chan int))
	requireError(t, recorder, http.StatusInternalServerError, "internal_error")
	recorder = httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, strings.Repeat("x", maxResponseBytes))
	requireError(t, recorder, http.StatusInternalServerError, "internal_error")

	oversized := controlstore.Node{ID: "node", TenantIDs: []string{"tenant"}, Capabilities: []string{strings.Repeat("x", maxResponseBytes)}}
	if _, _, err := pageNodeViews([]controlstore.Node{oversized}, pageRequest{limit: 1}); err == nil {
		t.Fatal("one oversized node unexpectedly fit the bounded response")
	}
}

func TestControlPlaneRouteMatrixPreservesIdempotencyAndConcealment(t *testing.T) {
	fixture := newServerFixture(t)
	tenantBody := `{"tenant_id":"tenant-a"}`
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, tenantBody), http.StatusCreated)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, tenantBody), http.StatusOK)
	operator := issueOperatorThroughAPI(t, fixture, "operator-a", "tenant-a")
	node := enrollNodeThroughAPI(t, fixture, operator, "enrollment-1", "node-1", []string{"tenant-a"})

	response := fixture.request(t, http.MethodGet, "/v1/tenants?limit=1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var tenants struct {
		Tenants []tenantResponse `json:"tenants"`
	}
	decodeResponse(t, response, &tenants)
	if len(tenants.Tenants) != 1 || tenants.Tenants[0].TenantID != "tenant-a" {
		t.Fatalf("tenant listing = %+v", tenants)
	}
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/missing", fixture.adminToken, ""),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/missing/nodes", fixture.adminToken, ""),
		http.StatusNotFound, "not_found")

	for _, request := range []struct {
		method string
		path   string
		token  string
		body   string
		status int
		code   string
	}{
		{http.MethodGet, "/v1/operators", fixture.adminToken, "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/v1/operators?unexpected=1", fixture.adminToken, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPost, "/v1/operators", operator, `{"request_id":"forbidden","role":"site_admin"}`, http.StatusForbidden, "forbidden"},
		{http.MethodDelete, "/v1/operators/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodGet, "/v1/enrollments", operator, "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/v1/enrollments?unexpected=1", operator, `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodGet, "/v1/enroll", "", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodDelete, "/v1/node-credentials/missing", fixture.adminToken, "", http.StatusNotFound, "not_found"},
		{http.MethodPost, "/v1/nodes/node-1", fixture.adminToken, `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/v1/tenants/tenant-a/nodes", operator, `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/v1/tenants/tenant-a/nodes/node-1", operator, `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodPost, "/executor-uplink/report?unexpected=1", node.Credential, `{}`, http.StatusBadRequest, "invalid_request"},
	} {
		requireError(t, fixture.request(t, request.method, request.path, request.token, request.body), request.status, request.code)
	}

	commandRaw := signedCommand(t, fixture.now, "command-1", "tenant-a", "node-1")
	commandBody := mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(commandRaw)})
	commandPath := "/v1/tenants/tenant-a/nodes/node-1/commands"
	requireStatus(t, fixture.request(t, http.MethodPost, commandPath, operator, commandBody), http.StatusCreated)
	requireStatus(t, fixture.request(t, http.MethodPost, commandPath, operator, commandBody), http.StatusOK)
	conflicting := signedCommand(t, fixture.now, "command-1", "tenant-a", "node-1")
	requireError(t, fixture.request(t, http.MethodPost, commandPath, operator,
		mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(conflicting)})),
		http.StatusConflict, "conflict")
	missingNode := signedCommand(t, fixture.now, "command-missing", "tenant-a", "missing")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants/tenant-a/nodes/missing/commands", operator,
		mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(missingNode)})),
		http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1/commands/command-1?unexpected=1", operator, ""),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/tenants/tenant-a/nodes/node-1/commands/command-1", operator, ""),
		http.StatusMethodNotAllowed, "method_not_allowed")

	missingReport := controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      "delivery-missing", DeliveryGeneration: 1, CommandID: "missing",
		CommandDigest: "sha256:" + strings.Repeat("0", 64), Status: controlprotocol.ExecutorStatusDone,
		ReportedStatus: "completed", ClaimGeneration: 1,
	}
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/report", node.Credential, mustJSON(t, missingReport)),
		http.StatusNotFound, "not_found")

	operatorID, err := fixture.server.auth.OperatorCredentialID(operator)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, fixture.request(t, http.MethodDelete, "/v1/operators/"+operatorID, fixture.adminToken, ""),
		http.StatusNoContent)
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/operators/"+operatorID, fixture.adminToken, ""),
		http.StatusNotFound, "not_found")
}

func TestReadinessFailsClosedAfterDurableStoreClosure(t *testing.T) {
	store, err := controlstore.Initialize(t.TempDir()+"/control", controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := controlauth.New(make([]byte, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Store: store, Auth: manager, LeaseDuration: time.Minute, MaxPoll: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/readiness", nil))
	requireError(t, recorder, http.StatusServiceUnavailable, "not_ready")
}

func issueOperatorThroughAPI(t *testing.T, fixture *serverFixture, requestID, tenantID string) string {
	t.Helper()
	response := fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken,
		mustJSON(t, map[string]string{"request_id": requestID, "role": "tenant_operator", "tenant_id": tenantID}))
	requireStatus(t, response, http.StatusCreated)
	var operator struct {
		Token string `json:"token"`
	}
	decodeResponse(t, response, &operator)
	return operator.Token
}

func enrollNodeThroughAPI(t *testing.T, fixture *serverFixture, operator, requestID, nodeID string, tenantIDs []string) controlauth.NodeCredentialFile {
	t.Helper()
	response := fixture.request(t, http.MethodPost, "/v1/enrollments", operator, mustJSON(t, struct {
		RequestID  string   `json:"request_id"`
		NodeID     string   `json:"node_id"`
		TenantIDs  []string `json:"tenant_ids"`
		TTLSeconds int      `json:"ttl_seconds"`
	}{requestID, nodeID, tenantIDs, 900}))
	requireStatus(t, response, http.StatusCreated)
	var enrollment struct {
		Token string `json:"enrollment_token"`
	}
	decodeResponse(t, response, &enrollment)
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "", mustJSON(t, map[string]string{
		"enrollment_token": enrollment.Token,
		"request_id":       requestID + "-exchange",
	}))
	requireStatus(t, response, http.StatusCreated)
	var credential controlauth.NodeCredentialFile
	decodeResponse(t, response, &credential)
	return credential
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
