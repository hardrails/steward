package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executoruplink"
)

type serverFixture struct {
	server     *Server
	store      *controlstore.Store
	now        time.Time
	adminToken string
}

func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	store, err := controlstore.Initialize(t.TempDir()+"/control", controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	manager, err := controlauth.New(bytes.Repeat([]byte{0x42}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 13, 20, 0, 0, 0, time.UTC)
	adminToken, _, err := store.BootstrapSiteAdmin(manager, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serverFixture{store: store, now: now, adminToken: adminToken}
	fixture.server, err = New(Config{
		Store: store, Auth: manager, LeaseDuration: 2 * time.Minute, MaxPoll: 32,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestControlPlaneEndToEndSignedCommandLifecycle(t *testing.T) {
	fixture := newServerFixture(t)

	response := fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`)
	requireStatus(t, response, http.StatusCreated)
	response = fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken, `{"role":"tenant_operator","tenant_id":"tenant-a"}`)
	requireStatus(t, response, http.StatusCreated)
	var operator struct {
		CredentialID string `json:"credential_id"`
		Token        string `json:"token"`
	}
	decodeResponse(t, response, &operator)
	if operator.CredentialID == "" || operator.Token == "" {
		t.Fatalf("operator response omitted credential material: %+v", operator)
	}

	response = fixture.request(t, http.MethodPost, "/v1/enrollments", operator.Token,
		`{"node_id":"node-1","tenant_ids":["tenant-a"],"ttl_seconds":900}`)
	requireStatus(t, response, http.StatusCreated)
	var enrollment struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	decodeResponse(t, response, &enrollment)
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		mustJSON(t, map[string]string{"enrollment_token": enrollment.EnrollmentToken, "request_id": "request-1"}))
	requireStatus(t, response, http.StatusCreated)
	var nodeCredential controlauth.NodeCredentialFile
	decodeResponse(t, response, &nodeCredential)
	if nodeCredential.Scope != "node" || nodeCredential.NodeID != "node-1" || nodeCredential.Credential == "" {
		t.Fatalf("unexpected node credential: %+v", nodeCredential)
	}

	// An exact exchange retry is recoverable and returns the same derived node
	// credential without retaining its bearer secret in the store.
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		mustJSON(t, map[string]string{"enrollment_token": enrollment.EnrollmentToken, "request_id": "request-1"}))
	requireStatus(t, response, http.StatusCreated)
	var retried controlauth.NodeCredentialFile
	decodeResponse(t, response, &retried)
	if retried != nodeCredential {
		t.Fatalf("exact enrollment retry changed credential: got %+v want %+v", retried, nodeCredential)
	}

	commandRaw := signedCommand(t, fixture.now, "command-1", "tenant-a", "node-1")
	response = fixture.request(t, http.MethodPost, "/v1/tenants/tenant-a/nodes/node-1/commands", operator.Token,
		mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(commandRaw)}))
	requireStatus(t, response, http.StatusCreated)
	var submitted commandResponse
	decodeResponse(t, response, &submitted)
	if submitted.CommandID != "command-1" || submitted.State != string(controlstore.CommandPending) {
		t.Fatalf("unexpected submitted command: %+v", submitted)
	}

	poll := controlprotocol.ExecutorPollRequestV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3, NodeID: "node-1", CredentialScope: "node",
		Capabilities: []string{"delivery-leases-v3", "signed-commands-v2"},
	}
	response = fixture.request(t, http.MethodPost, "/executor-uplink/poll", nodeCredential.Credential, mustJSON(t, poll))
	requireStatus(t, response, http.StatusOK)
	var polled struct {
		ProtocolVersion int                                  `json:"protocol_version"`
		Deliveries      []controlprotocol.ExecutorDeliveryV3 `json:"deliveries"`
	}
	decodeResponse(t, response, &polled)
	if polled.ProtocolVersion != 3 || len(polled.Deliveries) != 1 {
		t.Fatalf("unexpected poll response: %+v", polled)
	}
	delivery := polled.Deliveries[0]
	if delivery.CommandID != "command-1" || delivery.CommandDigest != dsse.Digest(commandRaw) {
		t.Fatalf("delivery did not preserve signed command identity: %+v", delivery)
	}

	fixture.now = fixture.now.Add(time.Second)
	report := controlprotocol.ExecutorReportV3{
		ProtocolVersion: 3, DeliveryID: delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest, Status: controlprotocol.ExecutorStatusDone,
		ReportedStatus: "success", ClaimGeneration: 1, Result: controlprotocol.ExecutorReportResultV3{RuntimeRef: "runtime-1"},
	}
	response = fixture.request(t, http.MethodPost, "/executor-uplink/report", nodeCredential.Credential, mustJSON(t, report))
	requireStatus(t, response, http.StatusOK)
	var reported controlprotocol.ExecutorReportResponseV3
	decodeResponse(t, response, &reported)
	if !reported.Applied {
		t.Fatal("terminal report was not applied")
	}

	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/nodes/node-1/commands/command-1", operator.Token, "")
	requireStatus(t, response, http.StatusOK)
	var terminal commandResponse
	decodeResponse(t, response, &terminal)
	if terminal.State != string(controlstore.CommandTerminal) || terminal.ReportedStatus != "success" {
		t.Fatalf("terminal command status was not retained: %+v", terminal)
	}

	// Revocation takes effect before another authenticated operation.
	response = fixture.request(t, http.MethodDelete, "/v1/operators/"+operator.CredentialID, fixture.adminToken, "")
	requireStatus(t, response, http.StatusNoContent)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("204 response missing no-store: %v", response.Header())
	}
	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a", operator.Token, "")
	requireError(t, response, http.StatusUnauthorized, "unauthorized")
}

func TestControlPlaneRejectsAmbiguousAndCrossTenantRequests(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-b"}`), http.StatusCreated)
	response := fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken,
		`{"role":"tenant_operator","tenant_id":"tenant-a"}`)
	requireStatus(t, response, http.StatusCreated)
	var operator struct {
		Token string `json:"token"`
	}
	decodeResponse(t, response, &operator)

	// Method handling is stable and does not depend on whether a credential was
	// supplied, preventing authorization behavior from replacing a route's 405.
	requireError(t, fixture.request(t, http.MethodPut, "/v1/tenants", "", `{}`), http.StatusMethodNotAllowed, "method_not_allowed")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-b", operator.Token, ""), http.StatusNotFound, "not_found")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-c","tenant_id":"tenant-d"}`), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-c","unexpected":true}`), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		strings.Repeat(" ", maxRequestBytes+1)), http.StatusRequestEntityTooLarge, "payload_too_large")
	requireError(t, fixture.request(t, http.MethodGet, "/missing", "", ""), http.StatusNotFound, "not_found")

	request := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	request.Header.Add("Authorization", "Bearer "+fixture.adminToken)
	request.Header.Add("Authorization", "Bearer "+fixture.adminToken)
	recorder := httptest.NewRecorder()
	fixture.server.ServeHTTP(recorder, request)
	requireError(t, recorder, http.StatusUnauthorized, "unauthorized")

	for _, response := range []*httptest.ResponseRecorder{
		fixture.request(t, http.MethodGet, "/v1/healthz", "", ""),
		fixture.request(t, http.MethodGet, "/v1/readiness", "", ""),
	} {
		requireStatus(t, response, http.StatusOK)
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("security response headers missing: %v", response.Header())
		}
	}
}

func (fixture *serverFixture) request(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	fixture.server.ServeHTTP(recorder, request)
	return recorder
}

func signedCommand(t *testing.T, now time.Time, commandID, tenantID, nodeID string) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRef, err := executoruplink.RuntimeRefV2(tenantID, nodeID, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: commandID, TenantID: tenantID, NodeID: nodeID,
		InstanceID: "agent-1", RuntimeRef: runtimeRef, Kind: "read", ClaimGeneration: 1,
		InstanceGeneration: 1, CommandSequence: 1, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
	}
	if err := statement.Validate(now); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandPayloadType, payload, "tenant-command", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}

func requireStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
}

func requireError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	requireStatus(t, response, status)
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	decodeResponse(t, response, &body)
	if body.Error != code || body.Message == "" {
		t.Fatalf("error response=%+v want code %q", body, code)
	}
}
