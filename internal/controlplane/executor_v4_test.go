package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestControlPlaneExecutorProtocolV4PersistsAndExposesAdmissionProjection(t *testing.T) {
	fixture := newServerFixture(t)
	admin, err := fixture.store.AuthenticateOperator(fixture.server.auth, fixture.adminToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := fixture.store.CreateTenant(admin, "tenant-a", fixture.now); err != nil || !created {
		t.Fatalf("create tenant = (%v, %v)", created, err)
	}
	enrollmentRaw, enrollment, _, err := fixture.store.CreateEnrollment(
		admin, fixture.server.auth, "node-1", []string{"tenant-a"},
		fixture.now.Add(time.Hour), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	capability := testEnrollmentCapability{
		ControllerInstanceID: fixture.server.auth.InstanceID(),
		EnrollmentID:         enrollment.ID, EnrollmentToken: enrollmentRaw,
		NodeID: enrollment.NodeID, TenantIDs: enrollment.TenantIDs, ExpiresAt: enrollment.ExpiresAt,
	}
	proof := fixture.evidenceIdentityProof(t, capability)
	nodeCredential, err := fixture.store.ExchangeEnrollment(
		fixture.server.auth, enrollmentRaw, "exchange-v4", proof, fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	runtimeRef := "executor-" + strings.Repeat("a", 64)
	commandRaw := signedServerV4AdmitCommand(t, fixture.now, runtimeRef)
	if _, created, err := fixture.store.SubmitCommand(
		admin, "tenant-a", "node-1", commandRaw, fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}

	fixture.now = fixture.now.Add(3 * time.Minute)
	poll := controlprotocol.ExecutorPollRequestV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		NodeID:          "node-1", CredentialScope: "node",
		Capabilities: []string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
	}
	response := fixture.request(
		t, http.MethodPost, "/executor-uplink/poll", nodeCredential.Credential, mustJSON(t, poll),
	)
	requireStatus(t, response, http.StatusOK)
	polled, err := controlprotocol.DecodeExecutorPollResponseV4(
		response.Body.Bytes(), controlprotocol.MaxExecutorDeliveryBytes,
	)
	if err != nil || len(polled.Deliveries) != 1 {
		t.Fatalf("decode v4 poll = (%+v, %v)", polled, err)
	}
	delivery, err := controlprotocol.DecodeExecutorDeliveryV4(polled.Deliveries[0])
	if err != nil {
		t.Fatal(err)
	}

	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    runtimeRef, Status: "created",
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
		Generation:    11, EvidenceKeyID: strings.Repeat("d", 32),
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
		ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: runtimeRef, Admission: &projection,
		},
	}
	fixture.now = fixture.now.Add(time.Minute)
	response = fixture.request(
		t, http.MethodPost, "/executor-uplink/report", nodeCredential.Credential, mustJSON(t, report),
	)
	requireStatus(t, response, http.StatusOK)
	var acknowledged controlprotocol.ExecutorReportResponseV4
	decodeResponse(t, response, &acknowledged)
	if acknowledged.ProtocolVersion != controlprotocol.ExecutorProtocolV4 || !acknowledged.Applied {
		t.Fatalf("unexpected v4 acknowledgement: %+v", acknowledged)
	}

	response = fixture.request(
		t, http.MethodGet,
		"/v1/tenants/tenant-a/nodes/node-1/commands/command-v4",
		fixture.adminToken,
		"",
	)
	requireStatus(t, response, http.StatusOK)
	var command commandResponse
	decodeResponse(t, response, &command)
	if command.CommandKind != "admit" || command.SignedClaimGeneration != 7 ||
		command.SignedRuntimeRef != runtimeRef || command.SignedInstanceGeneration != 11 ||
		command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
		command.AdmissionProjectionState != "present" ||
		command.Result == nil || command.Result.Admission == nil ||
		command.Result.Admission.RuntimeRef != runtimeRef {
		t.Fatalf("protocol-4 command view lost its signed binding or projection: %+v", command)
	}

	response = fixture.request(
		t, http.MethodPost, "/executor-uplink/poll", nodeCredential.Credential, mustJSON(t, poll),
	)
	requireStatus(t, response, http.StatusOK)
	if got := strings.TrimSpace(response.Body.String()); got != `{"protocol_version":4,"deliveries":[]}` {
		t.Fatalf("idle v4 poll response = %s", got)
	}
	if _, err := controlprotocol.DecodeExecutorPollResponseV4(
		response.Body.Bytes(), controlprotocol.MaxExecutorDeliveryBytes,
	); err != nil {
		t.Fatalf("idle v4 poll response is invalid: %v", err)
	}
}

func TestControlPlaneExecutorProtocolDispatchRejectsAmbiguityWithoutWideningV3(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(
		t,
		fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`),
		http.StatusCreated,
	)
	node := enrollNodeThroughAPI(
		t, fixture, fixture.adminToken, "enrollment-v4-boundary", "node-1", []string{"tenant-a"},
	)
	for _, body := range []string{
		`{"protocol_version":4,"protocol_version":3,"node_id":"node-1","credential_scope":"node","capabilities":[]}`,
		`{"protocol_version":4.0,"node_id":"node-1","credential_scope":"node","capabilities":[]}`,
		`{"protocol_version":5,"node_id":"node-1","credential_scope":"node","capabilities":[]}`,
	} {
		requireError(
			t,
			fixture.request(t, http.MethodPost, "/executor-uplink/poll", node.Credential, body),
			http.StatusBadRequest,
			"invalid_request",
		)
	}
	v3WithAdmission := `{"protocol_version":3,"delivery_id":"delivery","delivery_generation":1,` +
		`"command_id":"command","command_digest":"sha256:` + strings.Repeat("a", 64) + `",` +
		`"status":"done","reported_status":"stopped","claim_generation":1,` +
		`"result":{"admission":{"schema_version":"unexpected"}}}`
	requireError(
		t,
		fixture.request(t, http.MethodPost, "/executor-uplink/report", node.Credential, v3WithAdmission),
		http.StatusBadRequest,
		"invalid_request",
	)
}

func TestCommandViewMakesMissingSuccessfulAdmitProjectionExplicit(t *testing.T) {
	command := controlstore.Command{
		CommandKind: "admit", SignedRuntimeRef: "executor-" + strings.Repeat("a", 64),
		SignedClaimGeneration: 7, SignedInstanceGeneration: 11,
		DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
		State:            controlstore.CommandTerminal,
		Terminal: &controlstore.TerminalReport{Report: controlprotocol.ExecutorReportV3{
			ProtocolVersion: controlprotocol.ExecutorProtocolV4,
			Status:          controlprotocol.ExecutorStatusDone,
			ReportedStatus:  "stopped",
			ClaimGeneration: 7,
			Result: controlprotocol.ExecutorReportResultV3{
				RuntimeRef: "executor-" + strings.Repeat("a", 64),
			},
		}},
	}
	view := commandView(command)
	if view.AdmissionProjectionState != "missing" || view.Result == nil || view.Result.Admission != nil ||
		view.SignedRuntimeRef != command.SignedRuntimeRef ||
		view.SignedInstanceGeneration != command.SignedInstanceGeneration {
		t.Fatalf("missing projection view = %+v", view)
	}
}

func TestCommandViewExposesOnlyCorrelatedActivationCanaryProjection(t *testing.T) {
	terminal := []byte(`{"ok":true}`)
	receipts := []byte("authorize\nterminal\nexport\n")
	projection := controlprotocol.ExecutorActivationCanaryResultV1{
		SchemaVersion:        controlprotocol.ExecutorActivationCanaryResultSchemaV1,
		ActivationID:         "activation-1",
		AdmissionDigest:      "sha256:" + strings.Repeat("1", 64),
		TaskDigest:           "sha256:" + strings.Repeat("2", 64),
		PermitDigest:         "sha256:" + strings.Repeat("3", 64),
		RunID:                "run_" + strings.Repeat("4", 32),
		TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: "sha256:" + strings.Repeat("5", 64), Qualified: true,
	}
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	command := controlstore.Command{
		CommandKind: "activation-canary", SignedRuntimeRef: runtimeRef,
		SignedClaimGeneration: 7, SignedInstanceGeneration: 11,
		DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
		State:            controlstore.CommandTerminal,
		Terminal: &controlstore.TerminalReport{
			Report: controlprotocol.ExecutorReportV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				Status:          controlprotocol.ExecutorStatusDone,
				ReportedStatus:  "running", ClaimGeneration: 7,
				Result: controlprotocol.ExecutorReportResultV3{RuntimeRef: runtimeRef},
			},
			ActivationCanary: &projection,
		},
	}
	view := commandView(command)
	if view.ActivationCanaryProjectionState != "present" || view.Result == nil ||
		view.Result.ActivationCanary == nil ||
		view.Result.ActivationCanary.ActivationCheckpointDigest != projection.ActivationCheckpointDigest ||
		view.ReportedStatus != "running" || view.SignedInstanceGeneration != 11 {
		t.Fatalf("activation canary command view = %+v", view)
	}

	command.Terminal.ActivationCanary = nil
	view = commandView(command)
	if view.ActivationCanaryProjectionState != "missing" || view.Result == nil ||
		view.Result.ActivationCanary != nil {
		t.Fatalf("missing activation canary command view = %+v", view)
	}
}

func signedServerV4AdmitCommand(t *testing.T, now time.Time, runtimeRef string) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2,
		CommandID:     "command-v4", TenantID: "tenant-a", NodeID: "node-1",
		InstanceID: "agent-1", RuntimeRef: runtimeRef, Kind: "admit",
		ClaimGeneration: 7, InstanceGeneration: 11, CommandSequence: 1,
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		Payload:   json.RawMessage(`{}`),
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
