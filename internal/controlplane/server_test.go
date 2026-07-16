package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/executoruplink"
)

type serverFixture struct {
	server         *Server
	store          *controlstore.Store
	now            time.Time
	adminToken     string
	witnessPrivate ed25519.PrivateKey
	evidenceKeys   map[string]ed25519.PrivateKey
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
	adminToken, _, _, err := store.BootstrapSiteAdmin(manager, now)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serverFixture{
		store: store, now: now, adminToken: adminToken, witnessPrivate: testWitnessPrivate(),
		evidenceKeys: make(map[string]ed25519.PrivateKey),
	}
	fixture.server, err = New(Config{
		Store: store, Auth: manager, WitnessPrivateKey: fixture.witnessPrivate,
		LeaseDuration: 2 * time.Minute, MaxPoll: 32,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func testWitnessPrivate() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7a}, ed25519.SeedSize))
}

type testEnrollmentCapability struct {
	ControllerInstanceID string   `json:"controller_instance_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	EnrollmentToken      string   `json:"enrollment_token"`
	NodeID               string   `json:"node_id"`
	TenantIDs            []string `json:"tenant_ids"`
	ExpiresAt            string   `json:"expires_at"`
}

func (fixture *serverFixture) evidenceIdentityProof(t *testing.T, enrollment testEnrollmentCapability) controlprotocol.ExecutorEvidenceIdentityProofV1 {
	t.Helper()
	private, ok := fixture.evidenceKeys[enrollment.NodeID]
	if !ok {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private = generated
		fixture.evidenceKeys[enrollment.NodeID] = private
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		enrollment.ControllerInstanceID, enrollment.EnrollmentID,
		enrollment.NodeID, enrollment.NodeID, 1, private.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func enrollmentExchangeBody(t *testing.T, enrollment testEnrollmentCapability, requestID string, proof controlprotocol.ExecutorEvidenceIdentityProofV1) string {
	t.Helper()
	return mustJSON(t, struct {
		EnrollmentToken       string                                          `json:"enrollment_token"`
		RequestID             string                                          `json:"request_id"`
		EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
	}{enrollment.EnrollmentToken, requestID, proof})
}

func TestControlPlaneEndToEndSignedCommandLifecycle(t *testing.T) {
	fixture := newServerFixture(t)

	response := fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`)
	requireStatus(t, response, http.StatusCreated)
	operatorRequest := `{"request_id":"operator-request-1","role":"tenant_operator","tenant_id":"tenant-a"}`
	response = fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken, operatorRequest)
	requireStatus(t, response, http.StatusCreated)
	var operator struct {
		CredentialID string `json:"credential_id"`
		Token        string `json:"token"`
	}
	decodeResponse(t, response, &operator)
	if operator.CredentialID == "" || operator.Token == "" {
		t.Fatalf("operator response omitted credential material: %+v", operator)
	}
	response = fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken, operatorRequest)
	requireStatus(t, response, http.StatusOK)
	var retriedOperator struct {
		CredentialID string `json:"credential_id"`
		Token        string `json:"token"`
	}
	decodeResponse(t, response, &retriedOperator)
	if retriedOperator.CredentialID != operator.CredentialID || retriedOperator.Token != operator.Token {
		t.Fatalf("operator retry changed bearer: got %+v want %+v", retriedOperator, operator)
	}
	requireError(t, fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken,
		`{"request_id":"operator-request-1","role":"site_admin"}`), http.StatusConflict, "conflict")

	response = fixture.request(t, http.MethodPost, "/v1/enrollments", operator.Token,
		`{"request_id":"enrollment-request-1","node_id":"node-1","tenant_ids":["tenant-a"],"ttl_seconds":900}`)
	requireStatus(t, response, http.StatusCreated)
	var enrollment testEnrollmentCapability
	decodeResponse(t, response, &enrollment)
	if enrollment.ControllerInstanceID != fixture.server.auth.InstanceID() || enrollment.EnrollmentID == "" {
		t.Fatalf("enrollment omitted witness binding: %+v", enrollment)
	}
	response = fixture.request(t, http.MethodPost, "/v1/enrollments", operator.Token,
		`{"request_id":"enrollment-request-1","node_id":"node-1","tenant_ids":["tenant-a"],"ttl_seconds":900}`)
	requireStatus(t, response, http.StatusOK)
	var retriedEnrollment testEnrollmentCapability
	decodeResponse(t, response, &retriedEnrollment)
	if retriedEnrollment.EnrollmentToken != enrollment.EnrollmentToken ||
		retriedEnrollment.EnrollmentID != enrollment.EnrollmentID ||
		retriedEnrollment.ControllerInstanceID != enrollment.ControllerInstanceID {
		t.Fatal("exact enrollment issuance retry changed its bearer")
	}
	proof := fixture.evidenceIdentityProof(t, enrollment)
	requireError(t, fixture.request(t, http.MethodPost, "/v1/enroll", "",
		mustJSON(t, map[string]string{
			"enrollment_token": enrollment.EnrollmentToken,
			"request_id":       "request-1",
		})), http.StatusUnauthorized, "unauthorized")
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		enrollmentExchangeBody(t, enrollment, "request-1", proof))
	requireStatus(t, response, http.StatusCreated)
	var nodeCredential controlauth.NodeCredentialFile
	decodeResponse(t, response, &nodeCredential)
	if nodeCredential.Scope != "node" || nodeCredential.NodeID != "node-1" || nodeCredential.Credential == "" {
		t.Fatalf("unexpected node credential: %+v", nodeCredential)
	}
	nodeCredentialID, err := fixture.server.auth.NodeCredentialID(nodeCredential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, fixture.request(t, http.MethodDelete, "/v1/operators/"+nodeCredentialID, fixture.adminToken, ""),
		http.StatusNotFound, "not_found")

	// An exact exchange retry is recoverable and returns the same derived node
	// credential without retaining its bearer secret in the store.
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		enrollmentExchangeBody(t, enrollment, "request-1", proof))
	requireStatus(t, response, http.StatusCreated)
	var retried controlauth.NodeCredentialFile
	decodeResponse(t, response, &retried)
	if retried != nodeCredential {
		t.Fatalf("exact enrollment retry changed credential: got %+v want %+v", retried, nodeCredential)
	}

	evidencePoll := controlprotocol.ExecutorEvidencePollRequestV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: enrollment.ControllerInstanceID,
		ControlNodeID:        enrollment.NodeID,
		Stream:               proof.Claim.Stream,
		ReceiptNodeID:        proof.Claim.ReceiptNodeID,
		ReceiptEpoch:         proof.Claim.ReceiptEpoch,
		PublicKeySHA256:      proof.Claim.PublicKeySHA256,
	}
	response = fixture.request(t, http.MethodPost, "/evidence-uplink/poll", nodeCredential.Credential, mustJSON(t, evidencePoll))
	requireStatus(t, response, http.StatusOK)
	var evidencePollResponse controlprotocol.ExecutorEvidencePollResponseV1
	decodeResponse(t, response, &evidencePollResponse)
	if err := evidencePollResponse.Validate(); err != nil || evidencePollResponse.Status.Head == nil ||
		evidencePollResponse.Status.State != controlprotocol.ExecutorEvidenceStatusCurrent ||
		evidencePollResponse.Status.Head.Sequence != 0 {
		t.Fatalf("unexpected genesis evidence checkpoint: response=%+v err=%v", evidencePollResponse, err)
	}
	evidencePrivate := fixture.evidenceKeys[enrollment.NodeID]
	evidenceHead := *evidencePollResponse.Status.Head
	headClaim, err := controlprotocol.NewExecutorEvidenceHeadClaimV1(
		enrollment.ControllerInstanceID, enrollment.NodeID, evidenceHead, evidenceHead,
		evidencePollResponse.Challenge, nil, evidencePrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	headProof, err := controlprotocol.SignExecutorEvidenceHeadClaimV1(headClaim, evidencePrivate)
	if err != nil {
		t.Fatal(err)
	}
	nullFramesBody := `{"protocol_version":1,"head_proof":` + mustJSON(t, headProof) + `,"signed_frames_base64":null}`
	requireError(t, fixture.request(
		t, http.MethodPost, "/evidence-uplink/report", nodeCredential.Credential, nullFramesBody,
	), http.StatusBadRequest, "invalid_request")
	evidenceReport := controlprotocol.ExecutorEvidenceReportV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		HeadProof:       headProof,
	}
	response = fixture.request(t, http.MethodPost, "/evidence-uplink/report", nodeCredential.Credential, mustJSON(t, evidenceReport))
	requireStatus(t, response, http.StatusOK)
	var evidenceReportResponse controlprotocol.ExecutorEvidenceReportResponseV1
	decodeResponse(t, response, &evidenceReportResponse)
	if err := evidenceReportResponse.Validate(); err != nil || evidenceReportResponse.Applied ||
		evidenceReportResponse.Status.Head == nil || *evidenceReportResponse.Status.Head != evidenceHead {
		t.Fatalf("unexpected evidence acknowledgement: response=%+v err=%v", evidenceReportResponse, err)
	}

	response = fixture.request(t, http.MethodGet, "/v1/nodes/"+enrollment.NodeID+"/evidence", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var inspection controlprotocol.ExecutorEvidenceInspectionV1
	decodeResponse(t, response, &inspection)
	if err := inspection.Validate(); err != nil || inspection.IdentityProof == nil ||
		inspection.ControllerInstanceID != enrollment.ControllerInstanceID || inspection.ControlNodeID != enrollment.NodeID ||
		inspection.Status.Head == nil || *inspection.Status.Head != evidenceHead {
		t.Fatalf("unexpected online evidence inspection: inspection=%+v err=%v", inspection, err)
	}

	response = fixture.request(t, http.MethodGet, "/v1/nodes/"+enrollment.NodeID+"/evidence/export", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var evidenceExport controlprotocol.ExecutorEvidenceExportV1
	decodeResponse(t, response, &evidenceExport)
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(
		evidenceExport, fixture.witnessPrivate.Public().(ed25519.PublicKey),
	); err != nil || evidenceExport.Statement.Status.Head == nil || *evidenceExport.Statement.Status.Head != evidenceHead {
		t.Fatalf("unexpected offline evidence export: export=%+v err=%v", evidenceExport, err)
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
	if terminal.State != string(controlstore.CommandTerminal) || terminal.TerminalStatus != controlprotocol.ExecutorStatusDone ||
		terminal.ReportedStatus != "success" || terminal.ClaimGeneration == nil || *terminal.ClaimGeneration != 1 ||
		terminal.Result == nil || terminal.Result.RuntimeRef != "runtime-1" {
		t.Fatalf("terminal command status was not retained: %+v", terminal)
	}

	// An idle v3 poll must use an empty array, not null. The node's strict
	// decoder rejects null so a healthy idle fleet does not silently back off as
	// though the controller were incompatible.
	response = fixture.request(t, http.MethodPost, "/executor-uplink/poll", nodeCredential.Credential, mustJSON(t, poll))
	requireStatus(t, response, http.StatusOK)
	if got := strings.TrimSpace(response.Body.String()); got != `{"protocol_version":3,"deliveries":[]}` {
		t.Fatalf("idle poll response = %s", got)
	}
	if _, err := controlprotocol.DecodeExecutorPollResponseV3(response.Body.Bytes(), controlprotocol.MaxExecutorDeliveryBytes); err != nil {
		t.Fatalf("idle poll response is not accepted by the node decoder: %v", err)
	}

	requireError(t, fixture.request(t, http.MethodDelete, "/v1/node-credentials/"+nodeCredentialID, operator.Token, ""),
		http.StatusForbidden, "forbidden")
	response = fixture.request(t, http.MethodDelete, "/v1/node-credentials/"+nodeCredentialID, fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var credentialRevocation struct {
		CredentialID string `json:"credential_id"`
		NodeID       string `json:"node_id"`
		Revoked      bool   `json:"revoked"`
	}
	decodeResponse(t, response, &credentialRevocation)
	if credentialRevocation.CredentialID != nodeCredentialID || credentialRevocation.NodeID != "node-1" || !credentialRevocation.Revoked {
		t.Fatalf("node credential revocation = %+v", credentialRevocation)
	}
	response = fixture.request(t, http.MethodDelete, "/v1/node-credentials/"+nodeCredentialID, fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	decodeResponse(t, response, &credentialRevocation)
	if credentialRevocation.Revoked {
		t.Fatal("exact node credential revocation retry reported a second mutation")
	}
	if _, err := fixture.store.AuthenticateNode(fixture.server.auth, nodeCredential.Credential); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("revoked node credential remained active: %v", err)
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

func TestControlPlaneAcceptsRealEvidencePublisherAndExportsCheckpoint(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-a"}`), http.StatusCreated)
	credential := enrollNodeThroughAPI(t, fixture, fixture.adminToken, "evidence-enrollment", "node-evidence", []string{"tenant-a"})
	private := fixture.evidenceKeys[credential.NodeID]
	log, err := evidence.Open(filepath.Join(t.TempDir(), "executor-evidence.bin"), private, credential.NodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "runtime-evidence",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: 1,
		GrantID: "grant-evidence", Outcome: evidence.Allowed,
	}); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "node-credential.json")
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, credentialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(fixture.server)
	defer tlsServer.Close()
	publisher, err := executoruplink.NewEvidencePublisher(executoruplink.EvidencePublisherConfig{
		BaseURL: tlsServer.URL, CredentialPath: credentialPath,
		ControllerInstanceID: fixture.server.auth.InstanceID(), PollInterval: time.Second,
		HTTPClient: tlsServer.Client(), Log: log, PrivateKey: private,
		SecureExecutor: true, SecureNodeID: credential.NodeID, ProtectedTransport: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		publisher.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	var inspection controlprotocol.ExecutorEvidenceInspectionV1
	for {
		response := fixture.request(t, http.MethodGet, "/v1/nodes/node-evidence/evidence", fixture.adminToken, "")
		requireStatus(t, response, http.StatusOK)
		decodeResponse(t, response, &inspection)
		if inspection.Status.Head != nil && inspection.Status.Head.Sequence == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("publisher did not advance controller checkpoint: %+v", inspection)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evidence publisher did not stop after cancellation")
	}

	response := fixture.request(t, http.MethodGet, "/v1/nodes/node-evidence/evidence/export", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var exported controlprotocol.ExecutorEvidenceExportV1
	decodeResponse(t, response, &exported)
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(
		exported, fixture.witnessPrivate.Public().(ed25519.PublicKey),
	); err != nil || exported.Statement.Status.Head == nil || exported.Statement.Status.Head.Sequence != 1 {
		t.Fatalf("real publisher export=%+v err=%v", exported, err)
	}
}

func TestEvidenceExportRetriesConcurrentStickyFinding(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-a"}`), http.StatusCreated)
	credential := enrollNodeThroughAPI(
		t, fixture, fixture.adminToken, "export-race-enrollment", "node-export-race", []string{"tenant-a"},
	)
	identity, err := fixture.store.AuthenticateNode(fixture.server.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	private := fixture.evidenceKeys[credential.NodeID]
	public := private.Public().(ed25519.PublicKey)
	poll, err := fixture.store.PollExecutorEvidence(
		fixture.server.auth,
		identity,
		controlprotocol.ExecutorEvidencePollRequestV1{
			ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
			ControllerInstanceID: fixture.server.auth.InstanceID(),
			ControlNodeID:        credential.NodeID,
			Stream:               controlprotocol.ExecutorEvidenceStreamV1,
			ReceiptNodeID:        credential.NodeID,
			ReceiptEpoch:         1,
			PublicKeySHA256:      controlprotocol.ExecutorEvidencePublicKeySHA256(public),
		},
		fixture.now.Add(30*time.Second),
		fixture.now.Add(3*time.Minute),
	)
	if err != nil || poll.Status.Head == nil {
		t.Fatalf("poll=%#v err=%v", poll, err)
	}
	base := *poll.Status.Head
	observed := base
	observed.Sequence = 1
	observed.ChainHash = "sha256:" + strings.Repeat("1", 64)
	claim, err := controlprotocol.NewExecutorEvidenceHeadClaimV1(
		fixture.server.auth.InstanceID(), credential.NodeID,
		base, observed, poll.Challenge, nil, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceHeadClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	report := controlprotocol.ExecutorEvidenceReportV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		HeadProof:       proof,
	}

	firstTimestamp := make(chan struct{})
	releaseTimestamp := make(chan struct{})
	var timestampCalls atomic.Int32
	fixture.server.now = func() time.Time {
		if timestampCalls.Add(1) == 1 {
			close(firstTimestamp)
			<-releaseTimestamp
			return fixture.now.Add(90 * time.Second)
		}
		return fixture.now.Add(2 * time.Minute)
	}
	request := httptest.NewRequest(
		http.MethodGet, "/v1/nodes/"+credential.NodeID+"/evidence/export", nil,
	)
	request.Header.Set("Authorization", "Bearer "+fixture.adminToken)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fixture.server.ServeHTTP(recorder, request)
		close(done)
	}()
	select {
	case <-firstTimestamp:
	case <-time.After(5 * time.Second):
		t.Fatal("evidence export did not reach timestamp construction")
	}

	findingAt := fixture.now.Add(time.Minute)
	applied, applyErr := fixture.store.ApplyExecutorEvidenceReport(
		fixture.server.auth, identity, report, findingAt,
	)
	close(releaseTimestamp)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("evidence export did not complete after concurrent finding")
	}
	if applyErr != nil || !applied.Applied ||
		applied.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected {
		t.Fatalf("concurrent finding response=%#v err=%v", applied, applyErr)
	}
	requireStatus(t, recorder, http.StatusOK)
	var exported controlprotocol.ExecutorEvidenceExportV1
	decodeResponse(t, recorder, &exported)
	if err := controlprotocol.VerifyExecutorEvidenceExportV1(
		exported, fixture.witnessPrivate.Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatal(err)
	}
	if timestampCalls.Load() < 2 ||
		exported.Statement.Status.State != controlprotocol.ExecutorEvidenceStatusEquivocationDetected ||
		exported.Statement.Status.Finding == nil ||
		exported.Statement.Status.Finding.ObservedHead != observed ||
		exported.Statement.Status.Finding.DetectedAt != findingAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("export omitted concurrent finding after %d attempts: %#v", timestampCalls.Load(), exported.Statement)
	}
}

func TestEvidenceExportReturnsRetryHintAfterRepeatedAdvancement(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-a"}`), http.StatusCreated)
	credential := enrollNodeThroughAPI(
		t, fixture, fixture.adminToken, "export-contention-enrollment", "node-export-contention",
		[]string{"tenant-a"},
	)
	identity, err := fixture.store.AuthenticateNode(fixture.server.auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	private := fixture.evidenceKeys[credential.NodeID]
	public := private.Public().(ed25519.PublicKey)
	log, err := evidence.Open(
		filepath.Join(t.TempDir(), "export-contention-evidence.bin"), private, credential.NodeID, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	pollRequest := controlprotocol.ExecutorEvidencePollRequestV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: fixture.server.auth.InstanceID(),
		ControlNodeID:        credential.NodeID,
		Stream:               controlprotocol.ExecutorEvidenceStreamV1,
		ReceiptNodeID:        credential.NodeID,
		ReceiptEpoch:         1,
		PublicKeySHA256:      controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
	timestampCalls := 0
	fixture.server.now = func() time.Time {
		timestampCalls++
		at := fixture.now.Add(time.Duration(timestampCalls) * time.Minute)
		localBase, err := log.CurrentHead()
		if err != nil {
			t.Fatal(err)
		}
		poll, err := fixture.store.PollExecutorEvidence(
			fixture.server.auth, identity, pollRequest, at, at.Add(time.Minute),
		)
		if err != nil || poll.Status.Head == nil ||
			poll.Status.Head.Sequence != localBase.Sequence ||
			poll.Status.Head.ChainHash != fmt.Sprintf("sha256:%x", localBase.ChainHash) {
			t.Fatalf("contention poll=%#v local=%#v err=%v", poll, localBase, err)
		}
		if _, err := log.Append(evidence.Event{
			Type: evidence.AdmissionAllow, TenantID: "tenant-a",
			RuntimeRef:    fmt.Sprintf("runtime-contention-%d", timestampCalls),
			CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy",
			Generation: uint64(timestampCalls), GrantID: "grant-contention", Outcome: evidence.Allowed,
		}); err != nil {
			t.Fatal(err)
		}
		delta, err := log.ExportDelta(evidence.Coordinate{
			Sequence: localBase.Sequence, ChainHash: localBase.ChainHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		reported := controlprotocol.ExecutorEvidenceHeadV1{
			Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: credential.NodeID,
			ReceiptEpoch: 1, Sequence: delta.Head.Sequence,
			ChainHash:       fmt.Sprintf("sha256:%x", delta.Head.ChainHash),
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
		}
		claim, err := controlprotocol.NewExecutorEvidenceHeadClaimV1(
			fixture.server.auth.InstanceID(), credential.NodeID,
			*poll.Status.Head, reported, poll.Challenge, delta.Frames, public,
		)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := controlprotocol.SignExecutorEvidenceHeadClaimV1(claim, private)
		if err != nil {
			t.Fatal(err)
		}
		encodedFrames := make([]string, len(delta.Frames))
		for index, frame := range delta.Frames {
			encodedFrames[index] = base64.StdEncoding.EncodeToString(frame)
		}
		applied, err := fixture.store.ApplyExecutorEvidenceReport(
			fixture.server.auth,
			identity,
			controlprotocol.ExecutorEvidenceReportV1{
				ProtocolVersion:    controlprotocol.ExecutorEvidenceProtocolV1,
				HeadProof:          proof,
				SignedFramesBase64: encodedFrames,
			},
			at.Add(500*time.Millisecond),
		)
		if err != nil || !applied.Applied {
			t.Fatalf("contention advancement=%#v err=%v", applied, err)
		}
		return at.Add(time.Second)
	}

	response := fixture.request(
		t, http.MethodGet, "/v1/nodes/"+credential.NodeID+"/evidence/export", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusConflict)
	if response.Header().Get("Retry-After") != strconv.Itoa(evidenceExportRetryAfter) ||
		timestampCalls != maxEvidenceExportAttempts {
		t.Fatalf("retry-after=%q timestamp calls=%d", response.Header().Get("Retry-After"), timestampCalls)
	}
	var problem struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	decodeResponse(t, response, &problem)
	if problem.Error != "conflict" || !strings.Contains(problem.Message, "retry") {
		t.Fatalf("retryable conflict=%#v", problem)
	}
}

func TestControlPlaneRejectsAmbiguousAndCrossTenantRequests(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-b"}`), http.StatusCreated)
	response := fixture.request(t, http.MethodPost, "/v1/operators", fixture.adminToken,
		`{"request_id":"operator-request-1","role":"tenant_operator","tenant_id":"tenant-a"}`)
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
	request = httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	request.Header.Set("Authorization", "bearer "+fixture.adminToken)
	recorder = httptest.NewRecorder()
	fixture.server.ServeHTTP(recorder, request)
	requireStatus(t, recorder, http.StatusOK)

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

func TestNodePaginationHonorsEncodedResponseBound(t *testing.T) {
	tenantIDs := make([]string, 128)
	for index := range tenantIDs {
		tenantIDs[index] = "t" + leftPad(index, 3) + "-" + strings.Repeat("x", 123)
	}
	capabilities := make([]string, 64)
	for index := range capabilities {
		capabilities[index] = "c" + leftPad(index, 2) + "-" + strings.Repeat("y", 124)
	}
	nodes := make([]controlstore.Node, 500)
	for index := range nodes {
		nodes[index] = controlstore.Node{
			ID: "node-" + leftPad(index, 4), TenantIDs: tenantIDs, Capabilities: capabilities,
			CreatedAt: "2026-07-13T20:00:00Z", Active: true,
		}
	}
	views, next, err := pageNodeViews(nodes, pageRequest{limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) == 0 || len(views) >= len(nodes) || next != views[len(views)-1].NodeID {
		t.Fatalf("bounded page count=%d next=%q", len(views), next)
	}
	raw, err := json.Marshal(nodeListResponse{Nodes: views, NextAfter: next})
	if err != nil || len(raw)+1 > maxResponseBytes {
		t.Fatalf("encoded node page bytes=%d error=%v", len(raw)+1, err)
	}
	second, _, err := pageNodeViews(nodes, pageRequest{after: next, limit: 500})
	if err != nil || len(second) == 0 || second[0].NodeID <= next {
		t.Fatalf("second page starts incorrectly: first=%+v error=%v", second, err)
	}
}

func TestControlServerLeaseLimitMatchesStore(t *testing.T) {
	fixture := newServerFixture(t)
	if _, err := New(Config{
		Store: fixture.store, Auth: fixture.server.auth, WitnessPrivateKey: fixture.witnessPrivate,
		LeaseDuration: controlstore.MaxDeliveryLease,
		MaxPoll:       1,
	}); err != nil {
		t.Fatalf("maximum store lease rejected: %v", err)
	}
	if _, err := New(Config{
		Store: fixture.store, Auth: fixture.server.auth, WitnessPrivateKey: fixture.witnessPrivate,
		LeaseDuration: controlstore.MaxDeliveryLease + time.Nanosecond,
		MaxPoll:       1,
	}); err == nil {
		t.Fatal("lease above the store maximum was accepted")
	}
	if _, err := New(Config{
		Store: fixture.store, Auth: fixture.server.auth, LeaseDuration: time.Minute, MaxPoll: 1,
	}); err == nil {
		t.Fatal("missing evidence witness key was accepted")
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

func leftPad(value, width int) string {
	text := fmt.Sprint(value)
	return strings.Repeat("0", width-len(text)) + text
}
