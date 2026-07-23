package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func TestInteractionHTTPWorkflowKeepsSigningOffControl(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken,
		`{"tenant_id":"tenant-a"}`), http.StatusCreated)
	response := fixture.request(t, http.MethodPost, "/v1/enrollments", fixture.adminToken,
		`{"request_id":"interaction-enrollment","node_id":"node-1","tenant_ids":["tenant-a"],"ttl_seconds":900}`)
	requireStatus(t, response, http.StatusCreated)
	var enrollment testEnrollmentCapability
	decodeResponse(t, response, &enrollment)
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		enrollmentExchangeBody(t, enrollment, "interaction-exchange", fixture.evidenceIdentityProof(t, enrollment)))
	requireStatus(t, response, http.StatusCreated)
	var credential controlauth.NodeCredentialFile
	decodeResponse(t, response, &credential)

	interaction := controlplaneInteraction(fixture.now)
	batch := controlprotocol.InteractionRequestBatchV1{
		SchemaVersion: controlprotocol.InteractionBatchSchemaV1,
		NodeID:        "node-1", Interactions: []controlprotocol.InteractionRequestV1{interaction},
	}
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/interactions", fixture.adminToken, mustJSON(t, batch)),
		http.StatusUnauthorized, "unauthorized")
	response = fixture.request(t, http.MethodPost, "/executor-uplink/interactions", credential.Credential, mustJSON(t, batch))
	requireStatus(t, response, http.StatusOK)
	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/interactions?limit=1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var page interactionPage
	decodeResponse(t, response, &page)
	if len(page.Interactions) != 1 || page.Interactions[0].InteractionID != interaction.InteractionID ||
		page.Interactions[0].State != controlstore.InteractionOpen {
		t.Fatalf("interaction page = %+v", page)
	}
	response = fixture.request(t, http.MethodGet,
		"/v1/tenants/tenant-a/interactions/"+interaction.InteractionID, fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)

	body := []byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"primary"}`)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := interactionpermit.Statement{
		SchemaVersion: interactionpermit.SchemaV1,
		NodeID:        interaction.NodeID, TenantID: interaction.TenantID, InstanceID: interaction.InstanceID,
		RuntimeRef: interaction.RuntimeRef, GrantID: interaction.GrantID, Generation: interaction.Generation,
		CapsuleDigest: interaction.CapsuleDigest, PolicyDigest: interaction.PolicyDigest,
		InteractionID: interaction.InteractionID, RequestDigest: interaction.RequestDigest,
		ResponseDigest: interactionpermit.ResponseDigest(body), ResponseBytes: int64(len(body)),
		NotBefore: fixture.now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: fixture.now.Add(time.Hour).Format(time.RFC3339),
	}
	payload, _ := json.Marshal(statement)
	envelope, err := dsse.Sign(interactionpermit.PayloadType, payload, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := dsse.Marshal(envelope)
	submit := mustJSON(t, interactionResponseSubmit{
		PermitBase64:   base64.StdEncoding.EncodeToString(permit),
		ResponseBase64: base64.StdEncoding.EncodeToString(body),
	})
	response = fixture.request(t, http.MethodPost,
		"/v1/tenants/tenant-a/interactions/"+interaction.InteractionID+"/response", fixture.adminToken, submit)
	requireStatus(t, response, http.StatusAccepted)
	var queued controlstore.Interaction
	decodeResponse(t, response, &queued)
	if queued.State != controlstore.InteractionResponseQueued || queued.ResponseKeyID != "tenant-task" {
		t.Fatalf("queued interaction = %+v", queued)
	}
	if strings.Contains(response.Body.String(), `"choice"`) ||
		strings.Contains(response.Body.String(), "response_base64") {
		t.Fatalf("operator response leaked courier: %s", response.Body.String())
	}

	poll := controlprotocol.InteractionResponsePollRequestV1{
		SchemaVersion: controlprotocol.InteractionPollSchemaV1,
		NodeID:        "node-1", Limit: 8,
	}
	response = fixture.request(t, http.MethodPost, "/executor-uplink/interactions/responses/poll",
		credential.Credential, mustJSON(t, poll))
	requireStatus(t, response, http.StatusOK)
	var deliveries controlprotocol.InteractionResponsePollResponseV1
	decodeResponse(t, response, &deliveries)
	if len(deliveries.Deliveries) != 1 ||
		deliveries.Deliveries[0].InteractionID != interaction.InteractionID {
		t.Fatalf("interaction deliveries = %+v", deliveries)
	}
	ack := controlprotocol.InteractionResponseAckV1{
		SchemaVersion: controlprotocol.InteractionAckSchemaV1,
		InteractionID: interaction.InteractionID, PermitDigest: dsse.Digest(permit),
	}
	response = fixture.request(t, http.MethodPost, "/executor-uplink/interactions/responses/ack",
		credential.Credential, mustJSON(t, ack))
	requireStatus(t, response, http.StatusOK)
	response = fixture.request(t, http.MethodGet,
		"/v1/tenants/tenant-a/interactions/"+interaction.InteractionID, fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var resolved controlstore.Interaction
	decodeResponse(t, response, &resolved)
	if resolved.State != controlstore.InteractionResolved || resolved.ResolvedAt == "" {
		t.Fatalf("resolved interaction = %+v", resolved)
	}

	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/interactions?limit=101",
		fixture.adminToken, ""), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/interactions?after=missing",
		fixture.adminToken, ""), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodPost,
		"/v1/tenants/tenant-a/interactions/"+interaction.InteractionID+"/response",
		fixture.adminToken, `{"permit_base64":"!!!!","response_base64":"!!!!"}`),
		http.StatusBadRequest, "invalid_request")
}

func controlplaneInteraction(now time.Time) controlprotocol.InteractionRequestV1 {
	grantID := "grant-" + strings.Repeat("b", 64)
	key := "question-1"
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + key))
	value := controlprotocol.InteractionRequestV1{
		SchemaVersion:  controlprotocol.InteractionRequestSchemaV1,
		InteractionID:  "interaction-" + hex.EncodeToString(sum[:]),
		IdempotencyKey: key, Source: "agent", TenantID: "tenant-a", NodeID: "node-1",
		InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("d", 64),
		Kind:          "decision", Title: "Choose source",
		Prompt:  "Which source should the research agent use?",
		Options: []string{"primary", "secondary"}, AllowText: true,
		ObservedAt: now.Format(time.RFC3339), AcceptedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
	}
	value.RequestDigest = controlprotocol.InteractionRequestDigest(value)
	return value
}
