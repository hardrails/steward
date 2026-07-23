package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func TestInteractionCourierIsDurableBoundedAndOffAuthority(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	request := storedInteractionRequest(fixture.now.Add(2 * time.Minute))
	batch := controlprotocol.InteractionRequestBatchV1{
		SchemaVersion: controlprotocol.InteractionBatchSchemaV1,
		NodeID:        "node-1",
		Interactions:  []controlprotocol.InteractionRequestV1{request},
	}

	applied, err := fixture.store.RetainInteractions(node, batch, fixture.now.Add(3*time.Minute))
	if err != nil || applied != 1 {
		t.Fatalf("retain interactions = (%d, %v)", applied, err)
	}
	if applied, err = fixture.store.RetainInteractions(node, batch, fixture.now.Add(4*time.Minute)); err != nil || applied != 0 {
		t.Fatalf("replay interactions = (%d, %v)", applied, err)
	}
	listed, err := fixture.store.ListInteractions(fixture.admin, "tenant-a", fixture.now.Add(4*time.Minute))
	if err != nil || len(listed) != 1 || listed[0].State != InteractionOpen ||
		listed[0].Prompt != request.Prompt {
		t.Fatalf("listed interactions = (%+v, %v)", listed, err)
	}

	body := []byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"primary"}`)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit := signInteractionResponse(t, interactionStatement(request, body, fixture.now.Add(4*time.Minute)), private)
	resolved, created, err := fixture.store.SubmitInteractionResponse(
		fixture.admin,
		InteractionResponseInput{
			TenantID: "tenant-a", InteractionID: request.InteractionID,
			Permit: permit, Response: body,
		},
		fixture.now.Add(4*time.Minute),
	)
	if err != nil || !created || resolved.State != InteractionResponseQueued ||
		resolved.PermitDigest != dsse.Digest(permit) || resolved.ResponseBytes != int64(len(body)) {
		t.Fatalf("submit response = (%+v, %v, %v)", resolved, created, err)
	}
	public, _ := json.Marshal(resolved)
	if strings.Contains(string(public), `"choice"`) || strings.Contains(string(public), "permit_base64") ||
		strings.Contains(string(public), "response_base64") {
		t.Fatalf("operator projection leaked response courier: %s", public)
	}
	deliveries, err := fixture.store.PollInteractionResponses(node, fixture.now.Add(5*time.Minute), 8)
	if err != nil || len(deliveries) != 1 || deliveries[0].InteractionID != request.InteractionID ||
		deliveries[0].PermitBase64 == "" || deliveries[0].ResponseBase64 == "" {
		t.Fatalf("poll interaction responses = (%+v, %v)", deliveries, err)
	}
	appliedAck, err := fixture.store.AckInteractionResponse(node, controlprotocol.InteractionResponseAckV1{
		SchemaVersion: controlprotocol.InteractionAckSchemaV1,
		InteractionID: request.InteractionID,
		PermitDigest:  dsse.Digest(permit),
	}, fixture.now.Add(6*time.Minute))
	if err != nil || !appliedAck {
		t.Fatalf("ack response = (%v, %v)", appliedAck, err)
	}
	if appliedAck, err = fixture.store.AckInteractionResponse(node, controlprotocol.InteractionResponseAckV1{
		SchemaVersion: controlprotocol.InteractionAckSchemaV1,
		InteractionID: request.InteractionID,
		PermitDigest:  dsse.Digest(permit),
	}, fixture.now.Add(7*time.Minute)); err != nil || appliedAck {
		t.Fatalf("replay ack = (%v, %v)", appliedAck, err)
	}
	got, found, err := fixture.store.GetInteraction(
		fixture.admin, "tenant-a", request.InteractionID, fixture.now.Add(7*time.Minute),
	)
	if err != nil || !found || got.State != InteractionResolved || got.ResolvedAt == "" {
		t.Fatalf("get resolved interaction = (%+v, %v, %v)", got, found, err)
	}
	reopenControlFixture(t, &fixture)
	got, found, err = fixture.store.GetInteraction(
		fixture.admin, "tenant-a", request.InteractionID, fixture.now.Add(8*time.Minute),
	)
	if err != nil || !found || got.State != InteractionResolved ||
		got.PermitDigest != dsse.Digest(permit) {
		t.Fatalf("reopened interaction = (%+v, %v, %v)", got, found, err)
	}
}

func TestInteractionCourierRejectsConflictsExpiryAndWrongNode(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	request := storedInteractionRequest(fixture.now.Add(2 * time.Minute))
	batch := controlprotocol.InteractionRequestBatchV1{
		SchemaVersion: controlprotocol.InteractionBatchSchemaV1,
		NodeID:        "node-1", Interactions: []controlprotocol.InteractionRequestV1{request},
	}
	if _, err := fixture.store.RetainInteractions(node, batch, fixture.now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	changed := batch
	changed.Interactions = append([]controlprotocol.InteractionRequestV1(nil), batch.Interactions...)
	changed.Interactions[0].Prompt = "changed"
	changed.Interactions[0].RequestDigest = controlprotocol.InteractionRequestDigest(changed.Interactions[0])
	if _, err := fixture.store.RetainInteractions(node, changed, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	wrongNode := node
	wrongNode.NodeID = "node-2"
	if _, err := fixture.store.RetainInteractions(wrongNode, batch, fixture.now.Add(4*time.Minute)); err == nil {
		t.Fatal("wrong node retained interaction")
	}

	body := []byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"primary"}`)
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	statement := interactionStatement(request, body, fixture.now.Add(4*time.Minute))
	statement.RequestDigest = "sha256:" + strings.Repeat("9", 64)
	permit := signInteractionResponse(t, statement, private)
	if _, _, err := fixture.store.SubmitInteractionResponse(fixture.admin, InteractionResponseInput{
		TenantID: "tenant-a", InteractionID: request.InteractionID, Permit: permit, Response: body,
	}, fixture.now.Add(4*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched permit error = %v", err)
	}
	if _, _, err := fixture.store.SubmitInteractionResponse(fixture.admin, InteractionResponseInput{
		TenantID: "tenant-a", InteractionID: request.InteractionID, Permit: permit, Response: body,
	}, fixture.now.Add(3*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired permit error = %v", err)
	}
}

func TestInteractionSnapshotAndWALVersionFence(t *testing.T) {
	current, limits := populatedControlState(t)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != stateFormatWriteVersion || snapshot.Interactions == nil {
		t.Fatalf("interaction snapshot fence = (%d, nil=%v)", snapshot.Version, snapshot.Interactions == nil)
	}
	snapshot.Version = stateFormatWorkroomVersion
	snapshot.Interactions = nil
	legacy, _ := json.Marshal(snapshot)
	if _, err := decodeState(legacy, limits.MaxStateBytes); err != nil {
		t.Fatalf("legacy snapshot migration failed: %v", err)
	}
}

func storedInteractionRequest(now time.Time) controlprotocol.InteractionRequestV1 {
	grantID := "grant-" + strings.Repeat("b", 64)
	request := controlprotocol.InteractionRequestV1{
		SchemaVersion:  controlprotocol.InteractionRequestSchemaV1,
		IdempotencyKey: "question-1", Source: "agent",
		TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1", Generation: 7,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("d", 64),
		Kind:          "decision", Title: "Choose source", Prompt: "Which source should the research agent use?",
		Options: []string{"primary", "secondary"}, AllowText: true,
		ObservedAt: now.Format(time.RFC3339), AcceptedAt: now.Add(time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(2 * time.Hour).Format(time.RFC3339),
	}
	request.InteractionID = interactionTestID(grantID, request.IdempotencyKey)
	request.RequestDigest = controlprotocol.InteractionRequestDigest(request)
	return request
}

func interactionStatement(
	request controlprotocol.InteractionRequestV1,
	body []byte,
	now time.Time,
) interactionpermit.Statement {
	return interactionpermit.Statement{
		SchemaVersion: interactionpermit.SchemaV1,
		NodeID:        request.NodeID, TenantID: request.TenantID, InstanceID: request.InstanceID,
		RuntimeRef: request.RuntimeRef, GrantID: request.GrantID, Generation: request.Generation,
		CapsuleDigest: request.CapsuleDigest, PolicyDigest: request.PolicyDigest,
		InteractionID: request.InteractionID, RequestDigest: request.RequestDigest,
		ResponseDigest: interactionpermit.ResponseDigest(body), ResponseBytes: int64(len(body)),
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
}

func signInteractionResponse(t *testing.T, statement interactionpermit.Statement, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(interactionpermit.PayloadType, payload, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func interactionTestID(grantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + idempotencyKey))
	return "interaction-" + hex.EncodeToString(sum[:])
}
