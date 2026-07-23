package controlprotocol

import (
	"strings"
	"testing"
	"time"
)

func TestInteractionRequestValidatesExactDigestAndBatchIdentity(t *testing.T) {
	now := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	request := validInteractionRequest(now)
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	batch := InteractionRequestBatchV1{
		SchemaVersion: InteractionBatchSchemaV1,
		NodeID:        request.NodeID,
		Interactions:  []InteractionRequestV1{request},
	}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}

	changed := request
	changed.Prompt = "Different question"
	if err := changed.Validate(); err == nil {
		t.Fatal("request digest did not bind prompt")
	}
	duplicate := batch
	duplicate.Interactions = append(duplicate.Interactions, request)
	if err := duplicate.Validate(); err == nil {
		t.Fatal("batch accepted duplicate interaction")
	}
	wrongNode := batch
	wrongNode.NodeID = "node-2"
	if err := wrongNode.Validate(); err == nil {
		t.Fatal("batch accepted cross-node interaction")
	}
}

func TestInteractionRequestRequiresBoundedResponsePath(t *testing.T) {
	now := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	request := validInteractionRequest(now)
	request.Options = nil
	request.AllowText = false
	request.RequestDigest = InteractionRequestDigest(request)
	if err := request.Validate(); err == nil {
		t.Fatal("request accepted no response path")
	}

	request.Kind = "decision"
	request.Options = []string{"only-one"}
	request.RequestDigest = InteractionRequestDigest(request)
	if err := request.Validate(); err == nil {
		t.Fatal("decision accepted fewer than two choices")
	}
}

func validInteractionRequest(now time.Time) InteractionRequestV1 {
	grantID := "grant-" + strings.Repeat("b", 64)
	request := InteractionRequestV1{
		SchemaVersion:  InteractionRequestSchemaV1,
		IdempotencyKey: "question-1",
		Source:         "agent",
		TenantID:       "tenant-a",
		NodeID:         "node-1",
		InstanceID:     "agent-1",
		Generation:     7,
		RuntimeRef:     "executor-" + strings.Repeat("a", 64),
		GrantID:        grantID,
		CapsuleDigest:  "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:   "sha256:" + strings.Repeat("d", 64),
		Kind:           "decision",
		Title:          "Choose source",
		Prompt:         "Which source should the research agent use?",
		Options:        []string{"primary", "secondary"},
		AllowText:      true,
		TaskID:         "task-1",
		RunID:          "run-1",
		ObservedAt:     now.Format(time.RFC3339),
		AcceptedAt:     now.Add(time.Second).Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(time.Hour).Format(time.RFC3339),
	}
	request.InteractionID = interactionRequestID(grantID, request.IdempotencyKey)
	request.RequestDigest = InteractionRequestDigest(request)
	return request
}
