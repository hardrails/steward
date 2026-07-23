package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func TestInteractionClientValidatesPagesLookupsAndResponseCourier(t *testing.T) {
	interaction := controlClientInteraction()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/tenants/tenant-a/interactions":
			if request.URL.Query().Get("after") != "before" || request.URL.Query().Get("limit") != "1" {
				t.Errorf("unexpected interaction query: %s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(InteractionList{
				Interactions: []controlstore.Interaction{interaction},
				NextAfter:    interaction.InteractionID,
			})
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v1/tenants/tenant-a/interactions/"+interaction.InteractionID:
			_ = json.NewEncoder(writer).Encode(interaction)
		case request.Method == http.MethodPost &&
			request.URL.Path == "/v1/tenants/tenant-a/interactions/"+interaction.InteractionID+"/response":
			var body struct {
				PermitBase64   string `json:"permit_base64"`
				ResponseBase64 string `json:"response_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil ||
				body.PermitBase64 == "" || body.ResponseBase64 == "" {
				t.Errorf("invalid interaction courier: %+v err=%v", body, err)
			}
			queued := interaction
			queued.State = controlstore.InteractionResponseQueued
			queued.ResponseKeyID = "tenant-task"
			queued.PermitDigest = "sha256:" + strings.Repeat("e", 64)
			queued.ResponseDigest = "sha256:" + strings.Repeat("f", 64)
			queued.ResponseBytes = 2
			queued.ResponseQueuedAt = "2026-07-23T14:01:00Z"
			_ = json.NewEncoder(writer).Encode(queued)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListInteractions(context.Background(), "tenant-a", "before", 1)
	if err != nil || len(page.Interactions) != 1 || page.NextAfter != interaction.InteractionID {
		t.Fatalf("interaction page = (%+v, %v)", page, err)
	}
	got, err := client.GetInteraction(context.Background(), "tenant-a", interaction.InteractionID)
	if err != nil || got.InteractionID != interaction.InteractionID {
		t.Fatalf("interaction lookup = (%+v, %v)", got, err)
	}
	queued, err := client.SubmitInteractionResponse(
		context.Background(), "tenant-a", interaction.InteractionID, []byte("permit"), []byte("{}"),
	)
	if err != nil || queued.State != controlstore.InteractionResponseQueued {
		t.Fatalf("interaction response = (%+v, %v)", queued, err)
	}
}

func TestInteractionClientRejectsInvalidInputAndServerProjection(t *testing.T) {
	invalid := controlClientInteraction()
	invalid.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(InteractionList{
			Interactions: []controlstore.Interaction{invalid},
		})
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListInteractions(context.Background(), "tenant-a", "", 1); err == nil {
		t.Fatal("client accepted invalid interaction projection")
	}
	if _, err := client.ListInteractions(context.Background(), "-tenant", "", 1); err == nil {
		t.Fatal("client accepted invalid tenant")
	}
	if _, err := client.GetInteraction(context.Background(), "tenant-a", "bad id"); err == nil {
		t.Fatal("client accepted invalid interaction ID")
	}
	if _, err := client.SubmitInteractionResponse(
		context.Background(), "tenant-a", controlClientInteraction().InteractionID, nil, []byte("{}"),
	); err == nil {
		t.Fatal("client accepted empty response permit")
	}
}

func TestInteractionClientRejectsNoncanonicalPagesAndCourierResults(t *testing.T) {
	first := controlClientInteractionAt("question-1", time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC))
	second := controlClientInteractionAt("question-2", time.Date(2026, 7, 23, 14, 1, 0, 0, time.UTC))
	mode := "nil-page"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch mode {
		case "nil-page":
			_ = json.NewEncoder(writer).Encode(InteractionList{})
		case "oversized-page":
			_ = json.NewEncoder(writer).Encode(InteractionList{
				Interactions: []controlstore.Interaction{first, second},
			})
		case "noncanonical-page":
			_ = json.NewEncoder(writer).Encode(InteractionList{
				Interactions: []controlstore.Interaction{first, second},
			})
		case "bad-cursor":
			_ = json.NewEncoder(writer).Encode(InteractionList{
				Interactions: []controlstore.Interaction{second},
				NextAfter:    first.InteractionID,
			})
		case "wrong-lookup":
			changed := first
			changed.InteractionID = second.InteractionID
			_ = json.NewEncoder(writer).Encode(changed)
		case "wrong-courier-result":
			changed := first
			changed.TenantID = "tenant-b"
			_ = json.NewEncoder(writer).Encode(changed)
		default:
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []string{"nil-page", "oversized-page", "noncanonical-page", "bad-cursor"} {
		mode = selected
		limit := 1
		if selected == "noncanonical-page" {
			limit = 2
		}
		if _, err := client.ListInteractions(context.Background(), "tenant-a", "", limit); err == nil {
			t.Fatalf("%s interaction page was accepted", selected)
		}
	}
	mode = "wrong-lookup"
	if _, err := client.GetInteraction(context.Background(), "tenant-a", first.InteractionID); err == nil {
		t.Fatal("lookup accepted a mismatched interaction identity")
	}
	mode = "wrong-courier-result"
	if _, err := client.SubmitInteractionResponse(
		context.Background(), "tenant-a", first.InteractionID, []byte("permit"), []byte("{}"),
	); err == nil {
		t.Fatal("courier accepted a cross-tenant result")
	}
	if _, err := client.SubmitInteractionResponse(
		context.Background(), "tenant-a", first.InteractionID,
		make([]byte, interactionpermit.MaxEnvelopeBytes+1), []byte("{}"),
	); err == nil {
		t.Fatal("courier accepted an oversized response permit")
	}
	if _, err := client.SubmitInteractionResponse(
		context.Background(), "tenant-a", first.InteractionID,
		[]byte("permit"), make([]byte, interactionpermit.MaxResponseBytes+1),
	); err == nil {
		t.Fatal("courier accepted an oversized response body")
	}
}

func controlClientInteraction() controlstore.Interaction {
	return controlClientInteractionAt(
		"question-1",
		time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC),
	)
}

func controlClientInteractionAt(key string, now time.Time) controlstore.Interaction {
	grantID := "grant-" + strings.Repeat("b", 64)
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + key))
	request := controlprotocol.InteractionRequestV1{
		SchemaVersion:  controlprotocol.InteractionRequestSchemaV1,
		InteractionID:  "interaction-" + hex.EncodeToString(sum[:]),
		IdempotencyKey: key, Source: "agent", TenantID: "tenant-a", NodeID: "node-1",
		InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("d", 64),
		Kind:          "decision", Title: "Choose source", Prompt: "Which source should be used?",
		Options: []string{"primary", "secondary"}, AllowText: true,
		ObservedAt: now.Format(time.RFC3339), AcceptedAt: now.Add(time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	request.RequestDigest = controlprotocol.InteractionRequestDigest(request)
	return controlstore.Interaction{
		SchemaVersion: request.SchemaVersion, InteractionID: request.InteractionID,
		IdempotencyKey: request.IdempotencyKey, Source: request.Source,
		TenantID: request.TenantID, NodeID: request.NodeID, InstanceID: request.InstanceID,
		Generation: request.Generation, RuntimeRef: request.RuntimeRef, GrantID: request.GrantID,
		CapsuleDigest: request.CapsuleDigest, PolicyDigest: request.PolicyDigest,
		Kind: request.Kind, Title: request.Title, Prompt: request.Prompt,
		Options: request.Options, AllowText: request.AllowText, TaskID: request.TaskID, RunID: request.RunID,
		ObservedAt: request.ObservedAt, AcceptedAt: request.AcceptedAt, ExpiresAt: request.ExpiresAt,
		RequestDigest: request.RequestDigest, State: controlstore.InteractionOpen,
		ReceivedAt: now.Add(2 * time.Second).Format(time.RFC3339Nano),
	}
}
