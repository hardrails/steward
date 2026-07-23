package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func TestControlInteractionCommandsListShowAndSignResponse(t *testing.T) {
	now := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	previousNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousNow })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "task.private.pem")
	writeAgentPrivateKey(t, keyPath, private)
	tokenPath := filepath.Join(t.TempDir(), "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	interaction := cliInteraction(now)
	var submitted bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/tenants/tenant-a/interactions":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"interactions": []controlstore.Interaction{interaction},
			})
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v1/tenants/tenant-a/interactions/"+interaction.InteractionID:
			_ = json.NewEncoder(writer).Encode(interaction)
		case request.Method == http.MethodPost &&
			request.URL.Path == "/v1/tenants/tenant-a/interactions/"+interaction.InteractionID+"/response":
			var courier struct {
				PermitBase64   string `json:"permit_base64"`
				ResponseBase64 string `json:"response_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&courier); err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			permit, _ := base64.StdEncoding.DecodeString(courier.PermitBase64)
			response, _ := base64.StdEncoding.DecodeString(courier.ResponseBase64)
			var body interactionpermit.ResponseBody
			if err := json.Unmarshal(response, &body); err != nil ||
				body.Choice != "primary" || body.Text != "Use the official filing." {
				t.Errorf("response body = %+v err=%v", body, err)
			}
			verified, err := interactionpermit.Verify(
				permit, map[string]ed25519.PublicKey{"tenant-task": public}, now,
				interactionpermit.MaxValidity,
			)
			if err != nil || verified.Statement.InteractionID != interaction.InteractionID ||
				verified.Statement.RequestDigest != interaction.RequestDigest ||
				verified.Statement.ResponseDigest != interactionpermit.ResponseDigest(response) {
				t.Errorf("verified interaction response = %+v err=%v", verified, err)
			}
			submitted = true
			queued := interaction
			queued.State = controlstore.InteractionResponseQueued
			queued.ResponseKeyID = "tenant-task"
			queued.PermitDigest = dsse.Digest(permit)
			queued.ResponseDigest = interactionpermit.ResponseDigest(response)
			queued.ResponseBytes = int64(len(response))
			queued.ResponseQueuedAt = now.Format(time.RFC3339Nano)
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(queued)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	common := []string{"-tenant-id", "tenant-a", "-control-url", server.URL, "-token-file", tokenPath}
	var output bytes.Buffer
	if err := controlInteractionList(append(append([]string{}, common...), "-limit", "1"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), interaction.InteractionID) {
		t.Fatalf("list output = %s", output.String())
	}
	output.Reset()
	if err := controlInteractionShow(append(append([]string{}, common...), "-interaction-id", interaction.InteractionID), &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	respond := append(append([]string{}, common...),
		"-interaction-id", interaction.InteractionID,
		"-choice", "primary", "-text", "Use the official filing.",
		"-key", keyPath, "-key-id", "tenant-task")
	if err := controlInteractionRespond(respond, &output); err != nil {
		t.Fatal(err)
	}
	if !submitted || !strings.Contains(output.String(), controlstore.InteractionResponseQueued) {
		t.Fatalf("response submitted=%v output=%s", submitted, output.String())
	}
}

func TestControlInteractionCommandsRejectIncompleteOrUnsafeInput(t *testing.T) {
	for name, call := range map[string]func() error{
		"list": func() error { return controlInteractionList(nil, &bytes.Buffer{}) },
		"show": func() error { return controlInteractionShow(nil, &bytes.Buffer{}) },
		"respond": func() error {
			return controlInteractionRespond([]string{
				"-tenant-id", "tenant-a", "-interaction-id", "interaction-a",
				"-choice", "yes", "-key", "key.pem", "-key-id", "key",
				"-valid-for", "25h",
			}, &bytes.Buffer{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("invalid interaction command input was accepted")
			}
		})
	}
}

func cliInteraction(now time.Time) controlstore.Interaction {
	grantID := "grant-" + strings.Repeat("b", 64)
	key := "question-1"
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
		ObservedAt: now.Format(time.RFC3339), AcceptedAt: now.Format(time.RFC3339Nano),
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
		Options: request.Options, AllowText: request.AllowText,
		ObservedAt: request.ObservedAt, AcceptedAt: request.AcceptedAt,
		ExpiresAt: request.ExpiresAt, RequestDigest: request.RequestDigest,
		State: controlstore.InteractionOpen, ReceivedAt: now.Format(time.RFC3339Nano),
	}
}
