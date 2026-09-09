package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

func TestControlInteractionVerifyResponseUsesNativeSignerOffline(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	request := issuerResponse(f)
	permit, err := issuer.issueResponse(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := base64.StdEncoding.DecodeString(request.ResponseBase64)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	permitPath, responsePath := filepath.Join(directory, "permit"), filepath.Join(directory, "response")
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(permitPath, permit)
	write(responsePath, response)
	args := []string{"interaction", "verify-response", "-permit-file", permitPath,
		"-response-file", responsePath, "-public-key", f.publicPath, "-key-id", f.keyID,
		"-at", f.now.Format(time.RFC3339), "-max-validity", config.Validity.String()}
	// An offline verifier must not even parse an ambient context or acquire a
	// Control token/private key. This path is deliberately invalid for context IO.
	t.Setenv("STEWARD_CONTEXT_FILE", "not-an-absolute-path")
	var output bytes.Buffer
	if err := controlCommand(args, &output); err != nil {
		t.Fatal(err)
	}
	var value struct {
		Valid          bool                        `json:"valid"`
		EvaluatedAt    string                      `json:"evaluated_at"`
		KeyID          string                      `json:"key_id"`
		EnvelopeDigest string                      `json:"envelope_digest"`
		Statement      interactionpermit.Statement `json:"statement"`
	}
	if err := json.Unmarshal(output.Bytes(), &value); err != nil || !value.Valid ||
		value.EvaluatedAt != f.now.Format(time.RFC3339) || value.KeyID != f.keyID ||
		value.EnvelopeDigest != dsse.Digest(permit) || value.Statement.NodeID != request.Interaction.NodeID ||
		value.Statement.InteractionID != request.Interaction.InteractionID ||
		value.Statement.RequestDigest != request.Interaction.RequestDigest ||
		value.Statement.ResponseDigest != interactionpermit.ResponseDigest(response) ||
		value.Statement.ResponseBytes != int64(len(response)) {
		t.Fatalf("verification projection differs: %v", err)
	}
	if bytes.Contains(output.Bytes(), []byte("Only read")) {
		t.Fatal("verification output exposed the answer")
	}
	for _, test := range []struct {
		name string
		flag string
		text string
	}{
		{"wrong-key-id", "-key-id", "untrusted"},
		{"wrong-public-key", "-public-key", permitPath},
		{"expired", "-at", f.now.Add(time.Hour).Format(time.RFC3339)},
		{"not-yet-valid", "-at", f.now.Add(-time.Hour).Format(time.RFC3339)},
		{"fractional-time", "-at", f.now.Add(time.Millisecond).Format(time.RFC3339Nano)},
		{"too-long", "-max-validity", "1s"},
		{"zero-validity", "-max-validity", "0s"},
		{"oversized-validity", "-max-validity", "25h"},
		{"missing-permit", "-permit-file", filepath.Join(directory, "missing")},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := append([]string(nil), args...)
			for index := range changed {
				if changed[index] == test.flag {
					changed[index+1] = test.text
					break
				}
			}
			var failure bytes.Buffer
			if err := controlCommand(changed, &failure); err == nil || failure.Len() != 0 {
				t.Fatalf("unverified answer produced output: %v", err)
			}
		})
	}
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"different-answer", bytes.ReplaceAll(response, []byte("Only read"), []byte("Send mail"))},
		{"normalized-unicode", bytes.ReplaceAll(response, []byte("cafe\u0301"), []byte("caf\u00e9"))},
		{"added-whitespace", append(append([]byte(nil), response...), '\n')},
		{"empty", nil},
		{"oversized", bytes.Repeat([]byte("a"), interactionpermit.MaxResponseBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if bytes.Equal(test.body, response) {
				t.Fatal("test did not change the original response")
			}
			write(responsePath, test.body)
			var failure bytes.Buffer
			if err := controlCommand(args, &failure); err == nil || failure.Len() != 0 {
				t.Fatalf("changed response produced output: %v", err)
			}
		})
	}
	write(responsePath, response)
	envelope, err := dsse.Parse(permit)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
	tampered, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{nil, []byte("{}"), tampered, bytes.Repeat([]byte("a"), interactionpermit.MaxEnvelopeBytes+1)} {
		write(permitPath, body)
		var failure bytes.Buffer
		if err := controlCommand(args, &failure); err == nil || failure.Len() != 0 {
			t.Fatalf("invalid permit produced output: %v", err)
		}
	}
	write(permitPath, permit)
	if err := os.Chmod(responsePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := controlCommand(args, &bytes.Buffer{}); err == nil {
		t.Fatal("public answer file accepted")
	}
}

func TestControlInteractionVerifyResponseRejectsIncompleteAndNetworkArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"-key", "private.pem"}, {"-control-url", "https://invalid.example"}, {"extra"}} {
		var output bytes.Buffer
		if err := controlInteractionVerifyResponse(args, &output); err == nil || output.Len() != 0 {
			t.Fatalf("invalid verification arguments accepted: %v", err)
		}
	}
	if !strings.Contains(controlUsageError().Error(), "verify-response") {
		t.Fatal("verification command missing from usage")
	}
}
