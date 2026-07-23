package interactionpermit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestInspectAndVerifyExactInteractionResponse(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"choice":"approve","text":""}`)
	statement := validStatement(now, body)
	raw := signStatement(t, statement, "tenant-task", private)

	inspected, err := InspectUnverified(raw)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Statement != statement || inspected.KeyID != "tenant-task" ||
		inspected.EnvelopeDigest != dsse.Digest(raw) {
		t.Fatalf("inspected = %+v", inspected)
	}
	verified, err := Verify(raw, map[string]ed25519.PublicKey{"tenant-task": public}, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Statement.ResponseDigest != ResponseDigest(body) || verified.KeyID != "tenant-task" {
		t.Fatalf("verified = %+v", verified)
	}
}

func TestInteractionResponsePermitFailsClosed(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"choice":"approve","text":""}`)
	base := validStatement(now, body)

	tests := map[string]func(*Statement){
		"schema":          func(value *Statement) { value.SchemaVersion = "other" },
		"node":            func(value *Statement) { value.NodeID = "" },
		"runtime":         func(value *Statement) { value.RuntimeRef = "executor-invalid" },
		"grant":           func(value *Statement) { value.GrantID = "grant-invalid" },
		"generation":      func(value *Statement) { value.Generation = 0 },
		"interaction":     func(value *Statement) { value.InteractionID = "interaction-invalid" },
		"request digest":  func(value *Statement) { value.RequestDigest = "sha256:invalid" },
		"response digest": func(value *Statement) { value.ResponseDigest = "sha256:invalid" },
		"response bytes":  func(value *Statement) { value.ResponseBytes = 0 },
		"long validity": func(value *Statement) {
			value.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			raw := signStatement(t, candidate, "tenant-task", private)
			if _, err := InspectUnverified(raw); err == nil {
				t.Fatal("InspectUnverified accepted invalid statement")
			}
		})
	}

	raw := signStatement(t, base, "tenant-task", private)
	if _, err := Verify(raw, map[string]ed25519.PublicKey{"other": public}, now, time.Hour); err == nil {
		t.Fatal("Verify accepted untrusted key")
	}
	if _, err := Verify(raw, map[string]ed25519.PublicKey{"tenant-task": public}, now.Add(2*time.Hour), time.Hour); err == nil {
		t.Fatal("Verify accepted expired permit")
	}
	if _, err := Verify(raw, map[string]ed25519.PublicKey{"tenant-task": public}, now, MaxValidity+time.Second); err == nil {
		t.Fatal("Verify accepted unsafe local maximum")
	}
	if _, err := InspectUnverified(append(raw, '\n')); err == nil {
		t.Fatal("InspectUnverified accepted noncanonical envelope")
	}
	if _, err := InspectUnverified([]byte(strings.Repeat("x", MaxEnvelopeBytes+1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestInteractionResponsePermitRejectsOmittedAndUnknownFields(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"choice":"approve","text":""}`)
	statement := validStatement(now, body)

	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	delete(values, "generation")
	omitted, _ := json.Marshal(values)
	envelope, _ := dsse.Sign(PayloadType, omitted, "tenant-task", private)
	raw, _ := dsse.Marshal(envelope)
	if _, err := InspectUnverified(raw); err == nil {
		t.Fatal("InspectUnverified accepted omitted field")
	}

	values["generation"] = statement.Generation
	values["unexpected"] = true
	unknown, _ := json.Marshal(values)
	envelope, _ = dsse.Sign(PayloadType, unknown, "tenant-task", private)
	raw, _ = dsse.Marshal(envelope)
	if _, err := InspectUnverified(raw); err == nil {
		t.Fatal("InspectUnverified accepted unknown field")
	}
}

func validStatement(now time.Time, body []byte) Statement {
	return Statement{
		SchemaVersion: SchemaV1,
		NodeID:        "node-1", TenantID: "tenant-a", InstanceID: "agent-1",
		RuntimeRef:     "executor-" + strings.Repeat("a", 64),
		GrantID:        "grant-" + strings.Repeat("b", 64),
		Generation:     7,
		CapsuleDigest:  "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:   "sha256:" + strings.Repeat("d", 64),
		InteractionID:  "interaction-" + strings.Repeat("e", 64),
		RequestDigest:  "sha256:" + strings.Repeat("f", 64),
		ResponseDigest: ResponseDigest(body),
		ResponseBytes:  int64(len(body)),
		NotBefore:      now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:      now.Add(time.Hour).Format(time.RFC3339),
	}
}

func signStatement(t *testing.T, statement Statement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
