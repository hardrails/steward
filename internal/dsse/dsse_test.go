package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignVerifyAndDigest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign("application/test", []byte(`{"message":"exact bytes"}`), "test-key", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	payload, keyID, err := Verify(raw, "application/test", map[string]ed25519.PublicKey{"test-key": public})
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "test-key" || string(payload) != `{"message":"exact bytes"}` {
		t.Fatalf("unexpected verified artifact: %q %q", keyID, payload)
	}
	if Digest(raw) == Digest(append(append([]byte{}, raw...), ' ')) {
		t.Fatal("digest must identify exact artifact bytes")
	}
	if _, _, err := Verify(raw, "application/other", map[string]ed25519.PublicKey{"test-key": public}); err == nil {
		t.Fatal("expected payload type rejection")
	}
}

func TestParseRejectsDuplicateEnvelopeMember(t *testing.T) {
	_, err := Parse([]byte(`{"payloadType":"x","payloadType":"x","payload":"e30=","signatures":[{"keyid":"k","sig":"` + strings.Repeat("A", 88) + `"}]}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
}

func TestDecodeStrictRejectsNestedUnknownAndDuplicateFields(t *testing.T) {
	type nested struct {
		Name string `json:"name"`
	}
	type document struct {
		Nested nested `json:"nested"`
	}
	for _, raw := range []string{
		`{"nested":{"name":"a","name":"b"}}`,
		`{"nested":{"Name":"a"}}`,
		`{"nested":{"unknown":"a"}}`,
	} {
		var value document
		if err := DecodeStrictInto([]byte(raw), 1024, &value); err == nil {
			t.Fatalf("expected strict rejection for %s", raw)
		}
	}
}
