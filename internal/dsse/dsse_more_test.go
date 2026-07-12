package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictIntoSupportsBoundedRawMessageWithoutDuplicateKeys(t *testing.T) {
	var target struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := DecodeStrictInto([]byte(`{"payload":{"nested":[1,true,null]}}`), 1024, &target); err != nil {
		t.Fatal(err)
	}
	if string(target.Payload) != `{"nested":[1,true,null]}` {
		t.Fatalf("payload=%s", target.Payload)
	}
	if err := DecodeStrictInto([]byte(`{"payload":{"nested":1,"nested":2}}`), 1024, &target); err == nil {
		t.Fatal("duplicate raw-message key accepted")
	}
}

func TestSignAndParseRejectInvalidBoundsAndSignatures(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		payloadType string
		payload     []byte
		keyID       string
		key         ed25519.PrivateKey
	}{
		{name: "empty type", payloadType: "", payload: []byte("{}"), keyID: "key", key: private},
		{name: "nul key id", payloadType: "application/test", payload: []byte("{}"), keyID: "key\x00", key: private},
		{name: "short key", payloadType: "application/test", payload: []byte("{}"), keyID: "key", key: ed25519.PrivateKey("short")},
		{name: "oversized payload", payloadType: "application/test", payload: make([]byte, MaxPayloadBytes+1), keyID: "key", key: private},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Sign(test.payloadType, test.payload, test.keyID, test.key); err == nil {
				t.Fatal("invalid signing input was accepted")
			}
		})
	}

	validPayload := base64.StdEncoding.EncodeToString([]byte("{}"))
	validSignature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for _, raw := range []string{
		`{"payloadType":"application/test","payload":"` + validPayload + `","signatures":[]}`,
		`{"payloadType":"application/test","payload":"` + validPayload + `","signatures":[{"keyid":"key","sig":"` + validSignature + `"},{"keyid":"key","sig":"` + validSignature + `"}]}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("malformed envelope accepted: %s", raw)
		}
	}
	if _, _, err := Verify([]byte(`{"payloadType":"application/test","payload":"not-base64","signatures":[{"keyid":"key","sig":"`+validSignature+`"}]}`), "application/test", nil); err == nil {
		t.Fatal("invalid payload encoding accepted")
	}
}

func TestVerifyRejectsWrongAndUnknownKeys(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign("application/test", []byte("payload"), "known", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(raw, "application/test", map[string]ed25519.PublicKey{"known": other}); err == nil {
		t.Fatal("wrong public key accepted")
	}
	if _, _, err := Verify(raw, "application/test", map[string]ed25519.PublicKey{"other": public}); err == nil {
		t.Fatal("unknown key ID accepted")
	}
	envelope.Signatures[0].Sig = strings.Repeat("A", base64.StdEncoding.EncodedLen(ed25519.SignatureSize))
	bad, err := Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(bad, "application/test", map[string]ed25519.PublicKey{"known": public}); err == nil {
		t.Fatal("invalid signature accepted")
	}
}

func TestDecodeStrictRejectsTypesTrailingAndExcessiveDepth(t *testing.T) {
	type item struct {
		Count int      `json:"count"`
		Names []string `json:"names"`
	}
	for _, raw := range []string{
		`{"count":"1","names":[]}`,
		`{"count":1.2,"names":[]}`,
		`{"count":1,"names":"not-array"}`,
		`{"count":1,"names":[]} {}`,
	} {
		var destination item
		if err := DecodeStrictInto([]byte(raw), 1024, &destination); err == nil {
			t.Fatalf("strict decoder accepted %s", raw)
		}
	}
	var destination item
	if err := DecodeStrictInto([]byte(`{"count":1,"names":null}`), 1024, &destination); err != nil {
		t.Fatalf("optional slice null rejected: %v", err)
	}
	if err := DecodeStrictInto([]byte(`{}`), 1024, item{}); err == nil {
		t.Fatal("non-pointer destination accepted")
	}
}
