package actionpermit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

var testNow = time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)

func TestVerifyReturnsAllAuthenticatedBindings(t *testing.T) {
	public, private := testKey(t)
	statement := validStatement()
	raw := signStatement(t, statement, "authority-a", private)

	verified, err := Verify(raw, map[string]ed25519.PublicKey{"authority-a": public}, testNow, 5*time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Statement != statement {
		t.Fatalf("statement mismatch:\n got: %#v\nwant: %#v", verified.Statement, statement)
	}
	if verified.KeyID != "authority-a" {
		t.Fatalf("KeyID = %q", verified.KeyID)
	}
	if verified.EnvelopeDigest != dsse.Digest(raw) {
		t.Fatalf("EnvelopeDigest = %q, want %q", verified.EnvelopeDigest, dsse.Digest(raw))
	}
}

func TestVerifyRejectsInvalidSignedStatements(t *testing.T) {
	_, private := testKey(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name   string
		mutate func(*Statement)
	}{
		{"schema", func(s *Statement) { s.SchemaVersion = "steward.action-permit.v2" }},
		{"empty node", func(s *Statement) { s.NodeID = "" }},
		{"node whitespace only", func(s *Statement) { s.NodeID = " \t" }},
		{"tenant NUL", func(s *Statement) { s.TenantID = "tenant\x00a" }},
		{"instance too long", func(s *Statement) { s.InstanceID = strings.Repeat("a", 257) }},
		{"connector too long", func(s *Statement) { s.ConnectorID = strings.Repeat("a", 129) }},
		{"connector slash", func(s *Statement) { s.ConnectorID = "tickets/create" }},
		{"operation control", func(s *Statement) { s.OperationID = "read\nnow" }},
		{"operation slash", func(s *Statement) { s.OperationID = "issues/create" }},
		{"task leading dash", func(s *Statement) { s.TaskID = "-task" }},
		{"task slash", func(s *Statement) { s.TaskID = "task/123" }},
		{"generation zero", func(s *Statement) { s.Generation = 0 }},
		{"capsule digest prefix", func(s *Statement) { s.CapsuleDigest = "SHA256:" + strings.Repeat("a", 64) }},
		{"policy digest length", func(s *Statement) { s.PolicyDigest = digest + "a" }},
		{"route digest uppercase", func(s *Statement) { s.RoutePolicyDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"operation digest missing", func(s *Statement) { s.OperationDigest = "" }},
		{"request digest non hex", func(s *Statement) { s.RequestDigest = "sha256:" + strings.Repeat("g", 64) }},
		{"negative request bytes", func(s *Statement) { s.RequestBytes = -1 }},
		{"oversize request", func(s *Statement) { s.RequestBytes = MaxRequestBytes + 1 }},
		{"content type parameter", func(s *Statement) { s.ContentType = "application/json; charset=utf-8" }},
		{"bodyless with bytes", func(s *Statement) { s.ContentType = "" }},
		{"JSON without bytes", func(s *Statement) { s.RequestBytes = 0; s.RequestDigest = RequestDigest(nil) }},
		{"fractional not before", func(s *Statement) { s.NotBefore = "2026-07-13T11:59:00.000Z" }},
		{"offset expiry", func(s *Statement) { s.ExpiresAt = "2026-07-13T12:04:00+00:00" }},
		{"empty interval", func(s *Statement) { s.ExpiresAt = s.NotBefore }},
		{"reversed interval", func(s *Statement) { s.ExpiresAt = "2026-07-13T11:58:59Z" }},
		{"over local lifetime", func(s *Statement) { s.ExpiresAt = "2026-07-13T12:04:01Z" }},
		{"not yet valid", func(s *Statement) { s.NotBefore = "2026-07-13T12:00:01Z" }},
		{"expired", func(s *Statement) { s.ExpiresAt = "2026-07-13T12:00:00Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validStatement()
			test.mutate(&statement)
			raw := signStatement(t, statement, "authority-a", private)
			public := private.Public().(ed25519.PublicKey)
			if _, err := Verify(raw, map[string]ed25519.PublicKey{"authority-a": public}, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify error = %v, want ErrInvalid", err)
			}
		})
	}
	boundary := validStatement()
	boundary.RequestBytes = MaxRequestBytes
	if _, err := Verify(signStatement(t, boundary, "authority-a", private),
		map[string]ed25519.PublicKey{"authority-a": private.Public().(ed25519.PublicKey)}, testNow, 5*time.Minute); err != nil {
		t.Fatalf("Verify rejected exact request-size boundary: %v", err)
	}
	bodyless := validStatement()
	bodyless.ContentType = ""
	bodyless.RequestDigest = RequestDigest(nil)
	bodyless.RequestBytes = 0
	if _, err := Verify(signStatement(t, bodyless, "authority-a", private),
		map[string]ed25519.PublicKey{"authority-a": private.Public().(ed25519.PublicKey)}, testNow, 5*time.Minute); err != nil {
		t.Fatalf("Verify rejected bodyless operation metadata: %v", err)
	}
}

func TestVerifyPreservesOpaquePublicIdentities(t *testing.T) {
	public, private := testKey(t)
	statement := validStatement()
	statement.NodeID = " node / west "
	statement.TenantID = "tenant team α"
	statement.InstanceID = " instance with spaces "
	raw := signStatement(t, statement, "authority-a", private)

	verified, err := Verify(raw, map[string]ed25519.PublicKey{"authority-a": public}, testNow, 5*time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Statement.NodeID != statement.NodeID || verified.Statement.TenantID != statement.TenantID ||
		verified.Statement.InstanceID != statement.InstanceID {
		t.Fatalf("Verify changed opaque public identities: %#v", verified.Statement)
	}
}

func TestVerifyTimeBoundariesAndConfigurationFailClosed(t *testing.T) {
	public, private := testKey(t)
	raw := signStatement(t, validStatement(), "authority-a", private)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}

	for _, test := range []struct {
		name        string
		now         time.Time
		maxValidity time.Duration
		wantOK      bool
	}{
		{"at not-before", testNow.Add(-time.Minute), 5 * time.Minute, true},
		{"one nanosecond before expiry", testNow.Add(4*time.Minute - time.Nanosecond), 5 * time.Minute, true},
		{"at expiry", testNow.Add(4 * time.Minute), 5 * time.Minute, false},
		{"zero node time", time.Time{}, 5 * time.Minute, false},
		{"zero maximum", testNow, 0, false},
		{"negative maximum", testNow, -time.Second, false},
		{"over hard maximum", testNow, MaxValidity + time.Second, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Verify(raw, trusted, test.now, test.maxValidity)
			if (err == nil) != test.wantOK {
				t.Fatalf("Verify error = %v, wantOK = %v", err, test.wantOK)
			}
		})
	}

	long := validStatement()
	long.NotBefore = "2026-07-13T00:00:00Z"
	long.ExpiresAt = "2026-07-14T00:00:01Z"
	if _, err := Verify(signStatement(t, long, "authority-a", private), trusted, testNow, MaxValidity); err == nil {
		t.Fatal("Verify accepted validity greater than the 24-hour hard ceiling")
	}
}

func TestVerifyRejectsEnvelopeAndJSONAmbiguity(t *testing.T) {
	public, private := testKey(t)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}
	statement := validStatement()
	valid := signStatement(t, statement, "authority-a", private)

	wrongType := signPayload(t, "application/example+json", mustJSON(t, statement), "authority-a", private)
	untrustedPublic, _ := testKey(t)
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)/2] ^= 1
	invalidKeyID := signStatement(t, statement, "bad key", private)
	unknownPayload := append(mustJSON(t, statement)[:len(mustJSON(t, statement))-1], []byte(`,"extra":true}`)...)
	duplicatePayload := []byte(strings.Replace(string(mustJSON(t, statement)), `"node_id":"node/a"`, `"node_id":"node/a","node_id":"node/b"`, 1))
	missingZeroPayload := []byte(strings.Replace(string(mustJSON(t, statement)), `,"request_bytes":16`, "", 1))
	nullPayload := []byte(strings.Replace(string(mustJSON(t, statement)), `"request_bytes":16`, `"request_bytes":null`, 1))
	invalidUTF8Payload := bytes.Replace(mustJSON(t, statement), []byte("node/a"), []byte{'n', 'o', 'd', 'e', '/', 0xff}, 1)
	nonCanonicalEnvelope := append([]byte(" "), valid...)
	parsed, err := dsse.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signatures = append(parsed.Signatures, dsse.Signature{KeyID: "untrusted-extra", Sig: parsed.Signatures[0].Sig})
	multipleSignatures, err := dsse.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = dsse.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	newlinePayloadEnvelope := parsed
	newlinePayloadEnvelope.Payload = parsed.Payload[:4] + "\n" + parsed.Payload[4:]
	newlinePayload, err := json.Marshal(newlinePayloadEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	newlineSignatureEnvelope := parsed
	newlineSignatureEnvelope.Signatures = append([]dsse.Signature(nil), parsed.Signatures...)
	newlineSignatureEnvelope.Signatures[0].Sig = parsed.Signatures[0].Sig[:4] + "\n" + parsed.Signatures[0].Sig[4:]
	newlineSignature, err := json.Marshal(newlineSignatureEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonicalBitsEnvelope := parsed
	nonCanonicalBitsEnvelope.Signatures = append([]dsse.Signature(nil), parsed.Signatures...)
	signature := []byte(parsed.Signatures[0].Sig)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lastData := len(signature) - 3 // A 64-byte Ed25519 signature ends in two padding bytes.
	index := strings.IndexByte(alphabet, signature[lastData])
	if index < 0 || signature[len(signature)-2] != '=' || signature[len(signature)-1] != '=' {
		t.Fatalf("unexpected signature base64 %q", signature)
	}
	signature[lastData] = alphabet[index^1]
	nonCanonicalBitsEnvelope.Signatures[0].Sig = string(signature)
	nonCanonicalBits, err := json.Marshal(nonCanonicalBitsEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSignature, canonicalErr := base64.StdEncoding.DecodeString(parsed.Signatures[0].Sig)
	alternateSignature, alternateErr := base64.StdEncoding.DecodeString(string(signature))
	if canonicalErr != nil || alternateErr != nil || !bytes.Equal(canonicalSignature, alternateSignature) {
		t.Fatal("test setup did not produce an equivalent non-canonical base64 signature")
	}

	for _, test := range []struct {
		name    string
		raw     []byte
		trusted map[string]ed25519.PublicKey
	}{
		{"empty", nil, trusted},
		{"oversize", bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1), trusted},
		{"wrong payload type", wrongType, trusted},
		{"untrusted signature", valid, map[string]ed25519.PublicKey{"authority-a": untrustedPublic}},
		{"tampered envelope", tampered, trusted},
		{"invalid signing key ID", invalidKeyID, map[string]ed25519.PublicKey{"bad key": public}},
		{"non-canonical envelope", nonCanonicalEnvelope, trusted},
		{"multiple signatures", multipleSignatures, trusted},
		{"payload base64 with ignored newline", newlinePayload, trusted},
		{"signature base64 with ignored newline", newlineSignature, trusted},
		{"signature base64 with nonzero trailing bits", nonCanonicalBits, trusted},
		{"unknown payload field", signPayload(t, PayloadType, unknownPayload, "authority-a", private), trusted},
		{"duplicate payload field", signPayload(t, PayloadType, duplicatePayload, "authority-a", private), trusted},
		{"missing zero-capable field", signPayload(t, PayloadType, missingZeroPayload, "authority-a", private), trusted},
		{"null field", signPayload(t, PayloadType, nullPayload, "authority-a", private), trusted},
		{"invalid UTF-8 payload", signPayload(t, PayloadType, invalidUTF8Payload, "authority-a", private), trusted},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Verify(test.raw, test.trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRequestDigestUsesExactBytes(t *testing.T) {
	if got, want := RequestDigest(nil), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("RequestDigest(nil) = %q, want %q", got, want)
	}
	left := RequestDigest([]byte(`{"a":1}`))
	right := RequestDigest([]byte("{ \"a\": 1 }"))
	if left == right {
		t.Fatal("RequestDigest ignored byte-level JSON representation")
	}
}

func TestHeaderEncodingIsCanonicalAndBounded(t *testing.T) {
	raw := []byte(`{"payloadType":"example"}`)
	encoded, err := EncodeHeader(raw)
	if err != nil {
		t.Fatalf("EncodeHeader: %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("EncodeHeader used non-base64url alphabet: %q", encoded)
	}
	decoded, err := DecodeHeader(encoded)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("DecodeHeader = %q, %v", decoded, err)
	}

	maximum := bytes.Repeat([]byte{0xff}, MaxEnvelopeBytes)
	maximumHeader, err := EncodeHeader(maximum)
	if err != nil {
		t.Fatalf("EncodeHeader(maximum): %v", err)
	}
	if decoded, err := DecodeHeader(maximumHeader); err != nil || !bytes.Equal(decoded, maximum) {
		t.Fatalf("DecodeHeader(maximum) length = %d, error = %v", len(decoded), err)
	}

	if _, err := EncodeHeader(nil); err == nil {
		t.Fatal("EncodeHeader accepted an empty envelope")
	}
	if _, err := EncodeHeader(bytes.Repeat([]byte{'x'}, MaxEnvelopeBytes+1)); err == nil {
		t.Fatal("EncodeHeader accepted an oversize envelope")
	}

	for _, value := range []string{
		"",
		" " + encoded,
		encoded + " ",
		encoded + "\n",
		encoded + "=",
		encoded + "," + encoded,
		base64.StdEncoding.EncodeToString(raw),
		strings.Repeat("A", base64.RawURLEncoding.EncodedLen(MaxEnvelopeBytes)+1),
	} {
		if _, err := DecodeHeader(value); err == nil {
			t.Fatalf("DecodeHeader accepted non-canonical value %q", value)
		}
	}
	// RawURLEncoding decodes both Zh and Zg to the byte 'f'; only the canonical
	// trailing bits in Zg are accepted by the exact round trip.
	if _, err := DecodeHeader("Zh"); err == nil {
		t.Fatal("DecodeHeader accepted non-canonical trailing bits")
	}
	if got, err := DecodeHeader("Zg"); err != nil || string(got) != "f" {
		t.Fatalf("DecodeHeader(canonical) = %q, %v", got, err)
	}
}

func validStatement() Statement {
	return Statement{
		SchemaVersion: SchemaV1, NodeID: "node/a", TenantID: "tenant-a", InstanceID: "instance/a",
		Generation: 7, CapsuleDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), RoutePolicyDigest: "sha256:" + strings.Repeat("c", 64),
		ConnectorID: "tickets.create", OperationID: "issues.create", OperationDigest: "sha256:" + strings.Repeat("d", 64), TaskID: "task.123",
		RequestDigest: RequestDigest([]byte(`{"title":"help"}`)), RequestBytes: int64(len([]byte(`{"title":"help"}`))),
		ContentType: "application/json", NotBefore: "2026-07-13T11:59:00Z", ExpiresAt: "2026-07-13T12:04:00Z",
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func signStatement(t *testing.T, statement Statement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signPayload(t, PayloadType, mustJSON(t, statement), keyID, private)
}

func signPayload(t *testing.T, payloadType string, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	envelope, err := dsse.Sign(payloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
