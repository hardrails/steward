package taskpermit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

var testNow = time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)

func TestVerifyReturnsEveryAuthenticatedBinding(t *testing.T) {
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
	public, private := testKey(t)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name   string
		mutate func(*Statement)
	}{
		{"schema", func(s *Statement) { s.SchemaVersion = "steward.task-permit.v2" }},
		{"empty node", func(s *Statement) { s.NodeID = "" }},
		{"node whitespace only", func(s *Statement) { s.NodeID = " \t" }},
		{"node NUL", func(s *Statement) { s.NodeID = "node\x00a" }},
		{"node too long", func(s *Statement) { s.NodeID = strings.Repeat("n", 129) }},
		{"empty tenant", func(s *Statement) { s.TenantID = "" }},
		{"tenant too long", func(s *Statement) { s.TenantID = strings.Repeat("t", 129) }},
		{"empty instance", func(s *Statement) { s.InstanceID = "" }},
		{"instance too long", func(s *Statement) { s.InstanceID = strings.Repeat("i", 257) }},
		{"runtime prefix", func(s *Statement) { s.RuntimeRef = "container-" + strings.Repeat("a", 64) }},
		{"runtime short", func(s *Statement) { s.RuntimeRef = "executor-" + strings.Repeat("a", 63) }},
		{"runtime uppercase", func(s *Statement) { s.RuntimeRef = "executor-" + strings.Repeat("A", 64) }},
		{"runtime nonhex", func(s *Statement) { s.RuntimeRef = "executor-" + strings.Repeat("g", 64) }},
		{"grant prefix", func(s *Statement) { s.GrantID = "lease-" + strings.Repeat("b", 64) }},
		{"grant short", func(s *Statement) { s.GrantID = "grant-" + strings.Repeat("b", 63) }},
		{"grant uppercase", func(s *Statement) { s.GrantID = "grant-" + strings.Repeat("B", 64) }},
		{"generation zero", func(s *Statement) { s.Generation = 0 }},
		{"capsule digest prefix", func(s *Statement) { s.CapsuleDigest = "SHA256:" + strings.Repeat("a", 64) }},
		{"policy digest length", func(s *Statement) { s.PolicyDigest = digest + "a" }},
		{"route digest uppercase", func(s *Statement) { s.RoutePolicyDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"operation digest missing", func(s *Statement) { s.OperationPolicyDigest = "" }},
		{"request digest nonhex", func(s *Statement) { s.RequestDigest = "sha256:" + strings.Repeat("g", 64) }},
		{"empty service", func(s *Statement) { s.ServiceID = "" }},
		{"service leading dash", func(s *Statement) { s.ServiceID = "-hermes" }},
		{"service slash", func(s *Statement) { s.ServiceID = "hermes/run" }},
		{"service too long", func(s *Statement) { s.ServiceID = strings.Repeat("s", 129) }},
		{"empty operation", func(s *Statement) { s.OperationID = "" }},
		{"operation control", func(s *Statement) { s.OperationID = "run\nnow" }},
		{"operation slash", func(s *Statement) { s.OperationID = "runs/create" }},
		{"operation too long", func(s *Statement) { s.OperationID = strings.Repeat("o", 129) }},
		{"empty task", func(s *Statement) { s.TaskID = "" }},
		{"task leading dash", func(s *Statement) { s.TaskID = "-task" }},
		{"task slash", func(s *Statement) { s.TaskID = "task/123" }},
		{"task too long", func(s *Statement) { s.TaskID = strings.Repeat("x", 129) }},
		{"zero request bytes", func(s *Statement) { s.RequestBytes = 0; s.RequestDigest = RequestDigest(nil) }},
		{"negative request bytes", func(s *Statement) { s.RequestBytes = -1 }},
		{"oversize request", func(s *Statement) { s.RequestBytes = MaxRequestBytes + 1 }},
		{"empty content type", func(s *Statement) { s.ContentType = "" }},
		{"content type case", func(s *Statement) { s.ContentType = "Application/JSON" }},
		{"content type parameter", func(s *Statement) { s.ContentType = "application/json; charset=utf-8" }},
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
			if _, err := Verify(raw, trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifyAcceptsExactStatementBounds(t *testing.T) {
	public, private := testKey(t)
	statement := validStatement()
	statement.NodeID = strings.Repeat("n", 128)
	statement.TenantID = strings.Repeat("t", 128)
	statement.InstanceID = strings.Repeat("i", 256)
	statement.ServiceID = strings.Repeat("s", 128)
	statement.OperationID = strings.Repeat("o", 128)
	statement.TaskID = strings.Repeat("x", 128)
	statement.RequestBytes = MaxRequestBytes
	statement.NotBefore = "2026-07-13T11:59:00Z"
	statement.ExpiresAt = "2026-07-13T12:14:00Z"

	if _, err := Verify(
		signStatement(t, statement, "authority-a", private),
		map[string]ed25519.PublicKey{"authority-a": public}, testNow, MaxValidity,
	); err != nil {
		t.Fatalf("Verify rejected exact statement bounds: %v", err)
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

func TestVerifyRequiresEveryStatementField(t *testing.T) {
	public, private := testKey(t)
	trusted := map[string]ed25519.PublicKey{"authority-a": public}
	fields := []string{
		"schema_version", "node_id", "tenant_id", "instance_id", "runtime_ref", "grant_id", "generation",
		"capsule_digest", "policy_digest", "route_policy_digest", "service_id", "operation_id",
		"operation_policy_digest", "task_id", "request_digest", "request_bytes", "content_type", "not_before", "expires_at",
	}
	for _, field := range fields {
		t.Run("missing "+field, func(t *testing.T) {
			members := statementMembers(t, validStatement())
			delete(members, field)
			payload, err := json.Marshal(members)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(signPayload(t, PayloadType, payload, "authority-a", private), trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify missing %s error = %v, want ErrInvalid", field, err)
			}
		})
		t.Run("null "+field, func(t *testing.T) {
			members := statementMembers(t, validStatement())
			members[field] = json.RawMessage("null")
			payload, err := json.Marshal(members)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(signPayload(t, PayloadType, payload, "authority-a", private), trusted, testNow, 5*time.Minute); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify null %s error = %v, want ErrInvalid", field, err)
			}
		})
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
	long.NotBefore = "2026-07-13T11:59:00Z"
	long.ExpiresAt = "2026-07-13T12:14:01Z"
	if _, err := Verify(signStatement(t, long, "authority-a", private), trusted, testNow, MaxValidity); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify over-hard-limit error = %v, want ErrInvalid", err)
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
	longKeyID := signStatement(t, statement, strings.Repeat("k", 129), private)
	unknownPayload := append(mustJSON(t, statement)[:len(mustJSON(t, statement))-1], []byte(`,"extra":true}`)...)
	duplicatePayload := []byte(strings.Replace(string(mustJSON(t, statement)), `"node_id":"node/a"`, `"node_id":"node/a","node_id":"node/b"`, 1))
	wrongTypePayload := []byte(strings.Replace(string(mustJSON(t, statement)), `"request_bytes":`, `"request_bytes":"`, 1))
	wrongTypePayload = bytes.Replace(wrongTypePayload, []byte(`,"content_type"`), []byte(`","content_type"`), 1)
	invalidUTF8Payload := bytes.Replace(mustJSON(t, statement), []byte("node/a"), []byte{'n', 'o', 'd', 'e', '/', 0xff}, 1)
	nonCanonicalEnvelope := append([]byte(" "), valid...)

	parsed, err := dsse.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signatures = append(parsed.Signatures, dsse.Signature{KeyID: "other-authority", Sig: parsed.Signatures[0].Sig})
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
	nonCanonicalSignatureEnvelope := parsed
	nonCanonicalSignatureEnvelope.Signatures = append([]dsse.Signature(nil), parsed.Signatures...)
	nonCanonicalSignatureEnvelope.Signatures[0].Sig = alternateBase64(t, parsed.Signatures[0].Sig)
	nonCanonicalSignature, err := json.Marshal(nonCanonicalSignatureEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	missingPaddingEnvelope := parsed
	missingPaddingEnvelope.Signatures = append([]dsse.Signature(nil), parsed.Signatures...)
	missingPaddingEnvelope.Signatures[0].Sig = strings.TrimRight(parsed.Signatures[0].Sig, "=")
	missingPaddingSignature, err := json.Marshal(missingPaddingEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	shortSignatureEnvelope := parsed
	shortSignatureEnvelope.Signatures = append([]dsse.Signature(nil), parsed.Signatures...)
	shortSignatureEnvelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize-1))
	shortSignature, err := json.Marshal(shortSignatureEnvelope)
	if err != nil {
		t.Fatal(err)
	}

	paddedPayload := append(mustJSON(t, statement), '\n')
	for len(paddedPayload)%3 == 0 {
		paddedPayload = append(paddedPayload, '\n')
	}
	paddedRaw := signPayload(t, PayloadType, paddedPayload, "authority-a", private)
	if _, err := Verify(paddedRaw, trusted, testNow, 5*time.Minute); err != nil {
		t.Fatalf("test setup signed padded payload is not valid: %v", err)
	}
	paddedEnvelope, err := dsse.Parse(paddedRaw)
	if err != nil {
		t.Fatal(err)
	}
	paddedEnvelope.Payload = alternateBase64(t, paddedEnvelope.Payload)
	nonCanonicalPayloadBits, err := json.Marshal(paddedEnvelope)
	if err != nil {
		t.Fatal(err)
	}

	var reorderedMembers map[string]json.RawMessage
	if err := json.Unmarshal(valid, &reorderedMembers); err != nil {
		t.Fatal(err)
	}
	reorderedEnvelope, err := json.Marshal(reorderedMembers)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reorderedEnvelope, valid) {
		t.Fatal("test setup did not reorder the envelope")
	}
	unknownEnvelope := append(valid[:len(valid)-1], []byte(`,"extra":true}`)...)
	duplicateEnvelope := append(valid[:len(valid)-1], []byte(`,"payloadType":"`+PayloadType+`"}`)...)

	for _, test := range []struct {
		name    string
		raw     []byte
		trusted map[string]ed25519.PublicKey
	}{
		{"empty", nil, trusted},
		{"oversize", bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1), trusted},
		{"wrong payload type", wrongType, trusted},
		{"untrusted signature", valid, map[string]ed25519.PublicKey{"authority-a": untrustedPublic}},
		{"no trusted keys", valid, nil},
		{"tampered envelope", tampered, trusted},
		{"invalid signing key ID", invalidKeyID, map[string]ed25519.PublicKey{"bad key": public}},
		{"long signing key ID", longKeyID, map[string]ed25519.PublicKey{strings.Repeat("k", 129): public}},
		{"non-canonical envelope whitespace", nonCanonicalEnvelope, trusted},
		{"non-canonical envelope order", reorderedEnvelope, trusted},
		{"multiple signatures", multipleSignatures, trusted},
		{"payload base64 with ignored newline", newlinePayload, trusted},
		{"signature base64 with ignored newline", newlineSignature, trusted},
		{"signature base64 with nonzero trailing bits", nonCanonicalSignature, trusted},
		{"signature base64 without required padding", missingPaddingSignature, trusted},
		{"short signature", shortSignature, trusted},
		{"payload base64 with nonzero trailing bits", nonCanonicalPayloadBits, trusted},
		{"unknown envelope field", unknownEnvelope, trusted},
		{"duplicate envelope field", duplicateEnvelope, trusted},
		{"unknown payload field", signPayload(t, PayloadType, unknownPayload, "authority-a", private), trusted},
		{"duplicate payload field", signPayload(t, PayloadType, duplicatePayload, "authority-a", private), trusted},
		{"wrong payload member type", signPayload(t, PayloadType, wrongTypePayload, "authority-a", private), trusted},
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
	right := RequestDigest([]byte(`{ "a": 1 }`))
	if left == right {
		t.Fatal("RequestDigest ignored the byte-level JSON representation")
	}
}

func TestTaskDigestScopesLogicalWorkloadAndFramesTuple(t *testing.T) {
	base := TaskDigest("tenant-a", "agent-a", "task-a")
	if want := "sha256:9051bcf6094101b20956b9f7d1106da42c43f0e516d6114e488fa07024bffea0"; base != want {
		t.Fatalf("TaskDigest fixed vector = %q, want %q", base, want)
	}
	if !digest(base) {
		t.Fatalf("TaskDigest = %q, want canonical SHA-256 digest", base)
	}
	if repeated := TaskDigest("tenant-a", "agent-a", "task-a"); repeated != base {
		t.Fatalf("TaskDigest is not deterministic: %q then %q", base, repeated)
	}
	for _, changed := range []string{
		TaskDigest("tenant-b", "agent-a", "task-a"),
		TaskDigest("tenant-a", "agent-b", "task-a"),
		TaskDigest("tenant-a", "agent-a", "task-b"),
	} {
		if changed == base {
			t.Fatal("TaskDigest did not bind every logical workload coordinate")
		}
	}

	// These tuples have the same bytes under NUL-delimited framing. Length
	// framing must still keep them distinct, even before statement validation.
	left := TaskDigest("tenant", "instance", "task\x00id")
	right := TaskDigest("tenant", "instance\x00task", "id")
	if left == right {
		t.Fatal("TaskDigest is ambiguous across tuple boundaries")
	}

	connectorHash := sha256.New()
	_, _ = connectorHash.Write([]byte("steward-gateway-connector-call-v1\x00"))
	for _, value := range []string{"tenant-a", "agent-a", "task-a", "", ""} {
		_, _ = connectorHash.Write([]byte(value))
		_, _ = connectorHash.Write([]byte{0})
	}
	connectorDigest := "sha256:" + hex.EncodeToString(connectorHash.Sum(nil))
	if base == connectorDigest {
		t.Fatal("task spend identity collided with the connector-call digest domain")
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

	if _, err := EncodeHeader(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("EncodeHeader(empty) error = %v, want ErrInvalid", err)
	}
	if _, err := EncodeHeader(bytes.Repeat([]byte{'x'}, MaxEnvelopeBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("EncodeHeader(oversize) error = %v, want ErrInvalid", err)
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
		if _, err := DecodeHeader(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("DecodeHeader(%q) error = %v, want ErrInvalid", value, err)
		}
	}
	// Both values decode to "f" under permissive trailing-bit handling. Only
	// the exact canonical encoding is accepted.
	if _, err := DecodeHeader("Zh"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("DecodeHeader(non-canonical bits) error = %v, want ErrInvalid", err)
	}
	if got, err := DecodeHeader("Zg"); err != nil || string(got) != "f" {
		t.Fatalf("DecodeHeader(canonical) = %q, %v", got, err)
	}
}

func FuzzVerifyNeverPanics(f *testing.F) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(nil))
	f.Add([]byte(`{"payloadType":null}`))
	f.Add(signStatement(f, validStatement(), "authority-a", private))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Verify(raw, map[string]ed25519.PublicKey{"authority-a": public}, testNow, 5*time.Minute)
	})
}

func validStatement() Statement {
	body := []byte(`{"input":"do actual work"}`)
	return Statement{
		SchemaVersion: SchemaV1, NodeID: "node/a", TenantID: "tenant-a", InstanceID: "instance/a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: "grant-" + strings.Repeat("b", 64), Generation: 7,
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64), ServiceID: "hermes", OperationID: "hermes.run",
		OperationPolicyDigest: "sha256:" + strings.Repeat("f", 64), TaskID: "task.123",
		RequestDigest: RequestDigest(body), RequestBytes: int64(len(body)), ContentType: "application/json",
		NotBefore: "2026-07-13T11:59:00Z", ExpiresAt: "2026-07-13T12:04:00Z",
	}
}

func testKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func signStatement(t testing.TB, statement Statement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	return signPayload(t, PayloadType, mustJSON(t, statement), keyID, private)
}

func signPayload(t testing.TB, payloadType string, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
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

func mustJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func statementMembers(t testing.TB, statement Statement) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(mustJSON(t, statement), &members); err != nil {
		t.Fatal(err)
	}
	return members
}

func alternateBase64(t testing.TB, canonical string) string {
	t.Helper()
	padding := 0
	if strings.HasSuffix(canonical, "==") {
		padding = 2
	} else if strings.HasSuffix(canonical, "=") {
		padding = 1
	}
	if padding == 0 {
		t.Fatalf("base64 value has no unused trailing bits: %q", canonical)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := len(canonical) - padding - 1
	value := strings.IndexByte(alphabet, canonical[index])
	if value < 0 {
		t.Fatalf("base64 value has unexpected trailing character: %q", canonical)
	}
	mutated := []byte(canonical)
	mutated[index] = alphabet[value^1]
	canonicalBytes, canonicalErr := base64.StdEncoding.DecodeString(canonical)
	mutatedBytes, mutatedErr := base64.StdEncoding.DecodeString(string(mutated))
	if canonicalErr != nil || mutatedErr != nil || !bytes.Equal(canonicalBytes, mutatedBytes) {
		t.Fatal("test setup did not produce equivalent non-canonical base64")
	}
	return string(mutated)
}
