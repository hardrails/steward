package poolmembership

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestMembershipRoundTripAndBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := validStatement(now)
	raw, err := Sign(statement, "pool-authority-1", private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(raw, "pool-authority-1", public, now.Add(time.Minute))
	if err != nil || verified.Statement.NodeID != "node-a" || verified.Digest == "" || verified.KeyID != "pool-authority-1" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err := Verify(raw, "pool-authority-1", public, now.Add(time.Hour)); err == nil {
		t.Fatal("expired membership was accepted")
	}
	statement.NotAfter = now.Add(MaxLifetime + time.Second).Format(time.RFC3339Nano)
	if _, err := Sign(statement, "pool-authority-1", private); err == nil {
		t.Fatal("overlong membership was signed")
	}
}

func TestMembershipRejectsMalformedAndUntrustedEnvelopes(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := validStatement(now)
	if _, err := Sign(Statement{}, "authority-a", private); err == nil {
		t.Fatal("invalid statement was signed")
	}
	if _, err := Sign(statement, "authority-a", nil); err == nil {
		t.Fatal("invalid private key was accepted")
	}
	validRaw, err := Sign(statement, "authority-a", private)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]struct {
		raw    []byte
		keyID  string
		public ed25519.PublicKey
		now    time.Time
	}{
		"empty":         {keyID: "authority-a", public: public, now: now},
		"oversized":     {raw: make([]byte, (64<<10)+1), keyID: "authority-a", public: public, now: now},
		"invalid key":   {raw: validRaw, keyID: "bad/key", public: public, now: now},
		"invalid pub":   {raw: validRaw, keyID: "authority-a", public: []byte("short"), now: now},
		"zero time":     {raw: validRaw, keyID: "authority-a", public: public},
		"untrusted key": {raw: validRaw, keyID: "authority-b", public: public, now: now},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(input.raw, input.keyID, input.public, input.now); err == nil {
				t.Fatal("invalid verification input was accepted")
			}
		})
	}

	unknownPayload := []byte(`{"schema_version":1,"unknown":true}`)
	unknownRaw := signedPayload(t, PayloadType, unknownPayload, "authority-a", private)
	if _, err := Verify(unknownRaw, "authority-a", public, now); err == nil {
		t.Fatal("payload with unknown fields was accepted")
	}
	invalidPayload, err := json.Marshal(Statement{})
	if err != nil {
		t.Fatal(err)
	}
	invalidRaw := signedPayload(t, PayloadType, invalidPayload, "authority-a", private)
	if _, err := Verify(invalidRaw, "authority-a", public, now); err == nil {
		t.Fatal("invalid signed statement was accepted")
	}

	wrongType := signedPayload(t, "application/example", []byte(`{}`), "authority-a", private)
	invalidEncoding, err := json.Marshal(dsse.Envelope{
		PayloadType: PayloadType,
		Payload:     "%%%",
		Signatures:  []dsse.Signature{{KeyID: "authority-a", Sig: "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty":            nil,
		"oversized":        make([]byte, (64<<10)+1),
		"malformed":        []byte(`{"payloadType":`),
		"wrong type":       wrongType,
		"invalid encoding": invalidEncoding,
		"invalid payload":  invalidRaw,
	} {
		t.Run("inspect "+name, func(t *testing.T) {
			if _, err := Inspect(raw); err == nil {
				t.Fatal("invalid envelope was inspected")
			}
		})
	}
}

func TestMembershipValidationRejectsNonCanonicalClaims(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	base := validStatement(now)
	cases := map[string]func(*Statement){
		"schema":             func(value *Statement) { value.SchemaVersion = 2 },
		"controller":         func(value *Statement) { value.ControllerInstanceID = "bad/controller" },
		"generation":         func(value *Statement) { value.PoolMembershipGeneration = 0 },
		"empty tenants":      func(value *Statement) { value.TenantIDs = nil },
		"too many tenants":   func(value *Statement) { value.TenantIDs = make([]string, 65) },
		"architecture":       func(value *Statement) { value.Architecture = " bad" },
		"boot digest":        func(value *Statement) { value.BootIdentitySHA256 = "sha256:ABC" },
		"tenant identity":    func(value *Statement) { value.TenantIDs = []string{"bad/tenant"} },
		"tenant order":       func(value *Statement) { value.TenantIDs = []string{"tenant-b", "tenant-a"} },
		"issued time":        func(value *Statement) { value.IssuedAt = "yesterday" },
		"created time":       func(value *Statement) { value.PoolCreatedAt = "yesterday" },
		"issued before pool": func(value *Statement) { value.IssuedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano) },
		"noncanonical time":  func(value *Statement) { value.IssuedAt = "2026-07-22T12:00:00.000000000Z" },
		"not after":          func(value *Statement) { value.NotAfter = "tomorrow" },
		"empty window":       func(value *Statement) { value.NotAfter = value.IssuedAt },
		"overlong window":    func(value *Statement) { value.NotAfter = now.Add(MaxLifetime + time.Second).Format(time.RFC3339Nano) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			statement := base
			statement.TenantIDs = append([]string(nil), base.TenantIDs...)
			mutate(&statement)
			if err := Validate(statement); err == nil {
				t.Fatal("invalid statement was accepted")
			}
		})
	}

	for _, value := range []string{"", strings.Repeat("a", 4), " spaced", "bad\\identity", "bad\nidentity"} {
		if validIdentity(value, 3) {
			t.Fatalf("invalid identity %q accepted", value)
		}
	}
	for _, value := range []string{"", "sha512:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("g", 64)} {
		if validDigest(value) {
			t.Fatalf("invalid digest %q accepted", value)
		}
	}
}

func validStatement(now time.Time) Statement {
	return Statement{
		SchemaVersion: 1, ControllerInstanceID: "control-a", PoolID: "pool-a", PoolMembershipGeneration: 3,
		PoolCreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		NodeID:        "node-a", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		BootIdentitySHA256:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchedulingPolicySHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:               now.Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
}

func signedPayload(t *testing.T, payloadType string, payload []byte, keyID string, private ed25519.PrivateKey) []byte {
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
