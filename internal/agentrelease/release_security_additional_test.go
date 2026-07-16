package agentrelease

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestVerifyRejectsInvalidUTF8EmbeddedCapsule(t *testing.T) {
	fixture := newReleaseFixture(t)
	release := fixture.release
	release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(
		signRawCapsulePayload(t, []byte{0xff, 0xfe}, "publisher-a", fixture.private),
	)

	raw := signReleasePayload(t, release, "publisher-a", fixture.private)
	if _, err := Verify(
		raw,
		map[string]ed25519.PublicKey{"publisher-a": fixture.public},
		testNow,
	); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("Verify error = %v, want invalid UTF-8 rejection", err)
	}
}

func TestSignRejectsReleasePayloadExpandedByBoundedCapsule(t *testing.T) {
	fixture := newReleaseFixture(t)
	capsule := fixture.capsule
	capsule.Command = make([]string, 28)
	for index := range capsule.Command {
		capsule.Command[index] = strings.Repeat("x", 3000)
	}
	capsuleEnvelope := signCapsule(t, capsule, "publisher-a", fixture.private)
	if len(capsuleEnvelope) > MaxPayloadBytes {
		t.Fatalf("test capsule envelope = %d bytes, want at most %d", len(capsuleEnvelope), MaxPayloadBytes)
	}

	release := fixture.release
	release.CapsuleDSSEBase64 = base64.StdEncoding.EncodeToString(capsuleEnvelope)
	if _, err := Sign(release, "publisher-a", fixture.private, testNow); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "release payload exceeds") {
		t.Fatalf("Sign error = %v, want expanded release payload rejection", err)
	}
}
