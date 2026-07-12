package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T) (*Log, string, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipts.log")
	log, err := Open(path, private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	return log, path, public
}

func event(kind EventType) Event {
	return Event{Type: kind, TenantID: "tenant-a", RuntimeRef: "runtime-a",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: 1,
		GrantID: "grant-a", Outcome: Allowed, ErrorCode: "none", MetadataHash: "sha256:meta"}
}

func TestAppendAndVerifyChain(t *testing.T) {
	log, path, public := newLog(t)
	first, err := log.Append(event(AdmissionAllow))
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := event(InferenceAuthorize)
	secondEvent.Outcome = Committed
	second, err := log.Append(secondEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	last, err := Verify(path, public, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if last == nil || last.Sequence != second.Sequence || second.PreviousHash == first.PreviousHash {
		t.Fatalf("unexpected verified chain: first=%#v second=%#v last=%#v", first, second, last)
	}
}

func TestVerifyRejectsTamperTruncateReorderAndWrongKey(t *testing.T) {
	log, path, public := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(InferenceAuthorize)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("tamper", func(t *testing.T) {
		raw := append([]byte(nil), original...)
		raw[len(raw)-1] ^= 1
		mustWrite(t, path, raw)
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted tampering")
		}
	})
	t.Run("truncate", func(t *testing.T) {
		mustWrite(t, path, original[:len(original)-1])
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted truncation")
		}
	})
	t.Run("reorder", func(t *testing.T) {
		firstEnd := 4 + int(uint32(original[0])<<24|uint32(original[1])<<16|uint32(original[2])<<8|uint32(original[3]))
		raw := append(append([]byte(nil), original[firstEnd:]...), original[:firstEnd]...)
		mustWrite(t, path, raw)
		if _, err := Verify(path, public, "node-a", 1); err == nil {
			t.Fatal("verification accepted reordered frames")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		mustWrite(t, path, original)
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(path, other, "node-a", 1); err == nil {
			t.Fatal("verification accepted wrong key")
		}
	})
}

func TestOpenFailsClosedOnTruncatedExistingLog(t *testing.T) {
	log, path, _ := newLog(t)
	if _, err := log.Append(event(AdmissionAllow)); err != nil {
		t.Fatal(err)
	}
	private := append(ed25519.PrivateKey(nil), log.private...)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, raw[:len(raw)-2])
	if _, err := Open(path, private, "node-a", 1); err == nil {
		t.Fatal("Open accepted truncated evidence")
	}
}

func TestEvidenceRejectsUnsafeFilesMalformedFramesAndBounds(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unsafe.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, private, "node-a", 1); err == nil {
		t.Fatal("Open accepted over-permissive evidence file")
	}

	for name, raw := range map[string][]byte{
		"short-header": {0, 0, 0},
		"zero-frame":   {0, 0, 0, 0},
		"huge-frame":   evidenceFrameHeader(MaxEnvelopeBytes + 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, private, "node-a", 1); err == nil {
				t.Fatal("Open accepted malformed evidence frame")
			}
		})
	}

	log, path, _ := newLog(t)
	tooLarge := event(AdmissionAllow)
	tooLarge.RuntimeRef = strings.Repeat("x", 513)
	if _, err := log.Append(tooLarge); err == nil {
		t.Fatal("Append accepted oversized runtime ref")
	}
	bad := event(AdmissionAllow)
	bad.Type = EventType(255)
	if _, err := log.Append(bad); err == nil {
		t.Fatal("Append accepted unknown event type")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(event(AdmissionAllow)); err == nil {
		t.Fatal("Append after Close succeeded")
	}
	if _, err := Verify(path, nil, "node-a", 1); err == nil {
		t.Fatal("Verify accepted invalid public key")
	}
}

func evidenceFrameHeader(size int) []byte {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(size))
	return raw
}

func mustWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
