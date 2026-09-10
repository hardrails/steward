package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func linkedStop(parent Event) Event {
	body, _ := HermesStopRequest(parent.RunID)
	hash := sha256.Sum256(body)
	stop := parent
	stop.Phase, stop.Outcome = Authorize, Allowed
	stop.HTTPStatus, stop.ResponseBytes, stop.RunID = 0, 0, ""
	stop.OperationID = "hermes.stop"
	stop.TaskDigest, stop.PermitDigest = "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)
	stop.RequestDigest, stop.RequestBytes = "sha256:"+hex.EncodeToString(hash[:]), int64(len(body))
	stop.TargetTaskDigest, stop.TargetRunID = parent.TaskDigest, parent.RunID
	return stop
}

func TestStopReferencesOriginalRunWithoutTakingOwnership(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "linked-stop.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	work := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(work); err != nil {
		t.Fatal(err)
	}
	parent := validLifecycleDispatch(work, "run_0123456789abcdef0123456789abcdef")
	if _, err := log.Dispatch(parent); err != nil {
		t.Fatal(err)
	}
	stop := linkedStop(parent)
	if _, err := log.Begin(stop); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Dispatch(validLifecycleDispatch(stop, parent.RunID)); err != nil {
		t.Fatal(err)
	}
	if got := log.runOwners[runOwnershipFor(parent)]; got != parent {
		t.Fatal("stop replaced original run ownership")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var records []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 || records[1].Receipt.SchemaVersion != SchemaV4 ||
		records[2].Receipt.SchemaVersion != SchemaV8 || records[3].Receipt.SchemaVersion != SchemaV8 {
		t.Fatalf("wrong additive receipt formats: %#v", records)
	}
	log, err = Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := log.runOwners[runOwnershipFor(parent)]; got != parent {
		t.Fatal("restart lost original owner")
	}
	other := work
	other.TaskDigest, other.PermitDigest = "sha256:"+strings.Repeat("4", 64), "sha256:"+strings.Repeat("5", 64)
	if _, err := log.Begin(other); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Dispatch(validLifecycleDispatch(other, parent.RunID)); !errors.Is(err, ErrRunIDConflict) {
		t.Fatalf("ordinary work stole a controlled run: %v", err)
	}
	// A single-task export cannot prove this cross-task relationship.
	raw := append(append(append([]byte{}, records[2].Raw...), '\n'), records[3].Raw...)
	raw = append(raw, '\n')
	if _, err := VerifyPortableTaskEvidence(raw, public, "node-a/gateway", 1, stop.TaskDigest, stop.PermitDigest); err == nil {
		t.Fatal("portable proof accepted a stop without its parent")
	}
	// A correctly signed older-format envelope cannot smuggle the new reference
	// fields into the portable verifier, which does not carry parent evidence.
	downgraded := records[2].Receipt
	downgraded.SchemaVersion = SchemaV4
	payload, err := json.Marshal(downgraded)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(PayloadTypeV4, payload, KeyID(public), private)
	if err != nil {
		t.Fatal(err)
	}
	line, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPortableTaskEvidence(append(line, '\n'), public, "node-a/gateway", 1, stop.TaskDigest, stop.PermitDigest); err == nil || !strings.Contains(err.Error(), "expected lifecycle task") {
		t.Fatalf("downgraded linked receipt error=%v", err)
	}
}

func TestStopRequiresExactOriginalAuthorityAndCanonicalBody(t *testing.T) {
	parent := validLifecycleDispatch(validLifecycleEvent(Authorize, Allowed), "run_0123456789abcdef0123456789abcdef")
	for name, mutate := range map[string]func(*Event){
		"missing task":     func(e *Event) { e.TargetTaskDigest = "" },
		"wrong task":       func(e *Event) { e.TargetTaskDigest = "sha256:" + strings.Repeat("f", 64) },
		"self link":        func(e *Event) { e.TargetTaskDigest = e.TaskDigest },
		"wrong run":        func(e *Event) { e.TargetRunID = "run_ffffffffffffffffffffffffffffffff" },
		"wrong body":       func(e *Event) { e.RequestDigest = parent.RequestDigest },
		"wrong size":       func(e *Event) { e.RequestBytes++ },
		"wrong operation":  func(e *Event) { e.OperationID = "hermes.run" },
		"other tenant":     func(e *Event) { e.TenantID = "tenant-b" },
		"other runtime":    func(e *Event) { e.RuntimeRef = "executor-" + strings.Repeat("b", 64) },
		"other key":        func(e *Event) { e.AuthorityKeyID = "other-key" },
		"other generation": func(e *Event) { e.Generation++ },
		"other policy":     func(e *Event) { e.RoutePolicyDigest = "sha256:" + strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			_, private, _ := ed25519.GenerateKey(rand.Reader)
			log, err := Open(filepath.Join(t.TempDir(), "stop.ndjson"), private, "node-a/gateway", 1)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			work := validLifecycleEvent(Authorize, Allowed)
			if _, err := log.Begin(work); err != nil {
				t.Fatal(err)
			}
			if _, err := log.Dispatch(parent); err != nil {
				t.Fatal(err)
			}
			stop := linkedStop(parent)
			mutate(&stop)
			before := log.Head()
			if _, err := log.Begin(stop); err == nil {
				t.Fatal("invalid control accepted")
			}
			if log.Head() != before {
				t.Fatal("invalid control spent ledger state")
			}
		})
	}
}

func TestSignedStopWithoutHistoricalParentIsRejected(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "forged-link.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	parent := validLifecycleDispatch(validLifecycleEvent(Authorize, Allowed), "run_0123456789abcdef0123456789abcdef")
	log.mu.Lock()
	_, err = log.appendLocked(linkedStop(parent), 2*terminalReserveBytes)
	log.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil {
		t.Fatal("signature alone proved a nonexistent parent")
	}
	if restored, err := Open(path, private, "node-a/gateway", 1); err == nil {
		_ = restored.Close()
		t.Fatal("restart accepted a nonexistent parent")
	}
}
