package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAppendVerifyAndVisitConnectorLedger(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "connector-receipts.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := validEvent(Authorize, Allowed)
	head, err := log.Begin(first)
	if err != nil || head.Sequence != 1 || head.ChainHash == zeroHash() || head.KeyID != KeyID(public) {
		t.Fatalf("first head=%#v err=%v", head, err)
	}
	terminal := validEvent(Terminal, Committed)
	terminal.HTTPStatus, terminal.ResponseBytes = 201, 37
	head, err = log.Finish(terminal)
	if err != nil || head.Sequence != 2 {
		t.Fatalf("terminal head=%#v err=%v", head, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var records []VerifiedReceipt
	verified, err := VerifyRecords(path, public, "node-a/gateway", 1, func(receipt VerifiedReceipt) error {
		records = append(records, receipt)
		return nil
	})
	if err != nil || verified != head || len(records) != 2 {
		t.Fatalf("verified=%#v records=%d err=%v", verified, len(records), err)
	}
	if records[0].Receipt.Event != first || records[1].Receipt.Event != terminal || records[1].Hash != head.ChainHash {
		t.Fatalf("records=%#v", records)
	}

	reopened, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	denial := validEvent(Deny, Denied)
	denial.ErrorCode = "call_budget_exhausted"
	head, err = reopened.Append(denial)
	if err != nil || head.Sequence != 3 {
		t.Fatalf("reopened append head=%#v err=%v", head, err)
	}
	_ = reopened.Close()
}

func TestConnectorLedgerRejectsTamperReorderAndTruncation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeLedger := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ledger.ndjson")
		log, err := Open(path, private, "node-a/gateway", 7)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Begin(validEvent(Authorize, Allowed)); err != nil {
			t.Fatal(err)
		}
		terminal := validEvent(Terminal, Failed)
		terminal.ErrorCode = "upstream_unavailable"
		if _, err := log.Finish(terminal); err != nil {
			t.Fatal(err)
		}
		_ = log.Close()
		return path
	}

	t.Run("tamper", func(t *testing.T) {
		path := makeLedger(t)
		raw, _ := os.ReadFile(path)
		raw[len(raw)/2] ^= 1
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRecords(path, public, "node-a/gateway", 7, nil); err == nil {
			t.Fatal("tampered ledger verified")
		}
	})

	t.Run("reorder", func(t *testing.T) {
		path := makeLedger(t)
		raw, _ := os.ReadFile(path)
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if err := os.WriteFile(path, []byte(lines[1]+"\n"+lines[0]+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRecords(path, public, "node-a/gateway", 7, nil); err == nil {
			t.Fatal("reordered ledger verified")
		}
	})

	t.Run("truncate", func(t *testing.T) {
		path := makeLedger(t)
		raw, _ := os.ReadFile(path)
		if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRecords(path, public, "node-a/gateway", 7, nil); err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("truncated ledger err=%v", err)
		}
	})
}

func TestVerifyRecordsRejectsSignedOrphanTerminal(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "orphan-terminal.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	terminal := validEvent(Terminal, Failed)
	terminal.ErrorCode = "orphan_terminal"
	log.mu.Lock()
	_, err = log.appendLocked(terminal, 0)
	log.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil ||
		!strings.Contains(err.Error(), "no matching authorization") {
		t.Fatalf("signed orphan terminal verification err=%v", err)
	}
}

func TestConnectorLedgerRejectsSpentAuthorizationReplay(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "spent-replay.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	terminal := validEvent(Terminal, Committed)
	terminal.HTTPStatus = 200
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Begin(authorized); err == nil || !strings.Contains(err.Error(), "already spent") {
		t.Fatalf("live spent authorization replay err=%v", err)
	}

	// Simulate a correctly signed but semantically invalid history. All readers,
	// including offline evidence verification, must reject the permanent replay.
	log.mu.Lock()
	_, err = log.appendLocked(authorized, terminalReserveBytes)
	log.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil ||
		!strings.Contains(err.Error(), "duplicate spent authorization") {
		t.Fatalf("signed spent authorization replay verification err=%v", err)
	}
}

func TestConnectorLedgerConcurrentAppendHasOneChainOrder(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	const count = 32
	var wait sync.WaitGroup
	errorsCh := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			event := validEvent(Authorize, Allowed)
			event.TaskDigest, _ = TaskDigest(fmt.Sprintf("task-%d", index))
			_, err := log.Begin(event)
			errorsCh <- err
		}(index)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
	head, err := VerifyRecords(path, public, "node-a/gateway", 1, nil)
	if err != nil || head.Sequence != count {
		t.Fatalf("head=%#v err=%v", head, err)
	}
}

func TestConnectorLedgerValidatesEventsFilesAndTaskIDs(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	invalid := validEvent(Terminal, Committed)
	invalid.HTTPStatus = 0
	if _, err := log.Finish(invalid); err == nil {
		t.Fatal("committed terminal event without status was accepted")
	}
	invalid = validEvent(Deny, Denied)
	if _, err := log.Append(invalid); err == nil {
		t.Fatal("denial without reason was accepted")
	}
	if _, err := TaskDigest("../weak"); err == nil {
		t.Fatal("unsafe task id accepted")
	}
	first, err := TaskDigest("task-0123456789abcdef")
	if err != nil || !digest(first) {
		t.Fatalf("task digest=%q err=%v", first, err)
	}
	second, _ := TaskDigest("task-0123456789abcdef")
	if first != second {
		t.Fatal("task digest is not deterministic")
	}
	_ = log.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil {
		t.Fatal("world-readable ledger accepted")
	}
}

func TestValidateConnectorLedgerIsReadOnlyAndVerifiesExistingChain(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "prospective.ndjson")
	head, err := Validate(path, private, "node-a/gateway", 3)
	if err != nil {
		t.Fatal(err)
	}
	if head.Sequence != 0 || head.ChainHash != zeroHash() || head.KeyID != KeyID(public) {
		t.Fatalf("prospective head=%#v", head)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("validation created prospective ledger: %v", err)
	}

	log, err := Open(path, private, "node-a/gateway", 3)
	if err != nil {
		t.Fatal(err)
	}
	written, err := log.Begin(validEvent(Authorize, Allowed))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	verified, err := Validate(path, private, "node-a/gateway", 3)
	if err != nil || verified != written {
		t.Fatalf("verified=%#v written=%#v err=%v", verified, written, err)
	}
	if _, err := Validate(path, private, "other-node/gateway", 3); err == nil {
		t.Fatal("ledger verified under a different node identity")
	}
}

func TestOpenWithVisitReconstructsVerifiedRecords(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Begin(validEvent(Authorize, Allowed)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	visited := 0
	reopened, err := OpenWithVisit(path, private, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		visited++
		if record.Receipt.Event.Phase != Authorize || len(record.Raw) == 0 || record.Hash == "" {
			t.Fatalf("record=%#v", record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if visited != 1 || reopened.Head().Sequence != 1 {
		t.Fatalf("visited=%d head=%#v", visited, reopened.Head())
	}
	_ = reopened.Close()
}

func TestBeginReservesTerminalCapacityBeforeAuthorization(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := Open(filepath.Join(t.TempDir(), "ledger.ndjson"), private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if err := log.file.Truncate(MaxLogBytes - terminalReserveBytes/2); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Begin(validEvent(Authorize, Allowed)); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("authorization without terminal capacity err=%v", err)
	}
	if len(log.Pending()) != 0 || log.Head().Sequence != 0 {
		t.Fatalf("failed authorization changed ledger: pending=%d head=%#v", len(log.Pending()), log.Head())
	}
}

func validEvent(phase Phase, outcome Outcome) Event {
	task, _ := TaskDigest("task-0123456789abcdef")
	return Event{
		Phase: phase, Outcome: outcome, TenantID: "tenant-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64), Generation: 4,
		GrantID: "grant-" + strings.Repeat("d", 64), ConnectorID: "ticketing", OperationID: "create-ticket",
		TaskDigest: task, RequestBytes: 19,
	}
}
