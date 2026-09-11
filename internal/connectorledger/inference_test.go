package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
)

func inferenceEvent() Event {
	event := validEvent(Authorize, Allowed)
	event.Kind, event.ConnectorID, event.OperationID = InferenceAttempt, "", "chat-completions"
	event.RequestBytes = 42
	return event
}

func TestInferenceAttemptsUseDistinctSignedFormatAndSurviveRestart(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attempts.ndjson")
	log, err := Open(path, private, "node/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := inferenceEvent()
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(path, private, "node/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if len(log.Pending()) != 1 || log.Pending()[0] != first {
		t.Fatal("uncertain outbound attempt disappeared across restart")
	}
	if _, err := log.Begin(first); err == nil {
		t.Fatal("one attempt identity was accepted twice")
	}
	terminal := first
	terminal.Phase, terminal.Outcome, terminal.ErrorCode = Terminal, Failed, "outcome_unknown"
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := log.Begin(second); err != nil {
		t.Fatal(err)
	}
	terminal = second
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 429
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	var records []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node/gateway", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("expected two attempts, each with its terminal record: %d", len(records))
	}
	for _, record := range records {
		if record.Receipt.SchemaVersion != SchemaV9 {
			t.Fatal("inference was mislabeled as a connector or service task")
		}
		// Even with a valid signature, old format identities cannot carry the new kind.
		receipt := record.Receipt
		receipt.SchemaVersion = SchemaV3
		if err := validateReceipt(receipt, PayloadTypeV3, receipt.NodeID, receipt.Epoch, receipt.Sequence, receipt.PreviousHash); err == nil {
			t.Fatal("inference vocabulary accepted inside the older receipt format")
		}
	}
}

func TestInferenceAttemptsCannotClaimTaskAuthorityOrCompletion(t *testing.T) {
	mutations := map[string]func(*Event){
		"connector":  func(e *Event) { e.ConnectorID = "connector" },
		"service":    func(e *Event) { e.ServiceID = "service" },
		"run":        func(e *Event) { e.RunID = "run" },
		"request":    func(e *Event) { e.RequestDigest = "sha256:" + strings.Repeat("a", 64) },
		"dispatch":   func(e *Event) { e.Phase = Dispatch },
		"denial":     func(e *Event) { e.Phase, e.Outcome, e.ErrorCode = Deny, Denied, "denied" },
		"empty-body": func(e *Event) { e.RequestBytes = 0 },
		"output":     func(e *Event) { e.ResponseBytes = 1 },
		"result":     func(e *Event) { e.ResultDigest = "sha256:" + strings.Repeat("a", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			event := inferenceEvent()
			mutate(&event)
			if err := validateEvent(event); err == nil {
				t.Fatal("incoherent inference event accepted")
			}
		})
	}
}
