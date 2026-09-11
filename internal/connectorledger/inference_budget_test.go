package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInferenceAllowanceCountsUnknownAndLegacyAttemptsAfterRestart(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	log, err := Open(path, key, "node", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := inferenceEvent()
	// Existing signed history predates the configured cap; it cannot disappear.
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	terminal := first
	terminal.Phase, terminal.Outcome, terminal.ErrorCode = Terminal, Failed, "outcome_unknown"
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := log.BeginInference(second, 2); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(path, key, "node", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	third := first
	third.TaskDigest = "sha256:" + strings.Repeat("e", 64)
	before := log.Head()
	if _, err := log.BeginInference(third, 2); !errors.Is(err, ErrInferenceQuotaExceeded) {
		t.Fatalf("restart restored allowance: %v", err)
	}
	if log.Head() != before {
		t.Fatal("refusal appended a paid authorization")
	}
	// Completing the in-flight attempt, even successfully, cannot refund its use.
	second.Phase, second.Outcome, second.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(second); err != nil {
		t.Fatal(err)
	}
	if _, err := log.BeginInference(third, 2); !errors.Is(err, ErrInferenceQuotaExceeded) {
		t.Fatalf("terminal receipt restored allowance: %v", err)
	}
	third.GrantID = "grant-" + strings.Repeat("8", 64)
	if _, err := log.BeginInference(third, 2); err != nil {
		t.Fatalf("another grant lost its allowance: %v", err)
	}
}

func TestInferenceAllowanceSerializesConcurrentReservations(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := Open(filepath.Join(t.TempDir(), "ledger.ndjson"), key, "node", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	var accepted atomic.Int32
	var group sync.WaitGroup
	for index := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			event := inferenceEvent()
			event.TaskDigest = fmt.Sprintf("sha256:%064x", index+1)
			_, err := log.BeginInference(event, 3)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrInferenceQuotaExceeded) {
				t.Errorf("unexpected refusal: %v", err)
			}
		}()
	}
	group.Wait()
	if accepted.Load() != 3 || log.Head().Sequence != 3 {
		t.Fatalf("allowance over/under-reserved: accepted=%d sequence=%d", accepted.Load(), log.Head().Sequence)
	}
}

func TestInferenceAllowanceRejectsInvalidLimitsWithoutAReceipt(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := Open(filepath.Join(t.TempDir(), "ledger.ndjson"), key, "node", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for _, maximum := range []int{-1, 0, 1_000_001} {
		if _, err := log.BeginInference(inferenceEvent(), maximum); err == nil {
			t.Fatalf("accepted maximum %d", maximum)
		}
	}
	if _, err := log.BeginInference(validEvent(Authorize, Allowed), 1); err == nil {
		t.Fatal("accepted non-inference effect")
	}
	if log.Head().Sequence != 0 {
		t.Fatal("invalid limit authorized a call")
	}
}
