package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	terminal := validEvent(Terminal, Responded)
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

func TestConnectorLedgerReadsMixedLegacyAndPermitReceiptFormats(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mixed.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	denial := validEvent(Deny, Denied)
	denial.ErrorCode = "policy_denied"
	if _, err := log.Append(denial); err != nil {
		t.Fatal(err)
	}
	permitted := validEvent(Authorize, Allowed)
	permitted.TaskDigest = "sha256:" + strings.Repeat("9", 64)
	permitted.AuthorityKeyID = "approver-a"
	permitted.PermitDigest = "sha256:" + strings.Repeat("8", 64)
	permitted.RequestDigest = "sha256:" + strings.Repeat("7", 64)
	if _, err := log.Begin(permitted); err != nil {
		t.Fatal(err)
	}
	terminal := permitted
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var schemas []string
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		schemas = append(schemas, record.Receipt.SchemaVersion)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 3 || schemas[0] != SchemaV1 || schemas[1] != SchemaV2 || schemas[2] != SchemaV2 {
		t.Fatalf("mixed receipt schemas=%v", schemas)
	}
}

func TestConnectorLedgerRejectsConcurrentWriterThroughHardLink(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "connector-receipts.ndjson")
	alias := filepath.Join(directory, "connector-receipts-alias.ndjson")
	first, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if second, err := Open(alias, private, "node-a/gateway", 1); err == nil ||
		!strings.Contains(err.Error(), "already open by another writer") {
		if second != nil {
			_ = second.Close()
		}
		_ = first.Close()
		t.Fatalf("concurrent hard-link writer err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(alias, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatalf("open after owner closed: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
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
	terminal := validEvent(Terminal, Responded)
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
			event.TenantID = fmt.Sprintf("tenant-%d", index%2)
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

func TestLimitsValidateBoundedTenantPartitions(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.MaxTenants != 16 || defaults.MaxBytesPerTenant != 4<<20 {
		t.Fatalf("defaults=%#v", defaults)
	}
	if err := defaults.Validate(); err != nil {
		t.Fatalf("default limits: %v", err)
	}
	tests := []Limits{
		{MaxTenants: 0, MaxBytesPerTenant: minimumTenantBytes},
		{MaxTenants: 1, MaxBytesPerTenant: minimumTenantBytes - 1},
		{MaxTenants: 2, MaxBytesPerTenant: MaxLogBytes},
		{MaxTenants: int(^uint(0) >> 1), MaxBytesPerTenant: minimumTenantBytes},
	}
	for _, limits := range tests {
		if err := limits.Validate(); err == nil {
			t.Errorf("invalid limits accepted: %#v", limits)
		}
	}
}

func TestExplicitTenantBudgetsAreExactBoundedAndNonBorrowing(t *testing.T) {
	valid := Limits{TenantBudgets: map[string]int64{
		"tenant-a":   minimumTenantBytes,
		" tenant-b ": minimumTenantBytes,
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid exact budgets: %v", err)
	}
	invalid := []Limits{
		{TenantBudgets: map[string]int64{"": minimumTenantBytes}},
		{TenantBudgets: map[string]int64{"tenant-a": minimumTenantBytes - 1}},
		{TenantBudgets: map[string]int64{"tenant-a": MaxLogBytes, "tenant-b": minimumTenantBytes}},
		{MaxTenants: 1, MaxBytesPerTenant: minimumTenantBytes, TenantBudgets: map[string]int64{}},
	}
	tooMany := make(map[string]int64, MaxTenantBudgets+1)
	for index := 0; index <= MaxTenantBudgets; index++ {
		tooMany[fmt.Sprintf("tenant-%d", index)] = minimumTenantBytes
	}
	invalid = append(invalid, Limits{TenantBudgets: tooMany})
	for _, limits := range invalid {
		if err := limits.Validate(); err == nil {
			t.Errorf("invalid explicit budgets accepted: %#v", limits)
		}
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "explicit.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	unbudgeted := validEvent(Deny, Denied)
	unbudgeted.TenantID, unbudgeted.ErrorCode = "tenant-b", "policy_denied"
	if _, err := log.Append(unbudgeted); !errors.Is(err, ErrTenantUnbudgeted) {
		t.Fatalf("unbudgeted exact tenant err=%v", err)
	}
	spaced := unbudgeted
	spaced.TenantID = " tenant-b "
	if _, err := log.Append(spaced); err != nil {
		t.Fatalf("exact whitespace-bearing tenant was normalized: %v", err)
	}
}

func TestExplicitTenantBeginReservationIsAtomicAndIsolated(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{TenantBudgets: map[string]int64{
		"tenant-a": minimumTenantBytes,
		"tenant-b": minimumTenantBytes,
	}}
	path := filepath.Join(t.TempDir(), "begin-boundary.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := validEvent(Authorize, Allowed)
	if _, err := log.Begin(first); err != nil {
		t.Fatalf("first tenant-a reservation: %v", err)
	}
	second := first
	second.TaskDigest, _ = TaskDigest("second-a")
	if _, err := log.Begin(second); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("second tenant-a reservation err=%v", err)
	}
	other := first
	other.TenantID = "tenant-b"
	other.TaskDigest, _ = TaskDigest("first-b")
	if _, err := log.Begin(other); err != nil {
		t.Fatalf("tenant-a consumed tenant-b reservation: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Begin(second); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("tenant-a reservation did not survive restart: %v", err)
	}
	thirdB := other
	thirdB.TaskDigest, _ = TaskDigest("second-b")
	if _, err := reopened.Begin(thirdB); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("tenant-b reservation did not survive restart: %v", err)
	}
}

func TestConcurrentBeginsCannotOverdrawFinalTenantReservation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{TenantBudgets: map[string]int64{"tenant-a": minimumTenantBytes}}
	log, err := OpenWithLimits(filepath.Join(t.TempDir(), "concurrent-budget.ndjson"), private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	const contenders = 8
	start := make(chan struct{})
	errorsCh := make(chan error, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			event := validEvent(Authorize, Allowed)
			event.TaskDigest, _ = TaskDigest(fmt.Sprintf("contender-%d", index))
			_, beginErr := log.Begin(event)
			errorsCh <- beginErr
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	succeeded, exhausted := 0, 0
	for beginErr := range errorsCh {
		switch {
		case beginErr == nil:
			succeeded++
		case errors.Is(beginErr, ErrTenantQuotaExceeded):
			exhausted++
		default:
			t.Fatalf("unexpected Begin error: %v", beginErr)
		}
	}
	if succeeded != 1 || exhausted != contenders-1 {
		t.Fatalf("succeeded=%d exhausted=%d", succeeded, exhausted)
	}
}

func TestTenantReceiptQuotaCannotConsumeAnotherTenantSliceAndSurvivesRestart(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxTenants: 2, MaxBytesPerTenant: minimumTenantBytes}
	path := filepath.Join(t.TempDir(), "tenant-quota.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	denial := validEvent(Deny, Denied)
	denial.ErrorCode = "policy_denied"
	successful := 0
	for {
		if _, err := log.Append(denial); errors.Is(err, ErrTenantQuotaExceeded) {
			break
		} else if err != nil {
			t.Fatalf("fill tenant-a after %d records: %v", successful, err)
		}
		successful++
	}
	if successful == 0 {
		t.Fatal("tenant quota rejected an empty slice")
	}
	usedBeforeRestart := log.tenantBytes[denial.TenantID]
	if usedBeforeRestart <= 0 || usedBeforeRestart > limits.MaxBytesPerTenant {
		t.Fatalf("tenant-a usage=%d", usedBeforeRestart)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.tenantBytes[denial.TenantID]; got != usedBeforeRestart {
		t.Fatalf("tenant usage after restart=%d want=%d", got, usedBeforeRestart)
	}
	if _, err := reopened.Append(denial); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("exhausted tenant appended after restart: %v", err)
	}
	other := denial
	other.TenantID = "tenant-b"
	if _, err := reopened.Append(other); err != nil {
		t.Fatalf("tenant-a consumed tenant-b slice: %v", err)
	}
}

func TestTenantIdentitySlotsUseExactHistoricalIdentity(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxTenants: 2, MaxBytesPerTenant: minimumTenantBytes}
	path := filepath.Join(t.TempDir(), "tenant-identities.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	denial := validEvent(Deny, Denied)
	denial.ErrorCode = "policy_denied"
	if _, err := log.Append(denial); err != nil {
		t.Fatal(err)
	}
	spaced := denial
	spaced.TenantID = " tenant-a "
	if _, err := log.Append(spaced); err != nil {
		t.Fatal(err)
	}
	third := denial
	third.TenantID = "tenant-b"
	if _, err := log.Append(third); !errors.Is(err, ErrTenantIdentityCapacity) {
		t.Fatalf("third historical tenant identity err=%v", err)
	}
	if _, err := log.Append(denial); err != nil {
		t.Fatalf("existing tenant lost its identity slot: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Append(third); !errors.Is(err, ErrTenantIdentityCapacity) {
		t.Fatalf("tenant identity slots did not survive restart: %v", err)
	}
}

func TestPendingTerminalReservationIsChargedToTenantAfterRestart(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxTenants: 1, MaxBytesPerTenant: minimumTenantBytes}
	path := filepath.Join(t.TempDir(), "pending-reservation.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wantUsage := info.Size() + terminalReserveBytes
	if got := log.tenantBytes[authorized.TenantID]; got != wantUsage {
		t.Fatalf("live tenant usage=%d want=%d", got, wantUsage)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.tenantBytes[authorized.TenantID]; got != wantUsage {
		t.Fatalf("reconstructed tenant usage=%d want=%d", got, wantUsage)
	}
	terminal := authorized
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
	if _, err := reopened.Finish(terminal); err != nil {
		t.Fatalf("reserved terminal record could not be written: %v", err)
	}
}

func TestOpenWithLimitsRejectsHistoricalLimitViolations(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("identity capacity", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "identities.ndjson")
		log, err := Open(path, private, "node-a/gateway", 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, tenantID := range []string{"tenant-a", "tenant-b"} {
			denial := validEvent(Deny, Denied)
			denial.TenantID, denial.ErrorCode = tenantID, "policy_denied"
			if _, err := log.Append(denial); err != nil {
				t.Fatal(err)
			}
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		limits := Limits{MaxTenants: 1, MaxBytesPerTenant: MaxLogBytes}
		if reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil); !errors.Is(err, ErrTenantIdentityCapacity) {
			if reopened != nil {
				_ = reopened.Close()
			}
			t.Fatalf("historical tenant identities err=%v", err)
		}
	})

	t.Run("tenant bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bytes.ndjson")
		log, err := Open(path, private, "node-a/gateway", 1)
		if err != nil {
			t.Fatal(err)
		}
		denial := validEvent(Deny, Denied)
		denial.ErrorCode = "policy_denied"
		for log.tenantBytes[denial.TenantID] <= minimumTenantBytes {
			if _, err := log.Append(denial); err != nil {
				t.Fatal(err)
			}
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		limits := Limits{MaxTenants: 1, MaxBytesPerTenant: minimumTenantBytes}
		if reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil); !errors.Is(err, ErrTenantQuotaExceeded) {
			if reopened != nil {
				_ = reopened.Close()
			}
			t.Fatalf("historical tenant usage err=%v", err)
		}
	})
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
	invalid := validEvent(Terminal, Responded)
	invalid.HTTPStatus = 0
	if _, err := log.Finish(invalid); err == nil {
		t.Fatal("responded terminal event without status was accepted")
	}
	invalid = validEvent(Deny, Denied)
	if _, err := log.Append(invalid); err == nil {
		t.Fatal("denial without reason was accepted")
	}
	invalid = validEvent(Authorize, Allowed)
	invalid.PermitDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := log.Begin(invalid); err == nil {
		t.Fatal("permit digest without request digest was accepted")
	}
	permitted := validEvent(Authorize, Allowed)
	permitted.AuthorityKeyID = "approver-a"
	permitted.PermitDigest = "sha256:" + strings.Repeat("f", 64)
	permitted.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := log.Begin(permitted); err != nil {
		t.Fatalf("valid permitted authorization rejected: %v", err)
	}
	mismatched := permitted
	mismatched.Phase, mismatched.Outcome, mismatched.HTTPStatus = Terminal, Responded, 200
	mismatched.PermitDigest = "sha256:" + strings.Repeat("1", 64)
	if _, err := log.Finish(mismatched); err == nil {
		t.Fatal("terminal with a different permit digest was accepted")
	}
	terminal := permitted
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(terminal); err != nil {
		t.Fatalf("matching permitted terminal rejected: %v", err)
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

func TestConnectorLedgerPreservesPublicTenantIdentityWhitespace(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tenant-identity.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validEvent(Authorize, Allowed)
	authorized.TenantID = " tenant-a "
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	terminal := authorized
	terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(terminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err != nil {
		t.Fatalf("public tenant identity failed receipt verification: %v", err)
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
