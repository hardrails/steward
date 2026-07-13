package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func TestLifecycleTaskWritesTaskLocalChainAndSurvivesRestart(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "lifecycle.ndjson")
	limits := Limits{MaxTenants: 1, MaxBytesPerTenant: MinimumLifecycleTenantBytes}
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validLifecycleEvent(Authorize, Allowed)
	if head, err := log.Begin(authorized); err != nil || head.Sequence != 1 || log.reserved != 2*terminalReserveBytes {
		t.Fatalf("authorize head=%#v reserved=%d err=%v", head, log.reserved, err)
	}
	dispatched := validLifecycleDispatch(authorized, "run-0123456789abcdef")
	if head, err := log.Dispatch(dispatched); err != nil || head.Sequence != 2 || log.reserved != terminalReserveBytes {
		t.Fatalf("dispatch head=%#v reserved=%d err=%v", head, log.reserved, err)
	}
	if pending := log.Pending(); len(pending) != 1 || pending[0] != dispatched {
		t.Fatalf("pending dispatch=%#v", pending)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pending := reopened.Pending(); len(pending) != 1 || pending[0] != dispatched || reopened.reserved != terminalReserveBytes {
		_ = reopened.Close()
		t.Fatalf("reconstructed pending=%#v reserved=%d", pending, reopened.reserved)
	}
	terminal := validLifecycleTerminal(dispatched, TaskStatusAgentReportedCompleted)
	head, err := reopened.Finish(terminal)
	if err != nil || head.Sequence != 3 || reopened.reserved != 0 || len(reopened.Pending()) != 0 {
		_ = reopened.Close()
		t.Fatalf("terminal head=%#v reserved=%d pending=%#v err=%v", head, reopened.reserved, reopened.Pending(), err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	var records []VerifiedReceipt
	verified, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	})
	if err != nil || verified != head || len(records) != 3 {
		t.Fatalf("verified=%#v records=%d err=%v", verified, len(records), err)
	}
	for index, record := range records {
		if record.Receipt.SchemaVersion != SchemaV4 || record.Receipt.TaskSequence != uint64(index+1) {
			t.Fatalf("record %d=%#v", index, record.Receipt)
		}
		wantPrevious := zeroHash()
		if index > 0 {
			wantPrevious = records[index-1].Hash
		}
		if record.Receipt.PreviousTaskHash != wantPrevious {
			t.Fatalf("record %d previous task hash=%q want=%q", index, record.Receipt.PreviousTaskHash, wantPrevious)
		}
	}
	if records[1].Receipt.Event.Phase != Dispatch || records[2].Receipt.Event.TaskStatus != TaskStatusAgentReportedCompleted ||
		records[2].Receipt.Event.ResultDigest != terminal.ResultDigest {
		t.Fatalf("lifecycle records=%#v", records)
	}
}

func TestLifecycleTaskDirectFailureUsesTwoRecordChain(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "direct-failure.ndjson")
	limits := Limits{MaxTenants: 1, MaxBytesPerTenant: MinimumLifecycleTenantBytes}
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pending := log.Pending(); len(pending) != 1 || pending[0] != authorized || log.reserved != 2*terminalReserveBytes {
		_ = log.Close()
		t.Fatalf("reconstructed authorization=%#v reserved=%d", pending, log.reserved)
	}
	terminal := authorized
	terminal.Phase, terminal.Outcome, terminal.ErrorCode = Terminal, Failed, "grant_revoked"
	if head, err := log.Finish(terminal); err != nil || head.Sequence != 2 || log.reserved != 0 {
		t.Fatalf("direct terminal head=%#v reserved=%d err=%v", head, log.reserved, err)
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
	if len(records) != 2 || records[1].Receipt.TaskSequence != 2 ||
		records[1].Receipt.PreviousTaskHash != records[0].Hash || records[1].Receipt.Event.RunID != "" {
		t.Fatalf("direct terminal records=%#v", records)
	}
}

func TestLifecycleTaskCanRecordObservationAbandoned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "observation-abandoned.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	authorized := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	dispatched := validLifecycleDispatch(authorized, "run-0123456789abcdef")
	if _, err := log.Dispatch(dispatched); err != nil {
		t.Fatal(err)
	}
	abandoned := dispatched
	abandoned.Phase, abandoned.Outcome = Terminal, Failed
	abandoned.HTTPStatus, abandoned.ResponseBytes, abandoned.ErrorCode = 0, 0, "observation_abandoned"
	if head, err := log.Finish(abandoned); err != nil || head.Sequence != 3 || log.reserved != 0 {
		t.Fatalf("abandoned terminal head=%#v reserved=%d err=%v", head, log.reserved, err)
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
	if len(records) != 3 || records[2].Receipt.Event.ErrorCode != "observation_abandoned" ||
		records[2].Receipt.Event.RunID != dispatched.RunID || records[2].Receipt.Event.TaskStatus != "" {
		t.Fatalf("abandoned lifecycle records=%#v", records)
	}
}

func TestLifecycleTaskRejectsInvalidPhaseTransitions(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "transitions.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	authorized := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	dispatched := validLifecycleDispatch(authorized, "run-0123456789abcdef")
	premature := validLifecycleTerminal(dispatched, TaskStatusAgentReportedCompleted)
	if _, err := log.Finish(premature); err == nil {
		t.Fatal("agent-reported terminal state before dispatch was accepted")
	}
	if head, err := log.Dispatch(dispatched); err != nil || head.Sequence != 2 {
		t.Fatalf("dispatch head=%#v err=%v", head, err)
	}
	if _, err := log.Dispatch(dispatched); err == nil {
		t.Fatal("duplicate lifecycle dispatch was accepted")
	}
	wrongRun := validLifecycleTerminal(dispatched, TaskStatusAgentReportedCompleted)
	wrongRun.RunID = "run-different"
	if _, err := log.Finish(wrongRun); err == nil {
		t.Fatal("terminal state for a different run was accepted")
	}
	terminal := validLifecycleTerminal(dispatched, TaskStatusAgentReportedCompleted)
	if head, err := log.Finish(terminal); err != nil || head.Sequence != 3 {
		t.Fatalf("terminal head=%#v err=%v", head, err)
	}
	if _, err := log.Finish(terminal); err == nil {
		t.Fatal("second lifecycle terminal state was accepted")
	}
}

func TestLifecycleRunIDCannotAliasTasksLiveOrOnRestart(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "run-owner.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	firstDispatch := validLifecycleDispatch(first, "run-shared")
	if _, err := log.Dispatch(firstDispatch); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	second.PermitDigest = "sha256:" + strings.Repeat("5", 64)
	if _, err := log.Begin(second); err != nil {
		t.Fatal(err)
	}
	secondDispatch := validLifecycleDispatch(second, firstDispatch.RunID)
	if _, err := log.Dispatch(secondDispatch); !errors.Is(err, ErrRunIDConflict) {
		t.Fatalf("live duplicate run ID err=%v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ownership := runOwnershipFor(firstDispatch)
	if owner := reopened.runOwners[ownership]; owner != first.TaskDigest {
		t.Fatalf("reconstructed run owner=%q want=%q", owner, first.TaskDigest)
	}
	if _, err := reopened.Dispatch(secondDispatch); !errors.Is(err, ErrRunIDConflict) {
		t.Fatalf("duplicate run ID after restart err=%v", err)
	}
}

func TestVerifyRecordsRejectsSignedDuplicateRunID(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signed-run-conflict.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Dispatch(validLifecycleDispatch(first, "run-shared")); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	second.PermitDigest = "sha256:" + strings.Repeat("5", 64)
	if _, err := log.Begin(second); err != nil {
		t.Fatal(err)
	}
	// Bypass the public transition method to create a correctly signed and
	// globally chained, but semantically invalid, duplicate run record.
	log.mu.Lock()
	_, err = log.appendLocked(validLifecycleDispatch(second, "run-shared"), -terminalReserveBytes)
	log.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); !errors.Is(err, ErrRunIDConflict) {
		t.Fatalf("signed duplicate run ID err=%v", err)
	}
}

func TestLifecycleTaskChainsRemainIndependentWhenInterleaved(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "interleaved.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	first := validLifecycleEvent(Authorize, Allowed)
	second := first
	second.TenantID = "tenant-b"
	second.GrantID = "grant-" + strings.Repeat("f", 64)
	second.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	second.PermitDigest = "sha256:" + strings.Repeat("5", 64)
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Begin(second); err != nil {
		t.Fatal(err)
	}
	firstDispatch := validLifecycleDispatch(first, "run-first")
	secondDispatch := validLifecycleDispatch(second, "run-second")
	if _, err := log.Dispatch(firstDispatch); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Dispatch(secondDispatch); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Finish(validLifecycleTerminal(firstDispatch, TaskStatusAgentReportedCompleted)); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Finish(validLifecycleTerminal(secondDispatch, TaskStatusAgentReportedFailed)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	byTask := make(map[string][]VerifiedReceipt)
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		byTask[record.Receipt.Event.TaskDigest] = append(byTask[record.Receipt.Event.TaskDigest], record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, taskDigest := range []string{first.TaskDigest, second.TaskDigest} {
		records := byTask[taskDigest]
		if len(records) != 3 {
			t.Fatalf("task %q records=%#v", taskDigest, records)
		}
		for index, record := range records {
			wantPrevious := zeroHash()
			if index > 0 {
				wantPrevious = records[index-1].Hash
			}
			if record.Receipt.TaskSequence != uint64(index+1) || record.Receipt.PreviousTaskHash != wantPrevious {
				t.Fatalf("task %q record %d=%#v", taskDigest, index, record.Receipt)
			}
		}
	}
}

func TestLifecycleReservationsAreTenantLocal(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := Limits{TenantBudgets: map[string]int64{
		"tenant-a": MinimumLifecycleTenantBytes,
		"tenant-b": MinimumLifecycleTenantBytes,
	}}
	path := filepath.Join(t.TempDir(), "tenant-reservations.ndjson")
	log, err := OpenWithLimits(path, private, "node-a/gateway", 1, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	first := validLifecycleEvent(Authorize, Allowed)
	if _, err := log.Begin(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	second.PermitDigest = "sha256:" + strings.Repeat("5", 64)
	if _, err := log.Begin(second); !errors.Is(err, ErrTenantQuotaExceeded) {
		t.Fatalf("tenant borrowed another tenant's lifecycle reserve: %v", err)
	}
	other := second
	other.TenantID = "tenant-b"
	if _, err := log.Begin(other); err != nil {
		t.Fatalf("independent tenant reserve was unavailable: %v", err)
	}
}

func TestConnectorLedgerReadsMixedV3AndLifecycleV4(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mixed-v3-v4.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	legacy := validServiceTaskEvent(Authorize, Allowed)
	if _, err := log.Begin(legacy); err != nil {
		t.Fatal(err)
	}
	legacyTerminal := legacy
	legacyTerminal.Phase, legacyTerminal.Outcome, legacyTerminal.HTTPStatus = Terminal, Responded, 201
	legacyTerminal.ResponseBytes, legacyTerminal.RunID = 41, "run-legacy"
	if _, err := log.Finish(legacyTerminal); err != nil {
		t.Fatal(err)
	}
	lifecycle := validLifecycleEvent(Authorize, Allowed)
	lifecycle.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	lifecycle.PermitDigest = "sha256:" + strings.Repeat("5", 64)
	if _, err := log.Begin(lifecycle); err != nil {
		t.Fatal(err)
	}
	dispatch := validLifecycleDispatch(lifecycle, "run-lifecycle")
	if _, err := log.Dispatch(dispatch); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Finish(validLifecycleTerminal(dispatch, TaskStatusAgentReportedFailed)); err != nil {
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
	want := []string{SchemaV3, SchemaV3, SchemaV4, SchemaV4, SchemaV4}
	if len(schemas) != len(want) {
		t.Fatalf("schemas=%v", schemas)
	}
	for index := range want {
		if schemas[index] != want[index] {
			t.Fatalf("schemas=%v want=%v", schemas, want)
		}
	}
}

func TestLegacyReceiptJSONOmitsLifecycleCoordinates(t *testing.T) {
	event := validServiceTaskEvent(Authorize, Allowed)
	receipt := Receipt{
		SchemaVersion: SchemaV3,
		NodeID:        "node-a/gateway", Epoch: 1, Sequence: 1, PreviousHash: zeroHash(),
		ObservedAt: "2026-07-13T12:00:00Z", Event: event,
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	eventRaw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"` + SchemaV3 + `","node_id":"node-a/gateway","epoch":1,"sequence":1,"previous_hash":"` +
		zeroHash() + `","observed_at":"2026-07-13T12:00:00Z","event":` + string(eventRaw) + `}`
	if string(raw) != want {
		t.Fatalf("legacy receipt JSON changed\n got: %s\nwant: %s", raw, want)
	}
	receipt.TaskSequence, receipt.PreviousTaskHash = 1, zeroHash()
	if err := validateReceipt(receipt, PayloadTypeV3, "node-a/gateway", 1, 1, zeroHash()); err == nil ||
		!strings.Contains(err.Error(), "legacy connector receipt contains task-chain coordinates") {
		t.Fatalf("legacy receipt accepted lifecycle coordinates: %v", err)
	}
}

func TestVerifyRecordsRejectsSignedInvalidTaskCoordinates(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		sequence uint64
		previous string
	}{
		{name: "first sequence is not one", sequence: 2, previous: zeroHash()},
		{name: "first previous hash is not zero", sequence: 1, previous: "sha256:" + strings.Repeat("1", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid-task-chain.ndjson")
			receipt := Receipt{
				SchemaVersion: SchemaV4,
				NodeID:        "node-a/gateway", Epoch: 1, Sequence: 1, PreviousHash: zeroHash(),
				ObservedAt: "2026-07-13T12:00:00Z", Event: validLifecycleEvent(Authorize, Allowed),
				TaskSequence: test.sequence, PreviousTaskHash: test.previous,
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := dsse.Sign(PayloadTypeV4, payload, KeyID(public), private)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := dsse.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil ||
				!strings.Contains(err.Error(), "task-chain coordinates do not match") {
				t.Fatalf("signed invalid task coordinates err=%v", err)
			}
		})
	}
}

func validLifecycleEvent(phase Phase, outcome Outcome) Event {
	event := validServiceTaskEvent(phase, outcome)
	event.TaskProtocol = TaskProtocolLifecycleV1
	return event
}

func validLifecycleDispatch(authorized Event, runID string) Event {
	event := authorized
	event.Phase, event.Outcome = Dispatch, Responded
	event.HTTPStatus, event.ResponseBytes, event.RunID = 202, 47, runID
	return event
}

func validLifecycleTerminal(dispatched Event, status TaskStatus) Event {
	event := dispatched
	event.Phase, event.Outcome = Terminal, Responded
	event.HTTPStatus, event.ResponseBytes, event.TaskStatus = 200, 83, status
	event.ResultDigest = "sha256:" + strings.Repeat("9", 64)
	return event
}
