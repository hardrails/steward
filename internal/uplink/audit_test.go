package uplink

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAuditLoggerRecordAppendsWellFormedJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	if err := al.Record("cmd-1", "agent-1", kindProvision, "success", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := al.Record("cmd-2", "agent-2", kindStop, "failure", "unknown instance"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records := readAuditRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2:\n%+v", len(records), records)
	}
	if r := records[0]; r.CommandID != "cmd-1" || r.InstanceID != "agent-1" || r.Kind != kindProvision || r.Status != "success" || r.Error != "" {
		t.Fatalf("record 0 = %+v, want command_id=cmd-1 instance_id=agent-1 kind=provision status=success error=\"\"", r)
	}
	if records[0].Timestamp.IsZero() {
		t.Error("record 0 has a zero timestamp")
	}
	if r := records[1]; r.CommandID != "cmd-2" || r.Status != "failure" || r.Error != "unknown instance" {
		t.Fatalf("record 1 = %+v, want command_id=cmd-2 status=failure error=\"unknown instance\"", r)
	}
}

// TestAuditLoggerOmitsErrorFieldOnSuccess pins the JSON shape contract: the
// `error` key is entirely absent (omitempty), not present-and-empty, on a
// success record — a consumer that greps for the key's presence to detect a
// failure must not be fooled by an empty-string error on a success line.
func TestAuditLoggerOmitsErrorFieldOnSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	if err := al.Record("cmd-1", "agent-1", kindProvision, "success", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if strings.Contains(line, `"error"`) {
		t.Errorf("success record must omit the error key entirely, got: %s", line)
	}
}

// TestAuditLoggerAppendsAcrossReopens proves NewAuditLogger opens with
// O_APPEND, not O_TRUNC: a second logger instance over the same path (the
// shape a process restart takes) must add to the existing file, never
// silently discard it — the same "never lose durable history" expectation
// persist.go's atomic-rename discipline gives the state file, achieved here
// by a different mechanism (append-only, see audit.go's doc comment) rather
// than temp-file-then-rename.
func TestAuditLoggerAppendsAcrossReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	first, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger (first): %v", err)
	}
	if err := first.Record("cmd-1", "agent-1", kindProvision, "success", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger (second, reopening an existing file): %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.Record("cmd-2", "agent-2", kindStop, "success", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records := readAuditRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records after reopening, want 2 (the first record must survive the reopen)", len(records))
	}
	if records[0].CommandID != "cmd-1" || records[1].CommandID != "cmd-2" {
		t.Fatalf("records = %+v, want cmd-1 then cmd-2 in order", records)
	}
}

// TestAuditLoggerConcurrentRecordsNeverInterleave is the torn-write-tolerance
// proof: many goroutines calling Record concurrently on one AuditLogger must
// never produce a corrupt/merged line — every line in the file must parse as
// exactly one well-formed JSON object, and every one of the N records issued
// must be present. This is the append-only analog of the state file's
// crash-safety tests: there the mechanism is temp-file-then-rename, here it
// is O_APPEND plus one os.File.Write call per record under Go's own mutex
// (see audit.go's doc comment) — a different mechanism proving the same
// "never a torn/interleaved record" property. Run with -race, as CI's `go
// test -race ./...` already does for this package.
func TestAuditLoggerConcurrentRecordsNeverInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	al, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Close() }()

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A long instance_id maximizes the chance an interleaved/torn write
			// would be caught: more bytes per record means more opportunity for
			// two concurrent Write calls to visibly corrupt each other's line if
			// the append discipline were not actually atomic per-call.
			instanceID := strings.Repeat("x", 200)
			if err := al.Record("cmd", instanceID, kindProvision, "success", ""); err != nil {
				t.Errorf("Record(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %d is not valid JSON (a torn/interleaved write): %v\nline: %s", count, err, line)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != n {
		t.Fatalf("got %d well-formed records, want %d (every concurrent Record call must produce exactly one intact line)", count, n)
	}
}

func TestAuditLoggerNilIsInertNoOp(t *testing.T) {
	var al *AuditLogger
	if err := al.Record("cmd-1", "agent-1", kindProvision, "success", ""); err != nil {
		t.Errorf("Record on a nil *AuditLogger: got err %v, want nil (a no-op)", err)
	}
	if err := al.Close(); err != nil {
		t.Errorf("Close on a nil *AuditLogger: got err %v, want nil (a no-op)", err)
	}
}

func TestNewAuditLoggerFailsClosedOnUnwritablePath(t *testing.T) {
	// A path inside a nonexistent directory: os.OpenFile with O_CREATE cannot
	// create intermediate directories, so this must fail, naming the path.
	path := filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")
	_, err := NewAuditLogger(path)
	if err == nil {
		t.Fatal("expected an error opening an audit log file in a nonexistent directory, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path %q", err.Error(), path)
	}
}
