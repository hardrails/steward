package uplink

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLogger appends one JSON-lines record per executed uplink command to a
// file, for an operator who wants a durable, greppable trail of what commands
// this node executed and whether each succeeded or failed. It is optional
// (see cmd/steward's -audit-log-file flag): a nil *AuditLogger is a valid,
// disabled state, and Record/Close are both nil-safe so a caller never needs
// to branch on whether auditing is enabled.
//
// Records are appended, never rewritten — this is a different durability
// mechanism than internal/runtime's state-file persistence (see persist.go's
// saveSnapshot), and deliberately so: the state file is a small snapshot
// rewritten in full on every mutation, for which temp-file-then-rename is the
// right atomic-replace primitive; an audit log grows without bound by
// appending one record at a time, for which rewriting the whole file on every
// append would be O(n) per record and pointless I/O. The torn-write tolerance
// this file cares about is achieved a different way: the file is opened with
// O_APPEND, and each record is written with exactly one os.File.Write call
// (see Record) — POSIX guarantees a single write() to a file opened O_APPEND
// is atomic with respect to any OTHER writer appending to the same file, so
// two records can never interleave into a corrupt line, and a process that
// dies mid-write can only ever truncate its OWN last, in-flight record, never
// an earlier one that already completed its Write call. A reader must
// tolerate a malformed trailing line for exactly that reason.
type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

// auditRecord is one JSON-lines record: a command's terminal (reported)
// outcome.
type auditRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	CommandID  string    `json:"command_id,omitempty"`
	InstanceID string    `json:"instance_id"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
}

// NewAuditLogger opens path for appending, creating it (and no intermediate
// directories — same expectation as -state-file) if it does not already
// exist, and returns an AuditLogger writing to it. The file is opened once
// and held open for the caller's lifetime (see Close); every Record call
// appends to it without reopening. A failure to open is a fail-closed
// startup error naming the path and the fix, the same discipline
// runtime.LoadTracker and LoadCredential apply to their own files.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log file %q: %w (fix its path or permissions, or drop -audit-log-file to disable command auditing)", path, err)
	}
	return &AuditLogger{file: f}, nil
}

// Close closes the underlying file. Safe to call on a nil *AuditLogger
// (auditing disabled), returning nil.
func (a *AuditLogger) Close() error {
	if a == nil {
		return nil
	}
	return a.file.Close()
}

// Record appends one audit record for a command's terminal outcome. Safe to
// call on a nil *AuditLogger (auditing disabled): the call is then a no-op
// returning nil, so a caller never needs to branch on whether auditing is
// enabled before calling Record.
//
// status is expected to be "success" or "failure" (the vocabulary the audit
// log itself defines, distinct from the wire report's done/failed strings —
// see dispatcher.auditRecord, the one caller). errDetail is included only for
// a failure and is otherwise omitted from the JSON line (the `error` field is
// `omitempty`).
func (a *AuditLogger) Record(commandID, instanceID, kind, status, errDetail string) error {
	if a == nil {
		return nil
	}
	rec := auditRecord{
		Timestamp:  time.Now().UTC(),
		CommandID:  commandID,
		InstanceID: instanceID,
		Kind:       kind,
		Status:     status,
		Error:      errDetail,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal audit record: %w", err)
	}
	data = append(data, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.file.Write(data); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}
