// Package journal provides the small, durable operation journal used to
// reconcile multi-step host mutations after a crash. It deliberately records
// only fixed binary structs: callers must keep any richer operation details in
// their own durable state.
package journal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	// MaxRecordBytes bounds both startup work and the size of one durable intent.
	MaxRecordBytes  = 4096
	maxJournalBytes = 16 << 20
	journalVersion  = 1
)

// State is the only lifecycle vocabulary the journal accepts.
type State byte

const (
	Prepared    State = 1
	Committed   State = 2
	Compensated State = 3
)

// Operation is an immutable prepared operation or a recovered pending one.
type Operation struct {
	Sequence   uint64
	ID         string
	Target     string
	Generation uint64
}

type record struct {
	State State
	Operation
}

// Journal appends fsynced state transitions. A prepared operation that lacks a
// terminal transition is intentionally returned by Pending after restart; the
// owner must reconcile it before admitting a new conflicting mutation.
type Journal struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	next    uint64
	entries map[string]record
}

// Open creates a new owner-only journal or verifies and recovers an existing
// one. A truncated or malformed frame is never silently ignored.
func Open(path string) (*Journal, error) {
	if path == "" {
		return nil, errors.New("journal path is required")
	}
	created := false
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		created = true
	} else if err != nil {
		return nil, fmt.Errorf("stat journal %q: %w", path, err)
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("journal %q must be a regular file with mode 0600 or stricter", path)
	} else if info.Size() > maxJournalBytes {
		return nil, fmt.Errorf("journal %q exceeds %d bytes", path, maxJournalBytes)
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open journal %q: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("chmod journal %q: %w", path, err)
	}
	if created {
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	entries, next, err := scan(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("recover journal %q: %w", path, err)
	}
	return &Journal{path: path, file: f, next: next, entries: entries}, nil
}

// Prepare durably records work before the caller performs an external side
// effect. IDs are unique for the entire retained journal.
func (j *Journal) Prepare(id, target string, generation uint64) (Operation, error) {
	if !validText(id, 256) || !validText(target, 512) || generation == 0 {
		return Operation{}, errors.New("journal operation requires bounded id, target, and positive generation")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, exists := j.entries[id]; exists {
		return Operation{}, fmt.Errorf("journal operation %q already exists", id)
	}
	op := Operation{Sequence: j.next, ID: id, Target: target, Generation: generation}
	if err := j.append(record{State: Prepared, Operation: op}); err != nil {
		return Operation{}, err
	}
	j.entries[id] = record{State: Prepared, Operation: op}
	j.next++
	return op, nil
}

// Commit records that the prepared operation's externally observed end state is
// present. It is deliberately not an idempotent convenience: callers must not
// hide an unexpected duplicate completion.
func (j *Journal) Commit(id string) error { return j.finish(id, Committed) }

// Compensate records that a prepared operation was rolled back or otherwise
// made harmless after a failed step.
func (j *Journal) Compensate(id string) error { return j.finish(id, Compensated) }

func (j *Journal) finish(id string, state State) error {
	if !validText(id, 256) {
		return errors.New("journal operation id is invalid")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	current, ok := j.entries[id]
	if !ok {
		return fmt.Errorf("journal operation %q is unknown", id)
	}
	if current.State != Prepared {
		return fmt.Errorf("journal operation %q is already terminal", id)
	}
	next := current
	next.State = state
	next.Sequence = j.next
	if err := j.append(next); err != nil {
		return err
	}
	j.entries[id] = next
	j.next++
	return nil
}

// Pending returns a stable, sequence-sorted copy of operations that need
// reconciliation. It never returns mutable journal state.
func (j *Journal) Pending() []Operation {
	j.mu.Lock()
	defer j.mu.Unlock()
	pending := make([]Operation, 0)
	for _, entry := range j.entries {
		if entry.State == Prepared {
			pending = append(pending, entry.Operation)
		}
	}
	sort.Slice(pending, func(i, k int) bool { return pending[i].Sequence < pending[k].Sequence })
	return pending
}

// Close releases the journal file. The journal has already fsynced every
// accepted transition, so Close performs no implicit state transition.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func (j *Journal) append(value record) error {
	payload, err := marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > MaxRecordBytes {
		return errors.New("journal record exceeds size limit")
	}
	info, err := j.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(4+len(payload)) > maxJournalBytes {
		return errors.New("journal would exceed size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(j.file, header[:]); err != nil {
		return err
	}
	if err := writeAll(j.file, payload); err != nil {
		return err
	}
	return j.file.Sync()
}

func scan(f *os.File) (map[string]record, uint64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	entries := make(map[string]record)
	var expected uint64 = 1
	for {
		var header [4]byte
		_, err := io.ReadFull(f, header[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read frame header: %w", err)
		}
		size := binary.BigEndian.Uint32(header[:])
		if size == 0 || size > MaxRecordBytes {
			return nil, 0, errors.New("invalid journal frame size")
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(f, payload); err != nil {
			return nil, 0, fmt.Errorf("read journal frame: %w", err)
		}
		value, err := unmarshal(payload)
		if err != nil {
			return nil, 0, err
		}
		if value.Sequence != expected {
			return nil, 0, errors.New("journal sequence is not contiguous")
		}
		if err := apply(entries, value); err != nil {
			return nil, 0, err
		}
		expected++
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, 0, err
	}
	return entries, expected, nil
}

func apply(entries map[string]record, value record) error {
	current, exists := entries[value.ID]
	switch value.State {
	case Prepared:
		if exists {
			return fmt.Errorf("journal operation %q prepared twice", value.ID)
		}
		entries[value.ID] = value
	case Committed, Compensated:
		if !exists || current.State != Prepared || current.Target != value.Target || current.Generation != value.Generation {
			return fmt.Errorf("journal operation %q has invalid terminal transition", value.ID)
		}
		entries[value.ID] = value
	default:
		return errors.New("journal has invalid state")
	}
	return nil
}

// The fixed binary representation intentionally has no optional maps or JSON
// field-name ambiguity. version|state|sequence|generation|id|target.
func marshal(value record) ([]byte, error) {
	if value.Sequence == 0 || !validText(value.ID, 256) || !validText(value.Target, 512) || value.Generation == 0 {
		return nil, errors.New("invalid journal record")
	}
	if value.State != Prepared && value.State != Committed && value.State != Compensated {
		return nil, errors.New("invalid journal state")
	}
	buf := make([]byte, 0, 32+len(value.ID)+len(value.Target))
	buf = append(buf, journalVersion, byte(value.State))
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], value.Sequence)
	buf = append(buf, number[:]...)
	binary.BigEndian.PutUint64(number[:], value.Generation)
	buf = append(buf, number[:]...)
	buf = appendText(buf, value.ID)
	buf = appendText(buf, value.Target)
	return buf, nil
}

func unmarshal(raw []byte) (record, error) {
	if len(raw) < 18 || raw[0] != journalVersion {
		return record{}, errors.New("invalid journal record version")
	}
	value := record{State: State(raw[1])}
	value.Sequence = binary.BigEndian.Uint64(raw[2:10])
	value.Generation = binary.BigEndian.Uint64(raw[10:18])
	var ok bool
	value.ID, raw, ok = takeText(raw[18:])
	if !ok {
		return record{}, errors.New("invalid journal operation id")
	}
	value.Target, raw, ok = takeText(raw)
	if !ok || len(raw) != 0 {
		return record{}, errors.New("invalid journal operation target")
	}
	if _, err := marshal(value); err != nil {
		return record{}, err
	}
	return value, nil
}

func appendText(dst []byte, value string) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func takeText(raw []byte) (string, []byte, bool) {
	if len(raw) < 2 {
		return "", nil, false
	}
	length := int(binary.BigEndian.Uint16(raw[:2]))
	if length == 0 || len(raw) < 2+length {
		return "", nil, false
	}
	value := string(raw[2 : 2+length])
	return value, raw[2+length:], validText(value, 512)
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func writeAll(f *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := f.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
