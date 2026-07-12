package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// stateVersion is the on-disk format version. It is written into every snapshot
// and checked on load, so a future incompatible format change is detected and
// rejected (fail-closed) rather than silently mis-parsed.
const stateVersion = 1

const maxStateHeaderBytes = 4096

// StateFormatSummary reports the canonical version header physically observed
// in an existing supervisor state snapshot.
type StateFormatSummary struct {
	Present       bool
	FormatVersion int
}

// snapshot is the on-disk representation of a Tracker's state: the format
// version plus every currently tracked instance. The byID index is not stored;
// it is rebuilt from the instances on load, so the file cannot carry an index
// that disagrees with its own instances.
type snapshot struct {
	Version   int        `json:"version"`
	Instances []Instance `json:"instances"`
}

// InspectStateFormat reads only the bounded canonical header written by
// saveSnapshot. It deliberately does not load instances or reconcile process
// state, so upgrade inspection cannot mutate runtime state or act on PIDs.
func InspectStateFormat(path string) (StateFormatSummary, error) {
	if path == "" {
		return StateFormatSummary{}, errors.New("supervisor state path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q is missing", path)
	}
	if err != nil {
		return StateFormatSummary{}, fmt.Errorf("stat supervisor state %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() == 0 {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q must be a non-empty owner-only regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return StateFormatSummary{}, fmt.Errorf("open supervisor state %q for format inspection: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return StateFormatSummary{}, fmt.Errorf("stat opened supervisor state %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() == 0 {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q changed while it was opened for format inspection", path)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateHeaderBytes))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q has an invalid format header", path)
	}
	key, err := decoder.Token()
	if err != nil || key != "version" {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q does not begin with its canonical version header", path)
	}
	var version int
	if err := decoder.Decode(&version); err != nil || version <= 0 {
		return StateFormatSummary{}, fmt.Errorf("supervisor state %q has an invalid format version", path)
	}
	return StateFormatSummary{Present: true, FormatVersion: version}, nil
}

// LoadTracker returns a tracker bound to stateFile for durable state.
//
// If stateFile is empty, persistence is disabled and the result is identical to
// NewTracker: an in-memory-only tracker whose mutations are never written to
// disk. This is the default, unchanged behavior.
//
// If stateFile is non-empty:
//   - a missing file is treated as a first run: the tracker starts empty and no
//     error is returned (the file is created on the first mutation);
//   - an existing, well-formed file repopulates both the byRef and byID indexes
//     before this call returns, so the server can start serving fully restored
//     state;
//   - an existing file that is unreadable or malformed is a fatal, fail-closed
//     error whose message names the path and the fix, rather than silently
//     starting empty or panicking.
func LoadTracker(maxInstances int, stateFile string, opts ...Option) (*Tracker, error) {
	t := newTracker(maxInstances, stateFile, opts...)
	if stateFile == "" {
		return t, nil
	}
	if err := t.load(); err != nil {
		return nil, err
	}
	return t, nil
}

// load reads and validates t.stateFile, replacing the tracker's indexes with the
// file's contents. A missing file is not an error (first run). Callers hold no
// lock: load runs during construction, before the tracker is shared.
func (t *Tracker) load() error {
	data, err := os.ReadFile(t.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil // first run: the file is created on the first mutation.
	}
	if err != nil {
		return fmt.Errorf("read state file %q: %w (fix its permissions, or start with a fresh -state-file path)", t.stateFile, err)
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("state file %q is not valid Steward state JSON: %w (delete or repair the file, or start with a fresh -state-file path)", t.stateFile, err)
	}
	if snap.Version != stateVersion {
		return fmt.Errorf("state file %q has unsupported format version %d; this build reads version %d (delete the file, or start with a fresh -state-file path)", t.stateFile, snap.Version, stateVersion)
	}

	byRef := make(map[string]*Instance, len(snap.Instances))
	byID := make(map[string]string, len(snap.Instances))
	for _, inst := range snap.Instances {
		switch {
		case inst.InstanceID == "":
			return t.corruptErr("an instance is missing instance_id")
		case inst.RuntimeRef == "":
			return t.corruptErr(fmt.Sprintf("instance %q is missing runtime_ref", inst.InstanceID))
		case !inst.Status.Valid():
			return t.corruptErr(fmt.Sprintf("instance %q has unknown status %q", inst.InstanceID, inst.Status))
		case inst.Generation < 0:
			return t.corruptErr(fmt.Sprintf("instance %q has a negative generation %d", inst.InstanceID, inst.Generation))
		case inst.PID < 0:
			return t.corruptErr(fmt.Sprintf("instance %q has a negative pid %d", inst.InstanceID, inst.PID))
		case len(inst.Spec) > 0 && !IsJSONObject(inst.Spec):
			return t.corruptErr(fmt.Sprintf("instance %q has a non-object spec", inst.InstanceID))
		}
		if _, dup := byRef[inst.RuntimeRef]; dup {
			return t.corruptErr(fmt.Sprintf("duplicate runtime_ref %q", inst.RuntimeRef))
		}
		if _, dup := byID[inst.InstanceID]; dup {
			return t.corruptErr(fmt.Sprintf("duplicate instance_id %q", inst.InstanceID))
		}
		stored := inst.clone()
		byRef[stored.RuntimeRef] = stored
		byID[stored.InstanceID] = stored.RuntimeRef
	}

	// maxInstances is a DoS circuit-breaker on *growth*, not on reload: a file
	// that already holds more instances than the cap (e.g. written by a prior run
	// with a higher cap) is honored in full rather than silently truncated, and
	// new provisions stay blocked until the count drops back under the cap.
	t.byRef = byRef
	t.byID = byID

	// When process execution is enabled, reconcile any instance recorded as running a
	// real process against reality: a restart severed every process handle, so probe
	// the stored pid and either reattach (alive, degraded) or transition to STOPPED
	// (gone). See reconcileProcessesAfterLoad. When exec is disabled the loaded state
	// is honored verbatim — a state file written by a prior exec-enabled run loads as
	// plain data, its processes untouched.
	if t.execEnabled {
		t.reconcileProcessesAfterLoad()
	}
	return nil
}

// CheckDurableWritable reports whether this tracker can still durably persist a
// mutation, for the GET /v1/readiness gate. It is a no-op returning nil when no
// state file is configured (the in-memory default persists nothing, so there is
// nothing that can be un-writable).
//
// When a state file is configured it verifies the exact capability persistence
// depends on — creating a file in the state file's directory and (implicitly,
// via the OS) being able to rename it — by creating a uniquely-named probe temp
// file there and removing it immediately. This is what catches the failures a
// liveness probe deliberately does not (a directory gone read-only, a full or
// unmounted filesystem): saveSnapshot writes a temp file in this same directory
// and renames it over the state path, so if a temp file cannot be created here,
// the next real mutation's persist would fail and roll back too.
//
// The probe never races that atomic-rename persistence discipline: it uses a
// DISTINCT temp-file prefix (".steward-ready-*") from saveSnapshot's
// (".steward-state-*") and removes its own file, while saveSnapshot only ever
// creates and renames its own uniquely-named temp — neither enumerates or
// touches the other's files. It takes no lock: stateFile is fixed at
// construction, and a create-then-remove of a private temp name is independent
// of the live byRef/byID maps a mutation guards. This is why the liveness probe
// (handleHealthz) still refuses to do it — it is a readiness concern, run at a
// lower cadence, not a hot-path liveness one.
func (t *Tracker) CheckDurableWritable() error {
	if t.stateFile == "" {
		return nil
	}
	dir := filepath.Dir(t.stateFile)
	f, err := os.CreateTemp(dir, ".steward-ready-*.tmp")
	if err != nil {
		return fmt.Errorf("state directory %q is not writable: %w (fix its permissions or free space, or the next durable mutation will fail)", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// corruptErr builds a uniform fail-closed error for a structurally invalid state
// file, always naming the path and the remedy so the message passes the 3am
// test.
func (t *Tracker) corruptErr(detail string) error {
	return fmt.Errorf("state file %q is corrupt: %s (delete or repair the file, or start with a fresh -state-file path)", t.stateFile, detail)
}

// persistLocked writes the current tracker state to the configured state file.
// It is a no-op when no state file is configured (the in-memory default).
//
// It runs inside the tracker's single mutex, called by each mutating operation
// while that operation still holds the lock. Persisting under the lock is the
// simplest correct choice at this codebase's scale (a small in-memory map): it
// makes each mutation and its durable record atomic with respect to every other
// operation, so the file can never lag behind or race ahead of memory. Doing the
// write outside the lock would reintroduce exactly that ordering gap — two
// interleaved mutations could persist their snapshots out of order and leave the
// file reflecting an older state than memory. If the map ever grows large enough
// that a per-mutation disk write under the lock measurably stalls concurrent
// requests, revisit this with a copy-out-then-write-outside-the-lock scheme; it
// is not warranted today.
func (t *Tracker) persistLocked() error {
	if t.stateFile == "" {
		return nil
	}
	return saveSnapshot(t.stateFile, t.snapshotLocked())
}

// snapshotLocked builds a serializable snapshot of the tracker's live state.
// Callers must hold t.mu. Instances are deep-cloned so the snapshot never
// aliases live spec bytes, and sorted by runtime_ref so the on-disk file is
// deterministic (stable diffs, reproducible tests).
func (t *Tracker) snapshotLocked() snapshot {
	insts := make([]Instance, 0, len(t.byRef))
	for _, inst := range t.byRef {
		insts = append(insts, *inst.clone())
	}
	sort.Slice(insts, func(i, j int) bool { return insts[i].RuntimeRef < insts[j].RuntimeRef })
	return snapshot{Version: stateVersion, Instances: insts}
}

// saveSnapshot writes snap to path atomically: it marshals to a temp file in the
// same directory, fsyncs it, then renames it over path. os.Rename is atomic on a
// single filesystem, so a process that dies mid-write leaves either the intact
// previous file or the untouched temp file — never a half-written file readable
// as current state. The temp file lives in path's own directory (not os.TempDir)
// precisely so the rename stays within one filesystem; a cross-device rename is
// not atomic. On any failure the temp file is removed and the previous state
// file is left untouched.
func saveSnapshot(path string, snap snapshot) (err error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Disable HTML escaping so a spec containing <, >, or & is stored as-is rather
	// than rewritten to < etc. Compact (no SetIndent) means an already-compact
	// spec round-trips byte-for-byte; only insignificant JSON whitespace inside a
	// spec is normalized. Encode appends a trailing newline.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(snap); err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data := buf.Bytes()

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".steward-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Remove the temp file on every error path below. On success it has been
	// renamed away, so the Remove is a harmless no-op guarded by err == nil.
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp state file %q: %w", tmpName, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp state file %q: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file %q: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp state file over %q: %w", path, err)
	}
	return nil
}

// Valid reports whether s is one of the known lifecycle statuses. It gates
// loaded state so a corrupt or hand-edited file cannot inject an unknown
// status, and is exported so the HTTP layer can validate a caller-supplied
// `status` filter value the same way (one definition, not two copies that
// could drift).
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusStopped, StatusHibernated, StatusDestroyed, StatusFailed:
		return true
	default:
		return false
	}
}

// IsJSONObject reports whether raw (already-validated JSON) is a JSON object.
// json.RawMessage unmarshaling guarantees raw is well-formed JSON, so inspecting
// the first non-whitespace byte is sufficient. It is exported so the inbound REST
// handler and the outbound uplink client enforce the *same* "spec must be a JSON
// object" contract from one definition rather than two copies that could drift.
func IsJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}
