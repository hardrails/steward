package controlstore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
)

const (
	currentName = "CURRENT"
	lockName    = "LOCK"
)

// Store is a single-writer durable control-plane state machine. A successful
// mutation is published to readers only after its hash-chained WAL frame is
// synced to stable storage.
type Store struct {
	mu sync.Mutex
	// evidenceReportMu protects only bounded in-memory challenge consumption.
	// Durable controller state remains under mu so expensive receipt verification
	// can be serialized per credential without blocking unrelated store readers.
	evidenceReportMu sync.Mutex
	evidenceReports  map[string]*executorEvidenceReportGate
	// evidenceLastReports is a bounded, non-authoritative freshness cache under
	// mu. It is intentionally not serialized so an older binary can reopen
	// state after an installer rollback.
	evidenceLastReports map[string]time.Time

	dir        string
	limits     Limits
	lock       *os.File
	wal        *os.File
	generation uint64
	sequence   uint64
	lastHash   [sha256.Size]byte
	current    state
	poisoned   bool
	closed     bool

	syncFile func(*os.File) error
}

// Status is a bounded readiness summary. It intentionally contains no tenant
// identifiers, credentials, enrollment capabilities, or command bytes.
type Status struct {
	Generation  uint64 `json:"generation"`
	Sequence    uint64 `json:"sequence"`
	Tenants     int    `json:"tenants"`
	Nodes       int    `json:"nodes"`
	Credentials int    `json:"credentials"`
	Enrollments int    `json:"enrollments"`
	Commands    int    `json:"commands"`
	Deployments int    `json:"deployments"`
	Events      int    `json:"instance_events"`
}

// Initialize exclusively creates an empty store in an owner-only directory.
// It refuses to adopt partial or existing state.
func Initialize(directory string, limits Limits) (*Store, error) {
	directory, err := prepareDirectory(directory, true)
	if err != nil {
		return nil, err
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	lock, err := acquireLock(directory)
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			releaseLock(lock)
		}
	}()
	initialized, err := containsStateArtifacts(directory)
	if err != nil {
		return nil, err
	}
	if initialized {
		return nil, ErrAlreadyInitialized
	}

	initial := emptyState()
	payload, err := encodeState(initial, limits.MaxStateBytes)
	if err != nil {
		return nil, err
	}
	snapshotRaw, err := marshalSnapshot(snapshotEnvelope{Generation: 1, Payload: payload})
	if err != nil {
		return nil, err
	}
	walRaw, err := marshalWALHeader(walHeader{Generation: 1})
	if err != nil {
		return nil, err
	}
	currentRaw := marshalManifest(manifest{
		Generation: 1, SnapshotHash: hashBytes(snapshotRaw), WALHeaderHash: hashBytes(walRaw),
	})
	if err := writeExclusiveArtifact(directory, generationName("snapshot", 1), snapshotRaw); err != nil {
		return nil, fmt.Errorf("initialize control snapshot: %w", err)
	}
	if err := writeExclusiveArtifact(directory, generationName("wal", 1), walRaw); err != nil {
		return nil, fmt.Errorf("initialize control WAL: %w", err)
	}
	if err := writeExclusiveArtifact(directory, currentName, currentRaw); err != nil {
		return nil, fmt.Errorf("initialize control manifest: %w", err)
	}
	wal, _, err := openWALArtifact(filepath.Join(directory, generationName("wal", 1)), limits.MaxWALBytes)
	if err != nil {
		return nil, err
	}
	keepLock = true
	return &Store{
		dir: directory, limits: limits, lock: lock, wal: wal, generation: 1,
		current: initial, evidenceLastReports: make(map[string]time.Time),
		syncFile: func(file *os.File) error { return file.Sync() },
	}, nil
}

// Open acquires the exclusive writer lock, verifies the manifest and snapshot,
// replays complete WAL frames, and truncates only an incomplete final frame.
func Open(directory string, limits Limits) (*Store, error) {
	directory, err := prepareDirectory(directory, false)
	if err != nil {
		return nil, err
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	lock, err := acquireLock(directory)
	if err != nil {
		return nil, err
	}
	keepLock := false
	defer func() {
		if !keepLock {
			releaseLock(lock)
		}
	}()

	manifestRaw, err := readArtifact(filepath.Join(directory, currentName), manifestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read control manifest: %w", err)
	}
	selected, err := unmarshalManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	snapshotPath := filepath.Join(directory, generationName("snapshot", selected.Generation))
	snapshotRaw, err := readArtifact(snapshotPath, snapshotHeaderBytes+limits.MaxStateBytes)
	if err != nil {
		return nil, fmt.Errorf("read control snapshot: %w", err)
	}
	if digest := hashBytes(snapshotRaw); !bytes.Equal(digest[:], selected.SnapshotHash[:]) {
		return nil, errors.New("control snapshot does not match CURRENT")
	}
	snapshot, err := unmarshalSnapshot(snapshotRaw, limits.MaxStateBytes)
	if err != nil {
		return nil, err
	}
	if snapshot.Generation != selected.Generation {
		return nil, errors.New("control snapshot generation does not match CURRENT")
	}
	current, err := decodeState(snapshot.Payload, limits.MaxStateBytes)
	if err != nil {
		return nil, fmt.Errorf("decode control snapshot: %w", err)
	}
	if err := validateState(current, limits); err != nil {
		return nil, formatStateError(err)
	}

	walPath := filepath.Join(directory, generationName("wal", selected.Generation))
	wal, size, err := openWALArtifact(walPath, limits.MaxWALBytes)
	if err != nil {
		return nil, err
	}
	keepWAL := false
	defer func() {
		if !keepWAL {
			_ = wal.Close()
		}
	}()
	if size < walHeaderBytes {
		return nil, errors.New("control WAL is shorter than its header")
	}
	headerRaw := make([]byte, walHeaderBytes)
	if _, err := wal.ReadAt(headerRaw, 0); err != nil {
		return nil, fmt.Errorf("read control WAL header: %w", err)
	}
	if digest := hashBytes(headerRaw); !bytes.Equal(digest[:], selected.WALHeaderHash[:]) {
		return nil, errors.New("control WAL header does not match CURRENT")
	}
	header, err := unmarshalWALHeader(headerRaw)
	if err != nil {
		return nil, err
	}
	if header.Generation != snapshot.Generation || header.Sequence != snapshot.Sequence ||
		!bytes.Equal(header.LastHash[:], snapshot.LastHash[:]) {
		return nil, errors.New("control WAL header does not continue its snapshot")
	}
	current, sequence, lastHash, err := recoverWAL(wal, size, current, header.Sequence, header.LastHash, limits)
	if err != nil {
		return nil, err
	}
	if err := validateRecoveredExecutorReportV4Bindings(current); err != nil {
		return nil, formatStateError(err)
	}
	if err := validateRecoveredEvidenceCaptures(current); err != nil {
		return nil, formatStateError(err)
	}
	if _, err := wal.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("seek control WAL: %w", err)
	}
	keepLock, keepWAL = true, true
	return &Store{
		dir: directory, limits: limits, lock: lock, wal: wal, generation: selected.Generation,
		sequence: sequence, lastHash: lastHash, current: current,
		evidenceLastReports: make(map[string]time.Time),
		syncFile:            func(file *os.File) error { return file.Sync() },
	}, nil
}

// InspectRoot validates read-only Control state beneath a retained directory
// root and returns its
// recovered status without acquiring a pathname-based lock or repairing data.
// It is intended for backup restoration. An incomplete WAL tail is rejected
// rather than changed, and every artifact open rejects final-component links.
func InspectRoot(root *os.Root, limits Limits) (Status, error) {
	if root == nil {
		return Status{}, errors.New("control state root is required")
	}
	if err := limits.Validate(); err != nil {
		return Status{}, err
	}
	manifestRaw, err := readRootArtifact(root, currentName, manifestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Status{}, ErrNotInitialized
	}
	if err != nil {
		return Status{}, fmt.Errorf("read control manifest: %w", err)
	}
	selected, err := unmarshalManifest(manifestRaw)
	if err != nil {
		return Status{}, err
	}
	snapshotRaw, err := readRootArtifact(root, generationName("snapshot", selected.Generation), snapshotHeaderBytes+limits.MaxStateBytes)
	if err != nil {
		return Status{}, fmt.Errorf("read control snapshot: %w", err)
	}
	if digest := hashBytes(snapshotRaw); !bytes.Equal(digest[:], selected.SnapshotHash[:]) {
		return Status{}, errors.New("control snapshot does not match CURRENT")
	}
	snapshot, err := unmarshalSnapshot(snapshotRaw, limits.MaxStateBytes)
	if err != nil {
		return Status{}, err
	}
	if snapshot.Generation != selected.Generation {
		return Status{}, errors.New("control snapshot generation does not match CURRENT")
	}
	current, err := decodeState(snapshot.Payload, limits.MaxStateBytes)
	if err != nil {
		return Status{}, fmt.Errorf("decode control snapshot: %w", err)
	}
	if err := validateState(current, limits); err != nil {
		return Status{}, formatStateError(err)
	}

	wal, size, err := openRootArtifact(root, generationName("wal", selected.Generation), limits.MaxWALBytes)
	if err != nil {
		return Status{}, err
	}
	defer wal.Close()
	if size < walHeaderBytes {
		return Status{}, errors.New("control WAL is shorter than its header")
	}
	headerRaw := make([]byte, walHeaderBytes)
	if _, err := wal.ReadAt(headerRaw, 0); err != nil {
		return Status{}, fmt.Errorf("read control WAL header: %w", err)
	}
	if digest := hashBytes(headerRaw); !bytes.Equal(digest[:], selected.WALHeaderHash[:]) {
		return Status{}, errors.New("control WAL header does not match CURRENT")
	}
	header, err := unmarshalWALHeader(headerRaw)
	if err != nil {
		return Status{}, err
	}
	if header.Generation != snapshot.Generation || header.Sequence != snapshot.Sequence ||
		!bytes.Equal(header.LastHash[:], snapshot.LastHash[:]) {
		return Status{}, errors.New("control WAL header does not continue its snapshot")
	}
	current, sequence, _, err := recoverWALReader(wal, size, current, header.Sequence, header.LastHash, limits, nil)
	if err != nil {
		return Status{}, err
	}
	if err := validateRecoveredExecutorReportV4Bindings(current); err != nil {
		return Status{}, formatStateError(err)
	}
	if err := validateRecoveredEvidenceCaptures(current); err != nil {
		return Status{}, formatStateError(err)
	}
	return Status{
		Generation: selected.Generation, Sequence: sequence, Tenants: len(current.tenants),
		Nodes: len(current.nodes), Credentials: len(current.credentials), Enrollments: len(current.enrollments),
		Commands: len(current.commands), Deployments: len(current.deployments), Events: len(current.events),
	}, nil
}

// validateRecoveredExecutorReportV4Bindings authenticates each retained
// successful canary exactly once after the snapshot and WAL have converged on
// their final state. Hash-chain validation plus the cheap per-mutation binding
// checks protect replay; repeating Ed25519 verification for every intermediate
// state would make unrelated recovery work scale with retained canaries.
func validateRecoveredExecutorReportV4Bindings(current state) error {
	for _, command := range current.commands {
		if command.CommandKind != "activation-canary" ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
			command.State != CommandTerminal || command.Terminal == nil ||
			command.Terminal.Report.Status != controlprotocol.ExecutorStatusDone {
			continue
		}
		if err := validateExecutorReportV4Binding(
			command,
			executorReportV4FromTerminal(*command.Terminal),
		); err != nil {
			return errors.New("recovered activation canary report contradicts its signed command")
		}
	}
	return nil
}

func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var result error
	if store.wal != nil {
		result = store.wal.Close()
		store.wal = nil
	}
	if store.lock != nil {
		if err := syscall.Flock(int(store.lock.Fd()), syscall.LOCK_UN); result == nil && err != nil {
			result = err
		}
		if err := store.lock.Close(); result == nil && err != nil {
			result = err
		}
		store.lock = nil
	}
	return result
}

func (store *Store) Status() (Status, error) {
	if store == nil {
		return Status{}, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Status{}, err
	}
	return Status{
		Generation: store.generation, Sequence: store.sequence, Tenants: len(store.current.tenants),
		Nodes: len(store.current.nodes), Credentials: len(store.current.credentials),
		Enrollments: len(store.current.enrollments), Commands: len(store.current.commands),
		Deployments: len(store.current.deployments), Events: len(store.current.events),
	}, nil
}

func (store *Store) applyMutations(mutations ...mutation) error {
	if store == nil {
		return ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.applyMutationsLocked(mutations...)
}

func (store *Store) applyMutationsLocked(mutations ...mutation) error {
	if err := store.availableLocked(); err != nil {
		return err
	}
	if store.sequence == math.MaxUint64 {
		return ErrCapacityExceeded
	}
	payload, err := encodeTransaction(mutations...)
	if err != nil {
		return err
	}
	next, err := applyTransaction(store.current, transaction{Version: transactionFormatWriteVersion, Mutations: mutations})
	if err != nil {
		return err
	}
	if err := validateState(next, store.limits); err != nil {
		return formatStateError(err)
	}
	frame, record, err := marshalWALRecord(store.sequence+1, store.lastHash, payload, store.limits.MaxRecordBytes)
	if err != nil {
		return err
	}
	info, err := store.wal.Stat()
	if err != nil {
		store.poisoned = true
		return fmt.Errorf("stat control WAL before append: %w", err)
	}
	if info.Size()+int64(len(frame)) > store.limits.MaxWALBytes {
		if err := store.compactLocked(); err != nil {
			store.poisoned = true
			return fmt.Errorf("compact control WAL: %w", err)
		}
		info, err = store.wal.Stat()
		if err != nil {
			store.poisoned = true
			return fmt.Errorf("stat compacted control WAL: %w", err)
		}
		if info.Size()+int64(len(frame)) > store.limits.MaxWALBytes {
			return ErrCapacityExceeded
		}
	}
	if err := writeAll(store.wal, frame); err != nil {
		store.poisoned = true
		return fmt.Errorf("append control WAL: %w", err)
	}
	if err := store.syncFile(store.wal); err != nil {
		store.poisoned = true
		return fmt.Errorf("sync control WAL: %w", err)
	}
	store.current = next
	store.sequence = record.Sequence
	store.lastHash = record.Hash
	return nil
}

func (store *Store) availableLocked() error {
	if store.closed || store.poisoned || store.wal == nil || store.lock == nil {
		return ErrUnavailable
	}
	return nil
}

func (store *Store) compactLocked() error {
	if store.generation == math.MaxUint64 {
		return ErrCapacityExceeded
	}
	payload, err := encodeState(store.current, store.limits.MaxStateBytes)
	if err != nil {
		return err
	}
	nextGeneration := store.generation + 1
	snapshotRaw, err := marshalSnapshot(snapshotEnvelope{
		Generation: nextGeneration, Sequence: store.sequence, LastHash: store.lastHash, Payload: payload,
	})
	if err != nil {
		return err
	}
	headerRaw, err := marshalWALHeader(walHeader{
		Generation: nextGeneration, Sequence: store.sequence, LastHash: store.lastHash,
	})
	if err != nil {
		return err
	}
	snapshotName := generationName("snapshot", nextGeneration)
	walName := generationName("wal", nextGeneration)
	if err := writeAtomicArtifact(store.dir, snapshotName, snapshotRaw); err != nil {
		return err
	}
	if err := writeAtomicArtifact(store.dir, walName, headerRaw); err != nil {
		return err
	}
	newWAL, _, err := openWALArtifact(filepath.Join(store.dir, walName), store.limits.MaxWALBytes)
	if err != nil {
		return err
	}
	selected := marshalManifest(manifest{
		Generation: nextGeneration, SnapshotHash: hashBytes(snapshotRaw), WALHeaderHash: hashBytes(headerRaw),
	})
	if err := writeAtomicArtifact(store.dir, currentName, selected); err != nil {
		_ = newWAL.Close()
		return err
	}
	oldGeneration, oldWAL := store.generation, store.wal
	store.generation, store.wal = nextGeneration, newWAL
	_ = oldWAL.Close()
	_ = os.Remove(filepath.Join(store.dir, generationName("snapshot", oldGeneration)))
	_ = os.Remove(filepath.Join(store.dir, generationName("wal", oldGeneration)))
	_ = syncDirectory(store.dir)
	return nil
}

func recoverWAL(file *os.File, size int64, current state, sequence uint64, lastHash [sha256.Size]byte, limits Limits) (state, uint64, [sha256.Size]byte, error) {
	return recoverWALReader(file, size, current, sequence, lastHash, limits, func(offset int64) error {
		return repairIncompleteTail(file, offset)
	})
}

func recoverWALReader(file io.ReaderAt, size int64, current state, sequence uint64, lastHash [sha256.Size]byte, limits Limits, repair func(int64) error) (state, uint64, [sha256.Size]byte, error) {
	offset := int64(walHeaderBytes)
	for offset < size {
		start := offset
		if size-offset < 4 {
			if repair == nil {
				return state{}, 0, [sha256.Size]byte{}, errors.New("control WAL has an incomplete final frame")
			}
			if err := repair(start); err != nil {
				return state{}, 0, [sha256.Size]byte{}, err
			}
			break
		}
		var lengthRaw [4]byte
		if _, err := file.ReadAt(lengthRaw[:], offset); err != nil {
			return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("read control WAL frame length: %w", err)
		}
		length := int64(uint32(lengthRaw[0])<<24 | uint32(lengthRaw[1])<<16 | uint32(lengthRaw[2])<<8 | uint32(lengthRaw[3]))
		if length < walFrameFixedBytes || length > int64(limits.MaxRecordBytes) {
			return state{}, 0, [sha256.Size]byte{}, errors.New("control WAL contains an invalid complete frame length")
		}
		offset += 4
		if length > size-offset {
			available := size - offset
			prefixLength := available
			if prefixLength > walFramePrefixBytes {
				prefixLength = walFramePrefixBytes
			}
			prefix := make([]byte, int(prefixLength))
			if len(prefix) > 0 {
				if _, err := file.ReadAt(prefix, offset); err != nil {
					return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("read incomplete control WAL frame prefix: %w", err)
				}
			}
			if err := validateIncompleteWALFramePrefix(prefix, length); err != nil {
				return state{}, 0, [sha256.Size]byte{}, err
			}
			if repair == nil {
				return state{}, 0, [sha256.Size]byte{}, errors.New("control WAL has an incomplete final frame")
			}
			if err := repair(start); err != nil {
				return state{}, 0, [sha256.Size]byte{}, err
			}
			break
		}
		body := make([]byte, int(length))
		if _, err := file.ReadAt(body, offset); err != nil {
			return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("read control WAL frame: %w", err)
		}
		record, err := unmarshalWALRecord(body, limits.MaxRecordBytes)
		if err != nil {
			return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("verify control WAL frame at %d: %w", start, err)
		}
		if sequence == math.MaxUint64 || record.Sequence != sequence+1 || !bytes.Equal(record.Previous[:], lastHash[:]) {
			return state{}, 0, [sha256.Size]byte{}, errors.New("control WAL hash chain or sequence is discontinuous")
		}
		transaction, err := decodeTransaction(record.Payload, limits.MaxRecordBytes)
		if err != nil {
			return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("decode control WAL transaction: %w", err)
		}
		next, err := applyTransaction(current, transaction)
		if err != nil {
			return state{}, 0, [sha256.Size]byte{}, fmt.Errorf("apply control WAL transaction: %w", err)
		}
		if err := validateState(next, limits); err != nil {
			return state{}, 0, [sha256.Size]byte{}, formatStateError(err)
		}
		current, sequence, lastHash = next, record.Sequence, record.Hash
		offset += length
	}
	return current, sequence, lastHash, nil
}

func openRootArtifact(root *os.Root, name string, limit int64) (*os.File, int64, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, 0, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || validateArtifactInfo(info, limit) != nil {
		_ = file.Close()
		return nil, 0, errors.New("control artifact must be a bounded owner-only regular file with one link")
	}
	return file, info.Size(), nil
}

func readRootArtifact(root *os.Root, name string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("control artifact read limit must be positive")
	}
	file, _, err := openRootArtifact(root, name, int64(limit))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrCapacityExceeded
	}
	after, err := file.Stat()
	if err != nil || !sameArtifactSnapshot(before, after) {
		return nil, errors.New("control artifact changed while being read")
	}
	return raw, nil
}

func repairIncompleteTail(file *os.File, offset int64) error {
	if err := file.Truncate(offset); err != nil {
		return fmt.Errorf("truncate incomplete control WAL tail: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync repaired control WAL: %w", err)
	}
	return nil
}

func prepareDirectory(directory string, create bool) (string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == string(filepath.Separator) ||
		strings.ContainsRune(directory, '\x00') {
		return "", errors.New("control store directory must be clean, absolute, and non-root")
	}
	if create {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return "", fmt.Errorf("create control store directory: %w", err)
		}
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotInitialized
	}
	if err != nil {
		return "", fmt.Errorf("stat control store directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", errors.New("control store directory must be an owner-only 0700 directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return "", errors.New("control store directory must be owned by the service user")
	}
	return directory, nil
}

func acquireLock(directory string) (*os.File, error) {
	path := filepath.Join(directory, lockName)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open control store lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open control store lock returned an invalid file")
	}
	info, err := file.Stat()
	if err != nil || validateArtifactInfo(info, -1) != nil {
		_ = file.Close()
		return nil, errors.New("control store lock must be an owner-only regular file with one link")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("control store is locked by another writer: %w", err)
	}
	return file, nil
}

func releaseLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func containsStateArtifacts(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("read control store directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == currentName || strings.HasPrefix(name, "snapshot.") || strings.HasPrefix(name, "wal.") {
			return true, nil
		}
	}
	return false, nil
}

func openWALArtifact(path string, limit int64) (*os.File, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open control WAL: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, 0, errors.New("open control WAL returned an invalid file")
	}
	info, err := file.Stat()
	if err != nil || validateArtifactInfo(info, limit) != nil {
		_ = file.Close()
		return nil, 0, errors.New("control WAL must be a bounded owner-only regular file with one link")
	}
	return file, info.Size(), nil
}

func readArtifact(path string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("control artifact read limit must be positive")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open control artifact returned an invalid file")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || validateArtifactInfo(before, int64(limit)) != nil {
		return nil, errors.New("control artifact must be a bounded owner-only regular file with one link")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrCapacityExceeded
	}
	after, err := file.Stat()
	if err != nil || !sameArtifactSnapshot(before, after) {
		return nil, errors.New("control artifact changed while being read")
	}
	return raw, nil
}

func validateArtifactInfo(info os.FileInfo, limit int64) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("artifact is not an owner-only regular file")
	}
	if limit >= 0 && info.Size() > limit {
		return ErrCapacityExceeded
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Nlink) != 1 || int(stat.Uid) != os.Geteuid() {
		return errors.New("artifact ownership or link count is invalid")
	}
	return nil
}

func sameArtifactSnapshot(left, right os.FileInfo) bool {
	return os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func writeExclusiveArtifact(directory, name string, raw []byte) error {
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := writeAll(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	complete = true
	return nil
}

func writeAtomicArtifact(directory, name string, raw []byte) error {
	file, err := os.CreateTemp(directory, ".control-artifact-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(file, raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(directory, name)); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	complete = true
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

func writeAll(file *os.File, raw []byte) error {
	for len(raw) > 0 {
		written, err := file.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}
