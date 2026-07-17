// Package rolloutstore provides a rooted, append-only filesystem workspace
// for one owner-operated fleet rollout. It stores exact artifact bytes but
// does not interpret, authorize, sign, execute, or authenticate them.
package rolloutstore

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
)

const (
	LockFileName                       = ".lock"
	PlanFileName                       = "plan.json"
	ReleaseFileName                    = "release.dsse.json"
	PolicyFileName                     = "policy.dsse.json"
	ControllerWitnessPublicKeyFileName = "controller-witness.public"
	ProofFileName                      = "proof.json"

	TargetIntentKind                  = "intent.json"
	TargetServiceTrustKind            = "service-trust.json"
	TargetActivationPlanKind          = "activation-plan.json"
	TargetExecutorBeginKind           = "executor-begin.json"
	TargetAdmitCommandKind            = "admit-command.dsse.json"
	TargetAdmissionKind               = "admission.json"
	TargetStartCommandKind            = "start-command.dsse.json"
	TargetCanaryCommandKind           = "canary-command.dsse.json"
	TargetCanaryResultKind            = "canary-result.json"
	TargetCaptureExportKind           = "capture-export.json"
	TargetActivationStateKind         = "activation-state.json"
	TargetActivationProofKind         = "activation-proof.json"
	TargetGatewayReceiptPublicKeyKind = "gateway-receipt.public"

	MaxTargets             = 64
	MaxTargetIndex         = MaxTargets - 1
	MaxTargetStateSequence = uint64(999999999999)

	// MaxArtifactBytes is the largest limit assigned to any one artifact.
	// Smaller protocol objects have narrower name-specific limits below.
	MaxArtifactBytes = int64(1 << 20)
	// MaxWorkspaceBytes bounds all artifact and checkpoint bytes together.
	MaxWorkspaceBytes = int64(256 << 20)
	// MaxWorkspaceEntries accommodates every fixed target artifact plus more
	// than fifty checkpoints per target while keeping open-time work finite.
	MaxWorkspaceEntries = 4096

	targetPrefix         = "target-"
	targetIndexDigits    = 3
	targetStateMarker    = "-state-"
	targetStateDigits    = 12
	targetStateSuffix    = ".json"
	maxListedEntryBuffer = MaxWorkspaceEntries + 1

	maxRolloutPlanBytes      = int64(256 << 10)
	maxAgentReleaseBytes     = int64(256 << 10)
	maxPolicyBytes           = MaxArtifactBytes
	maxWitnessPublicKeyBytes = int64(64 << 10)
	maxRolloutProofBytes     = int64(128 << 10)
	maxServiceTrustBytes     = MaxArtifactBytes
	maxActivationPlanBytes   = int64(64 << 10)
	maxExecutorBeginBytes    = int64(64 << 10)
	maxActivationStateBytes  = int64(128 << 10)
	maxActivationProofBytes  = int64(128 << 10)
	maxGatewayPublicKeyBytes = int64(64 << 10)
	maxTargetStateBytes      = int64(64 << 10)
)

var (
	ErrLocked           = errors.New("rollout workspace is locked")
	ErrClosed           = errors.New("rollout workspace is closed")
	ErrPoisoned         = errors.New("rollout workspace write outcome is ambiguous")
	ErrAlreadyExists    = errors.New("rollout artifact already exists")
	ErrStateOrder       = errors.New("rollout target state checkpoint is not append-only")
	ErrCapacityExceeded = errors.New("rollout workspace capacity exceeded")
	ErrUnsafeWorkspace  = errors.New("unsafe rollout workspace")
	ErrInvalidName      = errors.New("invalid rollout artifact name")
)

var targetArtifactKinds = [...]string{
	TargetIntentKind,
	TargetServiceTrustKind,
	TargetActivationPlanKind,
	TargetExecutorBeginKind,
	TargetAdmitCommandKind,
	TargetAdmissionKind,
	TargetStartCommandKind,
	TargetCanaryCommandKind,
	TargetCanaryResultKind,
	TargetCaptureExportKind,
	TargetActivationStateKind,
	TargetActivationProofKind,
	TargetGatewayReceiptPublicKeyKind,
}

type artifactKind uint8

const (
	artifactInvalid artifactKind = iota
	artifactLock
	artifactFixed
	artifactTarget
	artifactTargetState
)

// Store holds one rooted directory descriptor and a lifetime exclusive lock.
// Its methods are safe for concurrent use. Artifacts are never overwritten,
// renamed, or removed.
type Store struct {
	directory     string
	identity      os.FileInfo
	root          *os.Root
	directoryLock *os.File
	lock          *os.File
	digests       map[string][sha256.Size]byte

	mu       sync.Mutex
	closed   bool
	poisoned bool
}

type workspaceSnapshot struct {
	entries      int
	bytes        int64
	info         map[string]os.FileInfo
	targetStates map[uint16][]string
}

// Create exclusively creates one owner-only workspace beneath an existing
// trusted parent, fsyncs both directories, and opens the resulting store.
func Create(directory string) (*Store, error) {
	if !validWorkspacePath(directory) {
		return nil, fmt.Errorf("%w: directory must be a clean absolute non-root path", ErrUnsafeWorkspace)
	}
	if _, err := os.Lstat(directory); err == nil {
		return nil, ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	requestedParent := filepath.Dir(directory)
	canonicalParent, err := filepath.EvalSymlinks(requestedParent)
	if err != nil || !validCanonicalPath(canonicalParent) {
		return nil, errors.Join(
			fmt.Errorf("%w: workspace parent has no canonical absolute path", ErrUnsafeWorkspace),
			err,
		)
	}
	if err := validateTrustedAncestors(canonicalParent); err != nil {
		return nil, err
	}
	parentBefore, err := os.Lstat(canonicalParent)
	if err != nil {
		return nil, fmt.Errorf("stat rollout workspace parent: %w", err)
	}
	parentRoot, err := os.OpenRoot(canonicalParent)
	if err != nil {
		return nil, fmt.Errorf("open rollout workspace parent: %w", err)
	}
	parentAnchored, anchoredErr := parentRoot.Stat(".")
	parentCurrent, currentErr := os.Lstat(canonicalParent)
	trustErr := validateTrustedAncestors(canonicalParent)
	if anchoredErr != nil || currentErr != nil || trustErr != nil ||
		!os.SameFile(parentBefore, parentAnchored) ||
		!os.SameFile(parentBefore, parentCurrent) {
		_ = parentRoot.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: workspace parent changed while opening", ErrUnsafeWorkspace),
			anchoredErr,
			currentErr,
			trustErr,
		)
	}

	name := filepath.Base(directory)
	if name == "." || name == string(filepath.Separator) || strings.ContainsRune(name, '\x00') {
		_ = parentRoot.Close()
		return nil, fmt.Errorf("%w: invalid workspace directory name", ErrUnsafeWorkspace)
	}
	if err := parentRoot.Mkdir(name, 0o700); err != nil {
		_ = parentRoot.Close()
		if errors.Is(err, os.ErrExist) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create rollout workspace: %w", err)
	}
	createdPath := filepath.Join(canonicalParent, name)
	createdInitial, err := parentRoot.Lstat(name)
	if err != nil || !validNewWorkspaceDirectory(createdInitial) {
		_ = parentRoot.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: newly created workspace is not an owner-only directory", ErrUnsafeWorkspace),
			err,
		)
	}

	childRoot, err := parentRoot.OpenRoot(name)
	if err != nil && errors.Is(err, os.ErrPermission) {
		// A restrictive umask can remove the owner's search bit. The standard
		// library has no descriptor-relative chmod, so verify the exact inode
		// before and after this pathname fallback.
		if chmodErr := os.Chmod(createdPath, 0o700); chmodErr != nil {
			_ = parentRoot.Close()
			return nil, fmt.Errorf("protect new rollout workspace: %w", chmodErr)
		}
		afterChmod, statErr := parentRoot.Lstat(name)
		if statErr != nil || !validWorkspaceDirectory(afterChmod) ||
			!os.SameFile(createdInitial, afterChmod) {
			_ = parentRoot.Close()
			return nil, errors.Join(
				fmt.Errorf("%w: new workspace changed while applying owner permissions", ErrUnsafeWorkspace),
				statErr,
			)
		}
		childRoot, err = parentRoot.OpenRoot(name)
	}
	if err != nil {
		_ = parentRoot.Close()
		return nil, fmt.Errorf("anchor new rollout workspace: %w", err)
	}
	anchoredBeforeChmod, err := childRoot.Stat(".")
	if err != nil || !validNewWorkspaceDirectory(anchoredBeforeChmod) ||
		!os.SameFile(createdInitial, anchoredBeforeChmod) {
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: new workspace changed while anchoring", ErrUnsafeWorkspace),
			err,
		)
	}
	childDirectory, err := childRoot.Open(".")
	if err != nil {
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	openedDirectory, err := childDirectory.Stat()
	if err != nil || !validNewWorkspaceDirectory(openedDirectory) ||
		!os.SameFile(createdInitial, openedDirectory) {
		_ = childDirectory.Close()
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: new workspace changed before permission hardening", ErrUnsafeWorkspace),
			err,
		)
	}
	if err := childDirectory.Chmod(0o700); err != nil {
		_ = childDirectory.Close()
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := childDirectory.Sync(); err != nil {
		_ = childDirectory.Close()
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := childDirectory.Close(); err != nil {
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	created, statErr := parentRoot.Lstat(name)
	anchored, anchoredErr := childRoot.Stat(".")
	if statErr != nil || anchoredErr != nil || !validWorkspaceDirectory(created) ||
		!validWorkspaceDirectory(anchored) || !os.SameFile(createdInitial, created) ||
		!os.SameFile(createdInitial, anchored) {
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: new workspace is not an owner-only directory", ErrUnsafeWorkspace),
			statErr,
			anchoredErr,
		)
	}
	if err := syncRoot(parentRoot); err != nil {
		_ = childRoot.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := parentRoot.Close(); err != nil {
		_ = childRoot.Close()
		return nil, err
	}
	return finishOpen(createdPath, anchored, childRoot)
}

// Open validates and anchors an existing owner-only workspace, acquires its
// nonblocking lifetime lock, and rejects unsafe or unexpected content.
func Open(directory string) (*Store, error) {
	if !validWorkspacePath(directory) {
		return nil, fmt.Errorf("%w: directory must be a clean absolute non-root path", ErrUnsafeWorkspace)
	}
	requested, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat rollout workspace: %w", err)
	}
	if !validWorkspaceDirectory(requested) {
		return nil, fmt.Errorf("%w: directory must be owned by this process with mode 0700", ErrUnsafeWorkspace)
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || !validCanonicalPath(canonical) {
		return nil, errors.Join(
			fmt.Errorf("%w: directory has no canonical absolute path", ErrUnsafeWorkspace),
			err,
		)
	}
	if err := validateTrustedAncestors(canonical); err != nil {
		return nil, err
	}
	before, err := os.Lstat(canonical)
	if err != nil {
		return nil, fmt.Errorf("stat canonical rollout workspace: %w", err)
	}
	if !validWorkspaceDirectory(before) || !os.SameFile(requested, before) {
		return nil, fmt.Errorf("%w: directory changed during canonicalization", ErrUnsafeWorkspace)
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, fmt.Errorf("open rollout workspace root: %w", err)
	}
	after, err := root.Stat(".")
	if err != nil || !validWorkspaceDirectory(after) || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, errors.Join(
			fmt.Errorf("%w: directory changed while opening", ErrUnsafeWorkspace),
			err,
		)
	}
	return finishOpen(canonical, after, root)
}

func finishOpen(directory string, identity os.FileInfo, root *os.Root) (*Store, error) {
	store := &Store{directory: directory, identity: identity, root: root}
	directoryLock, err := store.acquireDirectoryLock()
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	store.directoryLock = directoryLock
	if err := store.checkDirectoryLocked(); err != nil {
		_ = syscall.Flock(int(directoryLock.Fd()), syscall.LOCK_UN)
		_ = directoryLock.Close()
		_ = root.Close()
		return nil, err
	}
	lock, err := store.acquireLock()
	if err != nil {
		_ = syscall.Flock(int(directoryLock.Fd()), syscall.LOCK_UN)
		_ = directoryLock.Close()
		_ = root.Close()
		return nil, err
	}
	store.lock = lock
	if err := store.recoverStagingLocked(); err != nil {
		_ = store.closeLocked()
		return nil, err
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		_ = store.closeLocked()
		return nil, err
	}
	digests := make(map[string][sha256.Size]byte, len(snapshot.info))
	for name, info := range snapshot.info {
		if name == LockFileName {
			continue
		}
		raw, err := store.readArtifactLocked(name, MaxArtifactBytes, info, nil)
		if err != nil {
			_ = store.closeLocked()
			return nil, err
		}
		digests[name] = sha256.Sum256(raw)
	}
	finalSnapshot, err := store.auditLocked()
	if err != nil || !sameInventory(snapshot, finalSnapshot) {
		_ = store.closeLocked()
		return nil, errors.Join(
			fmt.Errorf("%w: workspace changed while establishing its digest baseline", ErrUnsafeWorkspace),
			err,
		)
	}
	store.digests = digests
	return store, nil
}

// TargetArtifactName returns the only accepted fixed artifact name for a
// zero-based target and one of the exported Target*Kind values.
func TargetArtifactName(target uint16, kind string) (string, error) {
	if target >= MaxTargets || !validTargetArtifactKind(kind) {
		return "", fmt.Errorf("%w: invalid target index or artifact kind", ErrInvalidName)
	}
	return fmt.Sprintf("%s%03d-%s", targetPrefix, target, kind), nil
}

// TargetStateName returns the only accepted checkpoint name for a target and
// sequence. Fixed-width decimal fields sort first by target, then sequence.
func TargetStateName(target uint16, sequence uint64) (string, error) {
	if target >= MaxTargets || sequence > MaxTargetStateSequence {
		return "", fmt.Errorf("%w: target or state sequence is outside its bound", ErrInvalidName)
	}
	return fmt.Sprintf(
		"%s%03d%s%012d%s",
		targetPrefix,
		target,
		targetStateMarker,
		sequence,
		targetStateSuffix,
	), nil
}

// Read returns a stable bounded snapshot whose digest matches the bytes seen
// when the Store opened or durably created the artifact.
func (store *Store) Read(name string, limit int64) ([]byte, error) {
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readLocked(name, limit, nil)
}

// afterOpen is test-only plumbing for deterministic pathname and inode races.
func (store *Store) readLocked(name string, limit int64, afterOpen func(*os.File) error) ([]byte, error) {
	if err := store.usableLocked(); err != nil {
		return nil, err
	}
	kind := classifyName(name)
	if kind == artifactInvalid || kind == artifactLock {
		return nil, fmt.Errorf("%w: artifact cannot be read", ErrInvalidName)
	}
	if limit <= 0 || limit > MaxArtifactBytes {
		return nil, fmt.Errorf(
			"%w: read limit must be between 1 and %d",
			ErrCapacityExceeded,
			MaxArtifactBytes,
		)
	}
	if _, err := store.auditLocked(); err != nil {
		return nil, err
	}
	before, err := store.root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect rollout artifact %q: %w", name, err)
	}
	if err := validateArtifact(name, before); err != nil {
		return nil, err
	}
	if before.Size() > limit {
		return nil, fmt.Errorf("%w: artifact %q exceeds its read limit", ErrCapacityExceeded, name)
	}
	raw, err := store.readArtifactLocked(name, limit, before, afterOpen)
	if err != nil {
		return nil, err
	}
	if store.digests != nil {
		expected, ok := store.digests[name]
		if !ok || sha256.Sum256(raw) != expected {
			return nil, fmt.Errorf(
				"%w: artifact %q bytes changed after the workspace was opened",
				ErrUnsafeWorkspace,
				name,
			)
		}
	}
	if _, err := store.auditLocked(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (store *Store) readArtifactLocked(
	name string,
	limit int64,
	before os.FileInfo,
	afterOpen func(*os.File) error,
) ([]byte, error) {
	file, err := store.root.OpenFile(
		name,
		os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open rollout artifact %q: %w", name, err)
	}
	closeWith := func(result []byte, cause error) ([]byte, error) {
		return result, errors.Join(cause, file.Close())
	}
	opened, err := file.Stat()
	if err != nil {
		return closeWith(nil, err)
	}
	named, err := store.root.Lstat(name)
	if err != nil || validateArtifact(name, opened) != nil || validateArtifact(name, named) != nil ||
		!sameSnapshot(before, opened) || !sameSnapshot(opened, named) {
		return closeWith(nil, errors.Join(
			fmt.Errorf("%w: artifact %q changed while opening", ErrUnsafeWorkspace, name),
			err,
		))
	}
	if afterOpen != nil {
		if err := afterOpen(file); err != nil {
			return closeWith(nil, err)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return closeWith(nil, err)
	}
	after, statErr := file.Stat()
	current, namedErr := store.root.Lstat(name)
	if statErr != nil || namedErr != nil || int64(len(raw)) != opened.Size() ||
		int64(len(raw)) > limit || validateArtifact(name, after) != nil ||
		validateArtifact(name, current) != nil || !sameSnapshot(opened, after) ||
		!sameSnapshot(opened, current) {
		return closeWith(nil, errors.Join(
			fmt.Errorf("%w: artifact %q changed while reading", ErrUnsafeWorkspace, name),
			statErr,
			namedErr,
		))
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return raw, nil
}

// WriteOnce exclusively creates, writes, fsyncs, and directory-syncs one
// fixed artifact. Target state checkpoints must use AppendTargetState.
func (store *Store) WriteOnce(name string, raw []byte) error {
	return store.writeOnce(name, raw, nil)
}

// Import durably snapshots externally obtained bytes without exposing a path.
// It has the same immutable inventory and durability rules as WriteOnce.
func (store *Store) Import(name string, raw []byte) error {
	return store.writeOnce(name, raw, nil)
}

// afterCreate is test-only plumbing for deterministic ambiguous failures.
func (store *Store) writeOnce(name string, raw []byte, afterCreate func(*os.File) error) error {
	if store == nil {
		return ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return err
	}
	kind := classifyName(name)
	if kind != artifactFixed && kind != artifactTarget && kind != artifactTargetState {
		return fmt.Errorf("%w: only fixed rollout artifacts may be written", ErrInvalidName)
	}
	if kind == artifactTargetState {
		return fmt.Errorf("%w: target states require AppendTargetState", ErrInvalidName)
	}
	return store.createLocked(name, raw, afterCreate)
}

// AppendTargetState writes exactly one numbered immutable state checkpoint.
func (store *Store) AppendTargetState(target uint16, sequence uint64, raw []byte) (string, error) {
	name, err := TargetStateName(target, sequence)
	if err != nil {
		return "", err
	}
	if store == nil {
		return "", ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return "", err
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return "", err
	}
	if _, err := store.root.Lstat(name); err == nil {
		return "", ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	expected, err := TargetStateName(target, uint64(len(snapshot.targetStates[target])))
	if err != nil || name != expected {
		return "", errors.Join(ErrStateOrder, err)
	}
	if err := store.createWithSnapshotLocked(name, raw, snapshot, nil); err != nil {
		return "", err
	}
	return name, nil
}

// ListTargetStates returns one target's checkpoint names in sequence order.
func (store *Store) ListTargetStates(target uint16) ([]string, error) {
	if target >= MaxTargets {
		return nil, fmt.Errorf("%w: target index is outside its bound", ErrInvalidName)
	}
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return nil, err
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return nil, err
	}
	return append([]string(nil), snapshot.targetStates[target]...), nil
}

func (store *Store) createLocked(name string, raw []byte, afterCreate func(*os.File) error) error {
	snapshot, err := store.auditLocked()
	if err != nil {
		return err
	}
	return store.createWithSnapshotLocked(name, raw, snapshot, afterCreate)
}

// Close releases the lifetime locks and rooted directory descriptor. It is
// idempotent.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.closeLocked()
}

func (store *Store) closeLocked() error {
	if store.closed {
		return nil
	}
	store.closed = true
	var failures []error
	if store.lock != nil {
		if err := syscall.Flock(int(store.lock.Fd()), syscall.LOCK_UN); err != nil {
			failures = append(failures, err)
		}
		if err := store.lock.Close(); err != nil {
			failures = append(failures, err)
		}
		store.lock = nil
	}
	if store.directoryLock != nil {
		if err := syscall.Flock(int(store.directoryLock.Fd()), syscall.LOCK_UN); err != nil {
			failures = append(failures, err)
		}
		if err := store.directoryLock.Close(); err != nil {
			failures = append(failures, err)
		}
		store.directoryLock = nil
	}
	if store.root != nil {
		if err := store.root.Close(); err != nil {
			failures = append(failures, err)
		}
		store.root = nil
	}
	return errors.Join(failures...)
}

func (store *Store) usableLocked() error {
	if store.closed || store.root == nil || store.directoryLock == nil || store.lock == nil {
		return ErrClosed
	}
	if store.poisoned {
		return ErrPoisoned
	}
	return store.checkDirectoryLocked()
}

func (store *Store) checkDirectoryLocked() error {
	if store.root == nil || store.identity == nil {
		return ErrClosed
	}
	if err := validateTrustedAncestors(store.directory); err != nil {
		return err
	}
	anchored, anchoredErr := store.root.Stat(".")
	current, currentErr := os.Lstat(store.directory)
	if anchoredErr != nil || currentErr != nil || !validWorkspaceDirectory(anchored) ||
		!validWorkspaceDirectory(current) || !os.SameFile(store.identity, anchored) ||
		!os.SameFile(store.identity, current) {
		return errors.Join(
			fmt.Errorf("%w: directory changed after opening", ErrUnsafeWorkspace),
			anchoredErr,
			currentErr,
		)
	}
	if store.directoryLock != nil {
		lockedDirectory, lockErr := store.directoryLock.Stat()
		if lockErr != nil || !validWorkspaceDirectory(lockedDirectory) ||
			!os.SameFile(store.identity, lockedDirectory) {
			return errors.Join(
				fmt.Errorf("%w: directory lock changed after opening", ErrUnsafeWorkspace),
				lockErr,
			)
		}
	}
	if store.lock != nil {
		openedLock, openedErr := store.lock.Stat()
		namedLock, namedErr := store.root.Lstat(LockFileName)
		if openedErr != nil || namedErr != nil || validateArtifact(LockFileName, openedLock) != nil ||
			validateArtifact(LockFileName, namedLock) != nil || !sameSnapshot(openedLock, namedLock) {
			return errors.Join(
				fmt.Errorf("%w: lifetime lock path changed after opening", ErrUnsafeWorkspace),
				openedErr,
				namedErr,
			)
		}
	}
	return nil
}

func (store *Store) acquireDirectoryLock() (*os.File, error) {
	directory, err := store.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open rollout workspace directory lock: %w", err)
	}
	closeWith := func(cause error) (*os.File, error) {
		_ = directory.Close()
		return nil, cause
	}
	info, err := directory.Stat()
	if err != nil || !validWorkspaceDirectory(info) || !os.SameFile(store.identity, info) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: directory lock identity is invalid", ErrUnsafeWorkspace),
			err,
		))
	}
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(ErrLocked)
		}
		return closeWith(fmt.Errorf("lock rollout workspace directory: %w", err))
	}
	return directory, nil
}

func (store *Store) acquireLock() (*os.File, error) {
	before, beforeErr := store.root.Lstat(LockFileName)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, beforeErr
	}
	flags := os.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	created := false
	file, err := store.root.OpenFile(LockFileName, flags|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		created = true
	} else if errors.Is(err, os.ErrExist) {
		file, err = store.root.OpenFile(LockFileName, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open rollout workspace lock: %w", err)
	}
	closeWith := func(cause error) (*os.File, error) {
		_ = file.Close()
		return nil, cause
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return closeWith(err)
		}
		if err := file.Sync(); err != nil {
			return closeWith(err)
		}
	}
	opened, statErr := file.Stat()
	named, namedErr := store.root.Lstat(LockFileName)
	if statErr != nil || namedErr != nil || validateArtifact(LockFileName, opened) != nil ||
		validateArtifact(LockFileName, named) != nil || !sameSnapshot(opened, named) ||
		(!created && (beforeErr != nil || !sameSnapshot(before, opened))) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: lock is not one stable owner-only file", ErrUnsafeWorkspace),
			statErr,
			namedErr,
		))
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(ErrLocked)
		}
		return closeWith(fmt.Errorf("lock rollout workspace: %w", err))
	}
	named, err = store.root.Lstat(LockFileName)
	if err != nil || validateArtifact(LockFileName, named) != nil || !sameSnapshot(opened, named) {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return closeWith(errors.Join(
			fmt.Errorf("%w: lock changed after acquisition", ErrUnsafeWorkspace),
			err,
		))
	}
	if created {
		if err := store.syncDirectoryLocked(); err != nil {
			_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			return closeWith(err)
		}
	}
	return file, nil
}

func (store *Store) auditLocked() (workspaceSnapshot, error) {
	if err := store.checkDirectoryLocked(); err != nil {
		return workspaceSnapshot{}, err
	}
	names, err := store.readEntryNamesLocked()
	if err != nil {
		return workspaceSnapshot{}, err
	}
	snapshot := workspaceSnapshot{
		entries:      len(names),
		info:         make(map[string]os.FileInfo, len(names)),
		targetStates: make(map[uint16][]string),
	}
	for _, name := range names {
		info, err := store.root.Lstat(name)
		if err != nil {
			return workspaceSnapshot{}, fmt.Errorf("inspect rollout workspace entry %q: %w", name, err)
		}
		if err := validateArtifact(name, info); err != nil {
			return workspaceSnapshot{}, err
		}
		if info.Size() > MaxWorkspaceBytes-snapshot.bytes {
			return workspaceSnapshot{}, ErrCapacityExceeded
		}
		snapshot.bytes += info.Size()
		snapshot.info[name] = info
		if target, _, ok := parseTargetStateName(name); ok {
			snapshot.targetStates[target] = append(snapshot.targetStates[target], name)
		}
	}
	if _, ok := snapshot.info[LockFileName]; !ok {
		return workspaceSnapshot{}, fmt.Errorf("%w: workspace lock disappeared", ErrUnsafeWorkspace)
	}
	if store.digests != nil {
		if len(snapshot.info) != len(store.digests)+1 {
			return workspaceSnapshot{}, fmt.Errorf(
				"%w: immutable artifact inventory changed after opening",
				ErrUnsafeWorkspace,
			)
		}
		for name := range store.digests {
			if _, ok := snapshot.info[name]; !ok {
				return workspaceSnapshot{}, fmt.Errorf(
					"%w: immutable artifact %q disappeared",
					ErrUnsafeWorkspace,
					name,
				)
			}
		}
		for name := range snapshot.info {
			if name == LockFileName {
				continue
			}
			if _, ok := store.digests[name]; !ok {
				return workspaceSnapshot{}, fmt.Errorf(
					"%w: artifact %q appeared outside this Store",
					ErrUnsafeWorkspace,
					name,
				)
			}
		}
	}
	afterNames, err := store.readEntryNamesLocked()
	if err != nil {
		return workspaceSnapshot{}, err
	}
	if !equalNames(names, afterNames) {
		return workspaceSnapshot{}, fmt.Errorf("%w: entries changed while auditing", ErrUnsafeWorkspace)
	}
	for _, name := range names {
		current, err := store.root.Lstat(name)
		if err != nil || validateArtifact(name, current) != nil ||
			!sameSnapshot(snapshot.info[name], current) {
			return workspaceSnapshot{}, errors.Join(
				fmt.Errorf("%w: entry %q changed while auditing", ErrUnsafeWorkspace, name),
				err,
			)
		}
	}
	if err := store.checkDirectoryLocked(); err != nil {
		return workspaceSnapshot{}, err
	}
	for target, states := range snapshot.targetStates {
		sort.Strings(states)
		for sequence, name := range states {
			expected, err := TargetStateName(target, uint64(sequence))
			if err != nil || name != expected {
				return workspaceSnapshot{}, errors.Join(ErrStateOrder, err)
			}
		}
		snapshot.targetStates[target] = states
	}
	return snapshot, nil
}

func (store *Store) readEntryNamesLocked() ([]string, error) {
	directory, err := store.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maxListedEntryBuffer)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > MaxWorkspaceEntries {
		return nil, ErrCapacityExceeded
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

func (store *Store) syncDirectoryLocked() error {
	if err := store.checkDirectoryLocked(); err != nil {
		return err
	}
	return syncRoot(store.root)
}

func syncRoot(root *os.Root) error {
	if root == nil {
		return ErrClosed
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func validWorkspacePath(directory string) bool {
	return directory != "" && filepath.IsAbs(directory) && filepath.Clean(directory) == directory &&
		directory != string(filepath.Separator) && !strings.ContainsRune(directory, '\x00')
}

func validCanonicalPath(directory string) bool {
	return filepath.IsAbs(directory) && filepath.Clean(directory) == directory &&
		directory != string(filepath.Separator)
}

func validateTrustedAncestors(directory string) error {
	euid := os.Geteuid()
	if euid < 0 {
		return fmt.Errorf("%w: ownership cannot be verified on this platform", ErrUnsafeWorkspace)
	}
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect rollout workspace ancestor %q: %w", current, err)
		}
		uid, _, ok := ownerAndLinks(info)
		if !ok || !info.IsDir() || uid != 0 && uid != euid {
			return fmt.Errorf("%w: untrusted ancestor %q", ErrUnsafeWorkspace, current)
		}
		if info.Mode().Perm()&0o022 != 0 && (uid != 0 || info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("%w: replaceable ancestor %q", ErrUnsafeWorkspace, current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func validWorkspaceDirectory(info os.FileInfo) bool {
	uid, _, ok := ownerAndLinks(info)
	return info != nil && ok && uid == os.Geteuid() && info.IsDir() &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Mode().Perm() == 0o700
}

func validNewWorkspaceDirectory(info os.FileInfo) bool {
	uid, _, ok := ownerAndLinks(info)
	return info != nil && ok && uid == os.Geteuid() && info.IsDir() &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Mode().Perm()&0o077 == 0
}

func validateArtifact(name string, info os.FileInfo) error {
	kind := classifyName(name)
	if kind == artifactInvalid {
		return fmt.Errorf("%w: unexpected entry %q", ErrUnsafeWorkspace, name)
	}
	uid, links, ok := ownerAndLinks(info)
	if info == nil || !ok || uid != os.Geteuid() || !info.Mode().IsRegular() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() < 0 {
		return fmt.Errorf("%w: entry %q is not an owner-only regular file", ErrUnsafeWorkspace, name)
	}
	if links != 1 {
		return fmt.Errorf("%w: entry %q has an external hard link", ErrUnsafeWorkspace, name)
	}
	if kind == artifactLock {
		if info.Size() != 0 {
			return fmt.Errorf("%w: lock file must be empty", ErrUnsafeWorkspace)
		}
	} else if maximum := artifactByteLimit(name); maximum <= 0 || info.Size() > maximum {
		return ErrCapacityExceeded
	}
	return nil
}

func artifactByteLimit(name string) int64 {
	switch name {
	case PlanFileName:
		return maxRolloutPlanBytes
	case ReleaseFileName:
		return maxAgentReleaseBytes
	case PolicyFileName:
		return maxPolicyBytes
	case ControllerWitnessPublicKeyFileName:
		return maxWitnessPublicKeyBytes
	case ProofFileName:
		return maxRolloutProofBytes
	case LockFileName:
		return 0
	}
	if maximum, ok := authorizationArtifactByteLimit(name); ok {
		return maximum
	}
	if _, _, ok := parseTargetStateName(name); ok {
		return maxTargetStateBytes
	}
	_, kind, ok := parseTargetArtifactName(name)
	if !ok {
		return 0
	}
	switch kind {
	case TargetServiceTrustKind:
		return maxServiceTrustBytes
	case TargetActivationPlanKind:
		return maxActivationPlanBytes
	case TargetExecutorBeginKind:
		return maxExecutorBeginBytes
	case TargetActivationStateKind:
		return maxActivationStateBytes
	case TargetActivationProofKind:
		return maxActivationProofBytes
	case TargetGatewayReceiptPublicKeyKind:
		return maxGatewayPublicKeyBytes
	default:
		return MaxArtifactBytes
	}
}

func classifyName(name string) artifactKind {
	switch name {
	case LockFileName:
		return artifactLock
	case PlanFileName, ReleaseFileName, PolicyFileName,
		ControllerWitnessPublicKeyFileName, ProofFileName:
		return artifactFixed
	default:
		if isAuthorizationArtifactName(name) {
			return artifactFixed
		}
		if _, _, ok := parseTargetStateName(name); ok {
			return artifactTargetState
		}
		if _, _, ok := parseTargetArtifactName(name); ok {
			return artifactTarget
		}
		return artifactInvalid
	}
}

func validTargetArtifactKind(kind string) bool {
	for _, candidate := range targetArtifactKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

func parseTargetArtifactName(name string) (target uint16, kind string, ok bool) {
	baseLength := len(targetPrefix) + targetIndexDigits + 1
	if len(name) <= baseLength || !strings.HasPrefix(name, targetPrefix) || name[baseLength-1] != '-' {
		return 0, "", false
	}
	index, ok := parseFixedDecimal(name[len(targetPrefix) : baseLength-1])
	if !ok || index >= uint64(MaxTargets) {
		return 0, "", false
	}
	kind = name[baseLength:]
	if !validTargetArtifactKind(kind) {
		return 0, "", false
	}
	return uint16(index), kind, true
}

func parseTargetStateName(name string) (target uint16, sequence uint64, ok bool) {
	expectedLength := len(targetPrefix) + targetIndexDigits + len(targetStateMarker) +
		targetStateDigits + len(targetStateSuffix)
	if len(name) != expectedLength || !strings.HasPrefix(name, targetPrefix) ||
		!strings.HasSuffix(name, targetStateSuffix) {
		return 0, 0, false
	}
	indexStart := len(targetPrefix)
	indexEnd := indexStart + targetIndexDigits
	if name[indexEnd:indexEnd+len(targetStateMarker)] != targetStateMarker {
		return 0, 0, false
	}
	index, ok := parseFixedDecimal(name[indexStart:indexEnd])
	if !ok || index >= uint64(MaxTargets) {
		return 0, 0, false
	}
	sequenceStart := indexEnd + len(targetStateMarker)
	sequence, ok = parseFixedDecimal(name[sequenceStart : sequenceStart+targetStateDigits])
	if !ok || sequence > MaxTargetStateSequence {
		return 0, 0, false
	}
	return uint16(index), sequence, true
}

func parseFixedDecimal(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	var parsed uint64
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
		parsed = parsed*10 + uint64(character-'0')
	}
	return parsed, true
}

func ownerAndLinks(info os.FileInfo) (int, uint64, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), uint64(stat.Nlink), true
}

func sameSnapshot(left, right os.FileInfo) bool {
	leftSeconds, leftNanos, leftOK := changeTime(left)
	rightSeconds, rightNanos, rightOK := changeTime(right)
	return sameIdentity(left, right) && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime()) && leftOK && rightOK &&
		leftSeconds == rightSeconds && leftNanos == rightNanos
}

func sameIdentity(left, right os.FileInfo) bool {
	return sameInode(left, right) && left.Mode() == right.Mode()
}

func sameInode(left, right os.FileInfo) bool {
	leftUID, leftLinks, leftOK := ownerAndLinks(left)
	rightUID, rightLinks, rightOK := ownerAndLinks(right)
	return left != nil && right != nil && leftOK && rightOK &&
		os.SameFile(left, right) && leftUID == rightUID && leftLinks == rightLinks
}

func changeTime(info os.FileInfo) (int64, int64, bool) {
	if info == nil || info.Sys() == nil {
		return 0, 0, false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, 0, false
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		field := value.FieldByName(name)
		if field.IsValid() && field.Kind() == reflect.Struct {
			seconds := field.FieldByName("Sec")
			nanoseconds := field.FieldByName("Nsec")
			if seconds.IsValid() && nanoseconds.IsValid() &&
				seconds.CanInt() && nanoseconds.CanInt() {
				return seconds.Int(), nanoseconds.Int(), true
			}
		}
	}
	seconds := value.FieldByName("Ctime")
	nanoseconds := value.FieldByName("Ctimensec")
	if seconds.IsValid() && nanoseconds.IsValid() && seconds.CanInt() && nanoseconds.CanInt() {
		return seconds.Int(), nanoseconds.Int(), true
	}
	return 0, 0, false
}

func equalNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameInventory(left, right workspaceSnapshot) bool {
	if left.entries != right.entries || left.bytes != right.bytes ||
		len(left.info) != len(right.info) {
		return false
	}
	for name, leftInfo := range left.info {
		rightInfo, ok := right.info[name]
		if !ok || !sameSnapshot(leftInfo, rightInfo) {
			return false
		}
	}
	return true
}

func writeAll(file *os.File, raw []byte) error {
	for written := 0; written < len(raw); {
		count, err := file.Write(raw[written:])
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrShortWrite
		}
		written += count
	}
	return nil
}
