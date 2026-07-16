// Package activationstore provides a rooted, append-only filesystem workspace
// for one node-local activation. It stores bytes but does not interpret,
// authorize, execute, or authenticate any activation artifact.
package activationstore

import (
	"context"
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

	"github.com/hardrails/steward/internal/ocibundle"
)

const (
	LockFileName                    = ".lock"
	ReleaseFileName                 = "release.dsse.json"
	PolicyFileName                  = "policy.dsse.json"
	IntentFileName                  = "intent.json"
	ImageArchiveFileName            = "image.oci.tar"
	PlanFileName                    = "plan.json"
	AdmissionFileName               = "admission.json"
	ServiceTrustFileName            = "service-trust.json"
	CanaryRequestFileName           = "canary.request.json"
	CanaryChallengeFileName         = "canary.challenge.json"
	CanaryTaskFileName              = "canary.task.json"
	CanarySubmitFileName            = "canary.submit.json"
	CanaryStatusFileName            = "canary.status.json"
	CanaryResultFileName            = "canary.result.json"
	ExecutorBaselineWitnessFileName = "executor-baseline-witness.json"
	ExecutorBeginFileName           = "executor-activation-begin.json"
	ExecutorCheckpointFileName      = "executor-activation-checkpoint.json"
	ExecutorDeltaFileName           = "executor-delta.bin"
	ExecutorFinalWitnessFileName    = "executor-final-witness.json"
	GatewayTaskReceiptsFileName     = "gateway-task-receipts.ndjson"
	ProofFileName                   = "proof.json"

	MaxWorkspaceEntries = 48
	// MaxSmallArtifactBytes bounds any one non-archive artifact. The Executor
	// delta is the largest valid small artifact and may consume this full
	// allowance.
	MaxSmallArtifactBytes = int64(16 << 20)
	// MaxSmallFilesBytes bounds all non-archive workspace bytes together. The
	// 40 MiB ceiling accommodates the maximum Executor delta, every bounded
	// companion artifact, and every state slot allowed by MaxWorkspaceEntries
	// while keeping the workspace finite.
	MaxSmallFilesBytes   = int64(40 << 20)
	MaxStateSequence     = uint64(999999999999)
	stateNamePrefix      = "state-"
	stateNameSuffix      = ".json"
	stateSequenceDigits  = 12
	maxListedEntryBuffer = MaxWorkspaceEntries + 1
)

var (
	ErrLocked           = errors.New("activation workspace is locked")
	ErrClosed           = errors.New("activation workspace is closed")
	ErrPoisoned         = errors.New("activation workspace write outcome is ambiguous")
	ErrAlreadyExists    = errors.New("activation artifact already exists")
	ErrStateOrder       = errors.New("activation state checkpoint is not append-only")
	ErrCapacityExceeded = errors.New("activation workspace capacity exceeded")
	ErrUnsafeWorkspace  = errors.New("unsafe activation workspace")
	ErrInvalidName      = errors.New("invalid activation artifact name")
)

type artifactKind uint8

const (
	artifactInvalid artifactKind = iota
	artifactLock
	artifactExternal
	artifactArchive
	artifactGenerated
	artifactState
)

type writeKind uint8

const (
	writeGenerated writeKind = iota
	writeExternal
	writeState
)

// Store holds one rooted directory descriptor and a lifetime exclusive lock.
// Its methods are safe for concurrent use. Generated artifacts are never
// overwritten, renamed, or removed.
type Store struct {
	directory     string
	identity      os.FileInfo
	root          *os.Root
	directoryLock *os.File
	lock          *os.File
	// digests binds every readable bounded artifact to the bytes observed when
	// the workspace opened or when this Store durably created the artifact.
	digests map[string][sha256.Size]byte

	mu       sync.Mutex
	closed   bool
	poisoned bool
}

type workspaceSnapshot struct {
	entries int
	bytes   int64
	states  []string
	info    map[string]os.FileInfo
}

// Create exclusively creates one new owner-only workspace beneath an existing
// trusted parent, fsyncs both directories, and opens the resulting store.
func Create(directory string) (*Store, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		directory == string(filepath.Separator) || strings.ContainsRune(directory, '\x00') {
		return nil, fmt.Errorf("%w: directory must be a clean absolute non-root path", ErrUnsafeWorkspace)
	}
	if _, err := os.Lstat(directory); err == nil {
		return nil, ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	requestedParent := filepath.Dir(directory)
	canonicalParent, err := filepath.EvalSymlinks(requestedParent)
	if err != nil || !filepath.IsAbs(canonicalParent) || filepath.Clean(canonicalParent) != canonicalParent {
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
		return nil, fmt.Errorf("stat activation workspace parent: %w", err)
	}
	parentRoot, err := os.OpenRoot(canonicalParent)
	if err != nil {
		return nil, fmt.Errorf("open activation workspace parent: %w", err)
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
		return nil, fmt.Errorf("create activation workspace: %w", err)
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
		// A restrictive process umask can remove the owner's search bit. There
		// is no portable descriptor-relative chmod API in the standard
		// library, so verify the exact inode both before and after this
		// pathname fallback. Normal umasks take the descriptor-first path.
		if chmodErr := os.Chmod(createdPath, 0o700); chmodErr != nil {
			_ = parentRoot.Close()
			return nil, fmt.Errorf("protect new activation workspace: %w", chmodErr)
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
		return nil, fmt.Errorf("anchor new activation workspace: %w", err)
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
// nonblocking lifetime lock, and rejects any unsafe or unexpected content.
func Open(directory string) (*Store, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		directory == string(filepath.Separator) || strings.ContainsRune(directory, '\x00') {
		return nil, fmt.Errorf("%w: directory must be a clean absolute non-root path", ErrUnsafeWorkspace)
	}
	requested, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat activation workspace: %w", err)
	}
	if !validWorkspaceDirectory(requested) {
		return nil, fmt.Errorf("%w: directory must be owned by this process with mode 0700", ErrUnsafeWorkspace)
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical ||
		canonical == string(filepath.Separator) {
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
		return nil, fmt.Errorf("stat canonical activation workspace: %w", err)
	}
	if !validWorkspaceDirectory(before) || !os.SameFile(requested, before) {
		return nil, fmt.Errorf("%w: directory changed during canonicalization", ErrUnsafeWorkspace)
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, fmt.Errorf("open activation workspace root: %w", err)
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
	snapshot, err := store.auditLocked()
	if err != nil {
		_ = store.closeLocked()
		return nil, err
	}
	digests := make(map[string][sha256.Size]byte, len(snapshot.info))
	for name := range snapshot.info {
		kind := classifyName(name)
		if kind == artifactLock || kind == artifactArchive {
			continue
		}
		raw, err := store.read(name, MaxSmallArtifactBytes, nil)
		if err != nil {
			_ = store.closeLocked()
			return nil, err
		}
		digests[name] = sha256.Sum256(raw)
	}
	store.digests = digests
	return store, nil
}

// StateCheckpointName returns the only accepted state-checkpoint name for a
// sequence. Fixed-width decimal names sort in state order.
func StateCheckpointName(sequence uint64) (string, error) {
	if sequence > MaxStateSequence {
		return "", fmt.Errorf("%w: state sequence exceeds twelve decimal digits", ErrInvalidName)
	}
	return fmt.Sprintf("%s%012d%s", stateNamePrefix, sequence, stateNameSuffix), nil
}

// Read returns a stable bounded snapshot of one small artifact and requires the
// bytes to match the Store's post-open content baseline. The OCI archive is
// deliberately excluded; Path is its only surface so the importer can snapshot
// and verify the large file directly.
func (store *Store) Read(name string, limit int64) ([]byte, error) {
	return store.read(name, limit, nil)
}

// The hook is test-only plumbing for deterministic pathname and inode races.
func (store *Store) read(name string, limit int64, afterOpen func(*os.File) error) ([]byte, error) {
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return nil, err
	}
	kind := classifyName(name)
	if kind == artifactInvalid || kind == artifactLock || kind == artifactArchive {
		return nil, fmt.Errorf("%w: artifact cannot be read through this method", ErrInvalidName)
	}
	if limit <= 0 || limit > MaxSmallArtifactBytes {
		return nil, fmt.Errorf("%w: read limit must be between 1 and %d", ErrCapacityExceeded, MaxSmallArtifactBytes)
	}
	if _, err := store.auditLocked(); err != nil {
		return nil, err
	}

	before, err := store.root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect activation artifact %q: %w", name, err)
	}
	if err := validateArtifact(name, before); err != nil {
		return nil, errors.Join(
			fmt.Errorf("%w: artifact %q is unsafe", ErrUnsafeWorkspace, name),
			err,
		)
	}
	if before.Size() > limit {
		return nil, fmt.Errorf("%w: artifact %q exceeds its read limit", ErrCapacityExceeded, name)
	}
	file, err := store.root.OpenFile(
		name,
		os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open activation artifact %q: %w", name, err)
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
	if store.digests != nil {
		expected, ok := store.digests[name]
		if !ok || sha256.Sum256(raw) != expected {
			return closeWith(nil, fmt.Errorf(
				"%w: artifact %q bytes changed after the workspace was opened",
				ErrUnsafeWorkspace,
				name,
			))
		}
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if _, err := store.auditLocked(); err != nil {
		return nil, err
	}
	return raw, nil
}

// WriteOnce exclusively creates, writes, fsyncs, and directory-syncs one
// generated artifact or state checkpoint. It never removes a partial file after
// creation because doing so would make an ambiguous write retryable.
func (store *Store) WriteOnce(name string, raw []byte) error {
	return store.writeOnce(name, raw, writeGenerated)
}

// Import exclusively copies one of the four small external inputs into a
// created workspace. The archive has a separate streaming import method.
func (store *Store) Import(name string, raw []byte) error {
	return store.writeOnce(name, raw, writeExternal)
}

// ImportArchive securely snapshots one owner-only regular source file into the
// fixed OCI archive name and requires its exact expected digest and byte length.
// A failed copy removes only the unchanged partial destination and
// directory-syncs that removal before returning.
func (store *Store) ImportArchive(
	sourcePath string,
	expected ocibundle.ArchiveIdentity,
) error {
	return store.ImportArchiveContext(context.Background(), sourcePath, expected)
}

// ImportArchiveContext is ImportArchive with cancellation propagated through
// the archive copy. Cancellation before durable publication removes and
// directory-syncs the unchanged partial destination.
func (store *Store) ImportArchiveContext(
	ctx context.Context,
	sourcePath string,
	expected ocibundle.ArchiveIdentity,
) error {
	return store.importArchiveContext(ctx, sourcePath, expected, nil)
}

// The hook is test-only plumbing for deterministic source changes after open.
func (store *Store) importArchive(
	sourcePath string,
	expected ocibundle.ArchiveIdentity,
	afterOpen func(*os.File) error,
) error {
	return store.importArchiveContext(context.Background(), sourcePath, expected, afterOpen)
}

func (store *Store) importArchiveContext(
	ctx context.Context,
	sourcePath string,
	expected ocibundle.ArchiveIdentity,
	afterOpen func(*os.File) error,
) error {
	if ctx == nil {
		return errors.New("activation archive import context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return ErrClosed
	}
	if !validArchiveIdentity(expected) {
		return fmt.Errorf("%w: expected archive identity is invalid", ErrUnsafeWorkspace)
	}
	if sourcePath == "" || !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath ||
		strings.ContainsRune(sourcePath, '\x00') {
		return fmt.Errorf("%w: archive source must be a clean absolute path", ErrUnsafeWorkspace)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.usableLocked(); err != nil {
		return err
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if snapshot.entries >= MaxWorkspaceEntries {
		return ErrCapacityExceeded
	}
	if _, err := store.root.Lstat(ImageArchiveFileName); err == nil {
		return ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	sourceBefore, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect OCI archive source: %w", err)
	}
	if err := validateArchiveSource(sourceBefore); err != nil {
		return err
	}
	source, err := os.OpenFile(
		sourcePath,
		os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("open OCI archive source: %w", err)
	}
	sourceOpen := true
	closeSource := func() error {
		if !sourceOpen {
			return nil
		}
		sourceOpen = false
		return source.Close()
	}
	sourceOpened, statErr := source.Stat()
	sourceNamed, namedErr := os.Lstat(sourcePath)
	if statErr != nil || namedErr != nil || validateArchiveSource(sourceOpened) != nil ||
		validateArchiveSource(sourceNamed) != nil || !sameSnapshot(sourceBefore, sourceOpened) ||
		!sameSnapshot(sourceOpened, sourceNamed) {
		return errors.Join(
			fmt.Errorf("%w: archive source changed while opening", ErrUnsafeWorkspace),
			statErr,
			namedErr,
			closeSource(),
		)
	}
	if sourceOpened.Size() != expected.Bytes {
		return errors.Join(
			fmt.Errorf("%w: archive source byte length does not match expected identity", ErrUnsafeWorkspace),
			closeSource(),
		)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, closeSource())
	}

	destination, err := store.root.OpenFile(
		ImageArchiveFileName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0o200,
	)
	if errors.Is(err, os.ErrExist) {
		return errors.Join(ErrAlreadyExists, closeSource())
	}
	if err != nil {
		return errors.Join(fmt.Errorf("create workspace OCI archive: %w", err), closeSource())
	}
	destinationOpen := true
	closeDestination := func() error {
		if !destinationOpen {
			return nil
		}
		destinationOpen = false
		return destination.Close()
	}
	destinationCreated, statErr := destination.Stat()
	if statErr != nil {
		return store.failArchiveImportLocked(
			statErr,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := destination.Chmod(0o200); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	destinationCreated, statErr = destination.Stat()
	destinationNamed, namedErr := store.root.Lstat(ImageArchiveFileName)
	if statErr != nil || namedErr != nil ||
		!validIncompleteOutput(destinationCreated, ocibundle.DefaultMaxArchiveBytes+1) ||
		!validIncompleteOutput(destinationNamed, ocibundle.DefaultMaxArchiveBytes+1) ||
		destinationCreated.Size() != 0 ||
		!sameSnapshot(destinationCreated, destinationNamed) {
		cause := errors.Join(
			fmt.Errorf("%w: archive destination changed while creating", ErrUnsafeWorkspace),
			statErr,
			namedErr,
		)
		return store.failArchiveImportLocked(
			cause,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if afterOpen != nil {
		if err := afterOpen(source); err != nil {
			return store.failArchiveImportLocked(
				err,
				source,
				&sourceOpen,
				destination,
				&destinationOpen,
				destinationCreated,
			)
		}
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	hasher := sha256.New()
	copied, copyErr := io.Copy(
		archiveImportContextWriter{
			ctx: ctx, writer: io.MultiWriter(destination, hasher),
		},
		archiveImportContextReader{
			ctx:    ctx,
			reader: io.LimitReader(source, expected.Bytes+1),
		},
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return store.failArchiveImportLocked(
			contextErr,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	observedDigest := fmt.Sprintf("sha256:%x", hasher.Sum(nil))
	if copyErr != nil || copied != sourceOpened.Size() || copied != expected.Bytes ||
		observedDigest != expected.Digest || copied <= 0 ||
		copied > ocibundle.DefaultMaxArchiveBytes {
		return store.failArchiveImportLocked(
			errors.Join(
				fmt.Errorf("%w: OCI archive source bytes do not match expected identity", ErrUnsafeWorkspace),
				copyErr,
			),
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	sourceAfter, sourceStatErr := source.Stat()
	sourceCurrent, sourceNamedErr := os.Lstat(sourcePath)
	destinationAfter, destinationStatErr := destination.Stat()
	destinationCurrent, destinationNamedErr := store.root.Lstat(ImageArchiveFileName)
	if sourceStatErr != nil || sourceNamedErr != nil || destinationStatErr != nil ||
		destinationNamedErr != nil || validateArchiveSource(sourceAfter) != nil ||
		validateArchiveSource(sourceCurrent) != nil ||
		!validIncompleteOutput(destinationAfter, ocibundle.DefaultMaxArchiveBytes+1) ||
		!validIncompleteOutput(destinationCurrent, ocibundle.DefaultMaxArchiveBytes+1) ||
		!sameSnapshot(sourceOpened, sourceAfter) ||
		!sameSnapshot(sourceOpened, sourceCurrent) ||
		!sameIdentity(destinationCreated, destinationAfter) ||
		!sameIdentity(destinationCreated, destinationCurrent) ||
		destinationAfter.Size() != copied || destinationCurrent.Size() != copied {
		return store.failArchiveImportLocked(
			errors.Join(
				fmt.Errorf("%w: archive source or destination changed while copying", ErrUnsafeWorkspace),
				sourceStatErr,
				sourceNamedErr,
				destinationStatErr,
				destinationNamedErr,
			),
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := destination.Sync(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	destinationSynced, destinationStatErr := destination.Stat()
	destinationCurrent, destinationNamedErr = store.root.Lstat(ImageArchiveFileName)
	if destinationStatErr != nil || destinationNamedErr != nil ||
		!validIncompleteOutput(destinationSynced, ocibundle.DefaultMaxArchiveBytes+1) ||
		!validIncompleteOutput(destinationCurrent, ocibundle.DefaultMaxArchiveBytes+1) ||
		!sameSnapshot(destinationAfter, destinationSynced) ||
		!sameSnapshot(destinationAfter, destinationCurrent) {
		return store.failArchiveImportLocked(
			errors.Join(
				fmt.Errorf("%w: archive destination changed while syncing", ErrUnsafeWorkspace),
				destinationStatErr,
				destinationNamedErr,
			),
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := destination.Chmod(0o600); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := destination.Sync(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	destinationPublished, destinationStatErr := destination.Stat()
	destinationCurrent, destinationNamedErr = store.root.Lstat(ImageArchiveFileName)
	if destinationStatErr != nil || destinationNamedErr != nil ||
		validateArtifact(ImageArchiveFileName, destinationPublished) != nil ||
		validateArtifact(ImageArchiveFileName, destinationCurrent) != nil ||
		!sameInode(destinationSynced, destinationPublished) ||
		!sameInode(destinationSynced, destinationCurrent) ||
		!sameSnapshot(destinationPublished, destinationCurrent) {
		return store.failArchiveImportLocked(
			errors.Join(
				fmt.Errorf("%w: archive destination changed while publishing", ErrUnsafeWorkspace),
				destinationStatErr,
				destinationNamedErr,
			),
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := closeSource(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := closeDestination(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	destinationCurrent, err = store.root.Lstat(ImageArchiveFileName)
	if err != nil || validateArtifact(ImageArchiveFileName, destinationCurrent) != nil ||
		!sameSnapshot(destinationPublished, destinationCurrent) || destinationCurrent.Size() != copied {
		return store.failArchiveImportLocked(
			errors.Join(
				fmt.Errorf("%w: archive destination changed after closing", ErrUnsafeWorkspace),
				err,
			),
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := ctx.Err(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if err := store.syncDirectoryLocked(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	if _, err := store.auditLocked(); err != nil {
		return store.failArchiveImportLocked(
			err,
			source,
			&sourceOpen,
			destination,
			&destinationOpen,
			destinationCreated,
		)
	}
	return nil
}

type archiveImportContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader archiveImportContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

type archiveImportContextWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer archiveImportContextWriter) Write(buffer []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := writer.writer.Write(buffer)
	if contextErr := writer.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

func (store *Store) failArchiveImportLocked(
	cause error,
	source *os.File,
	sourceOpen *bool,
	destination *os.File,
	destinationOpen *bool,
	destinationIdentity os.FileInfo,
) error {
	var closeErrors []error
	if source != nil && sourceOpen != nil && *sourceOpen {
		*sourceOpen = false
		closeErrors = append(closeErrors, source.Close())
	}
	if destination != nil && destinationOpen != nil && *destinationOpen {
		*destinationOpen = false
		closeErrors = append(closeErrors, destination.Close())
	}
	cleanupErr := store.removePartialArchiveLocked(destinationIdentity)
	if cleanupErr != nil {
		store.poisoned = true
		return errors.Join(cause, errors.Join(closeErrors...), cleanupErr, ErrPoisoned)
	}
	return errors.Join(cause, errors.Join(closeErrors...))
}

func (store *Store) removePartialArchiveLocked(identity os.FileInfo) error {
	current, err := store.root.Lstat(ImageArchiveFileName)
	if err != nil || identity == nil || !validRemovableOutput(current, ocibundle.DefaultMaxArchiveBytes+1) ||
		!sameInode(identity, current) {
		return errors.Join(
			fmt.Errorf("%w: partial archive cannot be removed safely", ErrUnsafeWorkspace),
			err,
		)
	}
	if err := store.root.Remove(ImageArchiveFileName); err != nil {
		return err
	}
	if _, err := store.root.Lstat(ImageArchiveFileName); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(
			fmt.Errorf("%w: partial archive remained after removal", ErrUnsafeWorkspace),
			err,
		)
	}
	return store.syncDirectoryLocked()
}

func (store *Store) writeOnce(name string, raw []byte, operation writeKind) error {
	if store == nil {
		return ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return err
	}
	kind := classifyName(name)
	allowed := operation == writeGenerated && kind == artifactGenerated ||
		operation == writeExternal && kind == artifactExternal ||
		operation == writeState && kind == artifactState
	if !allowed {
		switch operation {
		case writeExternal:
			return fmt.Errorf("%w: only the four small initial inputs may be imported", ErrInvalidName)
		case writeState:
			return fmt.Errorf("%w: invalid state checkpoint name", ErrInvalidName)
		default:
			return fmt.Errorf("%w: only fixed generated artifacts may be written", ErrInvalidName)
		}
	}
	if int64(len(raw)) > MaxSmallArtifactBytes {
		return fmt.Errorf("%w: artifact exceeds %d bytes", ErrCapacityExceeded, MaxSmallArtifactBytes)
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return err
	}
	if _, err := store.root.Lstat(name); err == nil {
		return ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if operation == writeState {
		expected, err := StateCheckpointName(uint64(len(snapshot.states)))
		if err != nil || name != expected {
			return errors.Join(ErrStateOrder, err)
		}
	}
	if snapshot.entries >= MaxWorkspaceEntries ||
		snapshot.bytes > MaxSmallFilesBytes-int64(len(raw)) {
		return ErrCapacityExceeded
	}

	file, err := store.root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0o200,
	)
	if errors.Is(err, os.ErrExist) {
		return ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("create activation artifact %q: %w", name, err)
	}
	created := true
	fail := func(cause error) error {
		if created {
			store.poisoned = true
		}
		return errors.Join(cause, file.Close(), ErrPoisoned)
	}
	if err := file.Chmod(0o200); err != nil {
		return fail(err)
	}
	opened, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	named, err := store.root.Lstat(name)
	if err != nil || !validIncompleteOutput(opened, MaxSmallArtifactBytes) ||
		!validIncompleteOutput(named, MaxSmallArtifactBytes) ||
		opened.Size() != 0 || !sameSnapshot(opened, named) {
		return fail(errors.Join(
			fmt.Errorf("%w: generated artifact %q changed while creating", ErrUnsafeWorkspace, name),
			err,
		))
	}
	if err := writeAll(file, raw); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	written, statErr := file.Stat()
	current, namedErr := store.root.Lstat(name)
	if statErr != nil || namedErr != nil || !validIncompleteOutput(written, MaxSmallArtifactBytes) ||
		!validIncompleteOutput(current, MaxSmallArtifactBytes) || written.Size() != int64(len(raw)) ||
		current.Size() != int64(len(raw)) || !sameIdentity(opened, written) ||
		!sameIdentity(opened, current) {
		return fail(errors.Join(
			fmt.Errorf("%w: generated artifact %q changed while writing", ErrUnsafeWorkspace, name),
			statErr,
			namedErr,
		))
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	published, statErr := file.Stat()
	current, namedErr = store.root.Lstat(name)
	if statErr != nil || namedErr != nil || validateArtifact(name, published) != nil ||
		validateArtifact(name, current) != nil || published.Size() != int64(len(raw)) ||
		current.Size() != int64(len(raw)) || !sameInode(written, published) ||
		!sameInode(written, current) || !sameSnapshot(published, current) {
		return fail(errors.Join(
			fmt.Errorf("%w: generated artifact %q changed while publishing", ErrUnsafeWorkspace, name),
			statErr,
			namedErr,
		))
	}
	if err := file.Close(); err != nil {
		store.poisoned = true
		return errors.Join(err, ErrPoisoned)
	}
	created = false
	current, err = store.root.Lstat(name)
	if err != nil || validateArtifact(name, current) != nil ||
		current.Size() != int64(len(raw)) || !sameSnapshot(published, current) {
		store.poisoned = true
		return errors.Join(
			fmt.Errorf("%w: generated artifact %q changed after closing", ErrUnsafeWorkspace, name),
			err,
			ErrPoisoned,
		)
	}
	if err := store.syncDirectoryLocked(); err != nil {
		store.poisoned = true
		return errors.Join(err, ErrPoisoned)
	}
	if _, err := store.auditLocked(); err != nil {
		store.poisoned = true
		return errors.Join(err, ErrPoisoned)
	}
	if store.digests == nil {
		store.digests = make(map[string][sha256.Size]byte)
	}
	store.digests[name] = sha256.Sum256(raw)
	return nil
}

// AppendState writes exactly one numbered immutable state checkpoint.
func (store *Store) AppendState(sequence uint64, raw []byte) (string, error) {
	name, err := StateCheckpointName(sequence)
	if err != nil {
		return "", err
	}
	if err := store.writeOnce(name, raw, writeState); err != nil {
		return "", err
	}
	return name, nil
}

// ListStateCheckpoints returns state checkpoint names in sequence order.
func (store *Store) ListStateCheckpoints() ([]string, error) {
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
	return append([]string(nil), snapshot.states...), nil
}

// LatestState reads the lexicographically latest fixed-width checkpoint and
// verifies that the state inventory did not change across the read.
func (store *Store) LatestState(limit int64) (name string, raw []byte, found bool, err error) {
	states, err := store.ListStateCheckpoints()
	if err != nil {
		return "", nil, false, err
	}
	if len(states) == 0 {
		return "", nil, false, nil
	}
	name = states[len(states)-1]
	raw, err = store.Read(name, limit)
	if err != nil {
		return "", nil, false, err
	}
	after, err := store.ListStateCheckpoints()
	if err != nil {
		return "", nil, false, err
	}
	if len(after) == 0 || after[len(after)-1] != name {
		return "", nil, false, fmt.Errorf("%w: latest state changed while reading", ErrUnsafeWorkspace)
	}
	return name, raw, true, nil
}

// Path returns an absolute path only for the OCI archive. Small artifacts never
// leave the rooted descriptor API.
func (store *Store) Path(name string) (string, error) {
	if store == nil {
		return "", ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.usableLocked(); err != nil {
		return "", err
	}
	if name != ImageArchiveFileName {
		return "", fmt.Errorf("%w: paths are exposed only for %s", ErrInvalidName, ImageArchiveFileName)
	}
	snapshot, err := store.auditLocked()
	if err != nil {
		return "", err
	}
	if _, ok := snapshot.info[ImageArchiveFileName]; !ok {
		return "", os.ErrNotExist
	}
	return filepath.Join(store.directory, ImageArchiveFileName), nil
}

// Close releases the lifetime lock and rooted directory descriptor. It is
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
		return nil, fmt.Errorf("open activation workspace directory lock: %w", err)
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
		return closeWith(fmt.Errorf("lock activation workspace directory: %w", err))
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
		return nil, fmt.Errorf("open activation workspace lock: %w", err)
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
		return closeWith(fmt.Errorf("lock activation workspace: %w", err))
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
		entries: len(names),
		info:    make(map[string]os.FileInfo, len(names)),
	}
	for _, name := range names {
		info, err := store.root.Lstat(name)
		if err != nil {
			return workspaceSnapshot{}, fmt.Errorf("inspect activation workspace entry %q: %w", name, err)
		}
		if err := validateArtifact(name, info); err != nil {
			return workspaceSnapshot{}, err
		}
		snapshot.info[name] = info
		if name != ImageArchiveFileName {
			if info.Size() > MaxSmallFilesBytes-snapshot.bytes {
				return workspaceSnapshot{}, ErrCapacityExceeded
			}
			snapshot.bytes += info.Size()
		}
		if classifyName(name) == artifactState {
			snapshot.states = append(snapshot.states, name)
		}
	}
	if _, ok := snapshot.info[LockFileName]; !ok {
		return workspaceSnapshot{}, fmt.Errorf("%w: workspace lock disappeared", ErrUnsafeWorkspace)
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
	sort.Strings(snapshot.states)
	for sequence, name := range snapshot.states {
		expected, err := StateCheckpointName(uint64(sequence))
		if err != nil || name != expected {
			return workspaceSnapshot{}, errors.Join(ErrStateOrder, err)
		}
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

func validateTrustedAncestors(directory string) error {
	euid := os.Geteuid()
	if euid < 0 {
		return fmt.Errorf("%w: ownership cannot be verified on this platform", ErrUnsafeWorkspace)
	}
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect activation workspace ancestor %q: %w", current, err)
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
	switch kind {
	case artifactLock:
		if info.Size() != 0 {
			return fmt.Errorf("%w: lock file must be empty", ErrUnsafeWorkspace)
		}
	case artifactArchive:
		if info.Size() <= 0 || info.Size() > ocibundle.DefaultMaxArchiveBytes {
			return fmt.Errorf("%w: OCI archive size is outside the importer limit", ErrUnsafeWorkspace)
		}
	default:
		if info.Size() > MaxSmallArtifactBytes {
			return ErrCapacityExceeded
		}
	}
	return nil
}

func validateArchiveSource(info os.FileInfo) error {
	uid, links, ok := ownerAndLinks(info)
	if info == nil || !ok || uid != os.Geteuid() || links != 1 || !info.Mode().IsRegular() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > ocibundle.DefaultMaxArchiveBytes {
		return fmt.Errorf(
			"%w: archive source must be a single-link owner-only regular file between 1 and %d bytes",
			ErrUnsafeWorkspace,
			ocibundle.DefaultMaxArchiveBytes,
		)
	}
	return nil
}

func validIncompleteOutput(info os.FileInfo, maximum int64) bool {
	uid, links, ok := ownerAndLinks(info)
	return info != nil && ok && uid == os.Geteuid() && links == 1 &&
		info.Mode().IsRegular() &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Mode().Perm() == 0o200 && info.Size() >= 0 && info.Size() <= maximum
}

func validRemovableOutput(info os.FileInfo, maximum int64) bool {
	if info == nil || info.Size() < 0 || info.Size() > maximum {
		return false
	}
	mode := info.Mode().Perm()
	if mode != 0 && mode != 0o200 && mode != 0o600 {
		return false
	}
	uid, links, ok := ownerAndLinks(info)
	return ok && uid == os.Geteuid() && links == 1 && info.Mode().IsRegular() &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func classifyName(name string) artifactKind {
	switch name {
	case LockFileName:
		return artifactLock
	case ReleaseFileName, PolicyFileName, IntentFileName, ServiceTrustFileName:
		return artifactExternal
	case ImageArchiveFileName:
		return artifactArchive
	case PlanFileName, AdmissionFileName, CanaryRequestFileName, CanaryChallengeFileName,
		CanaryTaskFileName, CanarySubmitFileName, CanaryStatusFileName, CanaryResultFileName,
		ExecutorBaselineWitnessFileName, ExecutorBeginFileName,
		ExecutorCheckpointFileName,
		ExecutorDeltaFileName, ExecutorFinalWitnessFileName,
		GatewayTaskReceiptsFileName, ProofFileName:
		return artifactGenerated
	default:
		if validStateCheckpointName(name) {
			return artifactState
		}
		return artifactInvalid
	}
}

func validStateCheckpointName(name string) bool {
	expectedLength := len(stateNamePrefix) + stateSequenceDigits + len(stateNameSuffix)
	if len(name) != expectedLength || !strings.HasPrefix(name, stateNamePrefix) ||
		!strings.HasSuffix(name, stateNameSuffix) {
		return false
	}
	digits := name[len(stateNamePrefix) : len(stateNamePrefix)+stateSequenceDigits]
	for _, character := range digits {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validArchiveIdentity(identity ocibundle.ArchiveIdentity) bool {
	const digestPrefix = "sha256:"
	if identity.Bytes < 1 || identity.Bytes > ocibundle.DefaultMaxArchiveBytes ||
		!strings.HasPrefix(identity.Digest, digestPrefix) {
		return false
	}
	digest := strings.TrimPrefix(identity.Digest, digestPrefix)
	if len(digest) != sha256.Size*2 {
		return false
	}
	for _, character := range digest {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
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
	if seconds.IsValid() && nanoseconds.IsValid() &&
		seconds.CanInt() && nanoseconds.CanInt() {
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
