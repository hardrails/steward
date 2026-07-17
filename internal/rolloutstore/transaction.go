package rolloutstore

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	stagingPrefix     = ".steward-stage-"
	maxStagingEntries = 1
)

// writeTransactionHooks is test-only plumbing for failures at durable
// transaction boundaries. A hook error models a process stopping at that
// boundary: the Store is poisoned and recovery is deferred until Open.
type writeTransactionHooks struct {
	afterStageCreate  func(*os.File) error
	afterDataSync     func(*os.File) error
	afterPreparedSync func(*os.File) error
	afterLink         func(*os.File) error
	afterPublishSync  func(*os.File) error
	afterStageRemove  func(*os.File) error
	afterCleanupSync  func(*os.File) error
}

func (store *Store) createWithSnapshotLocked(
	name string,
	raw []byte,
	snapshot workspaceSnapshot,
	afterCreate func(*os.File) error,
) error {
	var hooks *writeTransactionHooks
	if afterCreate != nil {
		hooks = &writeTransactionHooks{afterStageCreate: afterCreate}
	}
	return store.createTransactionWithSnapshotLocked(name, raw, snapshot, hooks)
}

// createTransactionWithSnapshotLocked publishes an immutable artifact with a
// same-directory hard-link transaction. Creating the final name with os.Link
// is atomic and fails if that name already exists, so no final artifact is
// ever replaced. Open reconciles the bounded staging state left by a crash.
func (store *Store) createTransactionWithSnapshotLocked(
	name string,
	raw []byte,
	snapshot workspaceSnapshot,
	hooks *writeTransactionHooks,
) error {
	maximum := artifactByteLimit(name)
	if maximum <= 0 {
		return fmt.Errorf("%w: artifact has no byte limit", ErrInvalidName)
	}
	if int64(len(raw)) > maximum {
		return fmt.Errorf("%w: artifact exceeds %d bytes", ErrCapacityExceeded, maximum)
	}
	if _, err := store.root.Lstat(name); err == nil {
		return ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if snapshot.entries >= MaxWorkspaceEntries ||
		snapshot.bytes > MaxWorkspaceBytes-int64(len(raw)) {
		return ErrCapacityExceeded
	}

	stageName, err := stagingName(name)
	if err != nil {
		return err
	}
	file, err := store.root.OpenFile(
		stageName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0o200,
	)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: staging entry already exists", ErrUnsafeWorkspace)
	}
	if err != nil {
		return fmt.Errorf("create rollout artifact staging entry %q: %w", stageName, err)
	}
	fail := func(cause error) error {
		store.poisoned = true
		return errors.Join(cause, file.Close(), ErrPoisoned)
	}
	if err := file.Chmod(0o200); err != nil {
		return fail(err)
	}
	opened, statErr := file.Stat()
	named, namedErr := store.root.Lstat(stageName)
	if statErr != nil || namedErr != nil ||
		validateTransactionFile(stageName, opened, 0o200, 1, maximum) != nil ||
		validateTransactionFile(stageName, named, 0o200, 1, maximum) != nil ||
		opened.Size() != 0 || !sameSnapshot(opened, named) {
		return fail(errors.Join(
			fmt.Errorf("%w: staging entry %q changed while creating", ErrUnsafeWorkspace, stageName),
			statErr,
			namedErr,
		))
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterStageCreate
	}, file); err != nil {
		return fail(err)
	}
	if err := writeAll(file, raw); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	written, statErr := file.Stat()
	named, namedErr = store.root.Lstat(stageName)
	if statErr != nil || namedErr != nil ||
		validateTransactionFile(stageName, written, 0o200, 1, maximum) != nil ||
		validateTransactionFile(stageName, named, 0o200, 1, maximum) != nil ||
		written.Size() != int64(len(raw)) || named.Size() != int64(len(raw)) ||
		!sameIdentity(opened, written) || !sameSnapshot(written, named) {
		return fail(errors.Join(
			fmt.Errorf("%w: staging entry %q changed while writing", ErrUnsafeWorkspace, stageName),
			statErr,
			namedErr,
		))
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterDataSync
	}, file); err != nil {
		return fail(err)
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	prepared, statErr := file.Stat()
	named, namedErr = store.root.Lstat(stageName)
	if statErr != nil || namedErr != nil ||
		validateTransactionFile(stageName, prepared, 0o600, 1, maximum) != nil ||
		validateTransactionFile(stageName, named, 0o600, 1, maximum) != nil ||
		prepared.Size() != int64(len(raw)) || named.Size() != int64(len(raw)) ||
		!sameInode(written, prepared) || !sameSnapshot(prepared, named) {
		return fail(errors.Join(
			fmt.Errorf("%w: staging entry %q changed while preparing", ErrUnsafeWorkspace, stageName),
			statErr,
			namedErr,
		))
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterPreparedSync
	}, file); err != nil {
		return fail(err)
	}

	if err := store.checkDirectoryLocked(); err != nil {
		return fail(err)
	}
	stagePath := filepath.Join(store.directory, stageName)
	finalPath := filepath.Join(store.directory, name)
	if err := os.Link(stagePath, finalPath); err != nil {
		return fail(fmt.Errorf("publish rollout artifact %q without replacement: %w", name, err))
	}
	if err := store.checkDirectoryLocked(); err != nil {
		return fail(err)
	}
	linked, statErr := file.Stat()
	staged, stagedErr := store.root.Lstat(stageName)
	final, finalErr := store.root.Lstat(name)
	if statErr != nil || stagedErr != nil || finalErr != nil ||
		validateLinkedPublication(name, linked, staged, final, maximum) != nil ||
		linked.Size() != int64(len(raw)) {
		return fail(errors.Join(
			fmt.Errorf("%w: linked artifact %q is not one stable publication", ErrUnsafeWorkspace, name),
			statErr,
			stagedErr,
			finalErr,
		))
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterLink
	}, file); err != nil {
		return fail(err)
	}
	if err := store.syncDirectoryLocked(); err != nil {
		return fail(err)
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterPublishSync
	}, file); err != nil {
		return fail(err)
	}

	linked, statErr = file.Stat()
	staged, stagedErr = store.root.Lstat(stageName)
	final, finalErr = store.root.Lstat(name)
	if statErr != nil || stagedErr != nil || finalErr != nil ||
		validateLinkedPublication(name, linked, staged, final, maximum) != nil ||
		linked.Size() != int64(len(raw)) {
		return fail(errors.Join(
			fmt.Errorf("%w: linked artifact %q changed before staging cleanup", ErrUnsafeWorkspace, name),
			statErr,
			stagedErr,
			finalErr,
		))
	}
	if err := store.root.Remove(stageName); err != nil {
		return fail(fmt.Errorf("remove rollout artifact staging entry %q: %w", stageName, err))
	}
	if _, err := store.root.Lstat(stageName); !errors.Is(err, os.ErrNotExist) {
		return fail(errors.Join(
			fmt.Errorf("%w: staging entry %q survived removal", ErrUnsafeWorkspace, stageName),
			err,
		))
	}
	cleaned, statErr := file.Stat()
	final, finalErr = store.root.Lstat(name)
	if statErr != nil || finalErr != nil || validateArtifact(name, cleaned) != nil ||
		validateArtifact(name, final) != nil || cleaned.Size() != int64(len(raw)) ||
		!sameSnapshot(cleaned, final) {
		return fail(errors.Join(
			fmt.Errorf("%w: artifact %q changed during staging cleanup", ErrUnsafeWorkspace, name),
			statErr,
			finalErr,
		))
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterStageRemove
	}, file); err != nil {
		return fail(err)
	}
	if err := store.syncDirectoryLocked(); err != nil {
		return fail(err)
	}
	if err := runWriteTransactionHook(hooks, func(h *writeTransactionHooks) func(*os.File) error {
		return h.afterCleanupSync
	}, file); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		store.poisoned = true
		return errors.Join(err, ErrPoisoned)
	}
	final, err = store.root.Lstat(name)
	if err != nil || validateArtifact(name, final) != nil ||
		final.Size() != int64(len(raw)) || !sameSnapshot(cleaned, final) {
		store.poisoned = true
		return errors.Join(
			fmt.Errorf("%w: artifact %q changed after publication", ErrUnsafeWorkspace, name),
			err,
			ErrPoisoned,
		)
	}
	store.digests[name] = sha256.Sum256(raw)
	if _, err := store.auditLocked(); err != nil {
		store.poisoned = true
		return errors.Join(err, ErrPoisoned)
	}
	return nil
}

func runWriteTransactionHook(
	hooks *writeTransactionHooks,
	selectHook func(*writeTransactionHooks) func(*os.File) error,
	file *os.File,
) error {
	if hooks == nil {
		return nil
	}
	hook := selectHook(hooks)
	if hook == nil {
		return nil
	}
	return hook(file)
}

func stagingName(finalName string) (string, error) {
	kind := classifyName(finalName)
	if kind != artifactFixed && kind != artifactTarget && kind != artifactTargetState {
		return "", fmt.Errorf("%w: artifact cannot be staged", ErrInvalidName)
	}
	return stagingPrefix + finalName, nil
}

func parseStagingName(name string) (string, bool) {
	if !strings.HasPrefix(name, stagingPrefix) {
		return "", false
	}
	finalName := strings.TrimPrefix(name, stagingPrefix)
	kind := classifyName(finalName)
	if kind != artifactFixed && kind != artifactTarget && kind != artifactTargetState {
		return "", false
	}
	return finalName, true
}

func validateTransactionFile(
	name string,
	info os.FileInfo,
	permissions os.FileMode,
	links uint64,
	maximum int64,
) error {
	uid, actualLinks, ok := ownerAndLinks(info)
	if info == nil || !ok || uid != os.Geteuid() || actualLinks != links ||
		!info.Mode().IsRegular() ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm() != permissions || info.Size() < 0 || maximum <= 0 {
		return fmt.Errorf("%w: transaction entry %q is not a bounded owner-only regular file", ErrUnsafeWorkspace, name)
	}
	if info.Size() > maximum {
		return fmt.Errorf("%w: transaction entry %q exceeds %d bytes", ErrCapacityExceeded, name, maximum)
	}
	return nil
}

func validateLinkedPublication(
	finalName string,
	opened os.FileInfo,
	staged os.FileInfo,
	final os.FileInfo,
	maximum int64,
) error {
	if err := validateTransactionFile(finalName, opened, 0o600, 2, maximum); err != nil {
		return err
	}
	if err := validateTransactionFile(finalName, staged, 0o600, 2, maximum); err != nil {
		return err
	}
	if err := validateTransactionFile(finalName, final, 0o600, 2, maximum); err != nil {
		return err
	}
	if !sameSnapshot(opened, staged) || !sameSnapshot(opened, final) {
		return fmt.Errorf("%w: staging and final names do not identify one stable inode", ErrUnsafeWorkspace)
	}
	return nil
}

// recoverStagingLocked resolves the only transaction states a process or
// power loss can leave. A standalone valid staging file was never published
// and is removed. A valid two-link staging/final pair was published and is
// completed by removing the staging name. Every other shape is preserved and
// rejected for an operator to inspect.
func (store *Store) recoverStagingLocked() error {
	if err := store.checkDirectoryLocked(); err != nil {
		return err
	}
	names, err := store.readRecoveryEntryNamesLocked()
	if err != nil {
		return err
	}
	type stagingEntry struct {
		stage string
		final string
	}
	staging := make([]stagingEntry, 0, maxStagingEntries)
	for _, name := range names {
		if finalName, ok := parseStagingName(name); ok {
			staging = append(staging, stagingEntry{stage: name, final: finalName})
		}
	}
	if len(staging) > maxStagingEntries {
		return fmt.Errorf("%w: workspace contains multiple staging transactions", ErrUnsafeWorkspace)
	}
	if len(names)-len(staging) > MaxWorkspaceEntries {
		return ErrCapacityExceeded
	}
	if len(staging) == 0 {
		return nil
	}
	if err := store.recoverStagingEntryLocked(staging[0].stage, staging[0].final); err != nil {
		return err
	}
	return store.checkDirectoryLocked()
}

func (store *Store) readRecoveryEntryNamesLocked() ([]string, error) {
	directory, err := store.root.Open(".")
	if err != nil {
		return nil, err
	}
	maximum := MaxWorkspaceEntries + maxStagingEntries
	entries, readErr := directory.ReadDir(maximum + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maximum {
		return nil, ErrCapacityExceeded
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	return names, nil
}

func (store *Store) recoverStagingEntryLocked(stageName, finalName string) error {
	maximum := artifactByteLimit(finalName)
	before, err := store.root.Lstat(stageName)
	if err != nil {
		return fmt.Errorf("inspect rollout staging entry %q: %w", stageName, err)
	}
	permissions := before.Mode().Perm()
	if permissions != 0o200 && permissions != 0o600 {
		return fmt.Errorf("%w: staging entry %q has invalid permissions", ErrUnsafeWorkspace, stageName)
	}
	_, links, ok := ownerAndLinks(before)
	if !ok || links < 1 || links > 2 {
		return fmt.Errorf("%w: staging entry %q has an invalid link count", ErrUnsafeWorkspace, stageName)
	}
	if err := validateTransactionFile(stageName, before, permissions, links, maximum); err != nil {
		return err
	}
	flags := os.O_RDONLY
	if permissions == 0o200 {
		flags = os.O_WRONLY
	}
	file, err := store.root.OpenFile(
		stageName,
		flags|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return errors.Join(
			fmt.Errorf("%w: staging entry %q cannot be opened without following links", ErrUnsafeWorkspace, stageName),
			err,
		)
	}
	closeWith := func(cause error) error {
		return errors.Join(cause, file.Close())
	}
	opened, statErr := file.Stat()
	current, namedErr := store.root.Lstat(stageName)
	if statErr != nil || namedErr != nil ||
		validateTransactionFile(stageName, opened, permissions, links, maximum) != nil ||
		validateTransactionFile(stageName, current, permissions, links, maximum) != nil ||
		!sameSnapshot(before, opened) || !sameSnapshot(opened, current) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: staging entry %q changed while opening", ErrUnsafeWorkspace, stageName),
			statErr,
			namedErr,
		))
	}
	final, finalErr := store.root.Lstat(finalName)
	switch {
	case errors.Is(finalErr, os.ErrNotExist):
		if links != 1 {
			return closeWith(fmt.Errorf(
				"%w: unpublished staging entry %q has another hard link",
				ErrUnsafeWorkspace,
				stageName,
			))
		}
		return store.removeUnpublishedStagingLocked(stageName, finalName, file, opened, permissions, maximum)
	case finalErr != nil:
		return closeWith(finalErr)
	default:
		if permissions != 0o600 || links != 2 ||
			validateLinkedPublication(finalName, opened, current, final, maximum) != nil {
			return closeWith(fmt.Errorf(
				"%w: staging entry %q and final artifact %q are not one publication",
				ErrUnsafeWorkspace,
				stageName,
				finalName,
			))
		}
		return store.finishLinkedPublicationLocked(stageName, finalName, file, opened, maximum)
	}
}

func (store *Store) removeUnpublishedStagingLocked(
	stageName string,
	finalName string,
	file *os.File,
	opened os.FileInfo,
	permissions os.FileMode,
	maximum int64,
) error {
	closeWith := func(cause error) error {
		return errors.Join(cause, file.Close())
	}
	current, namedErr := store.root.Lstat(stageName)
	anchored, statErr := file.Stat()
	if namedErr != nil || statErr != nil ||
		validateTransactionFile(stageName, current, permissions, 1, maximum) != nil ||
		validateTransactionFile(stageName, anchored, permissions, 1, maximum) != nil ||
		!sameSnapshot(opened, current) || !sameSnapshot(opened, anchored) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: unpublished staging entry %q changed before cleanup", ErrUnsafeWorkspace, stageName),
			namedErr,
			statErr,
		))
	}
	if _, err := store.root.Lstat(finalName); !errors.Is(err, os.ErrNotExist) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: final artifact %q appeared during staging cleanup", ErrUnsafeWorkspace, finalName),
			err,
		))
	}
	if err := store.checkDirectoryLocked(); err != nil {
		return closeWith(err)
	}
	if err := store.root.Remove(stageName); err != nil {
		return closeWith(err)
	}
	if _, err := store.root.Lstat(stageName); !errors.Is(err, os.ErrNotExist) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: unpublished staging entry %q survived cleanup", ErrUnsafeWorkspace, stageName),
			err,
		))
	}
	if _, err := store.root.Lstat(finalName); !errors.Is(err, os.ErrNotExist) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: final artifact %q appeared during staging cleanup", ErrUnsafeWorkspace, finalName),
			err,
		))
	}
	unlinked, statErr := file.Stat()
	if statErr != nil || !sameFileIgnoringLinks(opened, unlinked) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: unpublished staging inode changed during cleanup", ErrUnsafeWorkspace),
			statErr,
		))
	}
	if _, unlinkedLinks, ok := ownerAndLinks(unlinked); !ok || unlinkedLinks != 0 {
		return closeWith(fmt.Errorf("%w: unpublished staging inode still has a name", ErrUnsafeWorkspace))
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := store.syncDirectoryLocked(); err != nil {
		return err
	}
	if _, err := store.root.Lstat(finalName); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(
			fmt.Errorf("%w: final artifact %q appeared after staging recovery", ErrUnsafeWorkspace, finalName),
			err,
		)
	}
	return nil
}

func (store *Store) finishLinkedPublicationLocked(
	stageName string,
	finalName string,
	file *os.File,
	opened os.FileInfo,
	maximum int64,
) error {
	closeWith := func(cause error) error {
		return errors.Join(cause, file.Close())
	}
	anchored, statErr := file.Stat()
	staged, stagedErr := store.root.Lstat(stageName)
	final, finalErr := store.root.Lstat(finalName)
	if statErr != nil || stagedErr != nil || finalErr != nil ||
		!sameSnapshot(opened, anchored) ||
		validateLinkedPublication(finalName, anchored, staged, final, maximum) != nil {
		return closeWith(errors.Join(
			fmt.Errorf("%w: linked publication %q changed before cleanup", ErrUnsafeWorkspace, finalName),
			statErr,
			stagedErr,
			finalErr,
		))
	}
	if err := store.checkDirectoryLocked(); err != nil {
		return closeWith(err)
	}
	if err := store.root.Remove(stageName); err != nil {
		return closeWith(err)
	}
	if _, err := store.root.Lstat(stageName); !errors.Is(err, os.ErrNotExist) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: linked staging entry %q survived cleanup", ErrUnsafeWorkspace, stageName),
			err,
		))
	}
	anchored, statErr = file.Stat()
	final, finalErr = store.root.Lstat(finalName)
	if statErr != nil || finalErr != nil || validateArtifact(finalName, anchored) != nil ||
		validateArtifact(finalName, final) != nil || !sameSnapshot(anchored, final) {
		return closeWith(errors.Join(
			fmt.Errorf("%w: final artifact %q changed during recovery", ErrUnsafeWorkspace, finalName),
			statErr,
			finalErr,
		))
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := store.syncDirectoryLocked(); err != nil {
		return err
	}
	current, err := store.root.Lstat(finalName)
	if err != nil || validateArtifact(finalName, current) != nil || !sameSnapshot(final, current) {
		return errors.Join(
			fmt.Errorf("%w: recovered artifact %q changed after directory sync", ErrUnsafeWorkspace, finalName),
			err,
		)
	}
	return nil
}

func sameFileIgnoringLinks(left, right os.FileInfo) bool {
	leftUID, _, leftOK := ownerAndLinks(left)
	rightUID, _, rightOK := ownerAndLinks(right)
	return left != nil && right != nil && leftOK && rightOK && os.SameFile(left, right) &&
		leftUID == rightUID && left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}
