package mcpserver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	maxTaskResultFiles        = 1024
	maxTaskResultStoreBytes   = 256 << 20
	maxTaskResultStoreEntries = maxTaskResultFiles * 2
	taskResultSuffix          = ".result"
	taskResultTemporarySuffix = ".partial"
)

type taskResultStore struct {
	directory string
	identity  os.FileInfo
	root      *os.Root

	mu     sync.Mutex
	files  int
	bytes  int64
	closed bool
}

type taskResultReservation struct {
	store         *taskResultStore
	name          string
	temporaryName string
	path          string
	file          *os.File
	identity      os.FileInfo
	bytes         int64
	published     bool
	finished      bool
}

type storedTaskResultEntry struct {
	name string
	info os.FileInfo
}

type taskResultCleanup struct {
	entry         storedTaskResultEntry
	expectedLinks uint64
}

func newTaskResultStore(directory string) (*taskResultStore, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("MCP task result directory must be a clean absolute path")
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return nil, errors.New("MCP task result directory has no canonical absolute path")
	}
	if err := validateTrustedResultAncestors(canonical); err != nil {
		return nil, err
	}
	before, err := os.Lstat(canonical)
	if err != nil {
		return nil, err
	}
	if !validTaskResultDirectory(before) {
		return nil, errors.New("MCP task result directory must be owned by this process and have mode 0700")
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, err
	}
	after, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if !validTaskResultDirectory(after) || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, errors.New("MCP task result directory changed while opening")
	}
	store := &taskResultStore{directory: canonical, identity: after, root: root}
	if err := store.loadUsage(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return store, nil
}

func validateTrustedResultAncestors(directory string) error {
	euid := os.Geteuid()
	if euid < 0 {
		return errors.New("MCP task result ownership cannot be verified on this platform")
	}
	for current := directory; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		uid, ok := fileOwner(info)
		if !ok || !info.IsDir() || uid != 0 && uid != euid {
			return fmt.Errorf("MCP task result path has an untrusted ancestor: %s", current)
		}
		if info.Mode().Perm()&0o022 != 0 && (info.Mode()&os.ModeSticky == 0 || uid != 0) {
			return fmt.Errorf("MCP task result path has a replaceable ancestor: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func validTaskResultDirectory(info os.FileInfo) bool {
	uid, ok := fileOwner(info)
	return info != nil && ok && uid == os.Geteuid() && info.IsDir() && info.Mode().Perm() == 0o700
}

func validStoredTaskResult(info os.FileInfo) bool {
	uid, ok := fileOwner(info)
	return info != nil && ok && uid == os.Geteuid() && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 &&
		info.Size() >= 0 && info.Size() <= maxTaskObservationBytes
}

func storedTaskResultLinkCount(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true
}

func validStoredTaskResultLinks(info os.FileInfo, expected uint64) bool {
	links, ok := storedTaskResultLinkCount(info)
	return validStoredTaskResult(info) && ok && links == expected
}

func fileOwner(info os.FileInfo) (int, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

func taskResultName(taskDigest, permitDigest string) (string, error) {
	if !validTaskDigest(taskDigest) || !validTaskDigest(permitDigest) {
		return "", errors.New("invalid task result identity")
	}
	return strings.TrimPrefix(taskDigest, "sha256:") + "." + strings.TrimPrefix(permitDigest, "sha256:") + taskResultSuffix, nil
}

func validStoredTaskResultName(name string) bool {
	expected := 64 + 1 + 64 + len(taskResultSuffix)
	if len(name) != expected || name[64] != '.' || !strings.HasSuffix(name, taskResultSuffix) {
		return false
	}
	for _, section := range []string{name[:64], name[65:129]} {
		for _, character := range section {
			if character < '0' || character > '9' && character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func taskResultTemporaryName(name string) string {
	return name + taskResultTemporarySuffix
}

func storedTaskResultNameForEntry(name string) (string, bool, bool) {
	if validStoredTaskResultName(name) {
		return name, false, true
	}
	if strings.HasSuffix(name, taskResultTemporarySuffix) {
		resultName := strings.TrimSuffix(name, taskResultTemporarySuffix)
		if validStoredTaskResultName(resultName) {
			return resultName, true, true
		}
	}
	return "", false, false
}

func (store *taskResultStore) loadUsage() error {
	directory, err := store.root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(maxTaskResultStoreEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > maxTaskResultStoreEntries {
		return errors.New("MCP task result store exceeds its file-count limit")
	}
	results := make(map[string]storedTaskResultEntry, len(entries))
	temporaries := make(map[string]storedTaskResultEntry, len(entries))
	identities := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		resultName, temporary, validName := storedTaskResultNameForEntry(entry.Name())
		if !validName {
			return fmt.Errorf("MCP task result store contains an unexpected entry: %s", entry.Name())
		}
		info, err := store.root.Lstat(entry.Name())
		if err != nil || !validStoredTaskResult(info) {
			return errors.Join(fmt.Errorf("MCP task result store contains an unsafe entry: %s", entry.Name()), err)
		}
		stored := storedTaskResultEntry{name: entry.Name(), info: info}
		if temporary {
			temporaries[resultName] = stored
		} else {
			results[resultName] = stored
		}
		identities[resultName] = struct{}{}
	}
	if len(identities) > maxTaskResultFiles {
		return errors.New("MCP task result store exceeds its file-count limit")
	}

	cleanups := make([]taskResultCleanup, 0, len(temporaries)+1)
	for resultName := range identities {
		result, hasResult := results[resultName]
		temporary, hasTemporary := temporaries[resultName]
		switch {
		case hasResult && result.info.Size() == 0:
			if hasTemporary || !validStoredTaskResultLinks(result.info, 1) {
				return fmt.Errorf("MCP task result store contains an unsafe incomplete result: %s", result.name)
			}
			// Older Steward builds reserved the final name before writing. An
			// empty, single-link final is therefore an uncommitted legacy
			// reservation and is safe to remove during upgrade.
			cleanups = append(cleanups, taskResultCleanup{entry: result, expectedLinks: 1})
		case hasResult && hasTemporary && os.SameFile(result.info, temporary.info):
			if !validStoredTaskResultLinks(result.info, 2) || !validStoredTaskResultLinks(temporary.info, 2) {
				return fmt.Errorf("MCP task result store contains an unsafe published temporary: %s", temporary.name)
			}
			// Publication links the fsynced inode to the final name before
			// removing the temporary name. A two-link pair is the expected
			// crash state in that narrow window.
			cleanups = append(cleanups, taskResultCleanup{entry: temporary, expectedLinks: 2})
		case hasResult && hasTemporary:
			if !validStoredTaskResultLinks(result.info, 1) || !validStoredTaskResultLinks(temporary.info, 1) {
				return fmt.Errorf("MCP task result store contains an unsafe stale temporary: %s", temporary.name)
			}
			cleanups = append(cleanups, taskResultCleanup{entry: temporary, expectedLinks: 1})
		case hasResult:
			if !validStoredTaskResultLinks(result.info, 1) {
				return fmt.Errorf("MCP task result store contains an aliased result: %s", result.name)
			}
		case hasTemporary:
			if !validStoredTaskResultLinks(temporary.info, 1) {
				return fmt.Errorf("MCP task result store contains an aliased temporary entry: %s", temporary.name)
			}
			cleanups = append(cleanups, taskResultCleanup{entry: temporary, expectedLinks: 1})
		}
	}

	for _, cleanup := range cleanups {
		current, err := store.root.Lstat(cleanup.entry.name)
		if err != nil || !os.SameFile(cleanup.entry.info, current) || !validStoredTaskResultLinks(current, cleanup.expectedLinks) {
			return errors.Join(fmt.Errorf("MCP task result cleanup entry changed: %s", cleanup.entry.name), err)
		}
		if err := store.root.Remove(cleanup.entry.name); err != nil {
			return err
		}
	}
	if len(cleanups) > 0 {
		if err := store.syncDirectory(); err != nil {
			return err
		}
	}

	for resultName, result := range results {
		if result.info.Size() == 0 {
			continue
		}
		current, err := store.root.Lstat(resultName)
		if err != nil || !os.SameFile(result.info, current) || !validStoredTaskResultLinks(current, 1) {
			return errors.Join(fmt.Errorf("MCP task result changed during startup: %s", resultName), err)
		}
		if store.bytes > maxTaskResultStoreBytes-current.Size() {
			return errors.New("MCP task result store exceeds its byte limit")
		}
		store.files++
		store.bytes += current.Size()
	}
	return nil
}

func (store *taskResultStore) reserve(taskDigest, permitDigest string) (*taskResultReservation, error) {
	name, err := taskResultName(taskDigest, permitDigest)
	if err != nil {
		return nil, err
	}
	temporaryName := taskResultTemporaryName(name)
	if err := store.checkDirectory(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	if store.closed || store.root == nil {
		store.mu.Unlock()
		return nil, errors.New("terminal result store is closed")
	}
	if store.files >= maxTaskResultFiles {
		store.mu.Unlock()
		return nil, errors.New("terminal result store reached its file-count limit")
	}
	if _, err := store.root.Lstat(name); err == nil {
		store.mu.Unlock()
		return nil, errors.New("terminal result already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		store.mu.Unlock()
		return nil, err
	}
	file, err := store.root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		store.mu.Unlock()
		return nil, err
	}
	store.files++
	store.mu.Unlock()

	reservation := &taskResultReservation{
		store: store, name: name, temporaryName: temporaryName,
		path: filepath.Join(store.directory, name), file: file,
	}
	fail := func(cause error) (*taskResultReservation, error) {
		return nil, errors.Join(cause, reservation.discard())
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	opened, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	reservation.identity = opened
	if !validStoredTaskResultLinks(opened, 1) || opened.Size() != 0 {
		return fail(errors.New("terminal result reservation is not one empty owner-only regular file"))
	}
	current, err := store.root.Lstat(temporaryName)
	if err != nil || !validStoredTaskResultLinks(current, 1) || !os.SameFile(opened, current) {
		return fail(errors.Join(errors.New("terminal result reservation changed while opening"), err))
	}
	if _, err := store.root.Lstat(name); err == nil {
		return fail(errors.New("terminal result appeared while reserving"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if err := store.syncDirectory(); err != nil {
		return fail(err)
	}
	return reservation, nil
}

func (store *taskResultStore) checkDirectory() error {
	if store == nil || store.root == nil || store.identity == nil {
		return errors.New("terminal result directory is unavailable")
	}
	anchored, err := store.root.Stat(".")
	if err != nil || !validTaskResultDirectory(anchored) || !os.SameFile(store.identity, anchored) {
		return errors.Join(errors.New("terminal result directory changed after MCP startup"), err)
	}
	current, err := os.Lstat(store.directory)
	if err != nil || !validTaskResultDirectory(current) || !os.SameFile(store.identity, current) {
		return errors.Join(errors.New("terminal result directory path changed after MCP startup"), err)
	}
	return nil
}

func (store *taskResultStore) syncDirectory() error {
	if err := store.checkDirectory(); err != nil {
		return err
	}
	directory, err := store.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (store *taskResultStore) reserveBytes(amount int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || amount <= 0 || amount > maxTaskObservationBytes || store.bytes > maxTaskResultStoreBytes-amount {
		return errors.New("terminal result store reached its byte limit")
	}
	store.bytes += amount
	return nil
}

func (store *taskResultStore) release(files int, bytes int64) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if files > 0 && store.files >= files {
		store.files -= files
	}
	if bytes > 0 && store.bytes >= bytes {
		store.bytes -= bytes
	}
}

func (store *taskResultStore) close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.root == nil {
		return nil
	}
	return store.root.Close()
}

func (reservation *taskResultReservation) commit(raw []byte) error {
	if reservation == nil || reservation.finished || reservation.published || reservation.file == nil || reservation.identity == nil ||
		len(raw) == 0 || len(raw) > maxTaskObservationBytes {
		return errors.New("terminal result reservation cannot be committed")
	}
	failUnpublished := func(cause error) error {
		return errors.Join(cause, reservation.erase(), reservation.discard())
	}
	failPublished := func(cause error) error {
		reservation.finished = true
		return cause
	}
	if err := reservation.store.checkDirectory(); err != nil {
		return failUnpublished(err)
	}
	current, err := reservation.store.root.Lstat(reservation.temporaryName)
	if err != nil || !validStoredTaskResultLinks(current, 1) || !os.SameFile(reservation.identity, current) {
		return failUnpublished(errors.Join(errors.New("terminal result reservation changed before writing"), err))
	}
	if err := reservation.store.reserveBytes(int64(len(raw))); err != nil {
		return failUnpublished(err)
	}
	reservation.bytes = int64(len(raw))
	for written := 0; written < len(raw); {
		count, err := reservation.file.Write(raw[written:])
		if err != nil {
			return failUnpublished(err)
		}
		if count <= 0 {
			return failUnpublished(io.ErrShortWrite)
		}
		written += count
	}
	if err := reservation.file.Sync(); err != nil {
		return failUnpublished(err)
	}
	opened, err := reservation.file.Stat()
	if err != nil {
		return failUnpublished(err)
	}
	current, err = reservation.store.root.Lstat(reservation.temporaryName)
	if err != nil || !validStoredTaskResultLinks(opened, 1) || !validStoredTaskResultLinks(current, 1) ||
		opened.Size() != int64(len(raw)) || current.Size() != int64(len(raw)) ||
		!os.SameFile(reservation.identity, opened) || !os.SameFile(reservation.identity, current) {
		return failUnpublished(errors.Join(errors.New("terminal result temporary changed while writing"), err))
	}
	if err := reservation.file.Close(); err != nil {
		reservation.file = nil
		return failUnpublished(err)
	}
	reservation.file = nil
	current, err = reservation.store.root.Lstat(reservation.temporaryName)
	if err != nil || !validStoredTaskResultLinks(current, 1) || !os.SameFile(reservation.identity, current) || current.Size() != int64(len(raw)) {
		return failUnpublished(errors.Join(errors.New("terminal result temporary changed while closing"), err))
	}
	if _, err := reservation.store.root.Lstat(reservation.name); err == nil {
		return failUnpublished(errors.New("terminal result already exists before publication"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return failUnpublished(err)
	}
	if err := reservation.store.checkDirectory(); err != nil {
		return failUnpublished(err)
	}
	temporaryPath := filepath.Join(reservation.store.directory, reservation.temporaryName)
	if err := os.Link(temporaryPath, reservation.path); err != nil {
		return failUnpublished(fmt.Errorf("publish terminal result without overwrite: %w", err))
	}
	reservation.published = true
	published, publishErr := reservation.store.root.Lstat(reservation.name)
	temporary, temporaryErr := reservation.store.root.Lstat(reservation.temporaryName)
	if publishErr != nil || temporaryErr != nil || !validStoredTaskResultLinks(published, 2) ||
		!validStoredTaskResultLinks(temporary, 2) || published.Size() != int64(len(raw)) ||
		!os.SameFile(reservation.identity, published) || !os.SameFile(reservation.identity, temporary) {
		return failPublished(errors.Join(errors.New("terminal result publication changed before directory sync"), publishErr, temporaryErr))
	}
	// Persist the final link before removing the temporary one. A crash before
	// the next directory sync leaves either a safe partial or a two-link pair;
	// loadUsage recognizes and reconciles both states.
	if err := reservation.store.syncDirectory(); err != nil {
		return failPublished(err)
	}
	temporary, err = reservation.store.root.Lstat(reservation.temporaryName)
	if err != nil || !validStoredTaskResultLinks(temporary, 2) || !os.SameFile(reservation.identity, temporary) {
		return failPublished(errors.Join(errors.New("terminal result temporary changed before cleanup"), err))
	}
	if err := reservation.store.root.Remove(reservation.temporaryName); err != nil {
		return failPublished(err)
	}
	published, err = reservation.store.root.Lstat(reservation.name)
	if err != nil || !validStoredTaskResultLinks(published, 1) || !os.SameFile(reservation.identity, published) ||
		published.Size() != int64(len(raw)) {
		return failPublished(errors.Join(errors.New("terminal result changed after temporary cleanup"), err))
	}
	if err := reservation.store.syncDirectory(); err != nil {
		return failPublished(err)
	}
	reservation.finished = true
	return nil
}

func (reservation *taskResultReservation) erase() error {
	if reservation == nil || reservation.published || reservation.file == nil {
		return nil
	}
	if err := reservation.file.Truncate(0); err != nil {
		return err
	}
	return reservation.file.Sync()
}

func (reservation *taskResultReservation) discard() error {
	if reservation == nil || reservation.finished {
		return nil
	}
	if reservation.published {
		// Never erase or release quota for an inode once its final name is
		// visible. Startup safely removes a leftover temporary link.
		reservation.finished = true
		return nil
	}
	var closeErr error
	if reservation.file != nil {
		closeErr = reservation.file.Close()
		reservation.file = nil
	}
	removed := false
	var removeErr error
	current, err := reservation.store.root.Lstat(reservation.temporaryName)
	switch {
	case errors.Is(err, os.ErrNotExist):
		removeErr = errors.New("terminal result reservation disappeared; retaining quota conservatively")
	case err != nil:
		removeErr = err
	case reservation.identity == nil || !os.SameFile(reservation.identity, current):
		removeErr = errors.New("terminal result reservation path was replaced; refusing to remove it")
	default:
		removeErr = reservation.store.root.Remove(reservation.temporaryName)
		removed = removeErr == nil
	}
	var syncErr error
	if removed {
		syncErr = reservation.store.syncDirectory()
		reservation.store.release(1, reservation.bytes)
		reservation.bytes = 0
	}
	reservation.finished = true
	return errors.Join(closeErr, removeErr, syncErr)
}
