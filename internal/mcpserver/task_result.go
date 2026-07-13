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
	maxTaskResultFiles      = 1024
	maxTaskResultStoreBytes = 256 << 20
	taskResultSuffix        = ".result"
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
	store    *taskResultStore
	name     string
	path     string
	file     *os.File
	identity os.FileInfo
	bytes    int64
	finished bool
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

func (store *taskResultStore) loadUsage() error {
	directory, err := store.root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(maxTaskResultFiles + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > maxTaskResultFiles {
		return errors.New("MCP task result store exceeds its file-count limit")
	}
	removed := false
	for _, entry := range entries {
		if !validStoredTaskResultName(entry.Name()) {
			return fmt.Errorf("MCP task result store contains an unexpected entry: %s", entry.Name())
		}
		info, err := store.root.Lstat(entry.Name())
		if err != nil || !validStoredTaskResult(info) {
			return errors.Join(fmt.Errorf("MCP task result store contains an unsafe entry: %s", entry.Name()), err)
		}
		if info.Size() == 0 {
			if err := store.root.Remove(entry.Name()); err != nil {
				return err
			}
			removed = true
			continue
		}
		if store.bytes > maxTaskResultStoreBytes-info.Size() {
			return errors.New("MCP task result store exceeds its byte limit")
		}
		store.files++
		store.bytes += info.Size()
	}
	if removed {
		return store.syncDirectory()
	}
	return nil
}

func (store *taskResultStore) reserve(taskDigest, permitDigest string) (*taskResultReservation, error) {
	name, err := taskResultName(taskDigest, permitDigest)
	if err != nil {
		return nil, err
	}
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
	file, err := store.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		store.mu.Unlock()
		return nil, err
	}
	store.files++
	store.mu.Unlock()

	reservation := &taskResultReservation{
		store: store, name: name, path: filepath.Join(store.directory, name), file: file,
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
	if !validStoredTaskResult(opened) || opened.Size() != 0 {
		return fail(errors.New("terminal result reservation is not one empty owner-only regular file"))
	}
	current, err := store.root.Lstat(name)
	if err != nil || !validStoredTaskResult(current) || !os.SameFile(opened, current) {
		return fail(errors.Join(errors.New("terminal result reservation changed while opening"), err))
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
	if reservation == nil || reservation.finished || reservation.file == nil || reservation.identity == nil || len(raw) == 0 || len(raw) > maxTaskObservationBytes {
		return errors.New("terminal result reservation cannot be committed")
	}
	fail := func(cause error) error {
		return errors.Join(cause, reservation.erase(), reservation.discard())
	}
	if err := reservation.store.checkDirectory(); err != nil {
		return fail(err)
	}
	current, err := reservation.store.root.Lstat(reservation.name)
	if err != nil || !validStoredTaskResult(current) || !os.SameFile(reservation.identity, current) {
		return fail(errors.Join(errors.New("terminal result reservation changed before writing"), err))
	}
	if err := reservation.store.reserveBytes(int64(len(raw))); err != nil {
		return fail(err)
	}
	reservation.bytes = int64(len(raw))
	for written := 0; written < len(raw); {
		count, err := reservation.file.Write(raw[written:])
		if err != nil {
			return fail(err)
		}
		if count <= 0 {
			return fail(io.ErrShortWrite)
		}
		written += count
	}
	if err := reservation.file.Sync(); err != nil {
		return fail(err)
	}
	opened, err := reservation.file.Stat()
	if err != nil {
		return fail(err)
	}
	current, err = reservation.store.root.Lstat(reservation.name)
	if err != nil || !validStoredTaskResult(opened) || !validStoredTaskResult(current) ||
		opened.Size() != int64(len(raw)) || current.Size() != int64(len(raw)) ||
		!os.SameFile(reservation.identity, opened) || !os.SameFile(reservation.identity, current) {
		return fail(errors.Join(errors.New("terminal result file changed while writing"), err))
	}
	if err := reservation.file.Close(); err != nil {
		reservation.file = nil
		return fail(err)
	}
	reservation.file = nil
	current, err = reservation.store.root.Lstat(reservation.name)
	if err != nil || !validStoredTaskResult(current) || !os.SameFile(reservation.identity, current) || current.Size() != int64(len(raw)) {
		return fail(errors.Join(errors.New("terminal result file changed while closing"), err))
	}
	if err := reservation.store.syncDirectory(); err != nil {
		return fail(err)
	}
	reservation.finished = true
	return nil
}

func (reservation *taskResultReservation) erase() error {
	if reservation == nil || reservation.file == nil {
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
	var closeErr error
	if reservation.file != nil {
		closeErr = reservation.file.Close()
		reservation.file = nil
	}
	removed := false
	var removeErr error
	current, err := reservation.store.root.Lstat(reservation.name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		removeErr = errors.New("terminal result reservation disappeared; retaining quota conservatively")
	case err != nil:
		removeErr = err
	case reservation.identity == nil || !os.SameFile(reservation.identity, current):
		removeErr = errors.New("terminal result reservation path was replaced; refusing to remove it")
	default:
		removeErr = reservation.store.root.Remove(reservation.name)
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
