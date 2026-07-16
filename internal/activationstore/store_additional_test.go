package activationstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type stagedCancellationContext struct {
	context.Context
	calls    int
	cancelAt int
	actionAt int
	action   func()
}

func (ctx *stagedCancellationContext) Err() error {
	ctx.calls++
	if ctx.calls == ctx.actionAt && ctx.action != nil {
		ctx.action()
	}
	if ctx.cancelAt > 0 && ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

type syntheticFileInfo struct {
	name string
	size int64
	mode os.FileMode
	sys  any
}

func (info syntheticFileInfo) Name() string       { return info.name }
func (info syntheticFileInfo) Size() int64        { return info.size }
func (info syntheticFileInfo) Mode() os.FileMode  { return info.mode }
func (info syntheticFileInfo) ModTime() time.Time { return time.Time{} }
func (info syntheticFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info syntheticFileInfo) Sys() any           { return info.sys }

func openRootAndIdentity(t *testing.T, directory string) (*os.Root, os.FileInfo) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	return root, identity
}

func TestAdditionalPublicBoundaries(t *testing.T) {
	var nilStore *Store
	if _, err := nilStore.Read(ReleaseFileName, 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Read() error = %v, want ErrClosed", err)
	}
	if err := nilStore.WriteOnce(PlanFileName, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil WriteOnce() error = %v, want ErrClosed", err)
	}
	if err := nilStore.ImportArchiveContext(context.Background(), "/missing"); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil ImportArchiveContext() error = %v, want ErrClosed", err)
	}
	if _, err := nilStore.ListStateCheckpoints(); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil ListStateCheckpoints() error = %v, want ErrClosed", err)
	}
	if _, _, _, err := nilStore.LatestState(1); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil LatestState() error = %v, want ErrClosed", err)
	}
	if _, err := nilStore.Path(ImageArchiveFileName); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Path() error = %v, want ErrClosed", err)
	}
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil Close() error = %v", err)
	}

	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)
	//nolint:staticcheck // This adversarial case verifies the explicit nil-context guard.
	if err := store.ImportArchiveContext(nil, "/missing"); err == nil {
		t.Fatal("ImportArchiveContext(nil) succeeded")
	}
	uncleanSource := directory + string(filepath.Separator) + ".." +
		string(filepath.Separator) + filepath.Base(directory) +
		string(filepath.Separator) + "source"
	for _, source := range []string{"", "relative", uncleanSource} {
		if err := store.ImportArchiveContext(context.Background(), source); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("ImportArchiveContext(%q) error = %v, want ErrUnsafeWorkspace", source, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "missing.tar")
	if err := store.ImportArchive(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ImportArchive(missing) error = %v, want not-exist", err)
	}
	for _, limit := range []int64{0, -1, MaxSmallArtifactBytes + 1} {
		if _, err := store.Read(ReleaseFileName, limit); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Read(limit=%d) error = %v, want ErrCapacityExceeded", limit, err)
		}
	}
	if _, err := store.Read(ReleaseFileName, 1); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read(missing) error = %v, want not-exist", err)
	}
	if _, err := store.Path(ImageArchiveFileName); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Path(missing archive) error = %v, want not-exist", err)
	}
	if _, err := store.AppendState(MaxStateSequence+1, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("AppendState(oversize) error = %v, want ErrInvalidName", err)
	}
	if err := store.writeOnce(PlanFileName, nil, writeState); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("writeOnce(wrong state operation) error = %v, want ErrInvalidName", err)
	}
	store.poisoned = true
	if _, err := store.ListStateCheckpoints(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("poisoned ListStateCheckpoints() error = %v, want ErrPoisoned", err)
	}
}

func TestCreateAndOpenAdditionalFailures(t *testing.T) {
	for _, directory := range []string{"", "relative", string(filepath.Separator)} {
		if store, err := Create(directory); store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Create(%q) = (%v, %v), want ErrUnsafeWorkspace", directory, store, err)
		}
	}
	missingParent := filepath.Join(t.TempDir(), "missing", "workspace")
	if store, err := Create(missingParent); store != nil || err == nil {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("Create(missing parent) = (%v, %v), want error", store, err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if store, err := Open(missing); store != nil || err == nil || !errors.Is(err, os.ErrNotExist) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("Open(missing) = (%v, %v), want not-exist", store, err)
	}
	file := filepath.Join(t.TempDir(), "workspace")
	writeTestFile(t, filepath.Dir(file), filepath.Base(file), []byte("not a directory"), 0o700)
	if store, err := Open(file); store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("Open(file) = (%v, %v), want ErrUnsafeWorkspace", store, err)
	}
	if err := validateTrustedAncestors(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("validateTrustedAncestors(missing) succeeded")
	}
	if err := validateTrustedAncestors(file); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateTrustedAncestors(file) error = %v, want ErrUnsafeWorkspace", err)
	}
}

func TestArchiveImportCancellationAtEveryCheckpoint(t *testing.T) {
	probeDirectory := testWorkspace(t)
	probeStore := mustOpenStore(t, probeDirectory)
	probeSourceDirectory := t.TempDir()
	probeSource := filepath.Join(probeSourceDirectory, "archive")
	writeTestFile(t, probeSourceDirectory, "archive", []byte("archive"), 0o600)
	probe := &stagedCancellationContext{Context: context.Background()}
	if err := probeStore.ImportArchiveContext(probe, probeSource); err != nil {
		t.Fatalf("probe ImportArchiveContext() error = %v", err)
	}
	if probe.calls < 10 {
		t.Fatalf("probe context checks = %d, want at least 10", probe.calls)
	}

	for cancelAt := 1; cancelAt <= probe.calls; cancelAt++ {
		t.Run("checkpoint-"+decimalTestName(cancelAt), func(t *testing.T) {
			directory := testWorkspace(t)
			store := mustOpenStore(t, directory)
			sourceDirectory := t.TempDir()
			source := filepath.Join(sourceDirectory, "archive")
			writeTestFile(t, sourceDirectory, "archive", []byte("archive"), 0o600)
			ctx := &stagedCancellationContext{
				Context:  context.Background(),
				cancelAt: cancelAt,
			}
			err := store.ImportArchiveContext(ctx, source)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ImportArchiveContext(cancelAt=%d) error = %v, want context.Canceled", cancelAt, err)
			}
			if _, statErr := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("cancelAt=%d left partial archive: %v", cancelAt, statErr)
			}
			if _, listErr := store.ListStateCheckpoints(); listErr != nil {
				t.Fatalf("cancelAt=%d poisoned store after safe cleanup: %v", cancelAt, listErr)
			}
		})
	}
}

func decimalTestName(value int) string {
	const digits = "00000000000000000000"
	raw := []byte(digits)
	for index := len(raw) - 1; value > 0; index-- {
		raw[index] = byte('0' + value%10)
		value /= 10
	}
	return string(raw)
}

func TestArchiveImportAdaptersAndCleanupPoisoning(t *testing.T) {
	readerCtx := &stagedCancellationContext{Context: context.Background(), cancelAt: 2}
	buffer := make([]byte, 1)
	count, err := (archiveImportContextReader{ctx: readerCtx, reader: strings.NewReader("x")}).Read(buffer)
	if count != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("context reader = (%d, %v), want 1/context.Canceled", count, err)
	}
	writerCtx := &stagedCancellationContext{Context: context.Background(), cancelAt: 2}
	var destination bytes.Buffer
	count, err = (archiveImportContextWriter{ctx: writerCtx, writer: &destination}).Write([]byte("x"))
	if count != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("context writer = (%d, %v), want 1/context.Canceled", count, err)
	}

	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)
	path := filepath.Join(directory, ImageArchiveFileName)
	writeTestFile(t, directory, ImageArchiveFileName, []byte("partial"), 0o200)
	identity, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "archive-alias")
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	injected := errors.New("injected copy failure")
	err = store.failArchiveImportLocked(injected, nil, nil, nil, nil, identity)
	if !errors.Is(err, injected) || !errors.Is(err, ErrPoisoned) || !store.poisoned {
		t.Fatalf("failArchiveImportLocked() error = %v, poisoned=%v", err, store.poisoned)
	}
}

func TestReadHookAndDescriptorFailures(t *testing.T) {
	t.Run("hook error", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		injected := errors.New("injected read hook failure")
		if _, err := store.read(ReleaseFileName, 64, func(*os.File) error {
			return injected
		}); !errors.Is(err, injected) {
			t.Fatalf("read(hook error) error = %v, want injected error", err)
		}
	})
	t.Run("closed descriptor", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		if _, err := store.read(ReleaseFileName, 64, func(file *os.File) error {
			return file.Close()
		}); err == nil {
			t.Fatal("read(closed descriptor) succeeded")
		}
	})
}

func TestInternalLockAuditSyncAndCloseFailures(t *testing.T) {
	t.Run("closed root operations", func(t *testing.T) {
		directory := testWorkspace(t)
		root, identity := openRootAndIdentity(t, directory)
		store := &Store{directory: directory, identity: identity, root: root}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.acquireDirectoryLock(); err == nil {
			t.Fatal("acquireDirectoryLock(closed root) succeeded")
		}
		if _, err := store.readEntryNamesLocked(); err == nil {
			t.Fatal("readEntryNamesLocked(closed root) succeeded")
		}
		if err := syncRoot(root); err == nil {
			t.Fatal("syncRoot(closed root) succeeded")
		}
	})
	t.Run("directory lock identity mismatch", func(t *testing.T) {
		directory := testWorkspace(t)
		other := testWorkspace(t)
		root, _ := openRootAndIdentity(t, directory)
		defer root.Close()
		otherInfo, err := os.Lstat(other)
		if err != nil {
			t.Fatal(err)
		}
		store := &Store{directory: directory, identity: otherInfo, root: root}
		if _, err := store.acquireDirectoryLock(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("acquireDirectoryLock(mismatched identity) error = %v", err)
		}
	})
	t.Run("invalid existing lock", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, LockFileName, []byte("not empty"), 0o600)
		root, identity := openRootAndIdentity(t, directory)
		defer root.Close()
		store := &Store{directory: directory, identity: identity, root: root}
		if _, err := store.acquireLock(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("acquireLock(invalid file) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("lock is directory", func(t *testing.T) {
		directory := testWorkspace(t)
		if err := os.Mkdir(filepath.Join(directory, LockFileName), 0o700); err != nil {
			t.Fatal(err)
		}
		root, identity := openRootAndIdentity(t, directory)
		defer root.Close()
		store := &Store{directory: directory, identity: identity, root: root}
		if _, err := store.acquireLock(); err == nil {
			t.Fatal("acquireLock(directory) succeeded")
		}
	})
	t.Run("lock contention without directory lock", func(t *testing.T) {
		directory := testWorkspace(t)
		holder := mustOpenStore(t, directory)
		root, identity := openRootAndIdentity(t, directory)
		defer root.Close()
		contender := &Store{directory: directory, identity: identity, root: root}
		if _, err := contender.acquireLock(); !errors.Is(err, ErrLocked) {
			t.Fatalf("acquireLock(contender) error = %v, want ErrLocked", err)
		}
		if holder == nil {
			t.Fatal("unreachable")
		}
	})
	t.Run("audit requires lock entry", func(t *testing.T) {
		directory := testWorkspace(t)
		root, identity := openRootAndIdentity(t, directory)
		defer root.Close()
		store := &Store{directory: directory, identity: identity, root: root}
		if _, err := store.auditLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("auditLocked(no lock) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("sync revalidates directory", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := store.syncDirectoryLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("syncDirectoryLocked(tampered) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("close reports closed descriptors", func(t *testing.T) {
		directory := testWorkspace(t)
		store, err := Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.lock.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.directoryLock.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.root.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err == nil {
			t.Fatal("Close() with already-closed descriptors returned nil")
		}
	})
}

func TestPortableHelperFailureBranches(t *testing.T) {
	if validRemovableOutput(nil, 1) {
		t.Fatal("validRemovableOutput(nil) = true")
	}
	if validRemovableOutput(syntheticFileInfo{size: -1}, 1) {
		t.Fatal("validRemovableOutput(negative size) = true")
	}
	if validRemovableOutput(syntheticFileInfo{size: 2}, 1) {
		t.Fatal("validRemovableOutput(oversize) = true")
	}
	if validRemovableOutput(syntheticFileInfo{mode: 0o400}, 1) {
		t.Fatal("validRemovableOutput(read-only mode) = true")
	}
	if _, _, ok := ownerAndLinks(nil); ok {
		t.Fatal("ownerAndLinks(nil) succeeded")
	}
	if _, _, ok := ownerAndLinks(syntheticFileInfo{sys: "not-stat"}); ok {
		t.Fatal("ownerAndLinks(non-stat Sys) succeeded")
	}
	if _, _, ok := changeTime(nil); ok {
		t.Fatal("changeTime(nil) succeeded")
	}
	var nilStat *syscall.Stat_t
	if _, _, ok := changeTime(syntheticFileInfo{sys: nilStat}); ok {
		t.Fatal("changeTime(nil pointer) succeeded")
	}
	if _, _, ok := changeTime(syntheticFileInfo{sys: "not-struct"}); ok {
		t.Fatal("changeTime(non-struct) succeeded")
	}
	if _, _, ok := changeTime(syntheticFileInfo{sys: struct{ Other int }{}}); ok {
		t.Fatal("changeTime(struct without ctime) succeeded")
	}
	if equalNames([]string{"a"}, nil) {
		t.Fatal("equalNames(length mismatch) = true")
	}
	if equalNames([]string{"a"}, []string{"b"}) {
		t.Fatal("equalNames(content mismatch) = true")
	}
	if err := syncRoot(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("syncRoot(nil) error = %v, want ErrClosed", err)
	}
	file, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(file, []byte("x")); err == nil {
		t.Fatal("writeAll(closed file) succeeded")
	}
	if err := writeAll(nil, nil); err != nil {
		t.Fatalf("writeAll(nil, empty) error = %v", err)
	}

	readerCtx := &stagedCancellationContext{Context: context.Background(), cancelAt: 1}
	if count, err := (archiveImportContextReader{ctx: readerCtx, reader: strings.NewReader("x")}).Read(make([]byte, 1)); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled reader = (%d, %v)", count, err)
	}
	writerCtx := &stagedCancellationContext{Context: context.Background(), cancelAt: 1}
	if count, err := (archiveImportContextWriter{ctx: writerCtx, writer: io.Discard}).Write([]byte("x")); count != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled writer = (%d, %v)", count, err)
	}
}
