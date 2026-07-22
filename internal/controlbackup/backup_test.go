package controlbackup

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/controlwitness"
)

func TestCreateVerifyAndRestoreControlBackup(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	archive := filepath.Join(root, "control-backup.tar")
	createdAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	created, err := Create(state, archive, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != "verified" || created.Generation != 1 || created.Sequence != 0 ||
		created.Files < 8 || created.PayloadBytes == 0 || !validDigest(created.ArchiveSHA256) {
		t.Fatalf("created report = %+v", created)
	}
	info, err := os.Stat(archive)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup info=%v err=%v", info, err)
	}
	verified, err := Verify(archive)
	if err != nil {
		t.Fatal(err)
	}
	if verified != created {
		t.Fatalf("verified report=%+v want %+v", verified, created)
	}

	restored := filepath.Join(root, "restored")
	restoredReport, err := Restore(archive, restored)
	if err != nil {
		t.Fatal(err)
	}
	if restoredReport != created {
		t.Fatalf("restore report=%+v want %+v", restoredReport, created)
	}
	for _, name := range append([]string{"CURRENT", "LOCK"}, requiredIdentityFiles...) {
		if _, err := os.Stat(filepath.Join(restored, name)); err != nil {
			t.Fatalf("restored %s: %v", name, err)
		}
	}
	store, err := controlstore.Open(restored, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRequiresStoppedCompleteDefaultControlState(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, true)
	if _, err := Create(state, filepath.Join(root, "locked.tar"), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked store error = %v", err)
	}
	lockedStoresMu.Lock()
	store := lockedStores[state]
	delete(lockedStores, state)
	lockedStoresMu.Unlock()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(state, "controller.private.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(state, filepath.Join(root, "incomplete.tar"), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "controller identity") {
		t.Fatalf("incomplete identity error = %v", err)
	}
	if _, err := Create(state, filepath.Join(state, "nested.tar"), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "outside") {
		t.Fatalf("inside-state output error = %v", err)
	}
}

func TestVerifyRejectsHostileControlBackupEntries(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	archive := filepath.Join(root, "valid.tar")
	if _, err := Create(state, archive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(int, *tar.Header, []byte) (*tar.Header, []byte)
	}{
		{
			name: "path traversal",
			mutate: func(index int, header *tar.Header, raw []byte) (*tar.Header, []byte) {
				if index == 1 {
					header.Name = "state/../escaped"
				}
				return header, raw
			},
		},
		{
			name: "symlink",
			mutate: func(index int, header *tar.Header, raw []byte) (*tar.Header, []byte) {
				if index == 1 {
					header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "/etc/shadow", 0
					raw = nil
				}
				return header, raw
			},
		},
		{
			name: "payload mutation",
			mutate: func(index int, header *tar.Header, raw []byte) (*tar.Header, []byte) {
				if index == 1 && len(raw) > 0 {
					raw[0] ^= 0xff
				}
				return header, raw
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-")+".tar")
			rewriteArchive(t, archive, changed, test.mutate, false)
			if _, err := Verify(changed); err == nil {
				t.Fatal("hostile archive was accepted")
			}
		})
	}
	t.Run("undeclared trailing entry", func(t *testing.T) {
		changed := filepath.Join(root, "trailing.tar")
		rewriteArchive(t, archive, changed, func(_ int, header *tar.Header, raw []byte) (*tar.Header, []byte) {
			return header, raw
		}, true)
		if _, err := Verify(changed); err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("trailing entry error = %v", err)
		}
	})
	t.Run("bytes after terminator", func(t *testing.T) {
		changed := filepath.Join(root, "appended.tar")
		raw, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(changed, append(raw, []byte("smuggled")...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(changed); err == nil || !strings.Contains(err.Error(), "terminator") {
			t.Fatalf("appended bytes error = %v", err)
		}
	})
}

func TestRestoreIsPreviewSafeByConstruction(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	archive := filepath.Join(root, "valid.tar")
	if _, err := Create(state, archive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(archive, existing); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing restore error = %v", err)
	}
	if _, err := Restore(archive, "relative"); err == nil {
		t.Fatal("relative restore destination was accepted")
	}
	unsafeParent := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(archive, filepath.Join(unsafeParent, "state")); err == nil ||
		!strings.Contains(err.Error(), "not writable") {
		t.Fatalf("unsafe parent error = %v", err)
	}
}

func rewriteArchive(
	t *testing.T,
	source, destination string,
	mutate func(int, *tar.Header, []byte) (*tar.Header, []byte),
	trailing bool,
) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for index := 0; ; index++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		copyHeader := *header
		changedHeader, changedBody := mutate(index, &copyHeader, append([]byte(nil), body...))
		changedHeader.Size = int64(len(changedBody))
		if err := writer.WriteHeader(changedHeader); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(changedBody); err != nil {
			t.Fatal(err)
		}
	}
	if trailing {
		if err := writeTarEntry(writer, "state/undeclared", 0o600, []byte("unexpected")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	lockedStoresMu sync.Mutex
	lockedStores   = map[string]*controlstore.Store{}
)

func initializeControlState(t *testing.T, root string, keepLocked bool) string {
	t.Helper()
	state := filepath.Join(root, "state")
	store, err := controlstore.Initialize(state, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlauth.InitializeKey(filepath.Join(state, "auth.key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controlwitness.Initialize(
		filepath.Join(state, "witness.private.pem"), filepath.Join(state, "witness.public.pem"),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controlwitness.Initialize(
		filepath.Join(state, "controller.private.pem"), filepath.Join(state, "controller.public.pem"),
	); err != nil {
		t.Fatal(err)
	}
	if keepLocked {
		lockedStoresMu.Lock()
		lockedStores[state] = store
		lockedStoresMu.Unlock()
		t.Cleanup(func() {
			lockedStoresMu.Lock()
			retained := lockedStores[state]
			delete(lockedStores, state)
			lockedStoresMu.Unlock()
			if retained != nil {
				_ = retained.Close()
			}
		})
	} else if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestManifestDecoderRejectsUnknownAndNonCanonicalFields(t *testing.T) {
	if err := decodeStrict([]byte(`{"known":true,"unknown":true}`), &struct {
		Known bool `json:"known"`
	}{}); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
	if validStateName("../state") || validStateName("LOCK") || validDigest("sha256:no") {
		t.Fatal("unsafe manifest primitive was accepted")
	}
	if err := validCleanAbsolute("relative", false); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
