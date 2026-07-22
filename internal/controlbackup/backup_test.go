package controlbackup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	for _, name := range append([]string{"CURRENT"}, requiredIdentityFiles...) {
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
	stateAlias := filepath.Join(root, "state-alias")
	if err := os.Symlink(state, stateAlias); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(state, filepath.Join(stateAlias, "symlinked.tar"), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "outside") {
		t.Fatalf("symlinked inside-state output error = %v", err)
	}
}

func TestCreateRejectsInvalidPathAndTimeBoundaries(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	validOutput := filepath.Join(root, "backup.tar")
	validTime := time.Now().UTC()
	for _, test := range []struct {
		name   string
		state  string
		output string
		now    time.Time
	}{
		{name: "relative state", state: "relative", output: validOutput, now: validTime},
		{name: "relative output", state: state, output: "relative.tar", now: validTime},
		{name: "zero creation time", state: state, output: validOutput},
		{name: "missing state", state: filepath.Join(root, "missing-state"), output: validOutput, now: validTime},
		{name: "missing output parent", state: state, output: filepath.Join(root, "missing-parent", "backup.tar"), now: validTime},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Create(test.state, test.output, test.now); err == nil {
				t.Fatal("invalid backup boundary was accepted")
			}
		})
	}
	if err := os.WriteFile(validOutput, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(state, validOutput, validTime); err == nil || !strings.Contains(err.Error(), "exist") {
		t.Fatalf("existing output error = %v", err)
	}
}

func TestCreateRetainsVerifiedOutputDirectoryIdentity(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	outputParent := filepath.Join(root, "output")
	movedParent := filepath.Join(root, "moved-output")
	if err := os.Mkdir(outputParent, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(outputParent, "backup.tar")
	_, err := create(state, archive, time.Now().UTC(), func() {
		if err := os.Rename(outputParent, movedParent); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(state, outputParent); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "output parent changed") {
		t.Fatalf("substituted output parent error = %v", err)
	}
	for _, path := range []string{filepath.Join(state, "backup.tar"), filepath.Join(movedParent, "backup.tar")} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed backup remains at %s: %v", path, statErr)
		}
	}
}

func TestCreateRetainsStoppedStateDirectoryIdentity(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	movedState := filepath.Join(root, "moved-state")
	archive := filepath.Join(root, "backup.tar")
	_, err := create(state, archive, time.Now().UTC(), func() {
		if err := os.Rename(state, movedState); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(movedState, state); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatalf("substituted state directory error = %v", err)
	}
	if _, statErr := os.Lstat(archive); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed backup remains: %v", statErr)
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

func TestVerifyRejectsMalformedArchiveBoundaries(t *testing.T) {
	root := t.TempDir()
	if _, err := Verify("relative.tar"); err == nil {
		t.Fatal("relative archive was accepted")
	}
	if _, err := Verify(filepath.Join(root, "missing.tar")); err == nil {
		t.Fatal("missing archive was accepted")
	}

	empty := filepath.Join(root, "empty.tar")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(empty); err == nil || !strings.Contains(err.Error(), "manifest entry") {
		t.Fatalf("empty archive error = %v", err)
	}

	writeManifest := func(t *testing.T, path string, declared int64, raw []byte) {
		t.Helper()
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		writer := tar.NewWriter(file)
		if err := writer.WriteHeader(&tar.Header{
			Name: manifestName, Mode: 0o600, Size: declared, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}); err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write(raw)
		_ = writer.Close()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}

	truncated := filepath.Join(root, "truncated.tar")
	writeManifest(t, truncated, 8, []byte("{}"))
	if _, err := Verify(truncated); err == nil || !strings.Contains(err.Error(), "manifest body") {
		t.Fatalf("truncated manifest error = %v", err)
	}

	malformed := filepath.Join(root, "malformed.tar")
	writeManifest(t, malformed, 1, []byte("{"))
	if _, err := Verify(malformed); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("malformed manifest error = %v", err)
	}

	invalid := filepath.Join(root, "invalid.tar")
	writeManifest(t, invalid, 3, []byte("{}\n"))
	if _, err := Verify(invalid); err == nil {
		t.Fatal("invalid manifest was accepted")
	}

	state := initializeControlState(t, root, false)
	valid := filepath.Join(root, "valid-for-consumer.tar")
	if _, err := Create(state, valid, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(valid, func(ManifestFile, io.Reader) error { return errors.New("injected consumer failure") }); err == nil ||
		!strings.Contains(err.Error(), "injected consumer failure") {
		t.Fatalf("consumer error = %v", err)
	}
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

func TestRestoreRemovesReservedDestinationWhenDurabilityFails(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	archive := filepath.Join(root, "valid.tar")
	if _, err := Create(state, archive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "failed-restore")
	failDestinationSync := true
	_, err := restore(archive, destination, func(root *os.Root) error {
		if filepath.Base(root.Name()) == filepath.Base(destination) && failDestinationSync {
			failDestinationSync = false
			return errors.New("injected destination sync failure")
		}
		return syncRoot(root)
	})
	if err == nil || !strings.Contains(err.Error(), "injected destination sync failure") {
		t.Fatalf("restore error = %v", err)
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed restore destination remains: %v", statErr)
	}
}

func TestRestoreRetainsReservedDirectoryIdentity(t *testing.T) {
	root := t.TempDir()
	state := initializeControlState(t, root, false)
	archive := filepath.Join(root, "valid.tar")
	if _, err := Create(state, archive, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "restored")
	movedDestination := filepath.Join(root, "moved-restored")
	trap := filepath.Join(root, "trap")
	if err := os.Mkdir(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	swapped := false
	_, err := restore(archive, destination, func(opened *os.Root) error {
		if !swapped {
			if renameErr := os.Rename(destination, movedDestination); renameErr != nil {
				t.Fatal(renameErr)
			}
			if symlinkErr := os.Symlink(trap, destination); symlinkErr != nil {
				t.Fatal(symlinkErr)
			}
			swapped = true
		}
		return syncRoot(opened)
	})
	if err == nil || !strings.Contains(err.Error(), "changed before completion") {
		t.Fatalf("substituted restore destination error = %v", err)
	}
	entries, readErr := os.ReadDir(trap)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("substituted restore wrote outside retained root: entries=%v err=%v", entries, readErr)
	}
	entries, readErr = os.ReadDir(movedDestination)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed retained restore was not scrubbed: entries=%v err=%v", entries, readErr)
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

func TestBackupHelpersRejectHostileFilesystemAndManifestState(t *testing.T) {
	t.Run("regular file boundary", func(t *testing.T) {
		root := t.TempDir()
		missing := filepath.Join(root, "missing")
		if file, _, err := openRegular(missing, 1, 0o600); err == nil || file != nil {
			t.Fatal("missing file was opened")
		}
		wrongMode := filepath.Join(root, "wrong-mode")
		if err := os.WriteFile(wrongMode, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		if file, _, err := openRegular(wrongMode, 1, 0o600); err == nil || file != nil {
			t.Fatal("wrong-mode file was opened")
		}
		oversized := filepath.Join(root, "oversized")
		if err := os.WriteFile(oversized, []byte("xx"), 0o600); err != nil {
			t.Fatal(err)
		}
		if file, _, err := openRegular(oversized, 1, 0o600); err == nil || file != nil {
			t.Fatal("oversized file was opened")
		}
		hardlink := filepath.Join(root, "hardlink")
		if err := os.Link(oversized, hardlink); err != nil {
			t.Fatal(err)
		}
		if file, _, err := openRegular(oversized, 2, 0o600); err == nil || file != nil {
			t.Fatal("multiply linked file was opened")
		}
		if file, _, err := openRegular(root, 1, 0o700); err == nil || file != nil {
			t.Fatal("directory was opened as a regular file")
		}
		openedRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		defer openedRoot.Close()
		if _, err := createExclusiveRoot(openedRoot, filepath.Base(wrongMode), 0o600); err == nil {
			t.Fatal("existing output was overwritten")
		}
		if _, err := createExclusiveRoot(nil, "new", 0o600); err == nil {
			t.Fatal("nil output root was accepted")
		}
		if _, err := createExclusiveRoot(openedRoot, "nested/new", 0o600); err == nil {
			t.Fatal("nested output name was accepted")
		}
		if _, err := readRootRegular(nil, "file", 1, 0o600); err == nil {
			t.Fatal("nil read root was accepted")
		}
		if file, _, err := openRootRegular(openedRoot, "file", 1); err == nil || file != nil {
			t.Fatal("empty allowed mode set was accepted")
		}
	})

	t.Run("state inventory", func(t *testing.T) {
		unsafe := t.TempDir()
		if err := os.WriteFile(filepath.Join(unsafe, "bad name"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		unsafeRoot, err := os.OpenRoot(unsafe)
		if err != nil {
			t.Fatal(err)
		}
		defer unsafeRoot.Close()
		if files, err := openStateFilesRoot(unsafeRoot); err == nil || files != nil {
			t.Fatal("unsafe state filename was accepted")
		}
		crowded := t.TempDir()
		for index := 0; index < maxFiles+2; index++ {
			if err := os.WriteFile(filepath.Join(crowded, fmt.Sprintf("file-%03d", index)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		crowdedRoot, err := os.OpenRoot(crowded)
		if err != nil {
			t.Fatal(err)
		}
		defer crowdedRoot.Close()
		if files, err := openStateFilesRoot(crowdedRoot); err == nil || files != nil {
			t.Fatal("oversized state inventory was accepted")
		}
	})

	t.Run("manifest boundary", func(t *testing.T) {
		valid := validManifestFixture()
		if err := validateManifest(valid); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*Manifest){
			func(value *Manifest) { value.SchemaVersion = "unknown" },
			func(value *Manifest) { value.CreatedAt = "not-a-time" },
			func(value *Manifest) { value.Files = nil },
			func(value *Manifest) { value.Files[0].Mode = 0o777 },
			func(value *Manifest) { value.Files[0].SHA256 = "sha256:bad" },
			func(value *Manifest) { value.Files[0].Size = maxFileBytes + 1 },
			func(value *Manifest) { value.Files[1].Name = value.Files[0].Name },
			func(value *Manifest) { value.Files = value.Files[1:] },
		} {
			candidate := valid
			candidate.Files = append([]ManifestFile(nil), valid.Files...)
			mutate(&candidate)
			if err := validateManifest(candidate); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		}
	})

	t.Run("restored checkpoint identity", func(t *testing.T) {
		root := t.TempDir()
		state := initializeControlState(t, root, false)
		stateRoot, err := os.OpenRoot(state)
		if err != nil {
			t.Fatal(err)
		}
		defer stateRoot.Close()
		if err := validateRestoredStateRoot(stateRoot, Report{Generation: 2}); err == nil ||
			!strings.Contains(err.Error(), "checkpoint") {
			t.Fatalf("mismatched checkpoint error = %v", err)
		}
		missingIdentity := t.TempDir()
		missingRoot, err := os.OpenRoot(missingIdentity)
		if err != nil {
			t.Fatal(err)
		}
		defer missingRoot.Close()
		if err := validateDefaultIdentitySetRoot(missingRoot); err == nil ||
			!strings.Contains(err.Error(), "authentication identity") {
			t.Fatalf("missing identity error = %v", err)
		}
	})

	t.Run("identity material", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			mutate func(t *testing.T, state string)
		}{
			{
				name: "invalid authentication key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.WriteFile(filepath.Join(state, "auth.key"), []byte("invalid"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "missing witness private key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.Remove(filepath.Join(state, "witness.private.pem")); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "missing witness public key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.Remove(filepath.Join(state, "witness.public.pem")); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "invalid witness private key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.WriteFile(filepath.Join(state, "witness.private.pem"), []byte("invalid"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "invalid witness public key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.WriteFile(filepath.Join(state, "witness.public.pem"), []byte("invalid"), 0o644); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "mismatched witness pair",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					copyTestFile(t, filepath.Join(state, "controller.public.pem"), filepath.Join(state, "witness.public.pem"), 0o644)
				},
			},
			{
				name: "invalid controller private key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.WriteFile(filepath.Join(state, "controller.private.pem"), []byte("invalid"), 0o600); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "missing controller public key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.Remove(filepath.Join(state, "controller.public.pem")); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "invalid controller public key",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					if err := os.WriteFile(filepath.Join(state, "controller.public.pem"), []byte("invalid"), 0o644); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				name: "shared controller and witness identity",
				mutate: func(t *testing.T, state string) {
					t.Helper()
					copyTestFile(t, filepath.Join(state, "witness.private.pem"), filepath.Join(state, "controller.private.pem"), 0o600)
					copyTestFile(t, filepath.Join(state, "witness.public.pem"), filepath.Join(state, "controller.public.pem"), 0o644)
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				root := t.TempDir()
				state := initializeControlState(t, root, false)
				test.mutate(t, state)
				stateRoot, err := os.OpenRoot(state)
				if err != nil {
					t.Fatal(err)
				}
				defer stateRoot.Close()
				if err := validateDefaultIdentitySetRoot(stateRoot); err == nil {
					t.Fatal("invalid identity material was accepted")
				}
			})
		}
	})
}

func copyTestFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, mode); err != nil {
		t.Fatal(err)
	}
}

func validManifestFixture() Manifest {
	names := append([]string{"CURRENT"}, requiredIdentityFiles...)
	slices.Sort(names)
	files := make([]ManifestFile, len(names))
	for index, name := range names {
		files[index] = ManifestFile{
			Name: name, Size: 1, Mode: 0o600,
			SHA256: "sha256:" + strings.Repeat("a", sha256.Size*2),
		}
	}
	return Manifest{
		SchemaVersion: SchemaV1, CreatedAt: "2026-07-22T12:00:00Z", Generation: 1,
		Files: files,
	}
}
