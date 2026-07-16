package activationstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"

	"github.com/hardrails/steward/internal/ocibundle"
)

func testWorkspace(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeTestFile(t *testing.T, directory, name string, raw []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func testArchiveIdentity(raw []byte) ocibundle.ArchiveIdentity {
	return ocibundle.ArchiveIdentity{
		Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)),
		Bytes:  int64(len(raw)),
	}
}

func truncateTestFile(t *testing.T, directory, name string, size int64) {
	t.Helper()
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustOpenStore(t *testing.T, directory string) *Store {
	t.Helper()
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func mustStateName(t *testing.T, sequence uint64) string {
	t.Helper()
	name, err := StateCheckpointName(sequence)
	if err != nil {
		t.Fatalf("StateCheckpointName(%d) error = %v", sequence, err)
	}
	return name
}

func TestCanonicalInventoryAndStateNames(t *testing.T) {
	fixed := []string{
		LockFileName,
		ReleaseFileName,
		PolicyFileName,
		IntentFileName,
		ImageArchiveFileName,
		PlanFileName,
		AdmissionFileName,
		ServiceTrustFileName,
		CanaryRequestFileName,
		CanaryChallengeFileName,
		CanaryTaskFileName,
		CanarySubmitFileName,
		CanaryStatusFileName,
		CanaryResultFileName,
		ExecutorBaselineWitnessFileName,
		ExecutorBeginFileName,
		ExecutorCheckpointFileName,
		ExecutorDeltaFileName,
		ExecutorFinalWitnessFileName,
		GatewayTaskReceiptsFileName,
		ProofFileName,
	}
	want := []string{
		".lock",
		"release.dsse.json",
		"policy.dsse.json",
		"intent.json",
		"image.oci.tar",
		"plan.json",
		"admission.json",
		"service-trust.json",
		"canary.request.json",
		"canary.challenge.json",
		"canary.task.json",
		"canary.submit.json",
		"canary.status.json",
		"canary.result.json",
		"executor-baseline-witness.json",
		"executor-activation-begin.json",
		"executor-activation-checkpoint.json",
		"executor-delta.bin",
		"executor-final-witness.json",
		"gateway-task-receipts.ndjson",
		"proof.json",
	}
	if !reflect.DeepEqual(fixed, want) {
		t.Fatalf("fixed inventory = %#v, want %#v", fixed, want)
	}

	tests := []struct {
		sequence uint64
		want     string
	}{
		{0, "state-000000000000.json"},
		{1, "state-000000000001.json"},
		{42, "state-000000000042.json"},
		{MaxStateSequence, "state-999999999999.json"},
	}
	for _, test := range tests {
		name, err := StateCheckpointName(test.sequence)
		if err != nil || name != test.want || classifyName(name) != artifactState {
			t.Fatalf("StateCheckpointName(%d) = (%q, %v), want %q", test.sequence, name, err, test.want)
		}
	}
	if _, err := StateCheckpointName(MaxStateSequence + 1); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("oversize StateCheckpointName() error = %v, want ErrInvalidName", err)
	}
	for _, name := range []string{
		"state-1.json",
		"state-0000000000000.json",
		"state-00000000000a.json",
		"state-000000000001.bin",
		"state/000000000001.json",
	} {
		if validStateCheckpointName(name) || classifyName(name) != artifactInvalid {
			t.Fatalf("invalid state name %q was accepted", name)
		}
	}
}

func TestOpenAcceptsCompleteFixedInventory(t *testing.T) {
	directory := testWorkspace(t)
	for _, name := range []string{
		ReleaseFileName,
		PolicyFileName,
		IntentFileName,
		PlanFileName,
		AdmissionFileName,
		ServiceTrustFileName,
		CanaryRequestFileName,
		CanaryChallengeFileName,
		CanaryTaskFileName,
		CanarySubmitFileName,
		CanaryStatusFileName,
		CanaryResultFileName,
		ExecutorBaselineWitnessFileName,
		ExecutorBeginFileName,
		ExecutorCheckpointFileName,
		ExecutorDeltaFileName,
		ExecutorFinalWitnessFileName,
		GatewayTaskReceiptsFileName,
		ProofFileName,
		mustStateName(t, 0),
	} {
		writeTestFile(t, directory, name, []byte(name), 0o600)
	}
	truncateTestFile(t, directory, ImageArchiveFileName, 1)

	store := mustOpenStore(t, directory)
	states, err := store.ListStateCheckpoints()
	if err != nil {
		t.Fatalf("ListStateCheckpoints() error = %v", err)
	}
	if want := []string{mustStateName(t, 0)}; !reflect.DeepEqual(states, want) {
		t.Fatalf("states = %#v, want %#v", states, want)
	}
}

func TestOpenCreatesLifetimeLockAndRejectsContender(t *testing.T) {
	directory := testWorkspace(t)
	first := mustOpenStore(t, directory)

	info, err := os.Lstat(filepath.Join(directory, LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	_, links, ok := ownerAndLinks(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 || links != 1 {
		t.Fatalf("lock info = mode %v size %d links %d", info.Mode(), info.Size(), links)
	}

	second, err := Open(directory)
	if second != nil || !errors.Is(err, ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("contending Open() = (%v, %v), want ErrLocked", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() after release error = %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateImportAppendAndLatestState(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "activation")
	oldMask := syscall.Umask(0o777)
	store, err := Create(directory)
	syscall.Umask(oldMask)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory mode = %v, want 0700 directory", info.Mode())
	}
	if second, err := Create(directory); second != nil || !errors.Is(err, ErrAlreadyExists) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second Create() = (%v, %v), want ErrAlreadyExists", second, err)
	}

	inputs := map[string][]byte{
		ReleaseFileName:      []byte("release"),
		PolicyFileName:       []byte("policy"),
		IntentFileName:       []byte("intent"),
		ServiceTrustFileName: []byte("trust"),
	}
	for name, raw := range inputs {
		if err := store.Import(name, raw); err != nil {
			t.Fatalf("Import(%q) error = %v", name, err)
		}
		got, err := store.Read(name, 64)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("Read(%q) = (%q, %v), want %q", name, got, err, raw)
		}
	}
	if err := store.Import(ReleaseFileName, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate Import() error = %v, want ErrAlreadyExists", err)
	}
	if err := store.Import(PlanFileName, []byte("plan")); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Import(generated) error = %v, want ErrInvalidName", err)
	}
	if _, _, found, err := store.LatestState(64); err != nil || found {
		t.Fatalf("LatestState(empty) = (found=%v, err=%v), want false/nil", found, err)
	}
	firstName, err := store.AppendState(0, []byte("new"))
	if err != nil || firstName != mustStateName(t, 0) {
		t.Fatalf("AppendState(0) = (%q, %v)", firstName, err)
	}
	latestName, err := store.AppendState(1, []byte("passed"))
	if err != nil || latestName != mustStateName(t, 1) {
		t.Fatalf("AppendState(1) = (%q, %v)", latestName, err)
	}
	name, raw, found, err := store.LatestState(64)
	if err != nil || !found || name != latestName || string(raw) != "passed" {
		t.Fatalf("LatestState() = (%q, %q, %v, %v)", name, raw, found, err)
	}
	if _, err := store.AppendState(1, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate AppendState() error = %v, want ErrAlreadyExists", err)
	}
}

func TestOpenRejectsUnsafeDirectoryBoundaries(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		if _, err := Open("relative"); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(relative) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("unclean path", func(t *testing.T) {
		directory := testWorkspace(t)
		if _, err := Open(directory + string(filepath.Separator) + "."); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(unclean) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("filesystem root", func(t *testing.T) {
		if _, err := Open(string(filepath.Separator)); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(root) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("directory symlink", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(symlink) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("wrong directory mode", func(t *testing.T) {
		directory := testWorkspace(t)
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(directory); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(0750) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("replaceable user-owned ancestor", func(t *testing.T) {
		base := t.TempDir()
		ancestor := filepath.Join(base, "replaceable")
		directory := filepath.Join(ancestor, "workspace")
		if err := os.Mkdir(ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(directory); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(replaceable ancestor) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
}

func TestOpenRejectsUnsafeEntries(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"unexpected file": func(t *testing.T, directory string) {
			writeTestFile(t, directory, "notes.txt", []byte("x"), 0o600)
		},
		"symlink": func(t *testing.T, directory string) {
			target := filepath.Join(t.TempDir(), "target")
			writeTestFile(t, filepath.Dir(target), filepath.Base(target), []byte("x"), 0o600)
			if err := os.Symlink(target, filepath.Join(directory, ReleaseFileName)); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, directory string) {
			if err := os.Mkdir(filepath.Join(directory, ReleaseFileName), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, directory string) {
			path := filepath.Join(directory, PlanFileName)
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"group-readable file": func(t *testing.T, directory string) {
			writeTestFile(t, directory, ReleaseFileName, []byte("x"), 0o640)
		},
		"setuid file": func(t *testing.T, directory string) {
			writeTestFile(t, directory, PlanFileName, []byte("x"), 0o600)
			path := filepath.Join(directory, PlanFileName)
			if err := os.Chmod(path, 0o600|os.ModeSetuid); err != nil {
				t.Skipf("setuid mode unavailable: %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSetuid == 0 {
				t.Skip("filesystem cleared setuid mode")
			}
		},
		"sticky workspace": func(t *testing.T, directory string) {
			if err := os.Chmod(directory, 0o700|os.ModeSticky); err != nil {
				t.Skipf("sticky mode unavailable: %v", err)
			}
			info, err := os.Lstat(directory)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSticky == 0 {
				t.Skip("filesystem cleared sticky mode")
			}
		},
		"nonempty lock": func(t *testing.T, directory string) {
			writeTestFile(t, directory, LockFileName, []byte("not-empty"), 0o600)
		},
		"group-readable lock": func(t *testing.T, directory string) {
			writeTestFile(t, directory, LockFileName, nil, 0o640)
		},
		"hard-linked generated output": func(t *testing.T, directory string) {
			writeTestFile(t, directory, PlanFileName, []byte("plan"), 0o600)
			if err := os.Link(filepath.Join(directory, PlanFileName), filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		},
		"hard-linked external input": func(t *testing.T, directory string) {
			writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
			if err := os.Link(filepath.Join(directory, ReleaseFileName), filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		},
		"hard-linked archive": func(t *testing.T, directory string) {
			writeTestFile(t, directory, ImageArchiveFileName, []byte("archive"), 0o600)
			if err := os.Link(filepath.Join(directory, ImageArchiveFileName), filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		},
		"empty archive": func(t *testing.T, directory string) {
			writeTestFile(t, directory, ImageArchiveFileName, nil, 0o600)
		},
		"incomplete generated output": func(t *testing.T, directory string) {
			writeTestFile(t, directory, PlanFileName, []byte("partial"), 0o200)
		},
		"incomplete archive": func(t *testing.T, directory string) {
			writeTestFile(t, directory, ImageArchiveFileName, []byte("partial"), 0o200)
		},
		"archive beyond importer limit": func(t *testing.T, directory string) {
			truncateTestFile(t, directory, ImageArchiveFileName, ocibundle.DefaultMaxArchiveBytes+1)
		},
		"malformed state name": func(t *testing.T, directory string) {
			writeTestFile(t, directory, "state-1.json", []byte("{}"), 0o600)
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			directory := testWorkspace(t)
			prepare(t, directory)
			store, err := Open(directory)
			if store != nil {
				_ = store.Close()
			}
			if err == nil || (!errors.Is(err, ErrUnsafeWorkspace) && !errors.Is(err, ErrCapacityExceeded)) {
				t.Fatalf("Open() error = %v, want unsafe/capacity error", err)
			}
		})
	}
}

func TestArchiveExcludedFromSmallQuota(t *testing.T) {
	directory := testWorkspace(t)
	writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
	truncateTestFile(t, directory, ImageArchiveFileName, MaxSmallFilesBytes+1)

	store := mustOpenStore(t, directory)
	raw, err := store.Read(ReleaseFileName, 64)
	if err != nil || string(raw) != "release" {
		t.Fatalf("Read(release) = (%q, %v)", raw, err)
	}
	archivePath, err := store.Path(ImageArchiveFileName)
	canonical, canonicalErr := filepath.EvalSymlinks(directory)
	if canonicalErr != nil {
		t.Fatal(canonicalErr)
	}
	if err != nil || archivePath != filepath.Join(canonical, ImageArchiveFileName) {
		t.Fatalf("Path(archive) = (%q, %v)", archivePath, err)
	}
	if _, err := store.Path(ReleaseFileName); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Path(release) error = %v, want ErrInvalidName", err)
	}
	if _, err := store.Read(ImageArchiveFileName, MaxSmallArtifactBytes); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Read(archive) error = %v, want ErrInvalidName", err)
	}
}

func TestImportArchiveSecurelySnapshotsOwnerOnlySource(t *testing.T) {
	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)
	sourceDirectory := t.TempDir()
	sourcePath := filepath.Join(sourceDirectory, "source.oci.tar")
	want := bytes.Repeat([]byte("steward-archive-"), 8192)
	writeTestFile(t, sourceDirectory, filepath.Base(sourcePath), want, 0o600)

	oldMask := syscall.Umask(0o777)
	err := store.ImportArchive(sourcePath, testArchiveIdentity(want))
	syscall.Umask(oldMask)
	if err != nil {
		t.Fatalf("ImportArchive() error = %v", err)
	}
	archivePath, err := store.Path(ImageArchiveFileName)
	if err != nil {
		t.Fatalf("Path(archive) error = %v", err)
	}
	got, err := os.ReadFile(archivePath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("imported archive = (%d bytes, %v), want %d exact bytes", len(got), err, len(want))
	}
	info, err := os.Lstat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	_, links, ok := ownerAndLinks(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() != int64(len(want)) || links != 1 {
		t.Fatalf("archive mode=%v size=%d links=%d", info.Mode(), info.Size(), links)
	}
	if err := store.ImportArchive(sourcePath, testArchiveIdentity(want)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate ImportArchive() error = %v, want ErrAlreadyExists", err)
	}
}

func TestImportArchiveRejectsUnsafeSources(t *testing.T) {
	tests := map[string]func(*testing.T) string{
		"relative path": func(t *testing.T) string {
			return "archive.tar"
		},
		"symlink": func(t *testing.T) string {
			directory := t.TempDir()
			writeTestFile(t, directory, "target", []byte("archive"), 0o600)
			path := filepath.Join(directory, "link")
			if err := os.Symlink(filepath.Join(directory, "target"), path); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"group-readable": func(t *testing.T) string {
			directory := t.TempDir()
			writeTestFile(t, directory, "archive", []byte("archive"), 0o640)
			return filepath.Join(directory, "archive")
		},
		"empty": func(t *testing.T) string {
			directory := t.TempDir()
			writeTestFile(t, directory, "archive", nil, 0o600)
			return filepath.Join(directory, "archive")
		},
		"beyond importer limit": func(t *testing.T) string {
			directory := t.TempDir()
			truncateTestFile(t, directory, "archive", ocibundle.DefaultMaxArchiveBytes+1)
			return filepath.Join(directory, "archive")
		},
		"hard-linked source": func(t *testing.T) string {
			directory := t.TempDir()
			writeTestFile(t, directory, "archive", []byte("archive"), 0o600)
			if err := os.Link(filepath.Join(directory, "archive"), filepath.Join(directory, "alias")); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			return filepath.Join(directory, "archive")
		},
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			directory := testWorkspace(t)
			store := mustOpenStore(t, directory)
			err := store.ImportArchive(source(t), testArchiveIdentity([]byte("archive")))
			if !errors.Is(err, ErrUnsafeWorkspace) {
				t.Fatalf("ImportArchive() error = %v, want ErrUnsafeWorkspace", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected archive left a destination: %v", err)
			}
		})
	}
}

func TestImportArchiveRequiresExactExpectedIdentity(t *testing.T) {
	sourceDirectory := t.TempDir()
	sourcePath := filepath.Join(sourceDirectory, "archive")
	sourceRaw := []byte("archive")
	writeTestFile(t, sourceDirectory, "archive", sourceRaw, 0o600)

	tests := map[string]ocibundle.ArchiveIdentity{
		"missing identity": {},
		"malformed digest": {
			Digest: "sha256:not-a-digest",
			Bytes:  int64(len(sourceRaw)),
		},
		"wrong digest": testArchiveIdentity([]byte("changed")),
		"wrong length": {
			Digest: testArchiveIdentity(sourceRaw).Digest,
			Bytes:  int64(len(sourceRaw) + 1),
		},
	}
	for name, expected := range tests {
		t.Run(name, func(t *testing.T) {
			directory := testWorkspace(t)
			store := mustOpenStore(t, directory)
			err := store.ImportArchive(sourcePath, expected)
			if !errors.Is(err, ErrUnsafeWorkspace) {
				t.Fatalf("ImportArchive() error = %v, want ErrUnsafeWorkspace", err)
			}
			if _, statErr := os.Lstat(
				filepath.Join(directory, ImageArchiveFileName),
			); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("identity mismatch left an archive destination: %v", statErr)
			}
			if _, listErr := store.ListStateCheckpoints(); listErr != nil {
				t.Fatalf("identity mismatch poisoned the store: %v", listErr)
			}
		})
	}
}

func TestImportArchiveFailureRemovesPartialDestination(t *testing.T) {
	t.Run("source size change", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		sourceDirectory := t.TempDir()
		sourcePath := filepath.Join(sourceDirectory, "archive")
		writeTestFile(t, sourceDirectory, "archive", []byte("archive bytes"), 0o600)
		err := store.importArchive(
			sourcePath,
			testArchiveIdentity([]byte("archive bytes")),
			func(_ *os.File) error {
				return os.Truncate(sourcePath, 0)
			},
		)
		if err == nil {
			t.Fatal("ImportArchive() accepted a changing source")
		}
		if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed import left partial archive: %v", err)
		}
		if _, err := store.ListStateCheckpoints(); err != nil {
			t.Fatalf("store poisoned despite clean partial removal: %v", err)
		}
	})
	t.Run("same-size source change with restored mtime", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		sourceDirectory := t.TempDir()
		sourcePath := filepath.Join(sourceDirectory, "archive")
		writeTestFile(t, sourceDirectory, "archive", []byte("archive bytes"), 0o600)
		before, err := os.Stat(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		err = store.importArchive(
			sourcePath,
			testArchiveIdentity([]byte("archive bytes")),
			func(_ *os.File) error {
				if err := os.WriteFile(sourcePath, []byte("mutated bytes"), 0o600); err != nil {
					return err
				}
				return os.Chtimes(sourcePath, before.ModTime(), before.ModTime())
			},
		)
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("ImportArchive() error = %v, want ErrUnsafeWorkspace", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed import left partial archive: %v", err)
		}
	})
	t.Run("hook failure", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		sourceDirectory := t.TempDir()
		sourcePath := filepath.Join(sourceDirectory, "archive")
		writeTestFile(t, sourceDirectory, "archive", []byte("archive bytes"), 0o600)
		hookErr := errors.New("injected source failure")
		err := store.importArchive(
			sourcePath,
			testArchiveIdentity([]byte("archive bytes")),
			func(_ *os.File) error {
				return hookErr
			},
		)
		if !errors.Is(err, hookErr) {
			t.Fatalf("ImportArchive() error = %v, want injected error", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed import left partial archive: %v", err)
		}
	})
}

func TestImportArchiveContextCancellationRemovesPartialDestination(t *testing.T) {
	t.Run("before import", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		sourceDirectory := t.TempDir()
		sourcePath := filepath.Join(sourceDirectory, "archive")
		writeTestFile(t, sourceDirectory, "archive", []byte("archive bytes"), 0o600)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := store.ImportArchiveContext(
			ctx,
			sourcePath,
			testArchiveIdentity([]byte("archive bytes")),
		); !errors.Is(err, context.Canceled) {
			t.Fatalf("ImportArchiveContext() error = %v, want context canceled", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canceled import left an archive destination: %v", err)
		}
	})

	t.Run("after destination creation", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		sourceDirectory := t.TempDir()
		sourcePath := filepath.Join(sourceDirectory, "archive")
		writeTestFile(t, sourceDirectory, "archive", bytes.Repeat([]byte("archive"), 8192), 0o600)
		ctx, cancel := context.WithCancel(context.Background())
		sourceRaw := bytes.Repeat([]byte("archive"), 8192)
		err := store.importArchiveContext(
			ctx,
			sourcePath,
			testArchiveIdentity(sourceRaw),
			func(*os.File) error {
				cancel()
				return nil
			},
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("importArchiveContext() error = %v, want context canceled", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, ImageArchiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canceled import left a partial archive: %v", err)
		}
		if _, err := store.ListStateCheckpoints(); err != nil {
			t.Fatalf("store poisoned despite clean cancellation cleanup: %v", err)
		}
	})
}

func TestOpenEnforcesEntryAndSmallFileCaps(t *testing.T) {
	t.Run("entry cap", func(t *testing.T) {
		directory := testWorkspace(t)
		for sequence := uint64(0); sequence < MaxWorkspaceEntries; sequence++ {
			writeTestFile(t, directory, mustStateName(t, sequence), nil, 0o600)
		}
		store, err := Open(directory)
		if store != nil {
			_ = store.Close()
		}
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Open(over entry cap) error = %v, want ErrCapacityExceeded", err)
		}
	})
	t.Run("aggregate small bytes", func(t *testing.T) {
		directory := testWorkspace(t)
		truncateTestFile(t, directory, ReleaseFileName, MaxSmallArtifactBytes)
		truncateTestFile(t, directory, PolicyFileName, MaxSmallArtifactBytes)
		truncateTestFile(
			t, directory, IntentFileName,
			MaxSmallFilesBytes-2*MaxSmallArtifactBytes+1,
		)
		store, err := Open(directory)
		if store != nil {
			_ = store.Close()
		}
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Open(over byte cap) error = %v, want ErrCapacityExceeded", err)
		}
	})
	t.Run("individual small bytes", func(t *testing.T) {
		directory := testWorkspace(t)
		truncateTestFile(
			t, directory, ReleaseFileName, MaxSmallArtifactBytes+1,
		)
		store, err := Open(directory)
		if store != nil {
			_ = store.Close()
		}
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Open(over artifact cap) error = %v, want ErrCapacityExceeded", err)
		}
	})
	t.Run("exact small byte boundary", func(t *testing.T) {
		directory := testWorkspace(t)
		truncateTestFile(t, directory, ReleaseFileName, MaxSmallArtifactBytes)
		truncateTestFile(t, directory, PolicyFileName, MaxSmallArtifactBytes)
		truncateTestFile(
			t, directory, IntentFileName,
			MaxSmallFilesBytes-2*MaxSmallArtifactBytes,
		)
		store := mustOpenStore(t, directory)
		if _, err := store.ListStateCheckpoints(); err != nil {
			t.Fatalf("exact boundary audit error = %v", err)
		}
	})
}

func TestWriteOnceIsExclusiveDurableAndAppendOnly(t *testing.T) {
	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)

	oldMask := syscall.Umask(0o777)
	err := store.WriteOnce(PlanFileName, []byte("plan"))
	syscall.Umask(oldMask)
	if err != nil {
		t.Fatalf("WriteOnce(plan) error = %v", err)
	}
	info, err := os.Lstat(filepath.Join(directory, PlanFileName))
	if err != nil {
		t.Fatal(err)
	}
	_, links, ok := ownerAndLinks(info)
	if !ok || info.Mode().Perm() != 0o600 || links != 1 || info.Size() != 4 {
		t.Fatalf("plan mode=%v links=%d size=%d", info.Mode(), links, info.Size())
	}
	raw, err := store.Read(PlanFileName, 4)
	if err != nil || string(raw) != "plan" {
		t.Fatalf("Read(plan) = (%q, %v)", raw, err)
	}
	if err := store.WriteOnce(PlanFileName, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate WriteOnce() error = %v, want ErrAlreadyExists", err)
	}
	raw, err = os.ReadFile(filepath.Join(directory, PlanFileName))
	if err != nil || string(raw) != "plan" {
		t.Fatalf("plan after duplicate = (%q, %v)", raw, err)
	}

	if err := store.WriteOnce(ExecutorDeltaFileName, nil); err != nil {
		t.Fatalf("WriteOnce(empty binary delta) error = %v", err)
	}
	raw, err = store.Read(ExecutorDeltaFileName, 1)
	if err != nil || len(raw) != 0 {
		t.Fatalf("Read(empty binary delta) = (%v bytes, %v)", len(raw), err)
	}

	for _, sequence := range []uint64{0, 1, 2} {
		if _, err := store.AppendState(sequence, []byte(fmt.Sprintf("%d", sequence))); err != nil {
			t.Fatalf("WriteOnce(state %d) error = %v", sequence, err)
		}
	}
	states, err := store.ListStateCheckpoints()
	wantStates := []string{mustStateName(t, 0), mustStateName(t, 1), mustStateName(t, 2)}
	if err != nil || !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("ListStateCheckpoints() = (%#v, %v), want %#v", states, err, wantStates)
	}

	for _, name := range []string{
		ReleaseFileName,
		PolicyFileName,
		IntentFileName,
		ServiceTrustFileName,
		ImageArchiveFileName,
		LockFileName,
		"unknown.json",
		"../proof.json",
		"state-1.json",
		mustStateName(t, 3),
	} {
		if err := store.WriteOnce(name, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("WriteOnce(%q) error = %v, want ErrInvalidName", name, err)
		}
	}
	if _, err := store.AppendState(4, []byte("gap")); !errors.Is(err, ErrStateOrder) {
		t.Fatalf("gapped AppendState() error = %v, want ErrStateOrder", err)
	}
	if err := store.WriteOnce(AdmissionFileName, make([]byte, MaxSmallArtifactBytes+1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("oversize WriteOnce() error = %v, want ErrCapacityExceeded", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(PlanFileName, 4); !errors.Is(err, ErrClosed) {
		t.Fatalf("Read() after Close error = %v, want ErrClosed", err)
	}
	if err := store.WriteOnce(AdmissionFileName, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteOnce() after Close error = %v, want ErrClosed", err)
	}
	if _, err := store.ListStateCheckpoints(); !errors.Is(err, ErrClosed) {
		t.Fatalf("ListStateCheckpoints() after Close error = %v, want ErrClosed", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestWriteOnceEnforcesLiveQuotas(t *testing.T) {
	t.Run("entry cap", func(t *testing.T) {
		directory := testWorkspace(t)
		for sequence := uint64(0); sequence < MaxWorkspaceEntries-2; sequence++ {
			writeTestFile(t, directory, mustStateName(t, sequence), nil, 0o600)
		}
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, nil); err != nil {
			t.Fatalf("WriteOnce at entry boundary error = %v", err)
		}
		if err := store.WriteOnce(AdmissionFileName, nil); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("WriteOnce over entry cap error = %v, want ErrCapacityExceeded", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, AdmissionFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("over-cap artifact exists or stat failed: %v", err)
		}
	})
	t.Run("byte cap", func(t *testing.T) {
		directory := testWorkspace(t)
		truncateTestFile(t, directory, ReleaseFileName, MaxSmallArtifactBytes)
		truncateTestFile(t, directory, PolicyFileName, MaxSmallArtifactBytes)
		truncateTestFile(
			t, directory, IntentFileName,
			MaxSmallFilesBytes-2*MaxSmallArtifactBytes-1,
		)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("x")); err != nil {
			t.Fatalf("WriteOnce at byte boundary error = %v", err)
		}
		if err := store.WriteOnce(AdmissionFileName, []byte("x")); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("WriteOnce over byte cap error = %v, want ErrCapacityExceeded", err)
		}
	})
}

func TestReadRejectsPathAndInodeChanges(t *testing.T) {
	t.Run("named file replacement", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		oldPath := filepath.Join(t.TempDir(), "old-release")
		_, err := store.read(ReleaseFileName, 64, func(_ *os.File) error {
			if err := os.Rename(filepath.Join(directory, ReleaseFileName), oldPath); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(directory, ReleaseFileName), []byte("replaced"), 0o600)
		})
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(replaced file) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("hard link count change", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		_, err := store.read(ReleaseFileName, 64, func(_ *os.File) error {
			return os.Link(filepath.Join(directory, ReleaseFileName), filepath.Join(t.TempDir(), "alias"))
		})
		if err != nil && errors.Is(err, syscall.EPERM) {
			t.Skipf("hard links unavailable: %v", err)
		}
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(hard-link race) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("size change", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		_, err := store.read(ReleaseFileName, 64, func(_ *os.File) error {
			return os.Truncate(filepath.Join(directory, ReleaseFileName), 0)
		})
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(truncated file) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("same-size change with restored mtime", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		before, err := os.Stat(filepath.Join(directory, ReleaseFileName))
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.read(ReleaseFileName, 64, func(_ *os.File) error {
			path := filepath.Join(directory, ReleaseFileName)
			if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
				return err
			}
			return os.Chtimes(path, before.ModTime(), before.ModTime())
		})
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(restored mtime) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("newly imported bytes change with restored mtime", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.Import(ReleaseFileName, []byte("release")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, ReleaseFileName)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(ReleaseFileName, 64); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(mutated imported file) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("missing content baseline", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.Import(ReleaseFileName, []byte("release")); err != nil {
			t.Fatal(err)
		}
		delete(store.digests, ReleaseFileName)
		if _, err := store.Read(ReleaseFileName, 64); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read(missing baseline) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("caller bound", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, ReleaseFileName, []byte("release"), 0o600)
		store := mustOpenStore(t, directory)
		if _, err := store.Read(ReleaseFileName, 3); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Read(over caller bound) error = %v, want ErrCapacityExceeded", err)
		}
	})
	t.Run("binary delta", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		want := []byte{0, 1, 2, 0xff, 0}
		if err := store.WriteOnce(ExecutorDeltaFileName, want); err != nil {
			t.Fatal(err)
		}
		got, err := store.Read(ExecutorDeltaFileName, int64(len(want)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Read(binary delta) = (%v, %v), want %v", got, err, want)
		}
	})
}

func TestOperationsRejectPostOpenTampering(t *testing.T) {
	t.Run("unexpected entry", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		writeTestFile(t, directory, "unexpected", []byte("x"), 0o600)
		if _, err := store.ListStateCheckpoints(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("List after unexpected entry error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("generated hard link", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(directory, PlanFileName), filepath.Join(t.TempDir(), "alias")); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if _, err := store.Read(PlanFileName, 16); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read after hard link error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("permission widening", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, PlanFileName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(PlanFileName, 16); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Read after chmod error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("lock replacement", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := os.Remove(filepath.Join(directory, LockFileName)); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, directory, LockFileName, nil, 0o600)
		contender, contenderErr := Open(directory)
		if contender != nil {
			_ = contender.Close()
		}
		if !errors.Is(contenderErr, ErrLocked) {
			t.Fatalf("Open() after lock replacement error = %v, want ErrLocked from directory lock", contenderErr)
		}
		if _, err := store.ListStateCheckpoints(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("List after lock replacement error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("directory path replacement", func(t *testing.T) {
		base := t.TempDir()
		directory := filepath.Join(base, "workspace")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		store := mustOpenStore(t, directory)
		moved := filepath.Join(base, "moved")
		if err := os.Rename(directory, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListStateCheckpoints(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("List after directory replacement error = %v, want ErrUnsafeWorkspace", err)
		}
	})
}

func TestOpenRejectsGappedStateInventory(t *testing.T) {
	directory := testWorkspace(t)
	writeTestFile(t, directory, mustStateName(t, 0), []byte("zero"), 0o600)
	writeTestFile(t, directory, mustStateName(t, 2), []byte("two"), 0o600)
	store, err := Open(directory)
	if store != nil {
		_ = store.Close()
	}
	if !errors.Is(err, ErrStateOrder) {
		t.Fatalf("Open(gapped states) error = %v, want ErrStateOrder", err)
	}
}

func TestPathRevalidatesArchive(t *testing.T) {
	directory := testWorkspace(t)
	truncateTestFile(t, directory, ImageArchiveFileName, 1)
	store := mustOpenStore(t, directory)
	if _, err := store.Path(ImageArchiveFileName); err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, ImageArchiveFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Path(ImageArchiveFileName); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("Path() after chmod error = %v, want ErrUnsafeWorkspace", err)
	}
}

func TestConcurrentWriteOnceHasOneWinner(t *testing.T) {
	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)

	const writers = 24
	results := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results <- store.WriteOnce(PlanFileName, []byte(fmt.Sprintf("plan-%02d", index)))
		}(index)
	}
	wait.Wait()
	close(results)

	successes := 0
	exists := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyExists):
			exists++
		default:
			t.Fatalf("concurrent WriteOnce() unexpected error = %v", err)
		}
	}
	if successes != 1 || exists != writers-1 {
		t.Fatalf("concurrent results: success=%d exists=%d, want 1/%d", successes, exists, writers-1)
	}
	raw, err := store.Read(PlanFileName, 64)
	if err != nil || len(raw) != len("plan-00") {
		t.Fatalf("winning plan = (%q, %v)", raw, err)
	}
}
