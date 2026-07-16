package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestReadEnforcesPermissionPolicies(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, Regular); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, TrustFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, OwnerOnly); err == nil {
		t.Fatal("owner-only policy accepted group/world permissions")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 64, TrustFile); err == nil {
		t.Fatal("trust policy accepted group/world write permissions")
	}
	if _, err := Read(path, 0, Regular); err == nil {
		t.Fatal("zero limit accepted")
	}
}

func TestReadRejectsSymlinkFIFOReplacementAndGrowth(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(symlink, 64, Regular); err == nil {
		t.Fatal("symlink accepted")
	}

	fifo := filepath.Join(directory, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(fifo, 64, Regular); err == nil {
		t.Fatal("FIFO accepted")
	}

	if _, err := read(path, 64, Regular, func(*os.File) error {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString("-changed")
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}); err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("growing file err=%v", err)
	}

	if err := os.WriteFile(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacementFIFO := filepath.Join(directory, "replacement-fifo")
	if err := syscall.Mkfifo(replacementFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(path, 64, Regular, func(*os.File) error {
		return os.Rename(replacementFIFO, path)
	}); err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("path replacement err=%v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(path, 64, Regular, func(*os.File) error {
		return os.Remove(path)
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed path err=%v, want wrapped not-exist error", err)
	}
}

func TestReadRootRemainsConfinedAfterRootPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open directory is not portable on Windows")
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "root")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "input"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	moved := filepath.Join(parent, "moved")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "input"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, directory); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadRoot(root, "input", 64, TrustFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "inside" {
		t.Fatalf("root-confined read = %q, want inside", raw)
	}
	if _, err := ReadRoot(root, "../outside/input", 64, TrustFile); err == nil {
		t.Fatal("root-confined read escaped through parent traversal")
	}
}

func TestReadRootRejectsEscapingAndFinalSymlinks(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "root")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "input")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Skipf("create directory symlink fixture: %v", err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(directory, "final")); err != nil {
		t.Skipf("create file symlink fixture: %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ReadRoot(root, "escape/input", 64, TrustFile); err == nil {
		t.Fatal("root-confined read followed an escaping parent symlink")
	}
	if _, err := ReadRoot(root, "final", 64, TrustFile); err == nil {
		t.Fatal("root-confined read followed a final symlink")
	}
}

func TestReadRootPreservesPostReadStatError(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input")
	if err := os.WriteFile(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if _, err := readRoot(root, "input", 64, Regular, func(*os.File) error {
		return os.Remove(path)
	}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed root path err=%v, want wrapped not-exist error", err)
	}
}
