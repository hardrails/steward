package securefile

import (
	"os"
	"path/filepath"
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
}
