package journal

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryReturnsOnlyPreparedOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := log.Prepare("create-a", "tenant-a/instance-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Commit(first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := log.Prepare("create-b", "tenant-b/instance-b", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	log, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	pending := log.Pending()
	if len(pending) != 1 || pending[0] != second {
		t.Fatalf("pending = %#v, want %#v", pending, second)
	}
	if err := log.Compensate(second.ID); err != nil {
		t.Fatal(err)
	}
	if got := log.Pending(); len(got) != 0 {
		t.Fatalf("pending after compensate = %#v", got)
	}
}

func TestOpenRejectsTruncatedOrInvalidTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Prepare("op", "target", 1); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted truncated journal")
	}
}

func TestTerminalTransitionsCannotBeReplayed(t *testing.T) {
	log, err := Open(filepath.Join(t.TempDir(), "operations.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if _, err := log.Prepare("op", "target", 1); err != nil {
		t.Fatal(err)
	}
	if err := log.Commit("op"); err != nil {
		t.Fatal(err)
	}
	if err := log.Commit("op"); err == nil {
		t.Fatal("second commit unexpectedly succeeded")
	}
}

func TestJournalRejectsMalformedFilesAndUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	for name, raw := range map[string][]byte{
		"short-header": {0, 0, 0},
		"zero-frame":   {0, 0, 0, 0},
		"huge-frame":   frameHeader(MaxRecordBytes + 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil {
				t.Fatal("Open accepted malformed journal")
			}
		})
	}
	path := filepath.Join(dir, "permissions")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted group/world-readable journal")
	}
}

func TestJournalRejectsBadOperationsAndClosedWrites(t *testing.T) {
	log, err := Open(filepath.Join(t.TempDir(), "operations.log"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Prepare("", "target", 1); err == nil {
		t.Fatal("Prepare accepted empty id")
	}
	if _, err := log.Prepare("id", strings.Repeat("x", 513), 1); err == nil {
		t.Fatal("Prepare accepted oversized target")
	}
	if err := log.Commit("unknown"); err == nil {
		t.Fatal("Commit accepted unknown operation")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Prepare("closed", "target", 1); err == nil {
		t.Fatal("Prepare after Close succeeded")
	}
	if err := log.Compensate("closed"); err == nil {
		t.Fatal("Compensate after Close succeeded")
	}
}

func TestOpenForValidationIsStrictlyReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Prepare("pending", "tenant/instance", 1); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	validation, err := OpenForValidation(path)
	if err != nil {
		t.Fatal(err)
	}
	if pending := validation.Pending(); len(pending) != 1 || pending[0].ID != "pending" {
		t.Fatalf("pending = %#v", pending)
	}
	if _, err := validation.Prepare("new", "tenant/other", 2); err == nil || !strings.Contains(err.Error(), "validation only") {
		t.Fatalf("read-only Prepare error = %v", err)
	}
	if err := validation.Close(); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("read-only validation changed journal bytes or metadata")
	}
	missing := filepath.Join(filepath.Dir(path), "missing.log")
	if _, err := OpenForValidation(missing); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing journal error = %v", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("validation created missing journal: %v", err)
	}
}

func frameHeader(size int) []byte {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(size))
	return raw
}
