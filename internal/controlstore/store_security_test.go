package controlstore

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreFilesystemBoundaryRejectsAliasesPermissionsAndLinks(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"relative", string(filepath.Separator), filepath.Join(root, "a", "..", "b"), root + "\x00bad"} {
		if _, err := prepareDirectory(path, false); err == nil {
			t.Fatalf("unsafe store directory %q was accepted", path)
		}
	}
	if _, err := prepareDirectory(filepath.Join(root, "missing"), false); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("missing store directory error = %v", err)
	}

	wrongMode := filepath.Join(root, "wrong-mode")
	if err := os.Mkdir(wrongMode, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDirectory(wrongMode, false); err == nil {
		t.Fatal("group-readable store directory was accepted")
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "alias")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDirectory(symlink, false); err == nil {
		t.Fatal("symlinked store directory was accepted")
	}
	created := filepath.Join(root, "created")
	if got, err := prepareDirectory(created, true); err != nil || got != created {
		t.Fatalf("create secure store directory = (%q, %v)", got, err)
	}

	empty, err := containsStateArtifacts(created)
	if err != nil || empty {
		t.Fatalf("empty store artifact scan = (%v, %v)", empty, err)
	}
	if err := os.WriteFile(filepath.Join(created, "unrelated"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err = containsStateArtifacts(created)
	if err != nil || empty {
		t.Fatalf("unrelated file was treated as state = (%v, %v)", empty, err)
	}
	if err := os.WriteFile(filepath.Join(created, "snapshot.hostile"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := containsStateArtifacts(created)
	if err != nil || !present {
		t.Fatalf("snapshot artifact scan = (%v, %v)", present, err)
	}
}

func TestArtifactReadersRejectUnboundedMutableAndAliasedInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "artifact")
	if err := os.WriteFile(path, []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(path, 0); err == nil {
		t.Fatal("non-positive artifact limit was accepted")
	}
	if _, err := readArtifact(filepath.Join(directory, "missing"), 64); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing artifact error = %v", err)
	}
	if _, err := readArtifact(path, 3); err == nil {
		t.Fatal("oversized artifact was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(path, 64); err == nil {
		t.Fatal("group-readable artifact was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(path, 64); err == nil {
		t.Fatal("multiply-linked artifact was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(symlink, 64); err == nil {
		t.Fatal("symlinked artifact was accepted")
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openWALArtifact(path, 64); err == nil {
		t.Fatal("group-readable WAL was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openWALArtifact(path, 3); err == nil {
		t.Fatal("oversized WAL was accepted")
	}
	if _, _, err := openWALArtifact(symlink, 64); err == nil {
		t.Fatal("symlinked WAL was accepted")
	}
	if _, _, err := openWALArtifact(filepath.Join(directory, "missing"), 64); err == nil {
		t.Fatal("missing WAL was accepted")
	}
}

func TestStorePublicLifecycleIsIdempotentAndUnavailableAfterClose(t *testing.T) {
	var absent *Store
	if err := absent.Close(); err != nil {
		t.Fatalf("nil store close = %v", err)
	}
	if _, err := absent.Status(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store status = %v", err)
	}
	if err := absent.applyMutations(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store mutation = %v", err)
	}
	releaseLock(nil)

	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
	if _, err := store.Status(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store status = %v", err)
	}
	if err := store.applyMutations(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store mutation = %v", err)
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(empty, DefaultLimits()); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("open empty directory error = %v", err)
	}
	limits := DefaultLimits()
	limits.MaxTenants = 0
	if _, err := Initialize(filepath.Join(t.TempDir(), "invalid-limits"), limits); err == nil {
		t.Fatal("internally invalid limits were accepted")
	}
}

func TestArtifactMetadataValidation(t *testing.T) {
	if err := validateArtifactInfo(nil, 1); err == nil {
		t.Fatal("nil artifact metadata was accepted")
	}
	directory := t.TempDir()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateArtifactInfo(info, -1); err == nil {
		t.Fatal("directory was accepted as an artifact")
	}
	path := filepath.Join(directory, "artifact")
	if err := os.WriteFile(path, []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateArtifactInfo(info, 3); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("artifact metadata size error = %v", err)
	}
	if err := validateArtifactInfo(info, 4); err != nil {
		t.Fatalf("valid artifact metadata = %v", err)
	}
	if runtime.GOOS != "windows" {
		hardlink := filepath.Join(directory, "hardlink")
		if err := os.Link(path, hardlink); err != nil {
			t.Fatal(err)
		}
		info, err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateArtifactInfo(info, 4); err == nil {
			t.Fatal("multiply-linked artifact metadata was accepted")
		}
	}
}

func TestOpenRejectsManifestSnapshotAndWALSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"manifest checksum", func(t *testing.T, directory string) {
			path := filepath.Join(directory, currentName)
			raw := mustReadFile(t, path)
			raw[len(raw)-1] ^= 0xff
			mustWriteFile(t, path, raw)
		}},
		{"missing snapshot", func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, generationName("snapshot", 1))); err != nil {
				t.Fatal(err)
			}
		}},
		{"snapshot replacement", func(t *testing.T, directory string) {
			path := filepath.Join(directory, generationName("snapshot", 1))
			raw := mustReadFile(t, path)
			raw[len(raw)-1] ^= 0xff
			mustWriteFile(t, path, raw)
		}},
		{"snapshot generation", func(t *testing.T, directory string) {
			manifestPath := filepath.Join(directory, currentName)
			selected, err := unmarshalManifest(mustReadFile(t, manifestPath))
			if err != nil {
				t.Fatal(err)
			}
			snapshotPath := filepath.Join(directory, generationName("snapshot", 1))
			envelope, err := unmarshalSnapshot(mustReadFile(t, snapshotPath), DefaultLimits().MaxStateBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Generation++
			raw, err := marshalSnapshot(envelope)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, snapshotPath, raw)
			selected.SnapshotHash = hashBytes(raw)
			mustWriteFile(t, manifestPath, marshalManifest(selected))
		}},
		{"snapshot payload", func(t *testing.T, directory string) {
			manifestPath := filepath.Join(directory, currentName)
			selected, err := unmarshalManifest(mustReadFile(t, manifestPath))
			if err != nil {
				t.Fatal(err)
			}
			snapshotPath := filepath.Join(directory, generationName("snapshot", 1))
			envelope, err := unmarshalSnapshot(mustReadFile(t, snapshotPath), DefaultLimits().MaxStateBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Payload = []byte("not-json")
			raw, err := marshalSnapshot(envelope)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, snapshotPath, raw)
			selected.SnapshotHash = hashBytes(raw)
			mustWriteFile(t, manifestPath, marshalManifest(selected))
		}},
		{"short WAL", func(t *testing.T, directory string) {
			mustWriteFile(t, filepath.Join(directory, generationName("wal", 1)), []byte{1})
		}},
		{"WAL checksum", func(t *testing.T, directory string) {
			manifestPath := filepath.Join(directory, currentName)
			selected, err := unmarshalManifest(mustReadFile(t, manifestPath))
			if err != nil {
				t.Fatal(err)
			}
			walPath := filepath.Join(directory, generationName("wal", 1))
			raw := mustReadFile(t, walPath)
			raw[len(raw)-1] ^= 0xff
			mustWriteFile(t, walPath, raw)
			selected.WALHeaderHash = hashBytes(raw)
			mustWriteFile(t, manifestPath, marshalManifest(selected))
		}},
		{"WAL continuity", func(t *testing.T, directory string) {
			manifestPath := filepath.Join(directory, currentName)
			selected, err := unmarshalManifest(mustReadFile(t, manifestPath))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := marshalWALHeader(walHeader{Generation: 1, Sequence: 1})
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, filepath.Join(directory, generationName("wal", 1)), raw)
			selected.WALHeaderHash = hashBytes(raw)
			mustWriteFile(t, manifestPath, marshalManifest(selected))
		}},
		{"missing WAL", func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, generationName("wal", 1))); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "control")
			store, err := Initialize(directory, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, directory)
			if reopened, err := Open(directory, DefaultLimits()); err == nil {
				reopened.Close()
				t.Fatal("substituted durable artifact was accepted")
			}
		})
	}
}

func TestWALRecoveryRejectsInvalidLengthChainTransactionAndState(t *testing.T) {
	limits := DefaultLimits()
	tenant := Tenant{ID: "tenant-a", CreatedAt: "2026-07-14T00:00:00Z", Active: true}
	validTransaction, err := encodeTransaction(mutation{Kind: mutationTenant, Tenant: &tenant})
	if err != nil {
		t.Fatal(err)
	}
	unknownTransaction, err := encodeTransaction(mutation{Kind: "unknown", Tenant: &tenant})
	if err != nil {
		t.Fatal(err)
	}
	invalidTenant := tenant
	invalidTenant.ID = "bad id"
	invalidStateTransaction, err := encodeTransaction(mutation{Kind: mutationTenant, Tenant: &invalidTenant})
	if err != nil {
		t.Fatal(err)
	}
	var previous [sha256.Size]byte
	tests := []struct {
		name string
		raw  func(*testing.T) []byte
	}{
		{"invalid length", func(t *testing.T) []byte {
			header, err := marshalWALHeader(walHeader{Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			length := make([]byte, 4)
			binary.BigEndian.PutUint32(length, 1)
			return append(header, length...)
		}},
		{"sequence discontinuity", func(t *testing.T) []byte { return recoveryWALBytes(t, 2, previous, validTransaction, limits) }},
		{"transaction decoding", func(t *testing.T) []byte { return recoveryWALBytes(t, 1, previous, []byte("not-json"), limits) }},
		{"mutation application", func(t *testing.T) []byte { return recoveryWALBytes(t, 1, previous, unknownTransaction, limits) }},
		{"state validation", func(t *testing.T) []byte { return recoveryWALBytes(t, 1, previous, invalidStateTransaction, limits) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal")
			mustWriteFile(t, path, test.raw(t))
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := recoverWAL(file, info.Size(), emptyState(), 0, previous, limits); err == nil {
				t.Fatal("invalid WAL recovery input was accepted")
			}
		})
	}
}

func recoveryWALBytes(t *testing.T, sequence uint64, previous [sha256.Size]byte, payload []byte, limits Limits) []byte {
	t.Helper()
	header, err := marshalWALHeader(walHeader{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := marshalWALRecord(sequence, previous, payload, limits.MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	return append(header, frame...)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustWriteFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
