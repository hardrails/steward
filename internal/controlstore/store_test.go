package controlstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitializeOpenExclusiveAndOwnerOnly(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directory, DefaultLimits()); err == nil {
		t.Fatal("a second writer opened the control store")
	}
	if _, err := Initialize(directory, DefaultLimits()); err == nil {
		t.Fatal("Initialize adopted a live control store")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if status, err := store.Status(); err != nil || status.Generation != 1 || status.Sequence != 0 {
		t.Fatalf("status = (%+v, %v)", status, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{currentName, lockName, generationName("snapshot", 1), generationName("wal", 1)} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
			t.Fatalf("artifact %s = (%v, %v)", name, info, err)
		}
	}
	snapshotPath := filepath.Join(directory, generationName("snapshot", 1))
	if err := os.Chmod(snapshotPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directory, DefaultLimits()); err == nil {
		t.Fatal("Open accepted a group-readable snapshot")
	}
}

func TestWALRecoveryRepairsOnlyIncompleteTail(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	created := canonicalTimestamp(time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	tenant := Tenant{ID: "tenant-a", CreatedAt: created, Active: true}
	if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &tenant}); err != nil {
		t.Fatal(err)
	}
	wantSequence := store.sequence
	walPath := filepath.Join(directory, generationName("wal", store.generation))
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	wantSize := info.Size()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if store.sequence != wantSequence || len(store.current.tenants) != 1 {
		t.Fatalf("recovered state sequence=%d tenants=%d", store.sequence, len(store.current.tenants))
	}
	if info, err := os.Stat(walPath); err != nil || info.Size() != wantSize {
		t.Fatalf("repaired WAL = (%v, %v), want size %d", info, err, wantSize)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= walHeaderBytes+4+84 {
		t.Fatalf("WAL frame is unexpectedly short: %d", len(raw))
	}
	raw[walHeaderBytes+4+84] ^= 0xff
	if err := os.WriteFile(walPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directory, DefaultLimits()); err == nil {
		t.Fatal("Open repaired rather than rejected a complete corrupt frame")
	}
}

func TestInspectRootRejectsIncompleteTailWithoutRepair(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	walPath := filepath.Join(directory, generationName("wal", 1))
	file, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := InspectRoot(root, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "incomplete final frame") {
		t.Fatalf("read-only inspection error = %v", err)
	}
	after, err := os.Stat(walPath)
	if err != nil || after.Size() != before.Size() {
		t.Fatalf("read-only inspection changed WAL: before=%v after=%v err=%v", before.Size(), after.Size(), err)
	}
}

func TestInspectRootRejectsInvalidAndTamperedState(t *testing.T) {
	if _, err := InspectRoot(nil, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "root is required") {
		t.Fatalf("nil root error = %v", err)
	}

	openRoot := func(t *testing.T, directory string) *os.Root {
		t.Helper()
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		return root
	}
	initialized := func(t *testing.T) string {
		t.Helper()
		directory := filepath.Join(t.TempDir(), "control")
		store, err := Initialize(directory, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		return directory
	}

	t.Run("valid state", func(t *testing.T) {
		directory := initialized(t)
		status, err := InspectRoot(openRoot(t, directory), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if status.Generation != 1 || status.Sequence != 0 {
			t.Fatalf("status = %+v", status)
		}
	})

	t.Run("invalid limits", func(t *testing.T) {
		directory := initialized(t)
		limits := DefaultLimits()
		limits.MaxWALBytes = 0
		if _, err := InspectRoot(openRoot(t, directory), limits); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("invalid limits error = %v", err)
		}
	})

	t.Run("missing current", func(t *testing.T) {
		directory := t.TempDir()
		if _, err := InspectRoot(openRoot(t, directory), DefaultLimits()); !errors.Is(err, ErrNotInitialized) {
			t.Fatalf("missing CURRENT error = %v", err)
		}
	})

	t.Run("unsafe current mode", func(t *testing.T) {
		directory := initialized(t)
		if err := os.Chmod(filepath.Join(directory, currentName), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectRoot(openRoot(t, directory), DefaultLimits()); err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Fatalf("unsafe CURRENT error = %v", err)
		}
	})

	t.Run("snapshot digest mismatch", func(t *testing.T) {
		directory := initialized(t)
		path := filepath.Join(directory, generationName("snapshot", 1))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 0xff
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectRoot(openRoot(t, directory), DefaultLimits()); err == nil || !strings.Contains(err.Error(), "snapshot does not match") {
			t.Fatalf("snapshot digest error = %v", err)
		}
	})

	t.Run("short WAL", func(t *testing.T) {
		directory := initialized(t)
		path := filepath.Join(directory, generationName("wal", 1))
		if err := os.Truncate(path, walHeaderBytes-1); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectRoot(openRoot(t, directory), DefaultLimits()); err == nil || !strings.Contains(err.Error(), "shorter than its header") {
			t.Fatalf("short WAL error = %v", err)
		}
	})

	t.Run("WAL header digest mismatch", func(t *testing.T) {
		directory := initialized(t)
		path := filepath.Join(directory, generationName("wal", 1))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectRoot(openRoot(t, directory), DefaultLimits()); err == nil || !strings.Contains(err.Error(), "header does not match") {
			t.Fatalf("WAL header digest error = %v", err)
		}
	})
}

func TestInspectRootRejectsArtifactAndFormatSubstitution(t *testing.T) {
	initialized := func(t *testing.T) string {
		t.Helper()
		directory := filepath.Join(t.TempDir(), "control")
		store, err := Initialize(directory, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		return directory
	}
	updateCurrent := func(t *testing.T, directory string, update func(*manifest)) {
		t.Helper()
		path := filepath.Join(directory, currentName)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		current, err := unmarshalManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		update(&current)
		if err := os.WriteFile(path, marshalManifest(current), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, directory string)
	}{
		{
			name: "malformed CURRENT",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(directory, currentName), []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "linked CURRENT",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				path := filepath.Join(directory, currentName)
				if err := os.Link(path, filepath.Join(directory, "CURRENT.link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing snapshot",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Remove(filepath.Join(directory, generationName("snapshot", 1))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe snapshot mode",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(directory, generationName("snapshot", 1)), 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed authenticated snapshot",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				raw := make([]byte, snapshotHeaderBytes)
				if err := os.WriteFile(filepath.Join(directory, generationName("snapshot", 1)), raw, 0o600); err != nil {
					t.Fatal(err)
				}
				updateCurrent(t, directory, func(current *manifest) { current.SnapshotHash = hashBytes(raw) })
			},
		},
		{
			name: "snapshot generation mismatch",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				path := filepath.Join(directory, generationName("snapshot", 1))
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := unmarshalSnapshot(raw, DefaultLimits().MaxStateBytes)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.Generation = 2
				raw, err = marshalSnapshot(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				updateCurrent(t, directory, func(current *manifest) { current.SnapshotHash = hashBytes(raw) })
			},
		},
		{
			name: "missing WAL",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Remove(filepath.Join(directory, generationName("wal", 1))); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unsafe WAL mode",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				if err := os.Chmod(filepath.Join(directory, generationName("wal", 1)), 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed authenticated WAL header",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				path := filepath.Join(directory, generationName("wal", 1))
				raw := make([]byte, walHeaderBytes)
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				updateCurrent(t, directory, func(current *manifest) { current.WALHeaderHash = hashBytes(raw) })
			},
		},
		{
			name: "WAL continuation mismatch",
			mutate: func(t *testing.T, directory string) {
				t.Helper()
				path := filepath.Join(directory, generationName("wal", 1))
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				header, err := unmarshalWALHeader(raw)
				if err != nil {
					t.Fatal(err)
				}
				header.Generation = 2
				raw, err = marshalWALHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				updateCurrent(t, directory, func(current *manifest) { current.WALHeaderHash = hashBytes(raw) })
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := initialized(t)
			test.mutate(t, directory)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := InspectRoot(root, DefaultLimits()); err == nil {
				t.Fatal("substituted Control state was accepted")
			}
		})
	}
}

func TestMutationPublishesOnlyAfterSync(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.syncFile = func(*os.File) error { return errors.New("injected sync failure") }
	tenant := Tenant{ID: "tenant-a", CreatedAt: canonicalTimestamp(time.Now()), Active: true}
	if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &tenant}); err == nil {
		t.Fatal("mutation succeeded despite sync failure")
	}
	if _, published := store.current.tenants[tenant.ID]; published || store.sequence != 0 {
		t.Fatal("unsynced mutation was published to memory")
	}
	if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &tenant}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("poisoned store error = %v", err)
	}
}

func TestQuotaFailureDoesNotMutateState(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTenants = 1
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := canonicalTimestamp(time.Now())
	first := Tenant{ID: "tenant-a", CreatedAt: now, Active: true}
	second := Tenant{ID: "tenant-b", CreatedAt: now, Active: true}
	if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &first}); err != nil {
		t.Fatal(err)
	}
	if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &second}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("second tenant error = %v", err)
	}
	if len(store.current.tenants) != 1 || store.sequence != 1 {
		t.Fatalf("quota failure mutated state: tenants=%d sequence=%d", len(store.current.tenants), store.sequence)
	}
}

func TestWALCompactsBeforeItsHardLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCommandBytes = 128
	limits.MaxReportBytes = 128
	limits.MaxRecordBytes = 512
	limits.MaxWALBytes = 700
	directory := filepath.Join(t.TempDir(), "control")
	store, err := Initialize(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := canonicalTimestamp(time.Now())
	for _, id := range []string{"tenant-a", "tenant-b", "tenant-c", "tenant-d"} {
		tenant := Tenant{ID: id, CreatedAt: now, Active: true}
		if err := store.applyMutations(mutation{Kind: mutationTenant, Tenant: &tenant}); err != nil {
			t.Fatal(err)
		}
	}
	if store.generation <= 1 {
		t.Fatal("WAL did not compact before reaching its cap")
	}
	if info, err := store.wal.Stat(); err != nil || info.Size() > limits.MaxWALBytes {
		t.Fatalf("compacted WAL = (%v, %v)", info, err)
	}
	wantGeneration, wantSequence := store.generation, store.sequence
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(directory, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.generation != wantGeneration || store.sequence != wantSequence || len(store.current.tenants) != 4 {
		t.Fatalf("reopened compacted state generation=%d sequence=%d tenants=%d", store.generation, store.sequence, len(store.current.tenants))
	}
}
