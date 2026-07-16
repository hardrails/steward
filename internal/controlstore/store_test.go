package controlstore

import (
	"errors"
	"os"
	"path/filepath"
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
