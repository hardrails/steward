package executoruplink

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateStorePersistsFencingPositionWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := newStateStore(t, path)
	want := position{ClaimGeneration: 1, Generation: 2, Sequence: 7, ReportedStatus: "running"}
	if err := store.advance("tenant-a", "agent-1", want); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.position("tenant-a", "agent-1")
	if !ok || got != want {
		t.Fatalf("position = %#v, %v", got, ok)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o", info.Mode().Perm())
	}
	if err := reloaded.advance("tenant-a", "agent-1", position{ClaimGeneration: 1, Generation: 1, Sequence: 99, ReportedStatus: "stopped"}); err == nil {
		t.Fatal("state moved to an older generation")
	}
}

func TestStateStoreRejectsOversizedAdvanceAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store := newStateStore(t, path)
	err := store.advance("tenant-a", strings.Repeat("x", maxStateBytes), position{
		ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running",
	})
	if err == nil {
		t.Fatal("oversized state advance was accepted")
	}
	if reloaded, loadErr := LoadStateStore(path); loadErr != nil {
		t.Fatalf("oversized advance corrupted prior state: %v", loadErr)
	} else if _, ok := reloaded.position("tenant-a", strings.Repeat("x", maxStateBytes)); ok {
		t.Fatal("oversized position entered durable state")
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"positions":[]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(path); err == nil {
		t.Fatal("state file with trailing JSON was accepted")
	}
}

func TestStateStoreSeparatesTenantsWithSameInstanceID(t *testing.T) {
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	a := position{ClaimGeneration: 1, Generation: 1, Sequence: 9, ReportedStatus: "running"}
	b := position{ClaimGeneration: 3, Generation: 4, Sequence: 2, ReportedStatus: "stopped"}
	if err := store.advance("tenant-a", "shared", a); err != nil {
		t.Fatal(err)
	}
	if err := store.advance("tenant-b", "shared", b); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.position("tenant-a", "shared"); got != a {
		t.Fatalf("tenant-a position = %#v", got)
	}
	if got, _ := store.position("tenant-b", "shared"); got != b {
		t.Fatalf("tenant-b position = %#v", got)
	}
}

func TestLegacyStateRequiresExplicitSafeMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := `{"version":1,"positions":{"agent-1":{"generation":2,"sequence":7,"reported_status":"running"}}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(path); !errors.Is(err, ErrStateMigrationRequired) {
		t.Fatalf("load error = %v, want migration-required", err)
	}
	backup, err := MigrateStateStoreV1ToV2(path, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	backupRaw, err := os.ReadFile(backup)
	if err != nil || string(backupRaw) != legacy {
		t.Fatalf("backup=%q err=%v raw=%q", backup, err, backupRaw)
	}
	store, err := LoadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := position{Generation: 2, Sequence: 7, ReportedStatus: "running", LegacyClaimFence: true}
	if got, ok := store.position("tenant-a", "agent-1"); !ok || got != want {
		t.Fatalf("migrated position = %#v, %v", got, ok)
	}
	if !commandIsStale(command{ClaimGeneration: 99, InstanceGeneration: 2, CommandSequence: 7}, want) {
		t.Fatal("migration guessed a claim generation and weakened the legacy sequence fence")
	}
	upgraded := position{ClaimGeneration: 99, Generation: 2, Sequence: 8, ReportedStatus: "running"}
	if err := store.advance("tenant-a", "agent-1", upgraded); err != nil {
		t.Fatalf("advance out of legacy claim fence: %v", err)
	}
	if got, _ := store.position("tenant-a", "agent-1"); got != upgraded {
		t.Fatalf("upgraded position = %#v", got)
	}
	if _, err := MigrateStateStoreV1ToV2(path, "tenant-a"); err == nil {
		t.Fatal("version-2 state was accepted for downgrade migration")
	}
}

func TestMigrationNeverOverwritesExistingBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := `{"version":1,"positions":{}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".v1.bak", []byte("operator backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateStateStoreV1ToV2(path, "tenant-a"); err == nil {
		t.Fatal("migration overwrote an existing backup")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != legacy {
		t.Fatalf("failed migration changed source: %q", raw)
	}
}

func TestMigrationRejectsDuplicateLegacyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	duplicate := `{"version":1,"positions":{"agent":{"generation":1,"sequence":1,"reported_status":"running"},"agent":{"generation":2,"sequence":2,"reported_status":"stopped"}}}`
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateStateStoreV1ToV2(path, "tenant-a"); err == nil {
		t.Fatal("legacy state with a duplicate instance key was migrated")
	}
	if _, err := os.Stat(path + ".v1.bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid migration created a backup: %v", err)
	}
}

func TestMissingStateFailsClosedAndInitializationIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, err := LoadStateStore(path); err == nil {
		t.Fatal("missing state silently reset the fence")
	}
	if err := InitializeStateStore(path); err != nil {
		t.Fatal(err)
	}
	if err := InitializeStateStore(path); err == nil {
		t.Fatal("state initialization overwrote an existing fence")
	}
	if _, err := LoadStateStore(path); err != nil {
		t.Fatal(err)
	}
}

func TestStateStoreRejectsNullPositionsInsteadOfResettingFence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"version":2,"positions":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(path); err == nil {
		t.Fatal("null positions silently reset the replay fence")
	}
}

func newStateStore(t *testing.T, path string) *StateStore {
	t.Helper()
	if err := InitializeStateStore(path); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
