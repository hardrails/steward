package executoruplink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateStorePersistsFencingPositionWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := LoadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := position{Generation: 2, Sequence: 7, ReportedStatus: "running"}
	if err := store.advance("agent-1", want); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.position("agent-1")
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
	if err := reloaded.advance("agent-1", position{Generation: 1, Sequence: 99, ReportedStatus: "stopped"}); err == nil {
		t.Fatal("state moved to an older generation")
	}
}

func TestStateStoreRejectsOversizedAdvanceAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	store, _ := LoadStateStore(path)
	err := store.advance(strings.Repeat("x", maxStateBytes), position{
		Generation: 1, Sequence: 1, ReportedStatus: "running",
	})
	if err == nil {
		t.Fatal("oversized state advance was accepted")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("oversized state created a file: %v", statErr)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"positions":{}} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(path); err == nil {
		t.Fatal("state file with trailing JSON was accepted")
	}
}
