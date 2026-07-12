package executoruplink

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStateStoreRejectsUnsafeOrAmbiguousState(t *testing.T) {
	if _, err := LoadStateStore(""); err == nil {
		t.Fatal("empty state path was accepted")
	}
	dir := t.TempDir()
	cases := map[string]string{
		"malformed json":      `{`,
		"unsupported version": `{"version":99,"positions":[]}`,
		"unknown field":       `{"version":2,"positions":[],"extra":true}`,
		"duplicate record": `{"version":2,"positions":[` +
			`{"tenant_id":"tenant-a","instance_id":"agent","claim_generation":1,"generation":1,"sequence":1,"reported_status":"running"},` +
			`{"tenant_id":"tenant-a","instance_id":"agent","claim_generation":1,"generation":1,"sequence":2,"reported_status":"stopped"}]}`,
		"invalid record": `{"version":2,"positions":[` +
			`{"tenant_id":"","instance_id":"agent","claim_generation":1,"generation":1,"sequence":1,"reported_status":"running"}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if store, err := LoadStateStore(path); err == nil || store != nil {
				t.Fatalf("LoadStateStore = %#v, %v; want fail closed", store, err)
			}
		})
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(empty); err == nil {
		t.Fatal("empty state file was accepted")
	}
	over := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(over, []byte(strings.Repeat("x", maxStateBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(over); err == nil {
		t.Fatal("oversized state file was accepted")
	}
	unsafe := filepath.Join(dir, "unsafe.json")
	if err := os.WriteFile(unsafe, []byte(`{"version":2,"positions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(unsafe); err == nil {
		t.Fatal("group-readable state file was accepted")
	}
	link := filepath.Join(dir, "state-link.json")
	if err := os.Symlink(unsafe, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStateStore(link); err == nil {
		t.Fatal("state symlink was followed")
	}
}

func TestInitializeAndMigrationValidateBeforeChangingState(t *testing.T) {
	if err := InitializeStateStore(""); err == nil {
		t.Fatal("empty initialization path was accepted")
	}
	if err := InitializeStateStore(filepath.Join(t.TempDir(), "missing", "state.json")); err == nil {
		t.Fatal("initialization into a missing directory succeeded")
	}
	if _, err := MigrateStateStoreV1ToV2("ignored", " "); err == nil {
		t.Fatal("empty migration tenant was accepted")
	}

	for name, raw := range map[string]string{
		"unknown envelope field": `{"version":1,"positions":{},"extra":true}`,
		"null positions":         `{"version":1,"positions":null}`,
		"trailing json":          `{"version":1,"positions":{} } {}`,
		"unknown position field": `{"version":1,"positions":{"agent":{"generation":1,"sequence":1,"reported_status":"running","extra":true}}}`,
		"invalid position":       `{"version":1,"positions":{"":{"generation":0,"sequence":1,"reported_status":"running"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if backup, err := MigrateStateStoreV1ToV2(path, "tenant-a"); err == nil || backup != "" {
				t.Fatalf("migration = %q, %v; want rejection before backup", backup, err)
			}
			if _, err := os.Stat(path + ".v1.bak"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected migration created backup: %v", err)
			}
		})
	}
}

func TestAdvanceDoesNotPublishMemoryWhenAtomicReplaceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := newStateStore(t, path)
	want := position{ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running"}
	if err := store.advance("tenant-a", "agent", want); err != nil {
		t.Fatal(err)
	}
	store.path = t.TempDir() // rename onto a directory fails after the temp file is fully synced.
	err := store.advance("tenant-a", "agent", position{
		ClaimGeneration: 1, Generation: 1, Sequence: 2, ReportedStatus: "stopped",
	})
	if err == nil {
		t.Fatal("advance succeeded despite an unusable destination")
	}
	if got, ok := store.position("tenant-a", "agent"); !ok || got != want {
		t.Fatalf("failed durable advance changed memory: %#v, %v", got, ok)
	}
	if err := store.advance("tenant-a", "agent", position{
		ClaimGeneration: 0, Generation: 1, Sequence: 2, ReportedStatus: "stopped",
	}); err == nil {
		t.Fatal("invalid fencing coordinates were accepted")
	}
}

func TestStateEncodingIsDeterministicAndEnforcesFileLimit(t *testing.T) {
	a := map[stateKey]position{
		{TenantID: "tenant-b", InstanceID: "agent-z"}: {ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running"},
		{TenantID: "tenant-a", InstanceID: "agent-b"}: {ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running"},
		{TenantID: "tenant-a", InstanceID: "agent-a"}: {ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running"},
	}
	b := map[stateKey]position{
		{TenantID: "tenant-a", InstanceID: "agent-a"}: a[stateKey{TenantID: "tenant-a", InstanceID: "agent-a"}],
		{TenantID: "tenant-b", InstanceID: "agent-z"}: a[stateKey{TenantID: "tenant-b", InstanceID: "agent-z"}],
		{TenantID: "tenant-a", InstanceID: "agent-b"}: a[stateKey{TenantID: "tenant-a", InstanceID: "agent-b"}],
	}
	first, err := encodeState(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeState(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("state encoding depends on map iteration:\n%s\n%s", first, second)
	}

	tooLarge := make(map[stateKey]position, 5000)
	for i := 0; i < 5000; i++ {
		tenant := strings.Repeat("t", 115) + fmt.Sprintf("%05d", i)
		instance := strings.Repeat("i", 240) + fmt.Sprintf("%05d", i)
		tooLarge[stateKey{TenantID: tenant, InstanceID: instance}] = position{
			ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running",
		}
	}
	if _, err := encodeState(tooLarge); err == nil {
		t.Fatal("state larger than the durable file limit was encoded")
	}
}

func TestStateFilesystemHelpersReturnActionableErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if err := replaceStateFile(filepath.Join(missing, "state.json"), []byte("state")); err == nil {
		t.Fatal("replaceStateFile succeeded in missing directory")
	}
	if err := syncDirectory(missing); err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("syncDirectory error = %v", err)
	}
}
