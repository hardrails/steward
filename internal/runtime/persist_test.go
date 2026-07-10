package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// stateBoundTracker returns a tracker persisting to a fresh path under t.TempDir.
func stateBoundTracker(t *testing.T, maxInstances int) (*Tracker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	tr, err := LoadTracker(maxInstances, path)
	if err != nil {
		t.Fatalf("LoadTracker: unexpected err %v", err)
	}
	return tr, path
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)

	// Provision a spread of instances: with a spec, without a spec, and one that
	// is then transitioned to a non-PENDING status.
	a, _, err := tr.Provision("agent-a", 0, json.RawMessage(`{"model":"opus","memory_mb":512}`))
	if err != nil {
		t.Fatalf("provision a: %v", err)
	}
	b, _, err := tr.Provision("agent-b", 0, nil)
	if err != nil {
		t.Fatalf("provision b: %v", err)
	}
	c, _, err := tr.Provision("agent-c", 0, json.RawMessage(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("provision c: %v", err)
	}
	if _, err := tr.Start(b.RuntimeRef); err != nil {
		t.Fatalf("start b: %v", err)
	}
	if _, err := tr.Hibernate(c.RuntimeRef); err != nil {
		t.Fatalf("hibernate c: %v", err)
	}

	// "Restart": a brand-new tracker pointed at the same file must recover the
	// exact same state, including both indexes and every spec byte-for-byte.
	reloaded, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Len() != 3 {
		t.Fatalf("reloaded holds %d instances, want 3", reloaded.Len())
	}

	want := map[string]struct {
		id     string
		status Status
		spec   string
	}{
		a.RuntimeRef: {"agent-a", StatusPending, `{"model":"opus","memory_mb":512}`},
		b.RuntimeRef: {"agent-b", StatusRunning, ``},
		c.RuntimeRef: {"agent-c", StatusHibernated, `{"k":"v"}`},
	}
	for ref, w := range want {
		got, err := reloaded.Status(ref)
		if err != nil {
			t.Fatalf("reloaded status %s: %v", ref, err)
		}
		if got.InstanceID != w.id {
			t.Errorf("ref %s: instance_id=%q want %q", ref, got.InstanceID, w.id)
		}
		if got.Status != w.status {
			t.Errorf("ref %s: status=%q want %q", ref, got.Status, w.status)
		}
		if string(got.Spec) != w.spec {
			t.Errorf("ref %s: spec=%q want %q", ref, got.Spec, w.spec)
		}
	}

	// The rebuilt byID index must make provisioning idempotent across the restart.
	again, created, err := reloaded.Provision("agent-a", 0, json.RawMessage(`{"ignored":true}`))
	if err != nil {
		t.Fatalf("reprovision after reload: %v", err)
	}
	if created {
		t.Error("reprovision after reload reported created=true; byID index was not restored")
	}
	if again.RuntimeRef != a.RuntimeRef {
		t.Errorf("reprovision ref=%q want %q", again.RuntimeRef, a.RuntimeRef)
	}
}

func TestPersistPreservesCompactSpecNormalizesWhitespace(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)

	// A compact spec (the control-plane's normal case) must survive a restart
	// byte-for-byte, including characters (<, &) an HTML-escaping encoder would
	// otherwise rewrite.
	const compact = `{"url":"https://x/?a=1&b=2","expr":"a<b"}`
	exact, _, _ := tr.Provision("compact", 0, json.RawMessage(compact))
	// A spec carrying insignificant whitespace is preserved semantically; the
	// persisted form is normalized (compacted).
	spaced, _, _ := tr.Provision("spaced", 0, json.RawMessage(`{ "k" : "v" }`))

	reloaded, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	gotExact, err := reloaded.Status(exact.RuntimeRef)
	if err != nil {
		t.Fatalf("status compact: %v", err)
	}
	if string(gotExact.Spec) != compact {
		t.Errorf("compact spec after restart = %s, want byte-for-byte %s", gotExact.Spec, compact)
	}

	gotSpaced, err := reloaded.Status(spaced.RuntimeRef)
	if err != nil {
		t.Fatalf("status spaced: %v", err)
	}
	if string(gotSpaced.Spec) != `{"k":"v"}` {
		t.Errorf("spaced spec after restart = %s, want normalized {\"k\":\"v\"}", gotSpaced.Spec)
	}
}

func TestDestroyDoesNotSurviveRestart(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)

	keep, _, _ := tr.Provision("keep", 0, nil)
	gone, _, _ := tr.Provision("gone", 0, nil)
	if _, err := tr.Destroy(gone.RuntimeRef); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	reloaded, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Len() != 1 {
		t.Fatalf("reloaded holds %d instances, want 1", reloaded.Len())
	}
	if _, err := reloaded.Status(keep.RuntimeRef); err != nil {
		t.Errorf("kept instance missing after reload: %v", err)
	}
	if _, err := reloaded.Status(gone.RuntimeRef); err == nil {
		t.Error("destroyed instance resurrected after reload")
	}
}

func TestLoadMissingFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	tr, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("LoadTracker on missing file: unexpected err %v", err)
	}
	if tr.Len() != 0 {
		t.Fatalf("fresh tracker holds %d instances, want 0", tr.Len())
	}
	// A missing file is a first run: provisioning creates it.
	if _, _, err := tr.Provision("agent-1", 0, nil); err != nil {
		t.Fatalf("provision after empty start: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created on first mutation: %v", err)
	}
}

func TestEmptyStateFileDisablesPersistence(t *testing.T) {
	tr, err := LoadTracker(0, "")
	if err != nil {
		t.Fatalf("LoadTracker(\"\"): %v", err)
	}
	if _, _, err := tr.Provision("agent-1", 0, nil); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if tr.stateFile != "" {
		t.Fatalf("stateFile = %q, want empty (persistence disabled)", tr.stateFile)
	}
}

func TestLoadCorruptFileFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"not json", `this is not json`},
		{"truncated json", `{"version":1,"instances":[`},
		{"wrong version", `{"version":999,"instances":[]}`},
		{"missing instance_id", `{"version":1,"instances":[{"runtime_ref":"rt_1","status":"PENDING"}]}`},
		{"missing runtime_ref", `{"version":1,"instances":[{"instance_id":"a","status":"PENDING"}]}`},
		{"unknown status", `{"version":1,"instances":[{"instance_id":"a","runtime_ref":"rt_1","status":"BOGUS"}]}`},
		{"non-object spec", `{"version":1,"instances":[{"instance_id":"a","runtime_ref":"rt_1","status":"PENDING","spec":[1,2,3]}]}`},
		{"negative generation", `{"version":1,"instances":[{"instance_id":"a","runtime_ref":"rt_1","status":"PENDING","generation":-1}]}`},
		{"duplicate runtime_ref", `{"version":1,"instances":[{"instance_id":"a","runtime_ref":"rt_1","status":"PENDING"},{"instance_id":"b","runtime_ref":"rt_1","status":"PENDING"}]}`},
		{"duplicate instance_id", `{"version":1,"instances":[{"instance_id":"a","runtime_ref":"rt_1","status":"PENDING"},{"instance_id":"a","runtime_ref":"rt_2","status":"PENDING"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			tr, err := LoadTracker(0, path)
			if err == nil {
				t.Fatalf("LoadTracker on %s: got nil err, want fail-closed", c.name)
			}
			if tr != nil {
				t.Errorf("LoadTracker on %s: got non-nil tracker, want nil on error", c.name)
			}
			// The 3am test: the error must name the offending path.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the state file path %q", err, path)
			}
		})
	}
}

func TestSaveLeavesNoTempFile(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)
	dir := filepath.Dir(path)

	// Several mutations, each triggering an atomic save.
	inst, _, _ := tr.Provision("agent-1", 0, json.RawMessage(`{"a":1}`))
	if _, err := tr.Start(inst.RuntimeRef); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := tr.Stop(inst.RuntimeRef); err != nil {
		t.Fatalf("stop: %v", err)
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, ".steward-state-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind after save: %v", leftovers)
	}

	// The final file is present and parses as a versioned snapshot.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("state file does not parse: %v", err)
	}
	if snap.Version != stateVersion {
		t.Fatalf("snapshot version = %d, want %d", snap.Version, stateVersion)
	}
}

// TestFailedSaveIsAtomicAndRollsBack proves the two safety properties of a failed
// persist: the previous state file is left byte-for-byte intact (temp-then-rename
// never truncates the live file), and the in-memory mutation is rolled back so
// memory never diverges from the last durable state. Failure is forced by making
// the state file's directory unwritable, which blocks the temp-file create.
func TestFailedSaveIsAtomicAndRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions; cannot force a write failure")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "state.json")

	tr, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	kept, _, err := tr.Provision("kept", 0, json.RawMessage(`{"keep":true}`))
	if err != nil {
		t.Fatalf("provision kept: %v", err)
	}
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original state: %v", err)
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	// Restore write perms so t.TempDir cleanup can remove the directory.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, _, err := tr.Provision("doomed", 0, nil); err == nil {
		t.Fatal("provision into unwritable dir: got nil err, want persist failure")
	}
	// In-memory rollback: the doomed instance must not be tracked.
	if tr.Len() != 1 {
		t.Fatalf("tracker holds %d instances after failed persist, want 1 (rollback)", tr.Len())
	}
	if _, err := tr.Status(kept.RuntimeRef); err != nil {
		t.Errorf("kept instance lost after failed persist: %v", err)
	}

	// On-disk atomicity: the previous file is untouched.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod rw: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state after failed persist: %v", err)
	}
	if string(after) != string(orig) {
		t.Fatalf("state file changed by a failed persist:\n before=%s\n after =%s", orig, after)
	}
}

func TestConcurrentProvisionWithPersistence(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)
	const goroutines = 64

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			id := "agent-" + strconv.Itoa(idx)
			if _, _, err := tr.Provision(id, 0, json.RawMessage(`{"i":`+strconv.Itoa(idx)+`}`)); err != nil {
				t.Errorf("provision %s: %v", id, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if tr.Len() != goroutines {
		t.Fatalf("tracker holds %d instances, want %d", tr.Len(), goroutines)
	}
	// Every persisted mutation is consistent: a reload recovers all of them.
	reloaded, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("reload after concurrent persistence: %v", err)
	}
	if reloaded.Len() != goroutines {
		t.Fatalf("reloaded holds %d instances, want %d", reloaded.Len(), goroutines)
	}
}

// TestGenerationRoundTripsThroughPersistence pins task 1's acceptance check: a
// tracker provisioned with a non-zero generation, saved and reloaded via a
// -state-file, must recover the exact same generation.
func TestGenerationRoundTripsThroughPersistence(t *testing.T) {
	tr, path := stateBoundTracker(t, 0)

	inst, _, err := tr.Provision("agent-1", 5, json.RawMessage(`{"model":"opus"}`))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if inst.Generation != 5 {
		t.Fatalf("provisioned generation = %d, want 5", inst.Generation)
	}

	reloaded, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err := reloaded.Status(inst.RuntimeRef)
	if err != nil {
		t.Fatalf("reloaded status: %v", err)
	}
	if got.Generation != 5 {
		t.Fatalf("reloaded generation = %d, want 5 (round-tripped)", got.Generation)
	}
}

// TestOldFormatFileWithNoGenerationKeyLoadsAsZero pins the additive-field,
// no-format-version-bump promise: a hand-written state file predating the
// generation field (no "generation" key at all) must load successfully with
// every instance's generation defaulting to 0 ("no fencing"), not an error.
func TestOldFormatFileWithNoGenerationKeyLoadsAsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const oldFormat = `{"version":1,"instances":[{"instance_id":"agent-1","runtime_ref":"rt_old","status":"PENDING"}]}`
	if err := os.WriteFile(path, []byte(oldFormat), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	tr, err := LoadTracker(0, path)
	if err != nil {
		t.Fatalf("LoadTracker on a pre-generation state file: unexpected err %v", err)
	}
	got, err := tr.Status("rt_old")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got.Generation != 0 {
		t.Fatalf("generation = %d, want 0 (default for a file with no generation key)", got.Generation)
	}
}
