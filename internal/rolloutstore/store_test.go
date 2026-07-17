package rolloutstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func testWorkspace(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "rollout")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeTestFile(t *testing.T, directory, name string, raw []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func truncateTestFile(t *testing.T, directory, name string, size int64) {
	t.Helper()
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustTargetArtifactName(t *testing.T, target uint16, kind string) string {
	t.Helper()
	name, err := TargetArtifactName(target, kind)
	if err != nil {
		t.Fatalf("TargetArtifactName(%d, %q) error = %v", target, kind, err)
	}
	return name
}

func mustTargetStateName(t *testing.T, target uint16, sequence uint64) string {
	t.Helper()
	name, err := TargetStateName(target, sequence)
	if err != nil {
		t.Fatalf("TargetStateName(%d, %d) error = %v", target, sequence, err)
	}
	return name
}

func mustOpenStore(t *testing.T, directory string) *Store {
	t.Helper()
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store
}

func TestCanonicalInventoryNames(t *testing.T) {
	if PlanFileName != "plan.json" ||
		ReleaseFileName != "release.dsse.json" ||
		PolicyFileName != "policy.dsse.json" ||
		ControllerWitnessPublicKeyFileName != "controller-witness.public" ||
		ProofFileName != "proof.json" {
		t.Fatalf(
			"fixed names = (%q, %q, %q, %q, %q)",
			PlanFileName,
			ReleaseFileName,
			PolicyFileName,
			ControllerWitnessPublicKeyFileName,
			ProofFileName,
		)
	}
	wantKinds := []string{
		"intent.json",
		"service-trust.json",
		"activation-plan.json",
		"executor-begin.json",
		"admit-command.dsse.json",
		"admission.json",
		"start-command.dsse.json",
		"canary-command.dsse.json",
		"canary-result.json",
		"capture-export.json",
		"activation-state.json",
		"activation-proof.json",
		"gateway-receipt.public",
	}
	if got := targetArtifactKinds[:]; !reflect.DeepEqual(got, wantKinds) {
		t.Fatalf("target artifact kinds = %#v, want %#v", got, wantKinds)
	}
	for _, kind := range wantKinds {
		name := mustTargetArtifactName(t, 0, kind)
		if name != "target-000-"+kind || classifyName(name) != artifactTarget {
			t.Fatalf("target zero name = %q, kind=%v", name, classifyName(name))
		}
		name = mustTargetArtifactName(t, MaxTargetIndex, kind)
		if name != "target-063-"+kind || classifyName(name) != artifactTarget {
			t.Fatalf("last target name = %q, kind=%v", name, classifyName(name))
		}
	}
	for _, test := range []struct {
		target   uint16
		sequence uint64
		want     string
	}{
		{0, 0, "target-000-state-000000000000.json"},
		{1, 42, "target-001-state-000000000042.json"},
		{63, MaxTargetStateSequence, "target-063-state-999999999999.json"},
	} {
		name := mustTargetStateName(t, test.target, test.sequence)
		if name != test.want || classifyName(name) != artifactTargetState {
			t.Fatalf("TargetStateName(%d, %d) = %q, want %q", test.target, test.sequence, name, test.want)
		}
		gotTarget, gotSequence, ok := parseTargetStateName(name)
		if !ok || gotTarget != test.target || gotSequence != test.sequence {
			t.Fatalf("parseTargetStateName(%q) = (%d, %d, %v)", name, gotTarget, gotSequence, ok)
		}
	}
	if _, err := TargetArtifactName(MaxTargets, TargetIntentKind); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("TargetArtifactName(oversize) error = %v", err)
	}
	if _, err := TargetArtifactName(0, "unknown.json"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("TargetArtifactName(unknown) error = %v", err)
	}
	if _, err := TargetStateName(MaxTargets, 0); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("TargetStateName(oversize target) error = %v", err)
	}
	if _, err := TargetStateName(0, MaxTargetStateSequence+1); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("TargetStateName(oversize sequence) error = %v", err)
	}
	for _, name := range []string{
		"target-00-intent.json",
		"target-064-intent.json",
		"target-000-unknown.json",
		"target-000-state-1.json",
		"target-000-state-0000000000000.json",
		"target-000-state-00000000000x.json",
		"target/000-intent.json",
		"../target-000-intent.json",
	} {
		if classifyName(name) != artifactInvalid {
			t.Fatalf("invalid name %q was classified as %v", name, classifyName(name))
		}
	}
}

func TestCreateWriteReadAppendReopen(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "rollout")
	oldMask := syscall.Umask(0o777)
	store, err := Create(directory)
	syscall.Umask(oldMask)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory mode = %v, want 0700 directory", info.Mode())
	}
	if contender, err := Create(directory); contender != nil || !errors.Is(err, ErrAlreadyExists) {
		if contender != nil {
			_ = contender.Close()
		}
		t.Fatalf("second Create() = (%v, %v), want ErrAlreadyExists", contender, err)
	}

	plan := []byte(`{"schema":"plan"}`)
	intentName := mustTargetArtifactName(t, 0, TargetIntentKind)
	receiptName := mustTargetArtifactName(t, 63, TargetGatewayReceiptPublicKeyKind)
	if err := store.WriteOnce(PlanFileName, plan); err != nil {
		t.Fatalf("WriteOnce(plan) error = %v", err)
	}
	if err := store.Import(intentName, []byte("intent")); err != nil {
		t.Fatalf("Import(intent) error = %v", err)
	}
	if err := store.WriteOnce(receiptName, []byte("public-key")); err != nil {
		t.Fatalf("WriteOnce(receipt) error = %v", err)
	}
	for name, want := range map[string][]byte{
		PlanFileName: plan,
		intentName:   []byte("intent"),
		receiptName:  []byte("public-key"),
	} {
		got, err := store.Read(name, 1024)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Read(%q) = (%q, %v), want %q", name, got, err, want)
		}
	}
	if err := store.WriteOnce(PlanFileName, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate WriteOnce() error = %v, want ErrAlreadyExists", err)
	}
	if err := store.WriteOnce(mustTargetStateName(t, 0, 0), nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("WriteOnce(state) error = %v, want ErrInvalidName", err)
	}

	state00, err := store.AppendTargetState(0, 0, []byte("planned"))
	if err != nil || state00 != mustTargetStateName(t, 0, 0) {
		t.Fatalf("AppendTargetState(0, 0) = (%q, %v)", state00, err)
	}
	state01, err := store.AppendTargetState(0, 1, []byte("preflight"))
	if err != nil || state01 != mustTargetStateName(t, 0, 1) {
		t.Fatalf("AppendTargetState(0, 1) = (%q, %v)", state01, err)
	}
	state10, err := store.AppendTargetState(1, 0, []byte("planned"))
	if err != nil || state10 != mustTargetStateName(t, 1, 0) {
		t.Fatalf("AppendTargetState(1, 0) = (%q, %v)", state10, err)
	}
	if _, err := store.AppendTargetState(0, 1, nil); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate AppendTargetState() error = %v, want ErrAlreadyExists", err)
	}
	if _, err := store.AppendTargetState(0, 3, nil); !errors.Is(err, ErrStateOrder) {
		t.Fatalf("gapped AppendTargetState() error = %v, want ErrStateOrder", err)
	}
	wantStates := []string{state00, state01}
	states, err := store.ListTargetStates(0)
	if err != nil || !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("ListTargetStates(0) = (%#v, %v), want %#v", states, err, wantStates)
	}
	states[0] = "mutated-return-value"
	states, err = store.ListTargetStates(0)
	if err != nil || !reflect.DeepEqual(states, wantStates) {
		t.Fatalf("ListTargetStates() exposed internal state: (%#v, %v)", states, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(directory)
	if err != nil {
		t.Fatalf("Open(reopen) error = %v", err)
	}
	got, err := reopened.Read(PlanFileName, 1024)
	if err != nil || !bytes.Equal(got, plan) {
		t.Fatalf("Read after reopen = (%q, %v), want %q", got, err, plan)
	}
	states, err = reopened.ListTargetStates(1)
	if err != nil || !reflect.DeepEqual(states, []string{state10}) {
		t.Fatalf("ListTargetStates(1) after reopen = (%#v, %v)", states, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := reopened.Read(PlanFileName, 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Read after close error = %v, want ErrClosed", err)
	}
	if err := reopened.WriteOnce(ProofFileName, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteOnce after close error = %v, want ErrClosed", err)
	}
	if _, err := reopened.AppendTargetState(1, 1, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("AppendTargetState after close error = %v, want ErrClosed", err)
	}
	if _, err := reopened.ListTargetStates(1); !errors.Is(err, ErrClosed) {
		t.Fatalf("ListTargetStates after close error = %v, want ErrClosed", err)
	}
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil Close() error = %v", err)
	}
}

func TestOpenUsesNonblockingLifetimeLock(t *testing.T) {
	directory := testWorkspace(t)
	first := mustOpenStore(t, directory)
	lockInfo, err := os.Lstat(filepath.Join(directory, LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	_, links, ok := ownerAndLinks(lockInfo)
	if !ok || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 ||
		lockInfo.Size() != 0 || links != 1 {
		t.Fatalf("lock mode=%v size=%d links=%d", lockInfo.Mode(), lockInfo.Size(), links)
	}
	second, err := Open(directory)
	if second != nil || !errors.Is(err, ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("contending Open() = (%v, %v), want ErrLocked", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatalf("Open after release error = %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendAndWriteAreRaceSafe(t *testing.T) {
	store := mustOpenStore(t, testWorkspace(t))
	name := mustTargetArtifactName(t, 0, TargetIntentKind)
	var successes atomic.Int32
	var alreadyExists atomic.Int32
	var unexpected atomic.Value
	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			err := store.WriteOnce(name, []byte(fmt.Sprintf("worker-%d", worker)))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAlreadyExists):
				alreadyExists.Add(1)
			default:
				unexpected.Store(err)
			}
		}(worker)
	}
	wait.Wait()
	if value := unexpected.Load(); value != nil {
		t.Fatalf("concurrent WriteOnce unexpected error = %v", value)
	}
	if successes.Load() != 1 || alreadyExists.Load() != 31 {
		t.Fatalf("concurrent WriteOnce successes=%d already-exists=%d", successes.Load(), alreadyExists.Load())
	}

	successes.Store(0)
	alreadyExists.Store(0)
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.AppendTargetState(0, 0, []byte("planned"))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAlreadyExists):
				alreadyExists.Add(1)
			default:
				unexpected.Store(err)
			}
		}()
	}
	wait.Wait()
	if value := unexpected.Load(); value != nil {
		t.Fatalf("concurrent AppendTargetState unexpected error = %v", value)
	}
	if successes.Load() != 1 || alreadyExists.Load() != 31 {
		t.Fatalf("concurrent append successes=%d already-exists=%d", successes.Load(), alreadyExists.Load())
	}
}
