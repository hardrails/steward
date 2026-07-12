package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestHelperProcess is not a real test: it is the child process the exec tests
// spawn. When STEWARD_WANT_HELPER=1 is set in its environment it acts as a small,
// dependency-free workload (selected by STEWARD_HELPER_MODE) and os.Exit()s;
// otherwise it returns immediately so a normal `go test` run treats it as a
// trivially-passing test. This is the standard os/exec test pattern: the test
// binary re-execs itself rather than depending on an external helper binary.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("STEWARD_WANT_HELPER") != "1" {
		return
	}
	switch os.Getenv("STEWARD_HELPER_MODE") {
	case "ignore-sigterm":
		// Catch and ignore SIGTERM so only the SIGKILL escalation can end this
		// process — the workload a stop's grace-period escalation must be proven on.
		// Signal readiness AFTER registering the handler (by touching the ready file)
		// so the test only stops us once SIGTERM is guaranteed to be caught, not while
		// the re-exec'd binary is still starting up under the default disposition.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		if f := os.Getenv("STEWARD_HELPER_FILE"); f != "" {
			_ = os.WriteFile(f, []byte("ready"), 0o644)
		}
		for {
			time.Sleep(50 * time.Millisecond)
		}
	case "tick":
		// Append a byte to a file on a short interval, so a test can observe that
		// output stops accumulating while SIGSTOP'd and resumes after SIGCONT.
		file := os.Getenv("STEWARD_HELPER_FILE")
		for {
			if f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				_, _ = f.Write([]byte("x"))
				_ = f.Close()
			}
			time.Sleep(15 * time.Millisecond)
		}
	case "exit":
		// Run briefly, then exit on our own — an unexpected exit (crash) from
		// Steward's perspective when it did not request a stop.
		code := 0
		if c := os.Getenv("STEWARD_HELPER_EXIT_CODE"); c != "" {
			code, _ = strconv.Atoi(c)
		}
		time.Sleep(80 * time.Millisecond)
		os.Exit(code)
	default: // "sleep": live until stopped, dying on the default SIGTERM disposition.
		time.Sleep(60 * time.Second)
	}
	os.Exit(0)
}

// testBinary is the path to the running test binary, which the helper specs
// re-exec as their command.
func testBinary() string { return os.Args[0] }

// helperSpec builds a process spec whose command re-execs this test binary in
// TestHelperProcess, in the given mode, with any extra env merged in.
func helperSpec(mode string, extraEnv map[string]string) json.RawMessage {
	env := map[string]string{
		"STEWARD_WANT_HELPER": "1",
		"STEWARD_HELPER_MODE": mode,
	}
	for k, v := range extraEnv {
		env[k] = v
	}
	spec := map[string]any{
		"command": testBinary(),
		"args":    []string{"-test.run=^TestHelperProcess$", "--"},
		"env":     env,
	}
	b, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	return b
}

// syncBuffer is a mutex-guarded bytes.Buffer so a background monitor goroutine's
// log writes and the test's reads never race.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// execTracker builds an exec-enabled in-memory tracker with a short stop grace and
// a captured logger.
func execTracker(t *testing.T, grace time.Duration) (*Tracker, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	tr := NewTracker(0, WithExec(ExecConfig{
		Enabled:         true,
		StopGracePeriod: grace,
		Logger:          slog.New(slog.NewJSONHandler(buf, nil)),
	}))
	return tr, buf
}

// startedInstance provisions a command spec and starts it, returning the ref. It
// registers a cleanup that destroys the instance (terminating any live process) so
// a test never leaks a child.
func startedInstance(t *testing.T, tr *Tracker, id string, spec json.RawMessage) string {
	t.Helper()
	inst, _, err := tr.Provision(id, 0, spec)
	if err != nil {
		t.Fatalf("provision %s: %v", id, err)
	}
	ref := inst.RuntimeRef
	t.Cleanup(func() { _, _ = tr.Destroy(ref) })
	if _, err := tr.Start(ref); err != nil {
		t.Fatalf("start %s: %v", id, err)
	}
	return ref
}

func waitStatus(t *testing.T, tr *Tracker, ref string, want Status, timeout time.Duration) *Instance {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		inst, err := tr.Status(ref)
		if err == nil && inst.Status == want {
			return inst
		}
		time.Sleep(10 * time.Millisecond)
	}
	inst, _ := tr.Status(ref)
	t.Fatalf("instance %s did not reach %s within %s (last=%+v)", ref, want, timeout, inst)
	return nil
}

func waitContains(t *testing.T, buf *syncBuffer, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(buf.String()), []byte(substr)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log never contained %q within %s; got:\n%s", substr, timeout, buf.String())
}

// --- parseProcessSpec ---

func TestParseProcessSpecNoCommand(t *testing.T) {
	cases := []json.RawMessage{
		nil,
		json.RawMessage(``),
		json.RawMessage(`{}`),
		json.RawMessage(`{"owner":"a","memory_mb":512}`),
		json.RawMessage(`{"command":null}`),
		json.RawMessage(`[1,2,3]`), // not an object
	}
	for _, spec := range cases {
		ps, hasCommand, err := parseProcessSpec(spec)
		if hasCommand {
			t.Errorf("spec %s: hasCommand=true, want false", spec)
		}
		if ps != nil || err != nil {
			t.Errorf("spec %s: ps=%v err=%v, want nil,nil", spec, ps, err)
		}
	}
}

func TestParseProcessSpecValid(t *testing.T) {
	spec := json.RawMessage(`{"command":"/bin/echo","args":["a","b"],"env":{"K":"V"},"working_dir":"/tmp","extra":true}`)
	ps, hasCommand, err := parseProcessSpec(spec)
	if err != nil || !hasCommand {
		t.Fatalf("hasCommand=%v err=%v, want true,nil", hasCommand, err)
	}
	if ps.Command != "/bin/echo" {
		t.Errorf("command=%q", ps.Command)
	}
	if len(ps.Args) != 2 || ps.Args[0] != "a" || ps.Args[1] != "b" {
		t.Errorf("args=%v", ps.Args)
	}
	if ps.Env["K"] != "V" {
		t.Errorf("env=%v", ps.Env)
	}
	if ps.WorkingDir != "/tmp" {
		t.Errorf("working_dir=%q", ps.WorkingDir)
	}
}

func TestParseProcessSpecMalformed(t *testing.T) {
	cases := map[string]json.RawMessage{
		"command not a string":   json.RawMessage(`{"command":123}`),
		"command empty":          json.RawMessage(`{"command":""}`),
		"args not string array":  json.RawMessage(`{"command":"x","args":"nope"}`),
		"env not object":         json.RawMessage(`{"command":"x","env":["a"]}`),
		"working_dir not string": json.RawMessage(`{"command":"x","working_dir":5}`),
	}
	for name, spec := range cases {
		ps, hasCommand, err := parseProcessSpec(spec)
		if !hasCommand {
			t.Errorf("%s: hasCommand=false, want true (intent expressed)", name)
		}
		if err == nil {
			t.Errorf("%s: err=nil, want a malformed-spec error", name)
		}
		if ps != nil {
			t.Errorf("%s: ps=%v, want nil on error", name, ps)
		}
	}
}

// --- buildChildEnv ---

func TestBuildChildEnvMinimalBasePlusSpec(t *testing.T) {
	t.Setenv("PATH", "/custom/bin")
	// Steward's own secret env must NOT leak to the child.
	t.Setenv("STEWARD_UPLINK_CREDENTIAL", "super-secret")

	env := buildChildEnv(map[string]string{"FOO": "bar"})
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := bytes.Cut([]byte(kv), []byte("="))
		got[string(k)] = string(v)
	}
	if got["PATH"] != "/custom/bin" {
		t.Errorf("PATH=%q, want /custom/bin (copied from parent)", got["PATH"])
	}
	if got["FOO"] != "bar" {
		t.Errorf("FOO=%q, want bar (from spec.env)", got["FOO"])
	}
	if _, leaked := got["STEWARD_UPLINK_CREDENTIAL"]; leaked {
		t.Error("child env leaked a Steward secret; only PATH + spec.env must be present")
	}
	// Deterministic ordering (sorted): FOO before PATH.
	if env[0] != "FOO=bar" || env[1] != "PATH=/custom/bin" {
		t.Errorf("env not sorted: %v", env)
	}
}

func TestBuildChildEnvSpecOverridesPath(t *testing.T) {
	t.Setenv("PATH", "/base/bin")
	env := buildChildEnv(map[string]string{"PATH": "/override/bin"})
	if len(env) != 1 || env[0] != "PATH=/override/bin" {
		t.Errorf("env=%v, want [PATH=/override/bin]", env)
	}
}

func TestBuildChildEnvNoPathIsEmptyNonNil(t *testing.T) {
	saved, had := os.LookupEnv("PATH")
	_ = os.Unsetenv("PATH")
	defer func() {
		if had {
			_ = os.Setenv("PATH", saved)
		}
	}()
	env := buildChildEnv(nil)
	if env == nil {
		t.Fatal("env is nil; must be a non-nil (possibly empty) slice so exec never inherits the parent env")
	}
	if len(env) != 0 {
		t.Errorf("env=%v, want empty", env)
	}
}

// --- Provision gate ---

func TestProvisionRejectsCommandSpecWhenExecDisabled(t *testing.T) {
	tr := NewTracker(0) // exec disabled (default)
	_, _, err := tr.Provision("a", 0, json.RawMessage(`{"command":"/bin/echo"}`))
	if !errors.Is(err, ErrProcessExecDisabled) {
		t.Fatalf("err=%v, want ErrProcessExecDisabled", err)
	}
	if tr.Len() != 0 {
		t.Error("a rejected provision must not create an instance")
	}
}

func TestProvisionAllowsOpaqueSpecWhenExecDisabled(t *testing.T) {
	tr := NewTracker(0)
	// The historical opaque-config case: no command field, so completely unaffected.
	inst, created, err := tr.Provision("a", 0, json.RawMessage(`{"owner":"a"}`))
	if err != nil || !created {
		t.Fatalf("provision opaque spec: created=%v err=%v", created, err)
	}
	if inst.Status != StatusPending {
		t.Errorf("status=%q, want PENDING", inst.Status)
	}
}

func TestProvisionAllowsCommandSpecWhenExecEnabled(t *testing.T) {
	tr, _ := execTracker(t, time.Second)
	inst, created, err := tr.Provision("a", 0, json.RawMessage(`{"command":"/bin/echo","args":["hi"]}`))
	if err != nil || !created {
		t.Fatalf("provision command spec: created=%v err=%v", created, err)
	}
	if inst.Status != StatusPending {
		t.Errorf("status=%q, want PENDING (no process until start)", inst.Status)
	}
}

func TestProvisionRejectsMalformedCommandSpecWhenExecEnabled(t *testing.T) {
	tr, _ := execTracker(t, time.Second)
	_, _, err := tr.Provision("a", 0, json.RawMessage(`{"command":""}`))
	if !errors.Is(err, ErrInvalidProcessSpec) {
		t.Fatalf("err=%v, want ErrInvalidProcessSpec", err)
	}
	if tr.Len() != 0 {
		t.Error("a rejected provision must not create an instance")
	}
}

// --- real spawn / lifecycle ---

func TestStartSpawnsRealProcess(t *testing.T) {
	tr, _ := execTracker(t, time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("sleep", nil))

	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusRunning {
		t.Fatalf("status=%q, want RUNNING", inst.Status)
	}
	if inst.PID <= 0 {
		t.Fatalf("pid=%d, want a real pid", inst.PID)
	}
	// Prove the pid is a live OS process.
	if syscall.Kill(inst.PID, 0) != nil {
		t.Fatalf("pid %d is not alive", inst.PID)
	}
}

func TestStartFailsForUnknownCommand(t *testing.T) {
	tr, _ := execTracker(t, time.Second)
	inst, _, err := tr.Provision("a", 0, json.RawMessage(`{"command":"/nonexistent/steward-no-such-binary"}`))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	_, err = tr.Start(inst.RuntimeRef)
	if !errors.Is(err, ErrProcessStart) {
		t.Fatalf("start err=%v, want ErrProcessStart", err)
	}
	// The instance must NOT be falsely reported RUNNING.
	after, _ := tr.Status(inst.RuntimeRef)
	if after.Status != StatusPending {
		t.Errorf("status=%q after a failed start, want PENDING (unchanged)", after.Status)
	}
	if after.PID != 0 {
		t.Errorf("pid=%d after a failed start, want 0", after.PID)
	}
}

func TestStartIdempotentDoesNotDuplicateProcess(t *testing.T) {
	tr, _ := execTracker(t, time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("sleep", nil))
	first, _ := tr.Status(ref)

	second, err := tr.Start(ref)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if second.PID != first.PID {
		t.Fatalf("second start spawned a new process: pid %d != %d", second.PID, first.PID)
	}
	tr.mu.Lock()
	n := len(tr.procs)
	tr.mu.Unlock()
	if n != 1 {
		t.Fatalf("tracker holds %d processes, want exactly 1", n)
	}
}

func TestStopGracefulSIGTERM(t *testing.T) {
	tr, _ := execTracker(t, 5*time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("sleep", nil))
	pid := mustPID(t, tr, ref)

	inst, err := tr.Stop(ref)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if inst.Status != StatusStopped {
		t.Fatalf("status=%q, want STOPPED", inst.Status)
	}
	if inst.LastExitReason != exitReasonStopped {
		t.Errorf("last_exit_reason=%q, want %q (SIGTERM sufficed)", inst.LastExitReason, exitReasonStopped)
	}
	if inst.PID != 0 {
		t.Errorf("pid=%d after stop, want 0", inst.PID)
	}
	if processStillAlive(pid) {
		t.Errorf("pid %d still alive after stop", pid)
	}
}

func TestStopEscalatesToSIGKILL(t *testing.T) {
	grace := 250 * time.Millisecond
	tr, _ := execTracker(t, grace)
	readyFile := filepath.Join(t.TempDir(), "ready")
	ref := startedInstance(t, tr, "a", helperSpec("ignore-sigterm", map[string]string{"STEWARD_HELPER_FILE": readyFile}))
	// Wait until the helper has installed its SIGTERM-ignoring handler; otherwise a
	// stop racing its startup would kill it under the default disposition.
	waitFileExists(t, readyFile, 10*time.Second)
	pid := mustPID(t, tr, ref)

	start := time.Now()
	inst, err := tr.Stop(ref)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if inst.LastExitReason != exitReasonKilled {
		t.Fatalf("last_exit_reason=%q, want %q (SIGTERM was ignored, SIGKILL needed)", inst.LastExitReason, exitReasonKilled)
	}
	if elapsed < grace {
		t.Errorf("stop returned in %s, want >= the %s grace period (it must wait before SIGKILL)", elapsed, grace)
	}
	if processStillAlive(pid) {
		t.Errorf("pid %d survived SIGKILL escalation", pid)
	}
}

func TestHibernateSuspendsAndStartResumes(t *testing.T) {
	tr, _ := execTracker(t, 2*time.Second)
	dir := t.TempDir()
	tickFile := filepath.Join(dir, "ticks")
	ref := startedInstance(t, tr, "a", helperSpec("tick", map[string]string{"STEWARD_HELPER_FILE": tickFile}))

	// Wait for the helper to actually start ticking (the re-exec'd binary can be slow
	// to warm up under the race detector), then confirm the file is growing.
	waitFileNonEmpty(t, tickFile, 10*time.Second)

	if _, err := tr.Hibernate(ref); err != nil {
		t.Fatalf("hibernate: %v", err)
	}
	inst, _ := tr.Status(ref)
	if inst.Status != StatusHibernated {
		t.Fatalf("status=%q, want HIBERNATED", inst.Status)
	}

	// Give any in-flight write a moment to land, then confirm output has FROZEN.
	time.Sleep(60 * time.Millisecond)
	frozen := fileSize(t, tickFile)
	time.Sleep(200 * time.Millisecond)
	if grew := fileSize(t, tickFile); grew != frozen {
		t.Fatalf("tick file grew from %d to %d while HIBERNATED (SIGSTOP); it must not accumulate output", frozen, grew)
	}

	// Resume: output must accumulate again.
	if _, err := tr.Start(ref); err != nil {
		t.Fatalf("resume start: %v", err)
	}
	inst, _ = tr.Status(ref)
	if inst.Status != StatusRunning {
		t.Fatalf("status=%q after resume, want RUNNING", inst.Status)
	}
	time.Sleep(200 * time.Millisecond)
	if resumed := fileSize(t, tickFile); resumed <= frozen {
		t.Fatalf("tick file did not grow after SIGCONT resume (%d <= %d)", resumed, frozen)
	}
}

func TestResumePersistFailureReSuspendsProcess(t *testing.T) {
	// Mirror of the hibernate rollback: if resume's SIGCONT succeeds but persisting
	// RUNNING fails, the process must be re-suspended (SIGSTOP) and the status left
	// HIBERNATED — never a process actually running (consuming resources) while the
	// instance is still labeled HIBERNATED. Failure is forced by making the state
	// directory unwritable, the same technique persist_test.go uses.
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions; cannot force a persist failure")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "state.json")

	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: 2 * time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}

	tickFile := filepath.Join(t.TempDir(), "ticks")
	inst, _, err := tr.Provision("a", 0, helperSpec("tick", map[string]string{"STEWARD_HELPER_FILE": tickFile}))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	ref := inst.RuntimeRef
	// Restore write perms before destroying, so the destroy's own persist can succeed
	// and actually terminate the child (a destroy whose persist fails would leak it).
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700); _, _ = tr.Destroy(ref) })

	if _, err := tr.Start(ref); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFileNonEmpty(t, tickFile, 10*time.Second)
	if _, err := tr.Hibernate(ref); err != nil {
		t.Fatalf("hibernate: %v", err)
	}

	// Force the next persist to fail, then attempt a resume (Start from HIBERNATED).
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod ro: %v", err)
	}
	if _, err := tr.Start(ref); err == nil {
		t.Fatal("resume into an unwritable state dir: got nil err, want a persist failure")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod rw: %v", err)
	}

	// Status must have rolled back to HIBERNATED, not been left RUNNING.
	after, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if after.Status != StatusHibernated {
		t.Fatalf("status=%q after a failed resume, want HIBERNATED (rolled back)", after.Status)
	}

	// And the process must be re-suspended: its tick output must stay FROZEN. Without
	// the process-side rollback the SIGCONT would leave it running and ticking.
	time.Sleep(60 * time.Millisecond)
	frozen := fileSize(t, tickFile)
	time.Sleep(200 * time.Millisecond)
	if grew := fileSize(t, tickFile); grew != frozen {
		t.Fatalf("tick file grew from %d to %d after a failed resume; the process must be re-suspended (SIGSTOP), not left running", frozen, grew)
	}
}

func TestUnexpectedExitTransitionsToStopped(t *testing.T) {
	tr, buf := execTracker(t, time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("exit", map[string]string{"STEWARD_HELPER_EXIT_CODE": "3"}))

	// The helper exits on its own after ~80ms; the monitor must notice and transition
	// the instance to STOPPED (never FAILED), recording a crash.
	inst := waitStatus(t, tr, ref, StatusStopped, 3*time.Second)
	if inst.LastExitReason != exitReasonCrashed {
		t.Errorf("last_exit_reason=%q, want %q", inst.LastExitReason, exitReasonCrashed)
	}
	if inst.LastExitCode == nil || *inst.LastExitCode != 3 {
		t.Errorf("last_exit_code=%v, want 3", inst.LastExitCode)
	}
	if inst.PID != 0 {
		t.Errorf("pid=%d after crash, want 0", inst.PID)
	}
	// The distinguishing log line must name this an unexpected exit.
	waitContains(t, buf, "UNEXPECTEDLY", 2*time.Second)
}

func TestDestroyTerminatesProcess(t *testing.T) {
	tr, _ := execTracker(t, 2*time.Second)
	inst, _, err := tr.Provision("a", 0, helperSpec("sleep", nil))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	ref := inst.RuntimeRef
	if _, err := tr.Start(ref); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := mustPID(t, tr, ref)

	if _, err := tr.Destroy(ref); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := tr.Status(ref); !errors.Is(err, ErrNotFound) {
		t.Errorf("status after destroy: err=%v, want ErrNotFound", err)
	}
	if processStillAlive(pid) {
		t.Errorf("pid %d still alive after destroy", pid)
	}
}

// --- restart / reattach reconcile ---

func TestReconcileAfterLoadDeadProcess(t *testing.T) {
	// A previous run recorded a RUNNING command-instance; its process is now gone.
	// On reload with exec enabled, the liveness probe must transition it to STOPPED.
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn orphan: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Kill()
	_ = cmd.Wait() // reap, so the pid is truly gone

	// token is irrelevant here: the liveness probe fails first (the pid is gone), so
	// reattach is refused before identity is ever consulted.
	path := writeStateFile(t, "rt_dead", "a", StatusRunning, pid, "", helperSpec("sleep", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	inst, err := tr.Status("rt_dead")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusStopped {
		t.Fatalf("status=%q, want STOPPED (process did not survive the restart)", inst.Status)
	}
	if inst.LastExitReason != exitReasonSupervisionLost {
		t.Errorf("last_exit_reason=%q, want %q", inst.LastExitReason, exitReasonSupervisionLost)
	}
	if inst.PID != 0 {
		t.Errorf("pid=%d, want 0", inst.PID)
	}
}

func TestReconcileAfterLoadAliveProcessReattachesAndCanStop(t *testing.T) {
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn orphan: %v", err)
	}
	pid := cmd.Process.Pid
	// Reap the orphan promptly once it dies, so terminateReattached's liveness probe
	// sees it gone rather than lingering as a zombie (a zombie still answers signal 0).
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	// Record the orphan's real start-time witness so reattach can positively confirm
	// this exact process (not a pid-reuse stranger) is still alive.
	token, err := procStartToken(pid)
	if err != nil {
		t.Fatalf("read start-time witness: %v", err)
	}
	path := writeStateFile(t, "rt_alive", "a", StatusRunning, pid, token, helperSpec("sleep", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: 2 * time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	inst, err := tr.Status("rt_alive")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusRunning {
		t.Fatalf("status=%q, want RUNNING (process outlived the restart)", inst.Status)
	}
	// It must be reattached in degraded mode, and the WARN must name the limitation.
	tr.mu.Lock()
	sp := tr.procs["rt_alive"]
	tr.mu.Unlock()
	if sp == nil || !sp.reattached {
		t.Fatalf("instance was not reattached: sp=%v", sp)
	}
	waitContains(t, buf, "DEGRADED", time.Second)

	// A reattached instance can still be stopped by pid.
	stopped, err := tr.Stop("rt_alive")
	if err != nil {
		t.Fatalf("stop reattached: %v", err)
	}
	if stopped.Status != StatusStopped {
		t.Fatalf("status=%q after stop, want STOPPED", stopped.Status)
	}
	<-reaped
	if processStillAlive(pid) {
		t.Errorf("pid %d still alive after stopping the reattached instance", pid)
	}
}

func TestReconcileAfterLoadReattachedStopEscalatesToSIGKILL(t *testing.T) {
	// A reattached orphan that ignores SIGTERM must still be killable: the stop's
	// grace-period SIGKILL escalation runs against a process Steward can only signal
	// by pid (not Wait()), so this exercises terminateReattached's kill path.
	readyFile := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=ignore-sigterm", "STEWARD_HELPER_FILE="+readyFile)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn orphan: %v", err)
	}
	pid := cmd.Process.Pid
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})
	waitFileExists(t, readyFile, 10*time.Second) // the SIGTERM-ignoring handler is installed

	grace := 250 * time.Millisecond
	token, err := procStartToken(pid)
	if err != nil {
		t.Fatalf("read start-time witness: %v", err)
	}
	path := writeStateFile(t, "rt_x", "a", StatusRunning, pid, token, helperSpec("ignore-sigterm", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: grace, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}

	start := time.Now()
	stopped, err := tr.Stop("rt_x")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("stop reattached: %v", err)
	}
	if stopped.LastExitReason != exitReasonKilled {
		t.Fatalf("last_exit_reason=%q, want %q (SIGTERM ignored, SIGKILL needed)", stopped.LastExitReason, exitReasonKilled)
	}
	if elapsed < grace {
		t.Errorf("stop returned in %s, want >= the %s grace period", elapsed, grace)
	}
	<-reaped
	if processStillAlive(pid) {
		t.Errorf("pid %d survived the SIGKILL escalation", pid)
	}
}

// --- process-identity witness (pid-reuse) ---

func TestProcStartTokenStableAndFailsClosedWhenGone(t *testing.T) {
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	pid := cmd.Process.Pid
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	first, err := procStartToken(pid)
	if err != nil || first == "" {
		t.Fatalf("first read: token=%q err=%v, want a non-empty witness", first, err)
	}
	second, err := procStartToken(pid)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if first != second {
		t.Errorf("witness not stable across reads: %q != %q", first, second)
	}

	// Once the pid is gone the witness must FAIL CLOSED (an error), never return a
	// bogus value that could be mistaken for a match.
	_ = cmd.Process.Kill()
	<-reaped
	if tok, err := procStartToken(pid); err == nil {
		t.Errorf("dead pid returned witness %q with no error; procStartToken must fail closed", tok)
	}
}

func TestReconcileAfterLoadPidReuseForgedWitnessReportsSupervisionLost(t *testing.T) {
	// The CRITICAL pid-reuse case: the process Steward recorded is gone and an
	// UNRELATED process now holds its pid. The OS cannot be made to deterministically
	// hand a reused pid to a stranger in a test, so we prove the MECHANISM directly: a
	// live pid whose recorded start-time witness does not match its current one must be
	// treated as supervision-lost — and, above all, the live process must be left
	// UNTOUCHED, exactly as an unrelated host process (a cron job, a database, sshd)
	// would be.
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn stand-in: %v", err)
	}
	pid := cmd.Process.Pid
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	if !processStillAlive(pid) {
		t.Fatal("stand-in process is not alive; the test cannot distinguish a mismatch from a dead pid")
	}
	realToken, err := procStartToken(pid)
	if err != nil {
		t.Fatalf("read real witness: %v", err)
	}
	forged := realToken + " (forged)" // a witness the live pid's real one can never equal

	path := writeStateFile(t, "rt_reuse", "a", StatusRunning, pid, forged, helperSpec("sleep", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}

	inst, err := tr.Status("rt_reuse")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusStopped {
		t.Fatalf("status=%q, want STOPPED (identity witness mismatched: pid reuse suspected)", inst.Status)
	}
	if inst.LastExitReason != exitReasonSupervisionLost {
		t.Errorf("last_exit_reason=%q, want %q", inst.LastExitReason, exitReasonSupervisionLost)
	}
	if inst.PID != 0 {
		t.Errorf("pid=%d, want 0", inst.PID)
	}
	// It must NOT be reattached...
	tr.mu.Lock()
	_, tracked := tr.procs["rt_reuse"]
	tr.mu.Unlock()
	if tracked {
		t.Error("a pid whose identity could not be confirmed was reattached; it must be treated as supervision-lost")
	}
	// ...and CRITICALLY the live process must be untouched (never signalled). This is
	// the whole point of the fix: Steward must not SIGTERM/SIGKILL a stranger's pid.
	if !processStillAlive(pid) {
		t.Fatal("the unrelated live process was signalled during reconcile; Steward must never touch a pid it cannot confirm as its own")
	}
}

func TestReconcileAfterLoadMatchingWitnessReattaches(t *testing.T) {
	// The true-positive path: a live pid whose recorded start-time witness DOES match
	// its current one is provably the same process Steward spawned, so it reattaches.
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn orphan: %v", err)
	}
	pid := cmd.Process.Pid
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	token, err := procStartToken(pid)
	if err != nil {
		t.Fatalf("read witness: %v", err)
	}
	path := writeStateFile(t, "rt_match", "a", StatusRunning, pid, token, helperSpec("sleep", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	inst, err := tr.Status("rt_match")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusRunning {
		t.Fatalf("status=%q, want RUNNING (identity witness matched)", inst.Status)
	}
	tr.mu.Lock()
	sp := tr.procs["rt_match"]
	tr.mu.Unlock()
	if sp == nil || !sp.reattached {
		t.Fatalf("instance with a matching witness was not reattached: sp=%v", sp)
	}
}

func TestReconcileAfterLoadMissingWitnessFailsClosed(t *testing.T) {
	// A state file written before the identity witness existed (no proc_start_token)
	// must NOT reattach even when its pid is alive: without a recorded witness the
	// identity cannot be confirmed, so it fails closed to supervision-lost rather than
	// trusting a bare live pid.
	cmd := exec.Command(testBinary(), "-test.run=^TestHelperProcess$", "--")
	cmd.Env = append(os.Environ(), "STEWARD_WANT_HELPER=1", "STEWARD_HELPER_MODE=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn orphan: %v", err)
	}
	pid := cmd.Process.Pid
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	path := writeStateFile(t, "rt_nowitness", "a", StatusRunning, pid, "", helperSpec("sleep", nil))
	buf := &syncBuffer{}
	tr, err := LoadTracker(0, path, WithExec(ExecConfig{Enabled: true, StopGracePeriod: time.Second, Logger: slog.New(slog.NewJSONHandler(buf, nil))}))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	inst, err := tr.Status("rt_nowitness")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != StatusStopped {
		t.Fatalf("status=%q, want STOPPED (no witness recorded: identity unverifiable)", inst.Status)
	}
	if inst.LastExitReason != exitReasonSupervisionLost {
		t.Errorf("last_exit_reason=%q, want %q", inst.LastExitReason, exitReasonSupervisionLost)
	}
	// The live pid must be untouched.
	if !processStillAlive(pid) {
		t.Fatal("an unverified live pid was signalled during reconcile; it must be left untouched")
	}
}

// --- stop vs concurrent start race ---

func TestStopSupersededByConcurrentStartDoesNotOrphan(t *testing.T) {
	// The stop-vs-start race: while a Stop is parked outside the lock (its process
	// already dead but the instance not yet finalized), a concurrent Start spawns a
	// REPLACEMENT process for the same runtime_ref. On re-acquiring the lock, Stop must
	// not clobber that newer process's RUNNING status to STOPPED or delete it from
	// tracking — doing so would orphan a live child (never signalled again, its pid
	// persisted as 0 so a restart cannot find it either). testHookStopAfterTerminate
	// fires the concurrent Start at the exact window, so the race is deterministic.
	tr, _ := execTracker(t, 5*time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("sleep", nil))
	firstPID := mustPID(t, tr, ref)

	var newPID int
	var startErr error
	tr.testHookStopAfterTerminate = func() {
		// Runs while Stop holds no lock and the first process is already dead, so this
		// Start falls through to spawn a fresh process and registers it as the instance's
		// current one.
		inst, err := tr.Start(ref)
		startErr = err
		if inst != nil {
			newPID = inst.PID
		}
	}

	stopped, err := tr.Stop(ref)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if startErr != nil {
		t.Fatalf("concurrent start: %v", startErr)
	}
	if newPID <= 0 || newPID == firstPID {
		t.Fatalf("concurrent start did not spawn a distinct new process: newPID=%d firstPID=%d", newPID, firstPID)
	}

	// The racing Stop must have deferred to the newer process, not clobbered it.
	if stopped.Status != StatusRunning {
		t.Errorf("stop returned status=%q, want RUNNING (a concurrent start superseded it)", stopped.Status)
	}
	after, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if after.Status != StatusRunning {
		t.Errorf("status=%q after a superseded stop, want RUNNING", after.Status)
	}
	if after.PID != newPID {
		t.Errorf("pid=%d after a superseded stop, want the new process's pid %d (not clobbered to 0)", after.PID, newPID)
	}
	// The new process must still be tracked (not orphaned) and still alive.
	tr.mu.Lock()
	sp := tr.procs[ref]
	tr.mu.Unlock()
	if sp == nil {
		t.Fatal("the new process was deleted from tracking by the racing stop: it is now an unsignalable orphan")
	}
	if !processStillAlive(newPID) {
		t.Errorf("new process pid %d is not alive", newPID)
	}
}

func TestStopFinalizesStoppedWhenReplacementRolledBack(t *testing.T) {
	// Greptile P1 follow-up: while Stop is parked outside the lock, a concurrent Start
	// can spawn a replacement, fail to persist, and roll back — killing the replacement,
	// deleting t.procs[ref], and restoring the stale pre-stop RUNNING/pid. When Stop
	// re-locks, the tracked slot is EMPTY. Stop must still finalize STOPPED (its own
	// process is dead and nothing live replaced it), never defer to the absent process
	// and leave a phantom RUNNING pointing at a dead pid. The hook reproduces that net
	// effect (an emptied slot at re-lock) deterministically.
	tr, _ := execTracker(t, 5*time.Second)
	ref := startedInstance(t, tr, "a", helperSpec("sleep", nil))

	tr.testHookStopAfterTerminate = func() {
		// Mimic the rolled-back replacement: the slot ends up empty while the instance is
		// left at its stale pre-stop RUNNING/pid (which the Stop still owns and must clear).
		tr.mu.Lock()
		delete(tr.procs, ref)
		tr.mu.Unlock()
	}

	stopped, err := tr.Stop(ref)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.Status != StatusStopped {
		t.Fatalf("status=%q, want STOPPED (the stopped process is dead and nothing live replaced it)", stopped.Status)
	}
	if stopped.PID != 0 {
		t.Errorf("pid=%d, want 0 (no phantom RUNNING with a dead pid)", stopped.PID)
	}
	if stopped.LastExitReason != exitReasonStopped {
		t.Errorf("last_exit_reason=%q, want %q", stopped.LastExitReason, exitReasonStopped)
	}
	after, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if after.Status != StatusStopped || after.PID != 0 {
		t.Errorf("state=%s/pid %d after a superseded-then-rolled-back stop, want STOPPED/0", after.Status, after.PID)
	}
}

// --- helpers ---

func mustPID(t *testing.T, tr *Tracker, ref string) int {
	t.Helper()
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.PID <= 0 {
		t.Fatalf("pid=%d, want a real pid", inst.PID)
	}
	return inst.PID
}

func processStillAlive(pid int) bool {
	// Poll briefly: a just-signalled process may take a moment to actually exit.
	for i := 0; i < 50; i++ {
		if syscall.Kill(pid, 0) != nil {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return syscall.Kill(pid, 0) == nil
}

func waitFileExists(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("file %s never appeared within %s", path, timeout)
}

func waitFileNonEmpty(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("file %s never became non-empty within %s", path, timeout)
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// writeStateFile hand-authors a version-1 state file with a single instance, as a
// previous Steward run would have persisted it, and returns its path. A non-empty
// token records the process-identity witness (proc_start_token) that reattach
// re-verifies; an empty token omits the key, mirroring a state file written before the
// witness existed (which must then fail closed on reattach).
func writeStateFile(t *testing.T, ref, id string, status Status, pid int, token string, spec json.RawMessage) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	inst := map[string]any{
		"instance_id": id,
		"runtime_ref": ref,
		"status":      string(status),
		"created_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"pid":         pid,
		"spec":        json.RawMessage(spec),
	}
	if token != "" {
		inst["proc_start_token"] = token
	}
	snap := map[string]any{"version": 1, "instances": []any{inst}}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write state file: %v", err)
	}
	return path
}
