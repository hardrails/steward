package runtime

// This file holds Steward's real OS-process supervision: parsing the process
// fields out of an instance's otherwise-opaque spec, spawning and monitoring a
// child process, and the signal choreography behind start/stop/hibernate/destroy.
// It is deliberately kept apart from the pure state-machine logic in runtime.go —
// every function here is a no-op unless process execution was explicitly enabled
// (-enable-process-exec). When it is disabled (the default), the tracker is exactly
// the status map it has always been and none of this runs.
//
// Platform note: process supervision uses Unix process signals (SIGTERM, SIGKILL,
// SIGSTOP, SIGCONT) and a signal-0 liveness probe. Steward is an on-node Unix
// daemon (its CI and release targets are Linux; development is macOS), so these are
// always available; a Windows build of this package is not supported.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The last_exit_reason vocabulary. The status field cannot itself distinguish why
// a process is no longer running (an unexpected crash and a requested stop both
// land on STOPPED — Steward must never emit FAILED, see the StatusFailed doc
// comment), so this small closed set records the distinction an operator needs.
const (
	exitReasonStopped         = "stopped"          // exited within grace after SIGTERM (a graceful, requested stop)
	exitReasonKilled          = "killed"           // survived grace and was SIGKILLed (a forced, requested stop)
	exitReasonCrashed         = "crashed"          // exited on its own, unrequested (a crash)
	exitReasonSupervisionLost = "supervision_lost" // its pid was gone when Steward reloaded state after a restart
)

// procTerminatePollInterval bounds how often terminate re-probes a reattached
// orphan's liveness. A supervised child is awaited on its doneCh instead, with no
// polling; only an orphan (which Steward cannot Wait() on) is polled.
const procTerminatePollInterval = 20 * time.Millisecond

// processSpec is the process-execution view of an instance's opaque spec. Only
// these four fields are ever interpreted; every other key in the spec is ignored,
// so the spec stays the forwards-compatible, additionalProperties:true object it
// has always been. A spec is a "process spec" — one Steward backs with a real OS
// process — exactly when it carries a non-null "command" field.
type processSpec struct {
	Command    string
	Args       []string
	Env        map[string]string
	WorkingDir string
}

// parseProcessSpec inspects spec for process-execution intent.
//
// hasCommand is true when the spec is a JSON object carrying a non-null "command"
// key — the single signal that the caller wants real process supervision (the
// whole opt-in gate keys on this; see Tracker.Provision). When hasCommand is false,
// ps and err are both nil and the spec is treated exactly as the opaque,
// never-interpreted blob it has always been.
//
// When hasCommand is true and err is nil, ps is the fully parsed process spec.
// When hasCommand is true and err is non-nil, the caller expressed intent but the
// process spec is malformed (command not a non-empty string, or args/env/
// working_dir of the wrong JSON type) and ps is nil — the gate then rejects it
// rather than silently ignoring the caller's intent.
func parseProcessSpec(spec json.RawMessage) (ps *processSpec, hasCommand bool, err error) {
	trimmed := bytes.TrimSpace(spec)
	if len(trimmed) == 0 {
		return nil, false, nil
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(trimmed, &fields); e != nil {
		// Not a JSON object (callers already guarantee object-or-absent, but be
		// defensive): it cannot carry a command field, so it is not a process spec.
		return nil, false, nil
	}
	rawCmd, ok := fields["command"]
	if !ok || isJSONNull(rawCmd) {
		// No command key, or an explicit null: not a process spec. Treating an
		// explicit null as absent mirrors how a null spec is treated as no spec.
		return nil, false, nil
	}

	out := &processSpec{}
	if e := json.Unmarshal(rawCmd, &out.Command); e != nil {
		return nil, true, fmt.Errorf("command must be a JSON string")
	}
	if out.Command == "" {
		return nil, true, fmt.Errorf("command must be a non-empty string")
	}
	if raw, ok := fields["args"]; ok && !isJSONNull(raw) {
		if e := json.Unmarshal(raw, &out.Args); e != nil {
			return nil, true, fmt.Errorf("args must be a JSON array of strings")
		}
	}
	if raw, ok := fields["env"]; ok && !isJSONNull(raw) {
		if e := json.Unmarshal(raw, &out.Env); e != nil {
			return nil, true, fmt.Errorf("env must be a JSON object with string values")
		}
	}
	if raw, ok := fields["working_dir"]; ok && !isJSONNull(raw) {
		if e := json.Unmarshal(raw, &out.WorkingDir); e != nil {
			return nil, true, fmt.Errorf("working_dir must be a JSON string")
		}
	}
	return out, true, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// buildChildEnv constructs the child process's environment from a minimal,
// explicit base plus the spec's env, DELIBERATELY not inheriting Steward's own
// environment. Steward's environment may hold the uplink credential, TLS key
// paths, and other secrets; leaking those into an arbitrary spawned process is a
// real risk. So the child starts from nothing but PATH (copied from Steward's own
// PATH so the child — and anything it execs — can still locate executables) plus
// whatever spec.env explicitly supplies, which takes precedence over the base
// PATH. The result is always a non-nil slice (even when empty) so exec.Cmd never
// falls back to inheriting the full parent environment, which is its documented
// behavior for a nil Env.
func buildChildEnv(specEnv map[string]string) []string {
	base := map[string]string{}
	if path, ok := os.LookupEnv("PATH"); ok {
		base["PATH"] = path
	}
	for k, v := range specEnv {
		base[k] = v
	}
	keys := make([]string, 0, len(base))
	for k := range base {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(base))
	for _, k := range keys {
		env = append(env, k+"="+base[k])
	}
	return env
}

// supervisedProcess is Steward's handle on one real child process — or, after a
// restart, a reattached orphan (see below). Its own mutex guards the mutable
// fields; the tracker's mutex is a DIFFERENT lock and is never held while a
// blocking process operation (the terminate grace wait) runs, so a slow stop of
// one instance never freezes the whole tracker.
//
// Two modes:
//   - a freshly spawned child (reattached=false) has a monitor goroutine running
//     cmd.Wait(); doneCh is closed when it returns, and exitCode is then valid.
//     This is the normal, fully supervised mode.
//   - a reattached orphan (reattached=true) is a process Steward found still alive
//     by pid after a restart. Steward can still signal it (stop/hibernate/resume
//     work) and poll its liveness, but it is NOT this process's child, so it
//     cannot be Wait()ed or reaped and its stdout/stderr are gone forever. There is
//     no monitor goroutine and no doneCh; a later unexpected exit is noticed only
//     on the next liveness probe, not proactively. See Tracker.reconcileProcessesAfterLoad.
type supervisedProcess struct {
	proc       *os.Process
	reattached bool
	doneCh     chan struct{} // nil for a reattached orphan; closed by the monitor for a child

	mu          sync.Mutex
	intentional bool // an explicit stop/destroy latched this exit, so the monitor must not treat it as a crash
	exitCode    int
}

func (sp *supervisedProcess) markIntentional() {
	sp.mu.Lock()
	sp.intentional = true
	sp.mu.Unlock()
}

// hasExited reports whether the process is no longer running. For a supervised
// child it is the monitor's authoritative doneCh; for a reattached orphan it is a
// best-effort liveness probe (signal 0).
func (sp *supervisedProcess) hasExited() bool {
	if sp.reattached {
		return !processAlive(sp.proc)
	}
	select {
	case <-sp.doneCh:
		return true
	default:
		return false
	}
}

func (sp *supervisedProcess) suspend() error { return sp.proc.Signal(syscall.SIGSTOP) }
func (sp *supervisedProcess) resume() error  { return sp.proc.Signal(syscall.SIGCONT) }

func (sp *supervisedProcess) exitInfo() int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.exitCode
}

// terminate stops the process and returns once it is confirmed dead. It sends
// SIGCONT first (to unwedge a hibernated/suspended process so it can act on the
// next signal — a stopped process would otherwise queue SIGTERM until resumed),
// then SIGTERM, then — only if the process is still alive after grace — escalates
// to SIGKILL. It returns the exit code (or -1 when unknown: a reattached orphan, or
// a signal-killed child) and the reason: exitReasonStopped when SIGTERM sufficed,
// exitReasonKilled when the SIGKILL escalation was needed. It can block up to
// grace, so the tracker always calls it OUTSIDE its own mutex.
func (sp *supervisedProcess) terminate(grace time.Duration) (exitCode int, reason string) {
	_ = sp.proc.Signal(syscall.SIGCONT)
	_ = sp.proc.Signal(syscall.SIGTERM)

	if sp.reattached {
		return sp.terminateReattached(grace)
	}
	select {
	case <-sp.doneCh:
		return sp.exitInfo(), exitReasonStopped
	case <-time.After(grace):
		_ = sp.proc.Kill() // SIGKILL: uninterceptable, so the process cannot survive it
		<-sp.doneCh        // the monitor reaps the child and closes doneCh
		return sp.exitInfo(), exitReasonKilled
	}
}

// terminateReattached is terminate's polling variant for an orphan Steward cannot
// Wait() on: it probes liveness on an interval instead of blocking on a channel.
// SIGCONT and SIGTERM have already been sent by terminate.
func (sp *supervisedProcess) terminateReattached(grace time.Duration) (int, string) {
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !processAlive(sp.proc) {
			return -1, exitReasonStopped
		}
		time.Sleep(procTerminatePollInterval)
	}
	_ = sp.proc.Kill()
	// SIGKILL is immediate; poll only to confirm the pid is gone. The orphan is
	// reparented to init, which reaps it, so this loop resolves quickly in practice.
	killDeadline := time.Now().Add(grace)
	for time.Now().Before(killDeadline) {
		if !processAlive(sp.proc) {
			break
		}
		time.Sleep(procTerminatePollInterval)
	}
	return -1, exitReasonKilled
}

// processAlive reports whether proc is still running. Signal 0 delivers nothing but
// still performs the existence/permission check, so it is the standard "is this pid
// alive?" probe: a nil error means alive and signalable; an error (ESRCH — no such
// process, or os.ErrProcessDone for a reaped child) means gone.
//
// Liveness is NOT identity: signal 0 succeeding only proves SOME process holds this
// pid, not that it is the one Steward spawned. Across a restart the OS may have reused
// the pid for an unrelated process, so a bare liveness probe must be paired with an
// identity witness (procStartToken) before Steward signals a reattached pid. See
// reconcileProcessesAfterLoad.
func processAlive(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

// procStartToken returns a stable start-time witness for the process currently at
// pid. A pid alone is not an identity — the OS reuses pids — but a pid plus its start
// time is: a reused pid necessarily belongs to a process that started later, so a
// changed start time means the original process is gone. It shells out to
// `ps -o lstart=` rather than reading /proc, because one portable path then covers
// every platform Steward supports (Linux release/CI targets and macOS dev hosts both
// ship a `ps` with lstart, and neither needs cgo or a dependency). The witness is
// whole-second granularity — coarser than /proc/<pid>/stat's boot-tick starttime, but
// a pid reused after a Steward restart is astronomically unlikely to also land in the
// original's exact one-second start window, and the check fails CLOSED anyway (a coarse
// witness only ever risks a conservative supervision-lost, never a false reattach).
// Any failure — the pid gone, `ps` absent, empty output — returns an error, so a
// caller that cannot read the witness treats it as unverifiable rather than a match.
func procStartToken(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d for start-time witness", pid)
	}
	out, err := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", fmt.Errorf("read start-time witness for pid %d: %w", pid, err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("empty start-time witness for pid %d", pid)
	}
	return token, nil
}

// reattachIdentityConfirmed reports whether the process now at pid is provably the
// SAME one Steward spawned, by re-reading its start-time witness and comparing it to
// the one recorded at spawn (recorded). It FAILS CLOSED: an empty recorded witness (an
// older state file, or a spawn that could not read one), an unreadable current witness,
// or any mismatch all return false — so a reattach that cannot be positively proven
// never happens. Trusting a bare live pid instead is exactly the pid-reuse hole this
// closes: a stranger now holding a recycled pid must never inherit the original's
// stop/kill/suspend signals.
func reattachIdentityConfirmed(recorded string, pid int) bool {
	if recorded == "" {
		return false
	}
	current, err := procStartToken(pid)
	if err != nil {
		return false
	}
	return current == recorded
}

// spawn starts a fresh child for an instance per ps and begins supervising it. The
// caller holds t.mu. It uses exec.Command directly (never a shell) so
// caller-supplied args cannot be reinterpreted by shell metacharacters; the child's
// environment is the minimal, secret-free base buildChildEnv constructs; and
// stdout/stderr are inherited from Steward so child output lands in the same stream
// an operator already captures for Steward's logs. It returns the started process
// handle and its pid, or an error if the command could not be spawned (executable
// not found, permission denied, missing working_dir) — in which case NOTHING is
// tracked and the caller must not report the instance RUNNING.
func (t *Tracker) spawn(runtimeRef, instanceID string, ps *processSpec) (sp *supervisedProcess, pid int, startToken string, err error) {
	cmd := exec.Command(ps.Command, ps.Args...)
	cmd.Env = buildChildEnv(ps.Env)
	if ps.WorkingDir != "" {
		cmd.Dir = ps.WorkingDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, 0, "", err
	}
	pid = cmd.Process.Pid
	// Capture the process-identity witness immediately, so a later restart can prove
	// THIS process (not a stranger who reused its pid) is still alive before
	// reattaching. Best-effort: a spawn that already succeeded must not be torn down
	// just because the witness could not be read — an empty token simply makes a future
	// reattach fail closed (supervision reported lost) for this one instance.
	token, terr := procStartToken(pid)
	if terr != nil {
		token = ""
		t.logger.Warn("could not capture a start-time identity witness for a just-spawned process; it will be reported supervision-lost (not reattached) after a Steward restart",
			"runtime_ref", runtimeRef, "instance_id", instanceID, "pid", pid, "err", terr.Error())
	}
	sp = &supervisedProcess{proc: cmd.Process, doneCh: make(chan struct{})}
	go t.monitor(runtimeRef, instanceID, sp, cmd)
	t.logger.Info("supervised process started",
		"runtime_ref", runtimeRef, "instance_id", instanceID, "pid", pid, "command", ps.Command)
	return sp, pid, token, nil
}

// monitor is one child's supervision goroutine: it blocks in cmd.Wait() until the
// child exits (reaping it, so no zombie is left behind), records the exit code,
// closes doneCh, and — unless an explicit stop/destroy already latched this as an
// intentional termination — treats the exit as unexpected (a crash) and hands it to
// handleUnexpectedExit.
func (t *Tracker) monitor(runtimeRef, instanceID string, sp *supervisedProcess, cmd *exec.Cmd) {
	waitErr := cmd.Wait()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	sp.mu.Lock()
	sp.exitCode = code
	intentional := sp.intentional
	sp.mu.Unlock()
	close(sp.doneCh)
	if intentional {
		return // a stop/destroy is finalizing this exit's status itself
	}
	t.handleUnexpectedExit(runtimeRef, instanceID, sp, code, waitErr)
}

// handleUnexpectedExit transitions an instance to STOPPED after its supervised
// process exited on its own — a crash, not a requested stop. It acquires t.mu and
// acts only if THIS exact process is still the tracked one for a still-live instance
// in a live-process status, so a stale monitor from a superseded process (a
// stop-then-start cycle) or a since-destroyed instance is a harmless no-op.
//
// The status becomes STOPPED, never FAILED: StatusFailed is reserved for the
// control plane (see its doc comment) and Steward must never emit it. Because the
// status field cannot itself distinguish a crash from a requested stop, the
// distinction is recorded two other ways an operator and the logs CAN read: a
// distinct WARN line explicitly naming this an unexpected exit, and last_exit_reason
// set to "crashed" (a requested stop sets "stopped"/"killed").
func (t *Tracker) handleUnexpectedExit(runtimeRef, instanceID string, sp *supervisedProcess, code int, waitErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	inst, ok := t.byRef[runtimeRef]
	if !ok || t.procs[runtimeRef] != sp {
		return
	}
	if inst.Status != StatusRunning && inst.Status != StatusHibernated {
		return
	}
	inst.Status = StatusStopped
	inst.PID = 0
	inst.ProcStartToken = ""
	c := code
	inst.LastExitCode = &c
	inst.LastExitReason = exitReasonCrashed
	delete(t.procs, runtimeRef)
	if err := t.persistLocked(); err != nil {
		t.logger.Error("failed to persist state after an unexpected process exit; in-memory status is STOPPED but the state file may lag until the next mutation",
			"runtime_ref", runtimeRef, "instance_id", instanceID, "err", err)
	}
	t.logger.Warn("supervised process exited UNEXPECTEDLY (a crash, not a requested stop); instance transitioned to STOPPED",
		"runtime_ref", runtimeRef, "instance_id", instanceID, "exit_code", code, "wait_err", waitErrString(waitErr))
}

func waitErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// startExec is Start when process execution is enabled. It resolves the instance's
// spec to decide between a pure status transition (an opaque, non-process instance
// behaves exactly as it does with exec disabled), resuming a suspended process
// (SIGCONT), an idempotent no-op (already RUNNING with a live process — never a
// duplicate spawn), or spawning a fresh process. The caller holds no lock.
func (t *Tracker) startExec(runtimeRef string) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	inst, ok := t.byRef[runtimeRef]
	if !ok {
		return nil, ErrNotFound
	}
	if !transitionAllowed(inst.Status, StatusRunning) {
		return nil, fmt.Errorf("%w: %s cannot become %s", ErrInvalidStateTransition, inst.Status, StatusRunning)
	}

	ps, hasCommand, perr := parseProcessSpec(inst.Spec)
	if !hasCommand {
		// An opaque, non-process instance under an exec-enabled Steward behaves
		// exactly as it does with exec disabled: a pure status transition.
		return t.setStatusLocked(inst, StatusRunning)
	}
	if perr != nil {
		// The spec was validated at provision time, so this is not normally
		// reachable; fail closed rather than try to exec a malformed spec.
		return nil, fmt.Errorf("%w: %v", ErrInvalidProcessSpec, perr)
	}

	existing := t.procs[runtimeRef]

	// HIBERNATED + a live suspended process → resume it (SIGCONT), preserving its
	// in-memory state, rather than spawning a new one.
	if inst.Status == StatusHibernated && existing != nil && !existing.hasExited() {
		if err := existing.resume(); err != nil {
			return nil, fmt.Errorf("%w: resuming the suspended process failed: %v", ErrProcessStart, err)
		}
		prev := inst.Status
		inst.Status = StatusRunning
		if err := t.persistLocked(); err != nil {
			// Roll BOTH sides back: re-suspend the process (undo the SIGCONT) AND restore
			// HIBERNATED, so a persistence failure never leaves the process actually running
			// (consuming resources) while the instance is still labeled HIBERNATED. This is
			// the exact mirror of hibernateExec's rollback, which resumes on a failed persist.
			_ = existing.suspend()
			inst.Status = prev
			return nil, err
		}
		t.logger.Info("resumed suspended process (SIGCONT)", "runtime_ref", runtimeRef, "instance_id", inst.InstanceID)
		return inst.clone(), nil
	}

	// RUNNING + a live process → idempotent no-op. This is the self-transition
	// idempotency guarantee at the process level: a redelivered start must not fork
	// a second process (see transitionAllowed's doc comment on why idempotency matters).
	if inst.Status == StatusRunning && existing != nil && !existing.hasExited() {
		return inst.clone(), nil
	}

	// Every remaining case spawns fresh: PENDING/STOPPED, or a RUNNING/HIBERNATED
	// whose process handle is gone (a restart that could not reattach). Name the
	// discontinuity when we thought we had a process and no longer do.
	if inst.PID != 0 && (existing == nil || existing.hasExited()) {
		t.logger.Warn("starting an instance whose previous supervised process handle is gone (likely lost across a Steward restart); spawning a FRESH process, not resuming the original",
			"runtime_ref", runtimeRef, "instance_id", inst.InstanceID, "lost_pid", inst.PID)
	}

	sp, pid, startToken, err := t.spawn(runtimeRef, inst.InstanceID, ps)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProcessStart, err)
	}

	prevStatus := inst.Status
	prevPID := inst.PID
	prevToken := inst.ProcStartToken
	t.procs[runtimeRef] = sp
	inst.Status = StatusRunning
	inst.PID = pid
	inst.ProcStartToken = startToken
	inst.LastExitCode = nil
	inst.LastExitReason = ""
	if err := t.persistLocked(); err != nil {
		// Persisting the new RUNNING state failed: kill the just-spawned process so
		// we never leak an untracked child, roll the in-memory state back, and
		// surface the error. SIGKILL (not a graceful stop) keeps this rare error path
		// from blocking the lock on a grace wait; markIntentional stops the monitor
		// from also trying to grab t.mu we still hold.
		sp.markIntentional()
		_ = sp.proc.Kill()
		<-sp.doneCh
		delete(t.procs, runtimeRef)
		inst.Status = prevStatus
		inst.PID = prevPID
		inst.ProcStartToken = prevToken
		return nil, err
	}
	return inst.clone(), nil
}

// stopExec is Stop when process execution is enabled. It sends SIGTERM, waits up to
// the grace period, escalates to SIGKILL if still alive, and transitions to STOPPED
// once the process is confirmed dead. The blocking grace wait runs WITHOUT the
// tracker lock so stopping one instance never freezes the whole tracker.
func (t *Tracker) stopExec(runtimeRef string) (*Instance, error) {
	t.mu.Lock()
	inst, ok := t.byRef[runtimeRef]
	if !ok {
		t.mu.Unlock()
		return nil, ErrNotFound
	}
	if !transitionAllowed(inst.Status, StatusStopped) {
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: %s cannot become %s", ErrInvalidStateTransition, inst.Status, StatusStopped)
	}
	sp := t.procs[runtimeRef]
	if sp == nil {
		// No live process to signal (an opaque instance, an already-stopped one, or a
		// process handle lost across a restart): a pure status transition.
		out, err := t.setStatusLocked(inst, StatusStopped)
		t.mu.Unlock()
		return out, err
	}
	// Latch the coming exit as intentional so the monitor does not mis-report it as a
	// crash, then release the lock: terminate can block up to the grace period.
	sp.markIntentional()
	instanceID := inst.InstanceID
	t.mu.Unlock()

	exitCode, reason := sp.terminate(t.stopGracePeriod)

	// testHookStopAfterTerminate fires here, in production nil, to make the
	// stop-vs-concurrent-start race below deterministically testable: the process is
	// now dead but the lock is not yet re-acquired.
	if t.testHookStopAfterTerminate != nil {
		t.testHookStopAfterTerminate()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	inst, ok = t.byRef[runtimeRef]
	if !ok {
		// Destroyed while we were stopping: the instance is already gone, a superset
		// of the requested end state.
		return nil, ErrNotFound
	}
	if cur := t.procs[runtimeRef]; cur != nil && cur != sp {
		// A concurrent Start spawned a NEW, still-tracked process for this runtime_ref
		// while the lock was released for the grace wait (the same identity guard
		// handleUnexpectedExit uses). That newer process now owns the instance: clobbering
		// the status/PID to STOPPED and deleting it from t.procs here would orphan a live
		// child — never signalled again, its pid persisted as 0 so a restart cannot find
		// it either — and wrongly report a RUNNING instance STOPPED. The process THIS stop
		// terminated is already dead; leave the newer one untouched and return the current
		// state.
		//
		// We defer ONLY to a genuinely-present replacement (cur != nil). If the slot is
		// EMPTY — e.g. a concurrent Start that spawned a replacement and then rolled it
		// back on its own failed persist, deleting the entry and restoring the stale
		// pre-stop RUNNING/pid — there is nothing live to protect, so we must fall through
		// and finalize STOPPED here rather than defer and leave a phantom RUNNING pointing
		// at this stop's already-dead pid.
		t.logger.Info("stop superseded by a concurrent start; the newer supervised process is left tracked and running",
			"runtime_ref", runtimeRef, "instance_id", instanceID)
		return inst.clone(), nil
	}
	inst.Status = StatusStopped
	inst.PID = 0
	inst.ProcStartToken = ""
	c := exitCode
	inst.LastExitCode = &c
	inst.LastExitReason = reason
	delete(t.procs, runtimeRef)
	if err := t.persistLocked(); err != nil {
		return nil, err
	}
	t.logger.Info("stopped supervised process",
		"runtime_ref", runtimeRef, "instance_id", instanceID, "exit_code", exitCode, "reason", reason)
	return inst.clone(), nil
}

// hibernateExec is Hibernate when process execution is enabled: it suspends the
// process with SIGSTOP (preserving its in-memory state so a later Start can resume
// it via SIGCONT) rather than killing it. SIGSTOP is a fast signal send, so unlike
// stop this holds the tracker lock throughout.
func (t *Tracker) hibernateExec(runtimeRef string) (*Instance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	inst, ok := t.byRef[runtimeRef]
	if !ok {
		return nil, ErrNotFound
	}
	if !transitionAllowed(inst.Status, StatusHibernated) {
		return nil, fmt.Errorf("%w: %s cannot become %s", ErrInvalidStateTransition, inst.Status, StatusHibernated)
	}
	sp := t.procs[runtimeRef]
	if sp == nil {
		return t.setStatusLocked(inst, StatusHibernated)
	}
	if err := sp.suspend(); err != nil {
		return nil, fmt.Errorf("hibernate: suspending the process (SIGSTOP) failed: %w", err)
	}
	prev := inst.Status
	inst.Status = StatusHibernated
	if err := t.persistLocked(); err != nil {
		// Roll the status back AND resume the process, so a persistence failure never
		// leaves a suspended process mislabeled as still-running.
		_ = sp.resume()
		inst.Status = prev
		return nil, err
	}
	t.logger.Info("hibernated supervised process (SIGSTOP)", "runtime_ref", runtimeRef, "instance_id", inst.InstanceID)
	return inst.clone(), nil
}

// setStatusLocked sets inst.Status and persists, rolling the in-memory status back
// on a persistence failure. The caller holds t.mu. It is the shared no-process path
// for the exec-aware transitions (an opaque instance, or one whose process handle
// is gone) — identical in effect to the pure transition() path.
func (t *Tracker) setStatusLocked(inst *Instance, status Status) (*Instance, error) {
	prev := inst.Status
	inst.Status = status
	if err := t.persistLocked(); err != nil {
		inst.Status = prev
		return nil, err
	}
	return inst.clone(), nil
}

// reconcileProcessesAfterLoad runs once, during LoadTracker, when process execution
// is enabled and durable state has just been read. A restart severs Steward from
// every process it supervised: the *os.Process handles, the monitor goroutines,
// and — permanently — the stdout/stderr pipes are all gone. For each instance the
// state file records as RUNNING or HIBERNATED with a command spec and a pid, it does
// the one honest thing it still can: a best-effort liveness probe (signal 0) on the
// stored pid.
//
//   - pid gone → the process did not survive the restart; the instance is
//     transitioned to STOPPED (never FAILED) with last_exit_reason "supervision_lost"
//     and a clear WARN, so the lost supervision is visible rather than a phantom
//     RUNNING that maps to nothing.
//   - pid alive → the process outlived Steward (children are reparented to init on
//     Steward's exit). Steward REGAINS liveness-based control — it can still
//     stop/hibernate/resume the process by pid — but it has NOT regained the
//     process's stdout/stderr (those fds are gone forever) and cannot Wait()/reap it
//     or proactively detect a future crash. The instance keeps its status and is
//     reattached in this deliberately degraded, liveness-only mode, with a WARN
//     naming exactly that limitation.
//
// Any STOPPED correction is persisted before LoadTracker returns, so the durable
// state reflects the reconciled reality. It runs during construction, before the
// tracker is shared, so it needs no lock.
func (t *Tracker) reconcileProcessesAfterLoad() {
	changed := false
	for ref, inst := range t.byRef {
		if inst.Status != StatusRunning && inst.Status != StatusHibernated {
			continue
		}
		_, hasCommand, err := parseProcessSpec(inst.Spec)
		if !hasCommand || err != nil {
			continue
		}
		if inst.PID <= 0 {
			// A live-process status with no usable pid: nothing to probe or reattach.
			t.markSupervisionLost(inst, "no usable pid was recorded")
			changed = true
			continue
		}
		proc, ferr := os.FindProcess(inst.PID)
		if ferr != nil || !processAlive(proc) {
			t.markSupervisionLost(inst, "its pid did not survive the restart")
			changed = true
			continue
		}
		if !reattachIdentityConfirmed(inst.ProcStartToken, inst.PID) {
			// The pid is alive but is NOT provably the process Steward spawned: the OS may
			// have reused it for an unrelated process (a cron job, a database, sshd), or the
			// recorded identity witness is missing/unreadable. Reattaching would let a later
			// stop/hibernate/destroy signal a STRANGER's pid, so fail closed — Steward does
			// not touch that pid and reports supervision lost instead. This is what turns a
			// bare "pid alive" into a real "MY process is alive" check.
			t.markSupervisionLost(inst, "its pid is alive but is not the process Steward spawned (pid reuse) or its identity could not be verified; Steward did NOT signal that pid")
			changed = true
			continue
		}
		t.procs[ref] = &supervisedProcess{proc: proc, reattached: true}
		t.logger.Warn("reattached to a supervised process that outlived a Steward restart, in DEGRADED mode: liveness-checking and stop/hibernate/resume by pid are regained, but its stdout/stderr are gone permanently and a future unexpected exit can no longer be detected proactively",
			"runtime_ref", ref, "instance_id", inst.InstanceID, "pid", inst.PID, "status", inst.Status)
	}
	if changed {
		if err := t.persistLocked(); err != nil {
			t.logger.Error("failed to persist reconciled state after a restart; the correction will be re-applied on the next load", "err", err)
		}
	}
}

// markSupervisionLost transitions a reload-orphaned instance to STOPPED. cause names
// why the reattach could not happen (pid gone, pid reused by a stranger, no witness),
// so the single WARN tells an operator exactly what Steward observed and did. The
// caller (reconcileProcessesAfterLoad) persists the batch of corrections afterward.
func (t *Tracker) markSupervisionLost(inst *Instance, cause string) {
	priorStatus := inst.Status
	lostPID := inst.PID
	inst.Status = StatusStopped
	inst.PID = 0
	inst.ProcStartToken = ""
	inst.LastExitReason = exitReasonSupervisionLost
	t.logger.Warn("a supervised process could not be reattached after a Steward restart; instance transitioned to STOPPED (supervision lost): "+cause,
		"instance_id", inst.InstanceID, "lost_pid", lostPID, "prior_status", priorStatus)
}
