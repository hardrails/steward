package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

// overwriteConfigFile rewrites an existing config file at path with body, so a
// test can reload the SAME -config path SIGHUP re-reads (writeConfigFile always
// creates a fresh temp file at a new path, which SIGHUP would not see).
func overwriteConfigFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("overwrite config file %q: %v", path, err)
	}
}

// freeAddr reserves a free loopback TCP port, closes it, and returns the address
// so a steward subprocess can bind it and the test can then drive real HTTP
// against it. Unlike "127.0.0.1:0", this yields a concrete address the test knows
// up front. The brief close-then-rebind window is the standard, low-risk approach
// for integration tests that need a known port.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// stewardProc is a running steward subprocess under test. A background scanner
// accumulates its combined stdout/stderr into lines; waitForLog polls them.
type stewardProc struct {
	t       *testing.T
	cmd     *exec.Cmd
	baseURL string
	mu      sync.Mutex
	lines   []string
	waitCh  chan error
}

// startSteward launches the steward binary bound to addr with the given extra
// args and begins accumulating its log lines.
func startSteward(t *testing.T, bin, addr string, args ...string) *stewardProc {
	t.Helper()
	full := append([]string{"-addr", addr}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Env = stewardEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start steward: %v", err)
	}
	p := &stewardProc{t: t, cmd: cmd, baseURL: "http://" + addr, waitCh: make(chan error, 1)}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			p.mu.Lock()
			p.lines = append(p.lines, scanner.Text())
			p.mu.Unlock()
		}
	}()
	go func() { p.waitCh <- cmd.Wait() }()
	return p
}

func (p *stewardProc) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

// waitForLog blocks until a logged line contains want, failing the test if the
// process exits first or the timeout elapses.
func (p *stewardProc) waitForLog(want string, timeout time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, l := range p.snapshot() {
			if strings.Contains(l, want) {
				return
			}
		}
		select {
		case err := <-p.waitCh:
			p.t.Fatalf("steward exited before logging %q (err=%v):\n%s", want, err, strings.Join(p.snapshot(), "\n"))
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("timed out waiting for %q:\n%s", want, strings.Join(p.snapshot(), "\n"))
		}
	}
}

// sighup sends SIGHUP to the process.
func (p *stewardProc) sighup() {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		p.t.Fatalf("send SIGHUP: %v", err)
	}
}

// shutdown sends SIGTERM and asserts a clean exit within 5s.
func (p *stewardProc) shutdown() {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-p.waitCh:
		if err != nil {
			p.t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", err, strings.Join(p.snapshot(), "\n"))
		}
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		p.t.Fatal("steward did not exit within 5s of SIGTERM")
	}
}

// provision issues POST /v1/instances for id and returns (status code, decoded
// body). The body is decoded into a small struct exposing runtime_ref.
func (p *stewardProc) provision(id string) (int, string) {
	p.t.Helper()
	resp, err := http.Post(p.baseURL+"/v1/instances", "application/json",
		strings.NewReader(fmt.Sprintf(`{"instance_id":%q}`, id)))
	if err != nil {
		p.t.Fatalf("POST /v1/instances %q: %v", id, err)
	}
	defer resp.Body.Close()
	var body struct {
		RuntimeRef string `json:"runtime_ref"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.RuntimeRef
}

// getStatus issues GET path and returns the status code.
func (p *stewardProc) getStatus(path string) int {
	p.t.Helper()
	resp, err := http.Get(p.baseURL + path)
	if err != nil {
		p.t.Fatalf("GET %q: %v", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// capabilitiesMaxInstances reads GET /v1/capabilities and returns its reported
// max_instances, proving the live tracker value is what the endpoint advertises.
func (p *stewardProc) capabilitiesMaxInstances() int {
	p.t.Helper()
	resp, err := http.Get(p.baseURL + "/v1/capabilities")
	if err != nil {
		p.t.Fatalf("GET /v1/capabilities: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		MaxInstances int `json:"max_instances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		p.t.Fatalf("decode capabilities: %v", err)
	}
	return body.MaxInstances
}

// listInstanceCount reads GET /v1/instances and returns how many are tracked.
func (p *stewardProc) listInstanceCount() int {
	p.t.Helper()
	resp, err := http.Get(p.baseURL + "/v1/instances")
	if err != nil {
		p.t.Fatalf("GET /v1/instances: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Instances []json.RawMessage `json:"instances"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		p.t.Fatalf("decode instances: %v", err)
	}
	return len(body.Instances)
}

// TestSIGHUPHigherLimitUnblocksProvisioning pins the raise-the-cap path against
// the real binary: a config-file max_instances of 2 (the controlling layer — no
// -max-instances flag or env), filled to capacity so a third provision is 503,
// then rewritten to 5 and reloaded via SIGHUP. Provisioning past the old limit
// then succeeds, and GET /v1/capabilities reports the new cap live.
func TestSIGHUPHigherLimitUnblocksProvisioning(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)
	addr := freeAddr(t)

	cfg := writeConfigFile(t, `{"max_instances":2}`)
	p := startSteward(t, bin, addr, "-config", cfg)
	p.waitForLog("steward listening", 5*time.Second)

	if code, _ := p.provision("a"); code != http.StatusCreated {
		t.Fatalf("provision a: got %d, want 201", code)
	}
	if code, _ := p.provision("b"); code != http.StatusCreated {
		t.Fatalf("provision b: got %d, want 201", code)
	}
	if code, _ := p.provision("c"); code != http.StatusServiceUnavailable {
		t.Fatalf("provision c at cap 2: got %d, want 503 capacity_exceeded", code)
	}
	if got := p.capabilitiesMaxInstances(); got != 2 {
		t.Fatalf("capabilities max_instances = %d before reload, want 2", got)
	}

	// Raise the cap in the SAME file path and reload it.
	overwriteConfigFile(t, cfg, `{"max_instances":5}`)
	p.sighup()
	p.waitForLog("sighup reload: max_instances updated", 5*time.Second)

	// The previously-blocked provision now succeeds, and we can fill up to 5.
	if code, _ := p.provision("c"); code != http.StatusCreated {
		t.Fatalf("provision c after raising cap to 5: got %d, want 201", code)
	}
	if code, _ := p.provision("d"); code != http.StatusCreated {
		t.Fatalf("provision d: got %d, want 201", code)
	}
	if code, _ := p.provision("e"); code != http.StatusCreated {
		t.Fatalf("provision e (5th, at new cap): got %d, want 201", code)
	}
	if code, _ := p.provision("f"); code != http.StatusServiceUnavailable {
		t.Fatalf("provision f past new cap 5: got %d, want 503", code)
	}
	if got := p.capabilitiesMaxInstances(); got != 5 {
		t.Fatalf("capabilities max_instances = %d after reload, want 5", got)
	}

	p.shutdown()
}

// TestSIGHUPLowerLimitDoesNotEvict is the safety test: lowering the cap below the
// live instance count must evict NOTHING. It fills to 5, rewrites the file to 2,
// SIGHUPs, then asserts all three guarantees: (a) every one of the 5 instances is
// still individually reachable (proving none were destroyed/force-stopped), (b) a
// brand-new provision is refused with 503 (the lowered cap blocks growth), and
// (c) GET /v1/capabilities reports the new, lower cap.
func TestSIGHUPLowerLimitDoesNotEvict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)
	addr := freeAddr(t)

	cfg := writeConfigFile(t, `{"max_instances":5}`)
	p := startSteward(t, bin, addr, "-config", cfg)
	p.waitForLog("steward listening", 5*time.Second)

	refs := map[string]string{}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		code, ref := p.provision(id)
		if code != http.StatusCreated || ref == "" {
			t.Fatalf("provision %q: got %d ref=%q, want 201 with a runtime_ref", id, code, ref)
		}
		refs[id] = ref
	}
	if got := p.listInstanceCount(); got != 5 {
		t.Fatalf("instance count before reload = %d, want 5", got)
	}

	// Lower the cap below the live count and reload.
	overwriteConfigFile(t, cfg, `{"max_instances":2}`)
	p.sighup()
	p.waitForLog("sighup reload: max_instances updated", 5*time.Second)

	// (a) No eviction: every previously-provisioned instance is still individually
	// reachable, and the list still holds all 5.
	for id, ref := range refs {
		if code := p.getStatus("/v1/instances/" + ref); code != http.StatusOK {
			t.Errorf("instance %q (ref %s) returned %d after lowering the cap, want 200 — it must not be evicted", id, ref, code)
		}
	}
	if got := p.listInstanceCount(); got != 5 {
		t.Errorf("instance count after lowering the cap = %d, want 5 (no eviction)", got)
	}

	// (b) A new provision is refused: count 5 >= new cap 2.
	if code, _ := p.provision("f"); code != http.StatusServiceUnavailable {
		t.Errorf("new provision after lowering the cap: got %d, want 503 capacity_exceeded", code)
	}

	// (c) The endpoint reports the new, lower cap.
	if got := p.capabilitiesMaxInstances(); got != 2 {
		t.Errorf("capabilities max_instances = %d after lowering, want 2", got)
	}

	p.shutdown()
}

// TestSIGHUPNoConfigFileIsDocumentedNoOp pins the documented no-op: with no
// -config file at startup, SIGHUP logs a clear "nothing to reload" line (not
// silence, not a crash), and the process keeps serving normally afterward.
func TestSIGHUPNoConfigFileIsDocumentedNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)
	addr := freeAddr(t)

	p := startSteward(t, bin, addr)
	p.waitForLog("steward listening", 5*time.Second)

	p.sighup()
	p.waitForLog("sighup reload: no -config file was set at startup", 5*time.Second)

	// It keeps serving — the SIGHUP did not shut it down or wedge it.
	if code := p.getStatus("/v1/healthz"); code != http.StatusOK {
		t.Fatalf("GET /v1/healthz after SIGHUP no-op: got %d, want 200 (process must stay up)", code)
	}

	p.shutdown()
}

// TestSIGHUPFlagPrecedenceWinsOverFile pins that the startup precedence model
// governs the live reload path too: a -max-instances flag set at startup takes
// precedence over the config file, so a SIGHUP re-read of a file carrying a
// DIFFERENT max_instances neither applies the file's value nor is silently
// ignored — it logs a clear rejection and the flag's value stays in force.
func TestSIGHUPFlagPrecedenceWinsOverFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)
	addr := freeAddr(t)

	cfg := writeConfigFile(t, `{"max_instances":9}`)
	p := startSteward(t, bin, addr, "-config", cfg, "-max-instances", "3")
	p.waitForLog("steward listening", 5*time.Second)

	if got := p.capabilitiesMaxInstances(); got != 3 {
		t.Fatalf("capabilities max_instances = %d at startup, want the flag's 3", got)
	}

	p.sighup()
	p.waitForLog("sighup reload: max_instances not applied", 5*time.Second)

	if got := p.capabilitiesMaxInstances(); got != 3 {
		t.Errorf("capabilities max_instances = %d after SIGHUP, want the flag's 3 unchanged", got)
	}

	p.shutdown()
}

// TestReloadMaxInstancesBranches is the cheap, subprocess-free unit test over
// reloadMaxInstances's branch logic: it drives each documented outcome directly
// with a real tracker and temp config files, asserting both the resulting live cap
// and the grep-friendly "sighup reload:" log line. It complements the coarse
// integration tests above and pins the branches for the coverage/mutation floors.
func TestReloadMaxInstancesBranches(t *testing.T) {
	newLoggerBuf := func() (*slog.Logger, *bytes.Buffer) {
		var buf bytes.Buffer
		return slog.New(slog.NewJSONHandler(&buf, nil)), &buf
	}

	t.Run("no config file is a documented no-op", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		reloadMaxInstances("", true, tr, logger)
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7 unchanged", got)
		}
		if !strings.Contains(buf.String(), "no -config file was set at startup") {
			t.Errorf("missing the documented-no-op log line:\n%s", buf.String())
		}
	})

	t.Run("unreadable/invalid file keeps the live cap", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		// An unknown key fails loadConfigFile fail-closed.
		cfg := writeConfigFile(t, `{"max_instance":5}`)
		reloadMaxInstances(cfg, true, tr, logger)
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7 unchanged on a bad file", got)
		}
		if !strings.Contains(buf.String(), "re-reading the -config file failed") {
			t.Errorf("missing the read-failure log line:\n%s", buf.String())
		}
	})

	t.Run("file without max_instances is nothing to reload", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		cfg := writeConfigFile(t, `{"log_level":"info"}`)
		reloadMaxInstances(cfg, true, tr, logger)
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7 unchanged", got)
		}
		if !strings.Contains(buf.String(), "has no max_instances key") {
			t.Errorf("missing the no-key log line:\n%s", buf.String())
		}
	})

	t.Run("flag/env precedence blocks the file value", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		cfg := writeConfigFile(t, `{"max_instances":42}`)
		reloadMaxInstances(cfg, false, tr, logger) // fileMayApply=false
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7 unchanged when a flag/env pinned it", got)
		}
		out := buf.String()
		if !strings.Contains(out, "not applied") || !strings.Contains(out, "takes precedence") {
			t.Errorf("missing the precedence-rejection log line:\n%s", out)
		}
	})

	t.Run("non-positive file value is rejected", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		cfg := writeConfigFile(t, `{"max_instances":0}`)
		reloadMaxInstances(cfg, true, tr, logger)
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7 unchanged on a non-positive value", got)
		}
		out := buf.String()
		if !strings.Contains(out, "invalid max_instances") || !strings.Contains(out, "positive integer") {
			t.Errorf("rejection must name the problem and the positive-integer rule:\n%s", out)
		}
	})

	t.Run("no-change value is reported and not re-applied", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		cfg := writeConfigFile(t, `{"max_instances":7}`)
		reloadMaxInstances(cfg, true, tr, logger)
		if got := tr.MaxInstances(); got != 7 {
			t.Errorf("cap = %d, want 7", got)
		}
		if !strings.Contains(buf.String(), "unchanged") {
			t.Errorf("missing the no-change log line:\n%s", buf.String())
		}
	})

	t.Run("valid new value updates the live cap", func(t *testing.T) {
		tr := runtime.NewTracker(7)
		logger, buf := newLoggerBuf()
		cfg := writeConfigFile(t, `{"max_instances":25}`)
		reloadMaxInstances(cfg, true, tr, logger)
		if got := tr.MaxInstances(); got != 25 {
			t.Errorf("cap = %d, want 25 after a valid reload", got)
		}
		out := buf.String()
		if !strings.Contains(out, "max_instances updated") {
			t.Errorf("missing the success log line:\n%s", out)
		}
		// The success line names both the old and new cap for the operator.
		if !strings.Contains(out, `"old_max_instances":7`) || !strings.Contains(out, `"new_max_instances":25`) {
			t.Errorf("success line must name the old and new caps:\n%s", out)
		}
	})
}
