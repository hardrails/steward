package main

import (
	"bufio"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnvOr(t *testing.T) {
	t.Run("unset falls back", func(t *testing.T) {
		if got := envOr("STEWARD_TEST_UNSET", "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})
	t.Run("set value wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_ADDR", "0.0.0.0:9000")
		if got := envOr("STEWARD_TEST_ADDR", "fallback"); got != "0.0.0.0:9000" {
			t.Fatalf("got %q, want 0.0.0.0:9000", got)
		}
	})
	t.Run("empty value falls back", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_ADDR", "")
		if got := envOr("STEWARD_TEST_ADDR", "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})
}

func TestEnvOrInt(t *testing.T) {
	t.Run("unset falls back", func(t *testing.T) {
		if got := envOrInt("STEWARD_TEST_UNSET", 7); got != 7 {
			t.Fatalf("got %d, want 7", got)
		}
	})
	t.Run("valid int wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_MAX", "42")
		if got := envOrInt("STEWARD_TEST_MAX", 7); got != 42 {
			t.Fatalf("got %d, want 42", got)
		}
	})
	t.Run("invalid int falls back", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_MAX", "not-a-number")
		if got := envOrInt("STEWARD_TEST_MAX", 7); got != 7 {
			t.Fatalf("got %d, want 7", got)
		}
	})
}

func TestEnvBool(t *testing.T) {
	t.Run("unset falls back with no error", func(t *testing.T) {
		got, err := envBool("STEWARD_TEST_UNSET", true)
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if got != true {
			t.Fatalf("got %v, want true", got)
		}
	})
	t.Run(`"true" wins`, func(t *testing.T) {
		t.Setenv("STEWARD_TEST_BOOL", "true")
		got, err := envBool("STEWARD_TEST_BOOL", false)
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if got != true {
			t.Fatalf("got %v, want true", got)
		}
	})
	t.Run(`"1" wins`, func(t *testing.T) {
		t.Setenv("STEWARD_TEST_BOOL", "1")
		got, err := envBool("STEWARD_TEST_BOOL", false)
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if got != true {
			t.Fatalf("got %v, want true", got)
		}
	})
	t.Run("invalid value is a fail-closed error naming the value and key, not a silent fallback", func(t *testing.T) {
		// A "yes"/"on"/typo must NOT silently fall back -- an operator who tried to
		// set a security-relevant flag and typo'd it must see a startup error, not
		// silently get the opposite of what they configured.
		t.Setenv("STEWARD_TEST_BOOL", "yes")
		_, err := envBool("STEWARD_TEST_BOOL", true)
		if err == nil {
			t.Fatal("expected an error for an invalid boolean, got nil")
		}
		if !strings.Contains(err.Error(), "STEWARD_TEST_BOOL") || !strings.Contains(err.Error(), "yes") {
			t.Fatalf("error %q does not name the key and the bad value", err.Error())
		}
	})
}

func TestEnvDuration(t *testing.T) {
	t.Run("unset falls back with no error", func(t *testing.T) {
		got, err := envDuration("STEWARD_TEST_UNSET", 10*time.Second)
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if got != 10*time.Second {
			t.Fatalf("got %s, want 10s", got)
		}
	})
	t.Run("valid duration wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_INTERVAL", "30s")
		got, err := envDuration("STEWARD_TEST_INTERVAL", 10*time.Second)
		if err != nil {
			t.Fatalf("unexpected err %v", err)
		}
		if got != 30*time.Second {
			t.Fatalf("got %s, want 30s", got)
		}
	})
	t.Run("invalid duration is a fail-closed error naming the value and key", func(t *testing.T) {
		// A "30sec" typo for "30s" must NOT silently fall back to the default — it is
		// a startup config error the operator has to see and fix.
		t.Setenv("STEWARD_TEST_INTERVAL", "30sec")
		_, err := envDuration("STEWARD_TEST_INTERVAL", 10*time.Second)
		if err == nil {
			t.Fatal("a set-but-invalid duration must return an error, not fall back silently")
		}
		if !strings.Contains(err.Error(), "30sec") {
			t.Errorf("error %q does not name the bad value", err)
		}
		if !strings.Contains(err.Error(), "STEWARD_TEST_INTERVAL") {
			t.Errorf("error %q does not name the env var", err)
		}
	})
}

// TestUplinkBadCredentialExitsNonZero is the integration check for the fail-closed
// startup: with the uplink enabled but pointed at a missing credential file,
// steward must exit non-zero with a message naming the path — never start with a
// silently-disabled uplink.
func TestUplinkBadCredentialExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	missing := filepath.Join(t.TempDir(), "no-such-credential.json")
	cmd := exec.Command(bin,
		"-uplink-url", "http://control-plane.example",
		"-uplink-credential-file", missing,
		"-addr", "127.0.0.1:0",
	)
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit on a missing credential, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), missing) {
		t.Errorf("startup error does not name the missing credential path %q:\n%s", missing, out)
	}
}

// TestUplinkBadURLExitsNonZero is the integration check for the fail-closed
// startup with a malformed -uplink-url: a bare hostname like
// "control-plane.example" (the plausible forgot-"http://" operator typo) must be
// a startup error naming the bad value and what a valid one looks like — never a
// silently-started loop that logs "uplink enabled" and then fails every poll
// forever.
func TestUplinkBadURLExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	credPath := writeValidCredentialFile(t)

	const badURL = "control-plane.example"
	cmd := exec.Command(bin,
		"-uplink-url", badURL,
		"-uplink-credential-file", credPath,
		"-addr", "127.0.0.1:0",
	)
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit on a malformed -uplink-url, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), badURL) {
		t.Errorf("startup error does not name the bad URL %q:\n%s", badURL, out)
	}
	if !strings.Contains(string(out), "http") {
		t.Errorf("startup error does not name what a valid URL looks like (http(s)):\n%s", out)
	}
	if strings.Contains(string(out), "uplink enabled") {
		t.Errorf("uplink must not report enabled when the URL is malformed:\n%s", out)
	}
}

// TestUplinkPollIntervalAboveCapLogsWarning is the integration check for the
// silent-clamp finding: a -uplink-poll-interval above the 5-minute backoff cap
// must produce a startup WARN naming both the configured and effective interval,
// not a silent switch to the shorter cadence. The uplink URL only needs to be
// syntactically valid — the poller does not actually connect during startup.
func TestUplinkPollIntervalAboveCapLogsWarning(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	credPath := writeValidCredentialFile(t)

	cmd := exec.Command(bin,
		"-uplink-url", "http://127.0.0.1:1", // syntactically valid; never actually dialed by this test
		"-uplink-credential-file", credPath,
		"-uplink-poll-interval", "10m",
		"-addr", "127.0.0.1:0",
	)
	cmd.Env = stewardEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start steward: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	lineCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "poll interval exceeds the backoff cap") {
				lineCh <- line
				return
			}
		}
		close(lineCh)
	}()

	select {
	case line, ok := <-lineCh:
		if !ok {
			t.Fatal("steward exited or closed stdout before logging the poll-interval warning")
		}
		if !strings.Contains(line, "10m0s") {
			t.Errorf("warning does not name the configured interval 10m0s:\n%s", line)
		}
		if !strings.Contains(line, "5m0s") {
			t.Errorf("warning does not name the effective 5m cap:\n%s", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the poll-interval warning log")
	}
}

// TestUplinkInvalidPollIntervalEnvExitsNonZero is the integration check for the
// silent-fallback finding: a SET-but-invalid STEWARD_UPLINK_POLL_INTERVAL (a
// "30sec" typo for "30s") must be a fail-closed startup error naming the bad value
// and the env var, never a silent fall back to the 10s default.
func TestUplinkInvalidPollIntervalEnvExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	const badValue = "30sec"
	cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv("STEWARD_UPLINK_POLL_INTERVAL=" + badValue)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit on an invalid poll-interval env var, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), badValue) {
		t.Errorf("startup error does not name the bad value %q:\n%s", badValue, out)
	}
	if !strings.Contains(string(out), "STEWARD_UPLINK_POLL_INTERVAL") {
		t.Errorf("startup error does not name the env var:\n%s", out)
	}
}

// TestDisableInboundListenerWithoutUplinkExitsNonZero is the fail-closed startup
// check for a contradictory configuration: -disable-inbound-listener without
// -uplink-url would leave a node with neither an inbound listener nor an
// outbound uplink — unreachable in both directions. Steward must exit non-zero
// with a message naming both flags, never start dark.
func TestDisableInboundListenerWithoutUplinkExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin,
		"-disable-inbound-listener",
		"-addr", "127.0.0.1:0",
	)
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit with -disable-inbound-listener and no -uplink-url, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "-disable-inbound-listener") {
		t.Errorf("startup error does not name -disable-inbound-listener:\n%s", out)
	}
	if !strings.Contains(string(out), "-uplink-url") {
		t.Errorf("startup error does not name -uplink-url:\n%s", out)
	}
}

// TestDisableInboundListenerMalformedEnvExitsNonZero is the hosted-review
// finding (P2/security, "Invalid Disable Env Binds"): STEWARD_DISABLE_INBOUND_LISTENER
// is access-control-relevant, so a set-but-unparseable value ("yes", "on", a
// typo) must fail closed at startup, not silently fall back to false (listener
// left open) -- an operator who tried to close the inbound surface and typo'd
// the env var must see an error, never silently get the opposite of what they
// configured.
func TestDisableInboundListenerMalformedEnvExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv("STEWARD_DISABLE_INBOUND_LISTENER=yes")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit for STEWARD_DISABLE_INBOUND_LISTENER=yes, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "STEWARD_DISABLE_INBOUND_LISTENER") {
		t.Errorf("startup error does not name the env var:\n%s", out)
	}
	if !strings.Contains(string(out), "yes") {
		t.Errorf("startup error does not name the bad value:\n%s", out)
	}
}

// runStewardAndSignal starts the steward binary with args, waits (within a 5s
// deadline) for a log line containing want, confirms the process is still
// running past that point, sends SIGTERM, and waits for it to exit. It returns
// every line logged and the error from waiting for the process (nil means a
// clean exit).
func runStewardAndSignal(t *testing.T, bin string, args []string, want string) (lines []string, waitErr error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = stewardEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start steward: %v", err)
	}

	lineCh := make(chan string, 64)
	go func() {
		defer close(lineCh)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
	}()

	deadline := time.After(5 * time.Second)
	found := false
	for !found {
		select {
		case line, ok := <-lineCh:
			if !ok {
				t.Fatalf("steward exited before logging %q:\n%s", want, strings.Join(lines, "\n"))
			}
			lines = append(lines, line)
			if strings.Contains(line, want) {
				found = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}

	// Confirm the process stays up rather than exiting right after the marker
	// line, before signaling it.
	select {
	case line, ok := <-lineCh:
		if !ok {
			t.Fatal("steward exited immediately after startup; expected it to stay running")
		}
		lines = append(lines, line)
	case <-time.After(200 * time.Millisecond):
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	for line := range lineCh {
		lines = append(lines, line)
	}

	return lines, cmd.Wait()
}

// TestDisableInboundListenerStartsCleanWithUplink is the integration check for
// the server-less startup path: with -disable-inbound-listener and -uplink-url
// both set, steward must log "inbound listener disabled" (never "steward
// listening"), stay running (no inbound HTTP server, no early exit), and shut
// down cleanly — no nil-pointer panic on the guarded srv.Shutdown — on SIGTERM.
func TestDisableInboundListenerStartsCleanWithUplink(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	credPath := writeValidCredentialFile(t)

	lines, waitErr := runStewardAndSignal(t, bin, []string{
		"-disable-inbound-listener",
		"-uplink-url", "http://127.0.0.1:1", // syntactically valid; never actually dialed by this test
		"-uplink-credential-file", credPath,
	}, "inbound listener disabled")
	if waitErr != nil {
		t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
	}
	for _, line := range lines {
		if strings.Contains(line, "steward listening") {
			t.Errorf("\"steward listening\" must never be logged when the inbound listener is disabled:\n%s", line)
		}
	}
}

// TestDisableInboundListenerShutsDownOnFatalPollRejection is the hosted-review
// finding (P1, "Fatal Uplink Leaves Zombie"): when the inbound listener is
// disabled, the uplink is the ONLY control path. If the poll loop gives up on
// its own (classFatal -- a 401/403 credential rejection, not a shutdown-driven
// context cancellation), nothing used to signal the process to exit: main
// would block on <-ctx.Done() forever, serving nothing and doing nothing,
// while an operator's process-liveness check saw it as "up". This asserts the
// fix: the process exits ON ITS OWN, with no SIGTERM sent, once the poll loop
// fatally gives up with no listener to fall back to.
func TestDisableInboundListenerShutsDownOnFatalPollRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	// A fake control plane that rejects every poll with 401 -- classFatal in
	// the poller's classification, the same trigger a real revoked/rotated
	// credential would produce.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer fake.Close()

	credPath := writeValidCredentialFile(t)

	cmd := exec.Command(bin,
		"-disable-inbound-listener",
		"-uplink-url", fake.URL,
		"-uplink-credential-file", credPath,
		"-uplink-poll-interval", "20ms",
	)
	cmd.Env = stewardEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start steward: %v", err)
	}

	var lines []string
	lineCh := make(chan string, 64)
	go func() {
		defer close(lineCh)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-lineCh:
			if !ok {
				lineCh = nil
				continue
			}
			lines = append(lines, line)
		case waitErr := <-waitCh:
			// No SIGTERM was ever sent -- the process had to exit on its own.
			if waitErr != nil {
				t.Fatalf("expected a clean self-triggered exit, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
			}
			joined := strings.Join(lines, "\n")
			if !strings.Contains(joined, "credential rejected") {
				t.Errorf("expected the poller's fatal-rejection log, got:\n%s", joined)
			}
			if !strings.Contains(joined, "no inbound listener is configured") {
				t.Errorf("expected the zombie-prevention shutdown log naming the cause, got:\n%s", joined)
			}
			return
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatalf("timed out waiting for steward to exit on its own (zombie process):\n%s", strings.Join(lines, "\n"))
		}
	}
}

// TestListenerEnabledByDefault is the regression guard: with the flag unset,
// startup is exactly today's — the listener binds -addr and "steward
// listening" is logged — in both the uplink-off and uplink-on configs.
func TestListenerEnabledByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	t.Run("uplink off", func(t *testing.T) {
		lines, waitErr := runStewardAndSignal(t, bin, []string{"-addr", "127.0.0.1:0"}, "steward listening")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
	})

	t.Run("uplink on", func(t *testing.T) {
		credPath := writeValidCredentialFile(t)
		lines, waitErr := runStewardAndSignal(t, bin, []string{
			"-addr", "127.0.0.1:0",
			"-uplink-url", "http://127.0.0.1:1", // syntactically valid; never actually dialed by this test
			"-uplink-credential-file", credPath,
		}, "steward listening")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
	})
}

// integrationCoverDir is the directory the instrumented steward subprocess writes
// its coverage counters to, or "" to disable integration coverage. It is set by
// scripts/coverage.sh (and the coverage CI job) via STEWARD_TEST_COVERDIR.
//
// It is deliberately NOT GOCOVERDIR: `go test` overwrites GOCOVERDIR in the test
// process env with its own managed directory, and that directory also collects
// the go-test test-binary's coverage pods. `go tool covdata` will not merge the
// standalone binary's cmd/steward counters with the test binary's (their meta
// hashes differ — the test binary compiles main() but never calls it), so main()
// would be shadowed at 0%. Keeping the standalone binary's data in its own dir,
// injected as GOCOVERDIR per-subprocess below, keeps it a clean single-meta input
// that covdata reports honestly; the coverage script unions it with the unit
// profile.
func integrationCoverDir() string { return os.Getenv("STEWARD_TEST_COVERDIR") }

// buildSteward compiles the steward binary to a temp path and returns it. When
// integration coverage is enabled it builds with -cover so the REAL main() logic
// these subprocess tests already exercise — startup validation, uplink wiring,
// graceful shutdown — is counted. A plain `go build` binary is not
// coverage-instrumented, so that genuinely-run logic otherwise reports as 0%
// covered; the instrumented binary writes its counters (via GOCOVERDIR, set per
// subprocess by stewardEnv) to integrationCoverDir on exit. With coverage
// disabled (the normal `go test ./...` and the pre-commit hook) it builds plain
// and fast, exactly as before.
func buildSteward(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "steward")
	args := []string{"build", "-o", bin, "."}
	if integrationCoverDir() != "" {
		args = []string{"build", "-cover", "-o", bin, "."}
	}
	build := exec.Command("go", args...)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}
	return bin
}

// stewardEnv builds the environment for a steward subprocess. When integration
// coverage is enabled it points GOCOVERDIR at integrationCoverDir (replacing any
// GOCOVERDIR go test injected into this test process, so the standalone binary's
// counters land in our dedicated dir), then appends any extra "KEY=VALUE" entries
// the caller needs. It returns nil when nothing needs customizing, which leaves
// exec.Command's default of inheriting the parent environment.
func stewardEnv(extra ...string) []string {
	dir := integrationCoverDir()
	if dir == "" && len(extra) == 0 {
		return nil
	}
	base := os.Environ()
	env := make([]string, 0, len(base)+1+len(extra))
	for _, e := range base {
		if dir != "" && strings.HasPrefix(e, "GOCOVERDIR=") {
			continue // replace go test's managed GOCOVERDIR with our integration dir
		}
		env = append(env, e)
	}
	if dir != "" {
		env = append(env, "GOCOVERDIR="+dir)
	}
	return append(env, extra...)
}

// writeValidCredentialFile writes a valid uplink credential JSON file to a temp
// path and returns it, so tests exercising other startup failure modes don't
// also fail on a missing/corrupt credential.
func writeValidCredentialFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	const body = `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"tok"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write credential file: %v", err)
	}
	return path
}
