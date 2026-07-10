package main

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

// TestRateLimitStartupLogReflectsConfig is the integration check for the inbound
// rate-limiter wiring: with the inbound listener bound, steward logs whether
// per-source throttling is enabled — an INFO line naming the configured rate by
// default, and a WARN when it is disabled with -max-requests-per-second 0, so an
// operator can see at a glance whether the flood surface is throttled.
func TestRateLimitStartupLogReflectsConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	t.Run("enabled by default", func(t *testing.T) {
		lines, waitErr := runStewardAndSignal(t, bin, []string{"-addr", "127.0.0.1:0"}, "steward listening")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
		joined := strings.Join(lines, "\n")
		if !strings.Contains(joined, "inbound rate limiting enabled") {
			t.Errorf("expected the enabled-by-default rate-limit log line:\n%s", joined)
		}
		// The default budget is 20 requests/second per source; pin it so a changed
		// default is a visible, deliberate edit rather than a silent drift.
		if !strings.Contains(joined, `"max_requests_per_second_per_source":20`) {
			t.Errorf("expected the default rate (20/s per source) in the startup log:\n%s", joined)
		}
	})

	t.Run("disabled with zero", func(t *testing.T) {
		lines, waitErr := runStewardAndSignal(t, bin,
			[]string{"-addr", "127.0.0.1:0", "-max-requests-per-second", "0"}, "steward listening")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
		if !strings.Contains(strings.Join(lines, "\n"), "inbound rate limiting disabled") {
			t.Errorf("expected the disabled rate-limit WARN when -max-requests-per-second is 0:\n%s", strings.Join(lines, "\n"))
		}
	})
}

// integrationCoverDir is the directory the instrumented steward subprocess writes
// its coverage counters to, or "" to disable integration coverage. It is set by
// scripts/coverage.sh (and the coverage CI job) via STEWARD_TEST_COVERDIR.
//
// It is deliberately NOT GOCOVERDIR: `go test` overwrites GOCOVERDIR in the test
// process env with its own managed directory, which also collects the go-test
// test-binary's coverage pods. Keeping the standalone binary's counters in their
// own dir, injected as GOCOVERDIR per-subprocess below, keeps `go tool covdata`'s
// input a clean single-meta set instead of a mix of test-binary and real-binary
// pods; the coverage script unions the resulting profile with the unit profile.
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

// TestParseLogLevel pins task 2's parser: the level name is case-insensitive and
// surrounding whitespace is trimmed, and any other value fails closed with a
// message naming the bad value and the accepted set — never a silent default.
func TestParseLogLevel(t *testing.T) {
	valid := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"INFO":    slog.LevelInfo, // case-insensitive
		"  warn ": slog.LevelWarn, // surrounding whitespace trimmed
		"Error":   slog.LevelError,
	}
	for in, want := range valid {
		got, err := parseLogLevel(in)
		if err != nil {
			t.Fatalf("parseLogLevel(%q): unexpected err %v", in, err)
		}
		if got != want {
			t.Fatalf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}

	_, err := parseLogLevel("verbose")
	if err == nil {
		t.Fatal("parseLogLevel(\"verbose\") must return an error, not a silent default")
	}
	if !strings.Contains(err.Error(), "verbose") || !strings.Contains(err.Error(), "debug, info, warn, error") {
		t.Fatalf("error %q must name the bad value and the accepted set", err)
	}
}

// TestVersionFlag pins task 1: -version prints a version string and exits 0
// before binding any port or starting the uplink loop, and it short-circuits the
// flag-level startup guards so it still reports even alongside otherwise-fatal
// flags.
func TestVersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := filepath.Join(t.TempDir(), "steward")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	t.Run("prints version and exits zero without starting the server", func(t *testing.T) {
		out, err := exec.Command(bin, "-version").CombinedOutput()
		if err != nil {
			t.Fatalf("-version must exit 0, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "steward") {
			t.Errorf("-version output does not name steward:\n%s", out)
		}
		// It must short-circuit before any listener binds.
		if strings.Contains(string(out), "steward listening") {
			t.Errorf("-version must not start the HTTP server:\n%s", out)
		}
	})

	t.Run("short-circuits the flag-level startup guards", func(t *testing.T) {
		// -version is handled before the -max-instances / -log-level / listener
		// guards, so an otherwise-fatal flag combination still prints version and
		// exits 0 rather than failing closed on those.
		out, err := exec.Command(bin, "-version", "-max-instances=-5", "-disable-inbound-listener").CombinedOutput()
		if err != nil {
			t.Fatalf("-version must exit 0 even with otherwise-invalid flags, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "steward") {
			t.Errorf("-version output does not name steward:\n%s", out)
		}
	})
}

// TestLogLevelFlag pins task 2's wiring: a garbage level (flag or env) fails
// closed at startup naming the bad value and the accepted set, and a valid level
// starts and shuts down cleanly.
func TestLogLevelFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := filepath.Join(t.TempDir(), "steward")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	t.Run("invalid -log-level flag fails closed", func(t *testing.T) {
		out, err := exec.Command(bin, "-log-level", "verbose", "-addr", "127.0.0.1:0").CombinedOutput()
		if err == nil {
			t.Fatalf("expected a non-zero exit on an invalid -log-level, got success:\n%s", out)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected an ExitError, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "verbose") {
			t.Errorf("error does not name the bad value:\n%s", out)
		}
		if !strings.Contains(string(out), "debug, info, warn, error") {
			t.Errorf("error does not name the accepted levels:\n%s", out)
		}
	})

	t.Run("invalid STEWARD_LOG_LEVEL env fails closed", func(t *testing.T) {
		cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
		cmd.Env = append(os.Environ(), "STEWARD_LOG_LEVEL=chatty")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected a non-zero exit on an invalid STEWARD_LOG_LEVEL, got success:\n%s", out)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected an ExitError, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "chatty") {
			t.Errorf("error does not name the bad value:\n%s", out)
		}
	})

	t.Run("valid level starts clean", func(t *testing.T) {
		// "steward listening" is an INFO line, visible at debug; the process must
		// bind, stay up, and shut down cleanly on SIGTERM.
		lines, waitErr := runStewardAndSignal(t, bin, []string{"-log-level", "debug", "-addr", "127.0.0.1:0"}, "steward listening")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
	})
}

// TestNonPositiveMaxInstancesExitsNonZero pins task 4: a non-positive
// -max-instances (via flag or env) is a fail-closed startup error naming the flag
// and the fix, never a silent override to the 1024 default the operator did not
// ask for.
func TestNonPositiveMaxInstancesExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := filepath.Join(t.TempDir(), "steward")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	assertFailsClosed := func(t *testing.T, cmd *exec.Cmd) {
		t.Helper()
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected a non-zero exit, got success:\n%s", out)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("expected an ExitError, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "-max-instances") {
			t.Errorf("error does not name -max-instances:\n%s", out)
		}
		if !strings.Contains(string(out), "positive") {
			t.Errorf("error does not tell the operator to pass a positive value:\n%s", out)
		}
	}

	t.Run("flag zero", func(t *testing.T) {
		assertFailsClosed(t, exec.Command(bin, "-max-instances", "0", "-addr", "127.0.0.1:0"))
	})
	t.Run("flag negative", func(t *testing.T) {
		assertFailsClosed(t, exec.Command(bin, "-max-instances=-1", "-addr", "127.0.0.1:0"))
	})
	t.Run("env zero", func(t *testing.T) {
		cmd := exec.Command(bin, "-addr", "127.0.0.1:0")
		cmd.Env = append(os.Environ(), "STEWARD_MAX_INSTANCES=0")
		assertFailsClosed(t, cmd)
	})
}

// writeConfigFile writes body to a temp JSON config file and returns its path.
func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

// assertFailsWith runs cmd, asserts it exits non-zero with an ExitError, and that
// its combined output contains every substring in want. It supplies stewardEnv()
// (so integration coverage is captured) only when the caller has not already set an
// environment — a caller injecting env vars uses stewardEnv("KEY=val") itself.
func assertFailsWith(t *testing.T, cmd *exec.Cmd, want ...string) {
	t.Helper()
	if cmd.Env == nil {
		cmd.Env = stewardEnv()
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	for _, w := range want {
		if !strings.Contains(string(out), w) {
			t.Errorf("output does not contain %q:\n%s", w, out)
		}
	}
}

// assertExitsZero runs cmd, asserts a clean exit 0, and that stdout/stderr contains
// wantStdout (when non-empty). Env handling matches assertFailsWith.
func assertExitsZero(t *testing.T, cmd *exec.Cmd, wantStdout string) {
	t.Helper()
	if cmd.Env == nil {
		cmd.Env = stewardEnv()
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected a clean exit 0, got %v\n%s", err, out)
	}
	if wantStdout != "" && !strings.Contains(string(out), wantStdout) {
		t.Errorf("output does not contain %q:\n%s", wantStdout, out)
	}
}

// TestCheckConfigValid pins task 1's happy path: -check-config validates a good
// configuration and exits 0 WITHOUT binding a port, serving, or starting/dialing
// the uplink loop.
func TestCheckConfigValid(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	t.Run("exits zero and binds no port", func(t *testing.T) {
		// Occupy a port and hold it for the whole subprocess run. If -check-config
		// tried to bind -addr it would fail with "address already in use"; a clean
		// exit 0 on the occupied addr proves it created no listener.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupy a port: %v", err)
		}
		defer ln.Close()
		occupied := ln.Addr().String()

		cmd := exec.Command(bin, "-check-config", "-addr", occupied)
		cmd.Env = stewardEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("-check-config must exit 0 without binding -addr (port is occupied), got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "configuration valid") {
			t.Errorf("-check-config did not print the validation success line:\n%s", out)
		}
		if strings.Contains(string(out), "steward listening") {
			t.Errorf("-check-config must not start the HTTP server:\n%s", out)
		}
	})

	t.Run("valid uplink config does not start or dial the poll loop", func(t *testing.T) {
		cred := writeValidCredentialFile(t)
		// A syntactically valid URL pointed at a closed port: NewPoller validates it
		// but never dials; only Poller.Run (never called by -check-config) would.
		cmd := exec.Command(bin, "-check-config",
			"-uplink-url", "http://127.0.0.1:1",
			"-uplink-credential-file", cred,
		)
		cmd.Env = stewardEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("-check-config on a valid uplink config must exit 0, got %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "configuration valid") {
			t.Errorf("-check-config did not print the validation success line:\n%s", out)
		}
		// A dry run validates a config; it does not enable anything. The progress
		// logs must stay silent so the output is not misleading.
		if strings.Contains(string(out), "uplink enabled") {
			t.Errorf("-check-config must not report the uplink as enabled:\n%s", out)
		}
	})
}

// TestCheckConfigInvalidMatchesRealStartup pins the core promise of task 1: on every
// category of invalid config, -check-config exits non-zero with the SAME actionable
// message a real startup would — proven by running both the real startup path and
// the dry run with the same config and asserting both fail with the same markers.
func TestCheckConfigInvalidMatchesRealStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	validCred := writeValidCredentialFile(t)
	missingCred := filepath.Join(t.TempDir(), "no-such-credential.json")
	corruptState := filepath.Join(t.TempDir(), "corrupt-state.json")
	if err := os.WriteFile(corruptState, []byte("not valid steward state json"), 0o600); err != nil {
		t.Fatalf("write corrupt state file: %v", err)
	}

	cases := []struct {
		name string
		args []string // the invalid-config flags, shared by both invocations
		want []string // substrings both the real boot and the dry run must emit
	}{
		{"bad log level", []string{"-log-level", "verbose"}, []string{"verbose", "debug, info, warn, error"}},
		{"non-positive max-instances", []string{"-max-instances", "0"}, []string{"-max-instances", "positive"}},
		{"malformed uplink url", []string{"-uplink-url", "control-plane.example", "-uplink-credential-file", validCred}, []string{"control-plane.example", "http"}},
		{"missing credential file", []string{"-uplink-url", "http://control-plane.example", "-uplink-credential-file", missingCred}, []string{missingCred}},
		{"uplink url without credential file", []string{"-uplink-url", "http://control-plane.example"}, []string{"-uplink-credential-file"}},
		{"corrupt state file", []string{"-state-file", corruptState}, []string{corruptState}},
		{"malformed addr", []string{"-addr", "0.0.0.0.8080"}, []string{"0.0.0.0.8080"}},
		{"addr port out of range", []string{"-addr", "127.0.0.1:99999"}, []string{"127.0.0.1:99999", "99999"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Real startup fails closed on this config, before binding a port...
			realArgs := append([]string{"-addr", "127.0.0.1:0"}, tc.args...)
			assertFailsWith(t, exec.Command(bin, realArgs...), tc.want...)
			// ...and -check-config fails closed identically.
			checkArgs := append([]string{"-check-config"}, tc.args...)
			assertFailsWith(t, exec.Command(bin, checkArgs...), tc.want...)
		})
	}
}

// TestCheckConfigIgnoresAddrWhenInboundDisabled pins the guard on the new -addr
// validation: an uplink-only node (-disable-inbound-listener) never binds -addr, so
// a garbage -addr there must not fail a config that would otherwise be valid — the
// unconditional check would be a false positive for exactly the deployment shape
// -disable-inbound-listener exists for.
func TestCheckConfigIgnoresAddrWhenInboundDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	cred := writeValidCredentialFile(t)

	assertExitsZero(t, exec.Command(bin, "-check-config",
		"-addr", "garbage",
		"-disable-inbound-listener",
		"-uplink-url", "http://127.0.0.1:1",
		"-uplink-credential-file", cred,
	), "configuration valid")
}

// TestConfigFileValueApplied pins task 2's read-and-apply: a valid JSON config is
// accepted, and a value it carries actually reaches the validation sequence (proven
// by a config-only invalid value failing closed with its message).
func TestConfigFileValueApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	t.Run("a valid JSON config is accepted", func(t *testing.T) {
		cfg := writeConfigFile(t, `{"addr":"127.0.0.1:0","max_instances":16,"log_level":"debug","uplink_poll_interval":"20s"}`)
		assertExitsZero(t, exec.Command(bin, "-check-config", "-config", cfg), "configuration valid")
	})

	t.Run("a config-file value is read and applied", func(t *testing.T) {
		// With no flag or env for log-level, the file's value is what gets validated;
		// an invalid one must fail closed naming it, proving the file was applied
		// rather than silently ignored.
		cfg := writeConfigFile(t, `{"log_level":"verbose"}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), "verbose", "debug, info, warn, error")
	})

	t.Run("uplink settings from the file are applied and validated", func(t *testing.T) {
		// A whole uplink-only node configured from the file: a syntactically valid
		// URL, a real credential file, and the inbound listener disabled. The
		// resolved config must pass every check (valid URL, credential loads, and the
		// disable-inbound/uplink combination is allowed) without starting anything.
		cred := writeValidCredentialFile(t)
		cfg := writeConfigFile(t, fmt.Sprintf(
			`{"uplink_url":"http://127.0.0.1:1","uplink_credential_file":%q,"disable_inbound_listener":true}`, cred))
		assertExitsZero(t, exec.Command(bin, "-check-config", "-config", cfg), "configuration valid")
	})
}

// TestConfigFilePrecedence pins the precedence contract flag > env > config file.
// It uses log-level as the observable: the file supplies an INVALID value, and a
// higher-precedence VALID value winning makes -check-config exit 0, while the file's
// value winning would fail closed.
func TestConfigFilePrecedence(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	cfg := writeConfigFile(t, `{"log_level":"verbose"}`)

	t.Run("a flag overrides a config-file value", func(t *testing.T) {
		assertExitsZero(t, exec.Command(bin, "-check-config", "-config", cfg, "-log-level", "info"), "configuration valid")
	})

	t.Run("an env var overrides a config-file value", func(t *testing.T) {
		cmd := exec.Command(bin, "-check-config", "-config", cfg)
		cmd.Env = stewardEnv("STEWARD_LOG_LEVEL=info")
		assertExitsZero(t, cmd, "configuration valid")
	})

	t.Run("a flag overrides both an env var and a config-file value", func(t *testing.T) {
		// File says verbose (invalid), env says chatty (invalid), flag says info
		// (valid). A clean exit proves the flag beat both lower layers.
		cmd := exec.Command(bin, "-check-config", "-config", cfg, "-log-level", "info")
		cmd.Env = stewardEnv("STEWARD_LOG_LEVEL=chatty")
		assertExitsZero(t, cmd, "configuration valid")
	})
}

// TestMalformedConfigFileFailsClosed pins task 2's fail-closed loader: a garbage,
// unknown-key, trailing-data, or missing -config file is a startup error naming the
// file (never a silently-ignored or half-applied config), for a real boot and the
// dry run alike.
func TestMalformedConfigFileFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	t.Run("garbage JSON", func(t *testing.T) {
		cfg := writeConfigFile(t, `{not json`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), cfg)
		// The same malformed file also fails a real startup, before it binds a port.
		assertFailsWith(t, exec.Command(bin, "-config", cfg, "-addr", "127.0.0.1:0"), cfg)
	})

	t.Run("unknown key is rejected, not silently dropped", func(t *testing.T) {
		cfg := writeConfigFile(t, `{"max_instance":5}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), cfg, "unknown field")
	})

	t.Run("trailing data after the object", func(t *testing.T) {
		cfg := writeConfigFile(t, `{"addr":"127.0.0.1:0"}{}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), cfg, "trailing data")
	})

	t.Run("malformed duration value names the file and value", func(t *testing.T) {
		cfg := writeConfigFile(t, `{"uplink_poll_interval":"30sec"}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), cfg, "30sec")
	})

	t.Run("missing config file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-config.json")
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", missing), missing)
	})
}

// TestConfigFileAppliedToRealStartup proves the config file is honored by a REAL
// boot (not only by -check-config): a state_file from the file drives the durable-
// state path an actual startup logs, and a -state-file flag still overrides it.
func TestConfigFileAppliedToRealStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	fromFile := filepath.Join(t.TempDir(), "from-config-file.json")
	cfg := writeConfigFile(t, fmt.Sprintf(`{"state_file":%q}`, fromFile))

	t.Run("a config-file value drives real startup", func(t *testing.T) {
		lines, waitErr := runStewardAndSignal(t, bin, []string{"-config", cfg, "-addr", "127.0.0.1:0"}, "durable state enabled")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
		if !containsLine(lines, "durable state enabled", fromFile) {
			t.Errorf("real startup did not apply the config-file state_file %q:\n%s", fromFile, strings.Join(lines, "\n"))
		}
	})

	t.Run("a flag overrides the config-file value at real startup", func(t *testing.T) {
		fromFlag := filepath.Join(t.TempDir(), "from-flag.json")
		lines, waitErr := runStewardAndSignal(t, bin, []string{"-config", cfg, "-state-file", fromFlag, "-addr", "127.0.0.1:0"}, "durable state enabled")
		if waitErr != nil {
			t.Fatalf("expected a clean exit after SIGTERM, got %v\noutput:\n%s", waitErr, strings.Join(lines, "\n"))
		}
		if !containsLine(lines, "durable state enabled", fromFlag) {
			t.Errorf("the -state-file flag did not override the config-file value:\n%s", strings.Join(lines, "\n"))
		}
		if containsLine(lines, "durable state enabled", fromFile) {
			t.Errorf("the config-file state_file must not win over the -state-file flag:\n%s", strings.Join(lines, "\n"))
		}
	})
}

// containsLine reports whether any line contains every one of subs.
func containsLine(lines []string, subs ...string) bool {
	for _, line := range lines {
		all := true
		for _, s := range subs {
			if !strings.Contains(line, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
