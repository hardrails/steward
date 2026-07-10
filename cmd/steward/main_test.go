package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestEnvOrDuration(t *testing.T) {
	t.Run("unset falls back", func(t *testing.T) {
		if got := envOrDuration("STEWARD_TEST_UNSET", 10*time.Second); got != 10*time.Second {
			t.Fatalf("got %s, want 10s", got)
		}
	})
	t.Run("valid duration wins", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_INTERVAL", "30s")
		if got := envOrDuration("STEWARD_TEST_INTERVAL", 10*time.Second); got != 30*time.Second {
			t.Fatalf("got %s, want 30s", got)
		}
	})
	t.Run("invalid duration falls back", func(t *testing.T) {
		t.Setenv("STEWARD_TEST_INTERVAL", "not-a-duration")
		if got := envOrDuration("STEWARD_TEST_INTERVAL", 10*time.Second); got != 10*time.Second {
			t.Fatalf("got %s, want 10s", got)
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
	bin := filepath.Join(t.TempDir(), "steward")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	missing := filepath.Join(t.TempDir(), "no-such-credential.json")
	cmd := exec.Command(bin,
		"-uplink-url", "http://control-plane.example",
		"-uplink-credential-file", missing,
		"-addr", "127.0.0.1:0",
	)
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
	bin := filepath.Join(t.TempDir(), "steward")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	credPath := writeValidCredentialFile(t)

	const badURL = "control-plane.example"
	cmd := exec.Command(bin,
		"-uplink-url", badURL,
		"-uplink-credential-file", credPath,
		"-addr", "127.0.0.1:0",
	)
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
	bin := filepath.Join(t.TempDir(), "steward")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build steward: %v\n%s", err, out)
	}

	credPath := writeValidCredentialFile(t)

	cmd := exec.Command(bin,
		"-uplink-url", "http://127.0.0.1:1", // syntactically valid; never actually dialed by this test
		"-uplink-credential-file", credPath,
		"-uplink-poll-interval", "10m",
		"-addr", "127.0.0.1:0",
	)
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
