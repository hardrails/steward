package main

import (
	"errors"
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
