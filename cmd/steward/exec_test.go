package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCheckConfigEnableProcessExecValid: -check-config accepts process execution
// enabled with a valid (default) grace period, without binding a port or spawning
// anything.
func TestCheckConfigEnableProcessExecValid(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-check-config", "-enable-process-exec", "-allow-root-process-exec", "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("-check-config with -enable-process-exec must exit 0, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "configuration valid") {
		t.Errorf("-check-config did not print the validation success line:\n%s", out)
	}
}

func processExecTestConfig() resolvedConfig {
	return resolvedConfig{
		addr:                    "127.0.0.1:0",
		maxInstances:            16,
		uplinkCommandQueueDepth: 16,
		logLevel:                "info",
		enableProcessExec:       true,
		processStopGracePeriod:  time.Second,
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestListenerIsLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"LOCALHOST:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{":8080", false},
		{"192.0.2.10:8080", false},
		{"node.internal:8080", false},
		{"not-an-address", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := listenerIsLoopback(tt.addr); got != tt.want {
				t.Fatalf("listenerIsLoopback(%q)=%v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestProcessExecNonLoopbackRequiresAcknowledgement(t *testing.T) {
	originalUID := effectiveUID
	effectiveUID = func() int { return 1000 }
	t.Cleanup(func() { effectiveUID = originalUID })

	cfg := processExecTestConfig()
	cfg.addr = "0.0.0.0:8080"
	_, _, _, _, err := prepareRuntime(cfg, discardLogger(), true)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("non-loopback process exec error=%v, want explicit rejection", err)
	}

	cfg.allowNonLoopbackProcessExec = true
	_, _, _, auditLogger, err := prepareRuntime(cfg, discardLogger(), true)
	_ = auditLogger.Close()
	if err != nil {
		t.Fatalf("explicitly acknowledged non-loopback process exec: %v", err)
	}
}

func TestProcessExecRootRequiresAcknowledgement(t *testing.T) {
	originalUID := effectiveUID
	effectiveUID = func() int { return 0 }
	t.Cleanup(func() { effectiveUID = originalUID })

	cfg := processExecTestConfig()
	_, _, _, _, err := prepareRuntime(cfg, discardLogger(), true)
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root process exec error=%v, want explicit rejection", err)
	}

	cfg.allowRootProcessExec = true
	_, _, _, auditLogger, err := prepareRuntime(cfg, discardLogger(), true)
	_ = auditLogger.Close()
	if err != nil {
		t.Fatalf("explicitly acknowledged root process exec: %v", err)
	}
}

func TestProcessExecStateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{\"version\":1,\"instances\":[]}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateProcessExecStateFile(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("0644 state file error=%v, want actionable rejection", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProcessExecStateFile(path); err != nil {
		t.Fatalf("0600 state file rejected: %v", err)
	}
	if err := validateProcessExecStateFile(filepath.Join(t.TempDir(), "first-run.json")); err != nil {
		t.Fatalf("missing first-run state file rejected: %v", err)
	}
}

// TestCheckConfigNonPositiveGraceRejected: with execution enabled, a non-positive
// stop grace period is a fail-closed startup error naming the flag.
func TestCheckConfigNonPositiveGraceRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-check-config", "-enable-process-exec",
		"-process-stop-grace-period", "0s", "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit for a non-positive grace period, got success:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "process-stop-grace-period") {
		t.Errorf("startup error does not name -process-stop-grace-period:\n%s", out)
	}
}

// TestCheckConfigNonPositiveGraceIgnoredWhenExecDisabled: the grace period is only
// validated when execution is enabled; a non-positive value on an exec-disabled
// node must not fail a config that never uses it.
func TestCheckConfigNonPositiveGraceIgnoredWhenExecDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-check-config", "-process-stop-grace-period", "0s", "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a non-positive grace with exec disabled must be accepted, got %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "configuration valid") {
		t.Errorf("-check-config did not print the validation success line:\n%s", out)
	}
}

// TestEnableProcessExecMalformedEnvExitsNonZero: STEWARD_ENABLE_PROCESS_EXEC gates
// real command execution, so a set-but-unparseable value must fail closed, never
// silently pick the executing (or non-executing) side.
func TestEnableProcessExecMalformedEnvExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-check-config", "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv("STEWARD_ENABLE_PROCESS_EXEC=maybe")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit for STEWARD_ENABLE_PROCESS_EXEC=maybe, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "STEWARD_ENABLE_PROCESS_EXEC") {
		t.Errorf("startup error does not name the env var:\n%s", out)
	}
}

// TestProcessStopGraceMalformedEnvExitsNonZero: a set-but-unparseable duration is a
// fail-closed startup error naming the env var and the bad value.
func TestProcessStopGraceMalformedEnvExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-check-config", "-addr", "127.0.0.1:0")
	cmd.Env = stewardEnv("STEWARD_PROCESS_STOP_GRACE_PERIOD=10sec")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a non-zero exit for a malformed grace duration, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "STEWARD_PROCESS_STOP_GRACE_PERIOD") {
		t.Errorf("startup error does not name the env var:\n%s", out)
	}
}

// TestSchemaIncludesProcessExecFields: the -config JSON schema is generated by
// reflecting over fileConfig, so the two new keys appear automatically with the
// right types. This pins that they are present and typed as expected.
func TestSchemaIncludesProcessExecFields(t *testing.T) {
	raw, err := configSchemaJSON()
	if err != nil {
		t.Fatalf("configSchemaJSON: %v", err)
	}
	var schema struct {
		Properties map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if got := schema.Properties["enable_process_exec"]["type"]; got != "boolean" {
		t.Errorf("enable_process_exec type=%v, want boolean", got)
	}
	if got := schema.Properties["process_stop_grace_period"]["type"]; got != "string" {
		t.Errorf("process_stop_grace_period type=%v, want string", got)
	}
	if got := schema.Properties["allow_nonloopback_process_exec"]["type"]; got != "boolean" {
		t.Errorf("allow_nonloopback_process_exec type=%v, want boolean", got)
	}
	if got := schema.Properties["allow_root_process_exec"]["type"]; got != "boolean" {
		t.Errorf("allow_root_process_exec type=%v, want boolean", got)
	}
}
