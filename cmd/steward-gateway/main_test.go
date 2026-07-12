package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestRunVersionConfigurationAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "steward-gateway") {
		t.Fatalf("version code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run(context.Background(), []string{"-config", filepath.Join(t.TempDir(), "missing.json")}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "load configuration") {
		t.Fatalf("missing config code=%d stderr=%q", code, stderr.String())
	}
	directory, err := os.MkdirTemp("/tmp", "sg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("service-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "c.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: tokenPath, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "g"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), Routes: []gateway.Route{{ID: "local", BaseURL: "http://127.0.0.1:1", MaxConcurrent: 1}},
	}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"-check-config", "-config", configPath}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "configuration valid") {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if code := run(context.Background(), []string{"-unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid flag code=%d", code)
	}
}
