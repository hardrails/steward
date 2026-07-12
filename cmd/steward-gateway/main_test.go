package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(value)
}
func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.String()
}

func TestRunServesReloadsAndShutsDown(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("service-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{Version: 1, ControlSocket: filepath.Join(directory, "c.sock"), ServiceAddress: "127.0.0.1:0",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), Routes: []gateway.Route{{ID: "local", BaseURL: "http://127.0.0.1:1", MaxConcurrent: 1}}}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	write := func() {
		raw, _ := json.Marshal(config)
		if err := os.WriteFile(filepath.Join(directory, "gateway.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr synchronizedBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-config", filepath.Join(directory, "gateway.json")}, &stdout, &stderr)
	}()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(config.ControlSocket); err == nil {
			break
		}
	}
	if _, err := os.Stat(config.ControlSocket); err != nil {
		cancel()
		t.Fatalf("control socket: %v stderr=%s", err, stderr.String())
	}
	config.Routes[0].MaxConcurrent = 2
	write()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && !strings.Contains(stderr.String(), "configuration reloaded"); time.Sleep(10 * time.Millisecond) {
	}
	if !strings.Contains(stderr.String(), "configuration reloaded") {
		cancel()
		t.Fatalf("reload output=%s", stderr.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
}
