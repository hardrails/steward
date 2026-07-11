package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/executoruplink"
)

func TestReadTokenTrimsFileWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor-token")
	if err := os.WriteFile(path, []byte("development-only-executor-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := readToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "development-only-executor-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestReadTokenRejectsOverPermissiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor-token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("world-readable executor token was accepted")
	}
}

func TestExecutorMainServesHealthAndShutsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real executor binary")
	}
	bin := buildExecutor(t)
	socket := fakeDockerSocket(t, true)
	token := executorTokenFile(t)
	addr := freeAddress(t)
	cmd := exec.Command(bin, "-docker-socket", socket, "-token-file", token, "-addr", addr)
	cmd.Env = executorEnv()
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	url := "http://" + addr + "/v1/healthz"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if response, err := http.Get(url); err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	response, err := http.Get(url)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("executor health failed: response=%v err=%v output=%s", response, err, output.String())
	}
	response.Body.Close()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := waitCommand(cmd, 5*time.Second); err != nil {
		t.Fatalf("executor shutdown: %v output=%s", err, output.String())
	}
}

func TestExecutorMainRunsOutboundOnlyUplink(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real executor binary")
	}
	bin := buildExecutor(t)
	socket := fakeDockerSocket(t, true)
	token := executorTokenFile(t)
	var polls atomic.Int32
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/executor-uplink/poll" || r.Header.Get("Authorization") != "Bearer opaque" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer control.Close()
	dir := t.TempDir()
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{"version":1,"tenant_id":"tenant-a","node_id":"executor-1","credential":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err := executoruplink.InitializeStateStore(statePath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin,
		"-docker-socket", socket, "-token-file", token,
		"-disable-inbound-listener", "-uplink-url", control.URL,
		"-uplink-credential-file", credential,
		"-uplink-state-file", statePath,
		"-uplink-poll-interval", "10ms",
	)
	cmd.Env = executorEnv()
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for polls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if polls.Load() == 0 {
		t.Fatalf("executor never polled: %s", output.String())
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	if err := waitCommand(cmd, 5*time.Second); err != nil {
		t.Fatalf("outbound-only shutdown: %v output=%s", err, output.String())
	}
}

func TestExecutorMainFailsClosedOnMissingRunscAndPartialUplink(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	token := executorTokenFile(t)
	missingRunsc := exec.Command(bin, "-docker-socket", fakeDockerSocket(t, false), "-token-file", token)
	missingRunsc.Env = executorEnv()
	if output, err := missingRunsc.CombinedOutput(); err == nil || !strings.Contains(string(output), "runsc") {
		t.Fatalf("missing runsc did not fail closed: err=%v output=%s", err, output)
	}
	partial := exec.Command(bin,
		"-docker-socket", fakeDockerSocket(t, true), "-token-file", token,
		"-uplink-url", "http://127.0.0.1:1",
	)
	partial.Env = executorEnv()
	if output, err := partial.CombinedOutput(); err == nil || !strings.Contains(string(output), "uplink-credential-file") {
		t.Fatalf("partial uplink did not fail closed: err=%v output=%s", err, output)
	}
}

func TestExecutorMainVersionNeedsNoDockerOrCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	command := exec.Command(bin, "-version")
	command.Env = executorEnv()
	output, err := command.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(output), "steward-executor ") {
		t.Fatalf("version: err=%v output=%s", err, output)
	}
}

func TestExecutorMainCheckConfigValidatesWithoutServing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	addr := freeAddress(t)
	command := exec.Command(bin,
		"-check-config",
		"-docker-socket", fakeDockerSocket(t, true),
		"-token-file", executorTokenFile(t),
		"-addr", addr,
	)
	command.Env = executorEnv()
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "executor configuration valid\n" {
		t.Fatalf("check config: err=%v output=%s", err, output)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("check-config bound the listener: %v", err)
	}
	listener.Close()
}

func TestExecutorMainCheckConfigValidatesEveryUplinkFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	dir := t.TempDir()
	credential := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credential, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	if err := executoruplink.InitializeStateStore(state); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-check-config",
		"-docker-socket", fakeDockerSocket(t, true),
		"-token-file", executorTokenFile(t),
		"-disable-inbound-listener",
		"-uplink-url", "http://127.0.0.1:1",
		"-uplink-credential-file", credential,
		"-uplink-state-file", state,
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		command := exec.Command(bin, args...)
		command.Env = executorEnv()
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := run(base...); err != nil || output != "executor configuration valid\n" {
		t.Fatalf("valid uplink files: err=%v output=%s", err, output)
	}

	missingCredential := append([]string(nil), base...)
	missingCredential[9] = filepath.Join(dir, "missing-credential.json")
	if output, err := run(missingCredential...); err == nil || !strings.Contains(output, "credential") {
		t.Fatalf("missing credential passed: err=%v output=%s", err, output)
	}

	missingState := append([]string(nil), base...)
	missingState[11] = filepath.Join(dir, "missing-state.json")
	if output, err := run(missingState...); err == nil || !strings.Contains(output, "state") {
		t.Fatalf("missing state passed: err=%v output=%s", err, output)
	}

	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a PEM CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	badTLS := append(append([]string(nil), base...), "-uplink-tls-ca-file", badCA)
	badTLS[7] = "https://control.invalid"
	if output, err := run(badTLS...); err == nil || !strings.Contains(output, "CA") {
		t.Fatalf("malformed CA passed: err=%v output=%s", err, output)
	}
}

func TestExecutorMainInitializesFenceOnceWithoutDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the real executor binary")
	}
	bin := buildExecutor(t)
	path := filepath.Join(t.TempDir(), "state.json")
	command := exec.Command(bin, "-initialize-uplink-state", "-uplink-state-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize: %v output=%s", err, output)
	}
	if _, err := executoruplink.LoadStateStore(path); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(bin, "-initialize-uplink-state", "-uplink-state-file", path)
	command.Env = executorEnv()
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("second initialization overwrote fence: %s", output)
	}
}

func buildExecutor(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "steward-executor")
	args := []string{"build", "-o", bin, "."}
	if os.Getenv("STEWARD_EXECUTOR_TEST_COVERDIR") != "" {
		args = []string{"build", "-cover", "-o", bin, "."}
	}
	command := exec.Command("go", args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build executor: %v\n%s", err, output)
	}
	return bin
}

func executorEnv() []string {
	dir := os.Getenv("STEWARD_EXECUTOR_TEST_COVERDIR")
	if dir == "" {
		return nil
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOCOVERDIR=") {
			env = append(env, value)
		}
	}
	return append(env, "GOCOVERDIR="+dir)
}

func executorTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("local-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeDockerSocket(t *testing.T, runsc bool) string {
	t.Helper()
	file, err := os.CreateTemp("/tmp", "steward-executor-docker-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/info" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if runsc {
			_, _ = w.Write([]byte(`{"Runtimes":{"runsc":{}}}`))
		} else {
			_, _ = w.Write([]byte(`{"Runtimes":{"runc":{}}}`))
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = os.Remove(path) })
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func waitCommand(command *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		return <-done
	}
}
