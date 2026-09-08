package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type issuerIdentityProbe struct {
	Socket  string
	Private []string
	Request taskIssuerRequest
}

// Run in a disposable Linux container or the privileged CI step. No host keys,
// account creation, network, or runtime provisioning are needed.
func TestTaskIssuerSeparatesClientFromSigningIdentity(t *testing.T) {
	if os.Getenv("STEWARD_REQUIRE_ISSUER_IDENTITY_TEST") != "1" {
		t.Skip("requires explicit disposable-host identity test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("identity test requires root to start three different unprivileged UIDs")
	}
	for _, phase := range []string{"configured", "before-socket-restriction"} {
		t.Run(phase, func(t *testing.T) { proveTaskIssuerIdentities(t, phase) })
	}
}

func proveTaskIssuerIdentities(t *testing.T, phase string) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "issuer-identity-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	socketDirectory := filepath.Join(directory, "socket")
	if err = os.Mkdir(socketDirectory, 0o710); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(socketDirectory, 65532, 65533); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	signer := issuerIdentityCommand(t, ctx, "signer", 65532, 65532, []uint32{65533})
	signer.Env = append(signer.Env, "STEWARD_ISSUER_TEST_SOCKET="+filepath.Join(socketDirectory, "station.sock"))
	signer.Env = append(signer.Env, "STEWARD_ISSUER_TEST_PHASE="+phase)
	var diagnostics bytes.Buffer
	signer.Stderr = &diagnostics
	output, err := signer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stop, err := signer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stop.Close()
		// Drain the test runner's final status before waiting for its pipe to close.
		_, _ = io.Copy(io.Discard, output)
		if err := signer.Wait(); err != nil {
			t.Errorf("isolated signer failed: %v %s", err, diagnostics.String())
		}
	}()
	var probe issuerIdentityProbe
	if err = json.NewDecoder(output).Decode(&probe); err != nil {
		t.Fatalf("signer did not become ready: %v", err)
	}
	for _, path := range probe.Private {
		if _, err = os.Stat(path); err != nil {
			t.Fatalf("private probe target does not exist: %v", err)
		}
	}
	input, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"client", "outsider"} {
		uid := uint32(65533)
		if role == "outsider" {
			uid = 65534
		}
		command := issuerIdentityCommand(t, ctx, role, uid, uid, nil)
		command.Stdin = bytes.NewReader(input)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s identity proof failed: %v %s", role, err, output)
		}
	}
}

func issuerIdentityCommand(t *testing.T, ctx context.Context, role string, uid, gid uint32, groups []uint32) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestTaskIssuerIdentityProcess$")
	command.Env = []string{"TMPDIR=/tmp", "STEWARD_ISSUER_TEST_ROLE=" + role}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	return command
}

func TestTaskIssuerIdentityProcess(t *testing.T) {
	role := os.Getenv("STEWARD_ISSUER_TEST_ROLE")
	if role == "" {
		t.Skip("identity subprocess only")
	}
	if role == "signer" {
		fixture, config := newTaskIssuerFixture(t)
		issuer, err := openTaskIssuer(config)
		if err != nil {
			t.Fatal(err)
		}
		defer issuer.Close()
		socket := os.Getenv("STEWARD_ISSUER_TEST_SOCKET")
		var listener net.Listener
		if os.Getenv("STEWARD_ISSUER_TEST_PHASE") == "before-socket-restriction" {
			// Hold the review's suspected startup window open for the whole test:
			// an even more permissive 000 umask, no Chown/Chmod on the socket,
			// and an accepting signing handler. Parent traversal must still deny
			// outsiders before any connection can be queued.
			previousMask := syscall.Umask(0)
			listener, err = net.Listen("unix", socket)
			syscall.Umask(previousMask)
			if err == nil {
				info, statErr := os.Lstat(socket)
				if statErr != nil || info.Mode().Perm() != 0o777 || info.Sys().(*syscall.Stat_t).Gid != 65532 {
					t.Fatalf("startup probe did not preserve unrestricted socket: %v", statErr)
				}
			}
		} else {
			listener, err = listenTaskIssuer(socket, 65533)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan error, 1)
		go func() { finished <- runTaskIssuerServer(ctx, listener, issuer) }()
		probe := issuerIdentityProbe{Socket: socket, Request: issuerRequest(fixture), Private: []string{
			config.Key, filepath.Join(issuer.snapshots, "key"), filepath.Join(config.Store, "BINDING"),
		}}
		if err = json.NewEncoder(os.Stdout).Encode(probe); err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
		if err = <-finished; err != nil {
			t.Fatal(err)
		}
		return
	}
	var probe issuerIdentityProbe
	if err := json.NewDecoder(os.Stdin).Decode(&probe); err != nil {
		t.Fatal(err)
	}
	for _, path := range probe.Private {
		if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("%s did not deny private-file access: %v", role, err)
		}
	}
	if err := os.Remove(probe.Socket); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("%s could mutate the socket directory: %v", role, err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", probe.Socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	raw, err := json.Marshal(probe.Request)
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	for attempt := 0; attempt < 2; attempt++ {
		response, err := client.Post("http://station/v1/tasks", "application/json", bytes.NewReader(raw))
		if role == "outsider" {
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("outsider socket access was not denied: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTaskBundleBytes+1))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || len(body) == 0 || len(body) > maxTaskBundleBytes {
			t.Fatalf("separate-UID client could not obtain task authority: %d %v", response.StatusCode, readErr)
		}
		if attempt > 0 && !bytes.Equal(original, body) {
			t.Fatal("replay changed signed authority")
		}
		original = body
	}
}
