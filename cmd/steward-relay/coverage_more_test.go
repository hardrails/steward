package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenServiceListenerReplacesOnlyAUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "steward-relay-listener-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	for name, path := range map[string]string{
		"relative":       "s.sock",
		"unclean":        dir + "/nested/../s.sock",
		"wrong basename": filepath.Join(dir, "service.sock"),
		"missing parent": filepath.Join(dir, "missing", "s.sock"),
	} {
		t.Run(name, func(t *testing.T) {
			if listener, err := openServiceListener(path); err == nil || listener != nil {
				t.Fatalf("openServiceListener(%q) = %#v, %v; want rejection", path, listener, err)
			}
		})
	}

	socket := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(socket, []byte("operator data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := openServiceListener(socket); err == nil || listener != nil {
		t.Fatalf("regular file was replaced: listener=%#v err=%v", listener, err)
	}
	if raw, err := os.ReadFile(socket); err != nil || string(raw) != "operator data" {
		t.Fatalf("rejected regular path changed: raw=%q err=%v", raw, err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}

	stale, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := openServiceListener(socket)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	defer listener.Close()
	info, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Fatalf("service socket mode = %v", info.Mode())
	}

	accepted := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- "accept: " + err.Error()
			return
		}
		defer connection.Close()
		raw, err := io.ReadAll(connection)
		if err != nil {
			accepted <- "read: " + err.Error()
			return
		}
		accepted <- string(raw)
	}()
	client, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("service capability"))
	_ = client.Close()
	if got := <-accepted; got != "service capability" {
		t.Fatalf("accepted payload = %q", got)
	}
}

func TestRunRejectsPartialServiceAndListenerConflicts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	dir, err := os.MkdirTemp("/tmp", "steward-relay-run-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s.sock")

	for name, args := range map[string][]string{
		"target without socket": {"-service-target", "http://agent:8080"},
		"socket without target": {"-service-socket", socket},
		"target with path":      {"-service-target", "http://agent:8080/path", "-service-socket", socket},
		"target without port":   {"-service-target", "http://agent", "-service-socket", socket},
		"target wrong host":     {"-service-target", "http://localhost:8080", "-service-socket", socket},
	} {
		t.Run(name, func(t *testing.T) {
			stderr.Reset()
			if code := run(context.Background(), args, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}

	if err := os.WriteFile(socket, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run(context.Background(), []string{
		"-service-target", "http://agent:8080", "-service-socket", socket,
	}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "service listener") {
		t.Fatalf("regular socket path: code=%d stderr=%q", code, stderr.String())
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	stderr.Reset()
	if code := run(context.Background(), []string{
		"-egress-socket", filepath.Join(dir, "e.sock"), "-egress-addr", occupied.Addr().String(),
	}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "egress listener") {
		t.Fatalf("occupied egress address: code=%d stderr=%q", code, stderr.String())
	}

	stderr.Reset()
	if code := run(context.Background(), []string{
		"-inference-socket", filepath.Join(dir, "i.sock"), "-inference-addr", occupied.Addr().String(),
	}, &stdout, &stderr); code != 1 {
		t.Fatalf("asynchronous inference listener failure: code=%d stderr=%q", code, stderr.String())
	}
}

func TestRunServesAndStopsServiceUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "steward-relay-service-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stdout, stderr bytes.Buffer
	go func() {
		done <- run(ctx, []string{
			"-service-target", "http://agent:8080", "-service-socket", socket,
		}, &stdout, &stderr)
	}()
	deadline := time.Now().Add(2 * time.Second)
	var connection net.Conn
	for {
		connection, err = net.DialTimeout("unix", socket, 50*time.Millisecond)
		if err == nil {
			break
		}
		select {
		case code := <-done:
			t.Fatalf("run exited before serving: code=%d stderr=%q", code, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("service socket was not created: %s", stderr.String())
		}
		time.Sleep(time.Millisecond)
	}
	// A malformed request is rejected by net/http before the reverse proxy can
	// attempt DNS or an upstream connection. This proves the Unix listener is
	// actively served without making the test depend on a host named "agent".
	_, _ = io.WriteString(connection, "NOT HTTP\r\n\r\n")
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw, err := io.ReadAll(connection)
	_ = connection.Close()
	if err != nil || !strings.Contains(string(raw), "400 Bad Request") {
		cancel()
		<-done
		t.Fatalf("relay response=%q err=%v", raw, err)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("service socket remains after shutdown: %v", err)
	}
}

func TestEgressBridgeReportsUnexpectedAcceptErrorAndMissingGateway(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := serveEgressBridge(ctx, listener, "/missing/e.sock"); err == nil {
		t.Fatal("closed listener returned nil without context cancellation")
	}
	cancel()

	agent, peer := net.Pipe()
	missingSocket := filepath.Join(t.TempDir(), "missing.sock")
	done := make(chan struct{})
	go func() {
		bridgeEgress(agent, missingSocket)
		close(done)
	}()
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not return after gateway dial failure")
	}
}
