package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServiceProxyPreservesWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			t.Errorf("upgrade=%q", r.Header.Get("Upgrade"))
			return
		}
		connection, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(connection, connection)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	relay := httptest.NewServer(serviceProxy(target))
	defer relay.Close()
	relayURL, _ := url.Parse(relay.URL)
	connection, err := net.DialTimeout("tcp", relayURL.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := io.WriteString(connection, "GET /socket HTTP/1.1\r\nHost: relay\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d", response.StatusCode)
	}
	payload := []byte("opaque-websocket-frame")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echoed); err != nil || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo=%q err=%v", echoed, err)
	}
}

func TestRunVersionValidationAndShutdown(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "steward-relay") {
		t.Fatalf("version code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "at least one") {
		t.Fatalf("empty code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	serviceDirectory, err := os.MkdirTemp("/tmp", "srs-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(serviceDirectory)
	serviceSocket := filepath.Join(serviceDirectory, "s.sock")
	if code := run(context.Background(), []string{"-service-target", "https://agent:8080", "-service-socket", serviceSocket}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "http://agent:PORT") {
		t.Fatalf("target code=%d stderr=%q", code, stderr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stderr.Reset()
	if code := run(ctx, []string{
		"-inference-socket", filepath.Join(t.TempDir(), "i.sock"), "-inference-addr", "127.0.0.1:0",
		"-service-target", "http://agent:8080", "-service-socket", serviceSocket,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("shutdown code=%d stderr=%q", code, stderr.String())
	}
	if code := run(context.Background(), []string{"-bad-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid flag code=%d", code)
	}
}

func TestEgressBridgeForwardsOnlyToConfiguredUnixSocket(t *testing.T) {
	directory, _ := os.MkdirTemp("/tmp", "sre-")
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "e.sock")
	gateway, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	go func() {
		connection, err := gateway.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveEgressBridge(ctx, listener, socket) }()
	agent, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write([]byte("proxy-bytes")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("proxy-bytes"))
	if _, err := io.ReadFull(agent, buffer); err != nil || string(buffer) != "proxy-bytes" {
		t.Fatalf("bridge bytes=%q err=%v", buffer, err)
	}
	_ = agent.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("egress bridge did not stop")
	}
}

func TestEgressBridgeClosesBothDirectionsWhenGatewayDisappears(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "srb-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "e.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(accepted)
	}()

	agent, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		bridgeEgress(agent, socket)
		close(done)
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("relay did not connect to Gateway")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed Gateway left the agent-to-Gateway copy blocked")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay did not close the agent peer")
	}
	_ = peer.Close()
}

func TestInferenceProxyUsesOnlyConfiguredUnixSocketAndBoundsBody(t *testing.T) {
	directory, _ := os.MkdirTemp("/tmp", "sr-")
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "i.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path=%s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = upstream.Serve(listener) }()
	defer upstream.Close()
	recorder := httptest.NewRecorder()
	inferenceProxy(socket).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://relay/v1/models", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	inferenceProxy(filepath.Join(directory, "missing.sock")).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://relay/v1/models", nil))
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "gateway_unavailable") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
