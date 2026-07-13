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
	"strconv"
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

func TestConnectorProxyForwardsOnlyExactOperationsAndFailsClosedAfterRevocation(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "src-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Error(readErr)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/connectors/tickets/operations/create" || r.URL.RawQuery != "" || string(body) != `{"title":"bounded"}` {
			t.Errorf("request=%s %s?%s body=%q", r.Method, r.URL.Path, r.URL.RawQuery, body)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/json" ||
			r.Header.Get("X-Steward-Task-ID") != "task-0123456789abcdef" {
			t.Errorf("headers=%#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "gateway-state=secret")
		w.Header().Set("X-Steward-Test", "connector")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	})}
	go func() { _ = upstream.Serve(listener) }()
	defer upstream.Close()

	handler := connectorProxy(socket)
	request := httptest.NewRequest(http.MethodPost, "/v1/connectors/tickets/operations/create", strings.NewReader(`{"title":"bounded"}`))
	request.Header.Set("Authorization", "Bearer agent-secret")
	request.Header.Set("Cookie", "agent-state=secret")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Steward-Task-ID", "task-0123456789abcdef")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != `{"created":true}` ||
		response.Header().Get("X-Steward-Test") != "connector" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("status=%d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
	}

	// A connector grant is revoked by removing c.sock. DisableKeepAlives forces
	// every later operation through a fresh socket lookup instead of retaining
	// authority through a pooled connection.
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/connectors/tickets/operations/create", nil))
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "connector_unavailable") {
		t.Fatalf("revoked status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestConnectorProxyRejectsTraversalQueriesAndOversizeBodiesBeforeDial(t *testing.T) {
	handler := connectorProxy(filepath.Join(t.TempDir(), "missing.sock"))
	tests := []struct {
		name, method, target string
	}{
		{name: "parent traversal", method: http.MethodPost, target: "/v1/connectors/../operations/admin"},
		{name: "encoded traversal", method: http.MethodPost, target: "/v1/connectors/%2e%2e/operations/admin"},
		{name: "nested encoded traversal", method: http.MethodPost, target: "/v1/connectors/%252e%252e/operations/admin"},
		{name: "backslash traversal", method: http.MethodPost, target: "/v1/connectors/..%5cadmin/operations/read"},
		{name: "extra path", method: http.MethodPost, target: "/v1/connectors/tickets/operations/create/extra"},
		{name: "query", method: http.MethodPost, target: "/v1/connectors/tickets/operations/create?scope=admin"},
		{name: "absolute form", method: http.MethodPost, target: "http://elsewhere/v1/connectors/tickets/operations/create"},
		{name: "connect tunnel", method: http.MethodConnect, target: "/v1/connectors/tickets/operations/create"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.target, nil))
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "connector_denied") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}

	oversize := httptest.NewRequest(http.MethodPost, "/v1/connectors/tickets/operations/create", strings.NewReader("small"))
	oversize.ContentLength = maxConnectorRequestBytes + 1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, oversize)
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "request_too_large") {
		t.Fatalf("oversize status=%d body=%q", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/connectors/tickets/operations/create", nil))
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "connector_unavailable") {
		t.Fatalf("missing socket status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestConnectorProxyRejectsOversizeGatewayResponse(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sro-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(maxConnectorResponseBytes+1, 10))
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = upstream.Serve(listener) }()
	defer upstream.Close()

	response := httptest.NewRecorder()
	connectorProxy(socket).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/connectors/tickets/operations/read", nil))
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "response_too_large") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRunServesConnectorAtFixedAddressAlongsideInferenceAndShutsDown(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "srr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "c.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = upstream.Serve(listener) }()
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	var stdout, stderr bytes.Buffer
	go func() {
		done <- run(ctx, []string{
			"-connector-socket", socket,
			"-inference-socket", filepath.Join(directory, "i.sock"),
			"-inference-addr", "127.0.0.1:0",
		}, &stdout, &stderr)
	}()

	client := &http.Client{Timeout: time.Second}
	var response *http.Response
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		response, err = client.Get("http://127.0.0.1:8081/v1/connectors/tickets/operations/read")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		<-done
		t.Fatalf("fixed connector listener did not start: %v; stderr=%q", err, stderr.String())
	}
	raw, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(raw) != `{"ok":true}` {
		cancel()
		<-done
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, raw, readErr)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connector relay did not shut down")
	}
}
