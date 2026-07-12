package gateway

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedServiceWebSocketAndLifecycleRevocation(t *testing.T) {
	slowStarted := make(chan context.Context, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("outer credentials reached service: auth=%q proxy=%q cookie=%q", r.Header.Get("Authorization"), r.Header.Get("Proxy-Authorization"), r.Header.Get("Cookie"))
		}
		if r.URL.Path == "/slow" {
			slowStarted <- r.Context()
			<-r.Context().Done()
			return
		}
		if r.URL.Path != "/socket" || r.URL.RawQuery != "channel=one" || !websocketUpgrade(r) {
			http.Error(w, "bad upgrade", http.StatusBadRequest)
			return
		}
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Accept: " + webSocketAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n" +
			"Sec-WebSocket-Protocol: steward-test\r\nSet-Cookie: upstream=secret\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		payload := make([]byte, 64)
		for {
			count, err := buffer.Read(payload)
			if count > 0 {
				if _, writeErr := connection.Write(payload[:count]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	server, _ := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "service", 1), TenantID: "tenant", InstanceID: "service", Generation: 1,
		Service: true, ServiceURL: upstream.URL}
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	front := httptest.NewServer(server.ServiceHandler())
	defer front.Close()

	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/socket", nil)
	unauthorized.Header.Set("Connection", "Upgrade")
	unauthorized.Header.Set("Upgrade", "websocket")
	recorder := httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized upgrade status=%d", recorder.Code)
	}
	malformed := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/socket", nil)
	malformed.Header.Set("Authorization", "Bearer service-secret")
	malformed.Header.Set("Upgrade", "websocket")
	recorder = httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(recorder, malformed)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("malformed upgrade status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	checkRevocation := func(action string) {
		t.Helper()
		httpDone := make(chan struct{})
		go func() {
			defer close(httpDone)
			request, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/services/"+grant.GrantID+"/slow", nil)
			request.Header.Set("Authorization", "Bearer service-secret")
			request.Header.Set("Proxy-Authorization", "Bearer outer-proxy")
			request.Header.Set("Cookie", "outer=secret")
			response, err := http.DefaultClient.Do(request)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
		}()
		var upstreamContext context.Context
		select {
		case upstreamContext = <-slowStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("ordinary service request did not reach upstream")
		}
		connection, reader, response := openServiceWebSocket(t, front.URL, grant.GrantID)
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Sec-Websocket-Protocol") != "steward-test" ||
			response.Header.Get("X-Steward-Service-Grant") != "active" {
			connection.Close()
			t.Fatalf("unsafe or incomplete upgrade headers: %v", response.Header)
		}
		if _, err := connection.Write([]byte("ping")); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		echo := make([]byte, 4)
		if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
			connection.Close()
			t.Fatalf("echo=%q err=%v", echo, err)
		}
		method, path, want := http.MethodPost, "/v1/grants/"+grant.GrantID+"/deactivate", http.StatusOK
		if action == "unregister" {
			method, path, want = http.MethodDelete, "/v1/grants/"+grant.GrantID, http.StatusNoContent
		}
		controlRequest(t, server, method, path, nil, want)
		select {
		case <-upstreamContext.Done():
		case <-time.After(2 * time.Second):
			connection.Close()
			t.Fatalf("%s did not cancel ordinary service upstream", action)
		}
		select {
		case <-httpDone:
		case <-time.After(2 * time.Second):
			connection.Close()
			t.Fatalf("ordinary service request survived %s", action)
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := reader.ReadByte(); err == nil {
			connection.Close()
			t.Fatalf("WebSocket survived %s", action)
		}
		_ = connection.Close()
	}

	checkRevocation("deactivate")
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	checkRevocation("unregister")
}

func TestServiceConcurrencyAndWebSocketByteBounds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	server, _ := testGateway(t, upstream.URL)
	grant := Grant{GrantID: GrantID("tenant", "service", 2), TenantID: "tenant", InstanceID: "service", Generation: 2,
		Service: true, ServiceURL: upstream.URL, Active: true}
	server.mu.Lock()
	server.grants[grant.GrantID] = grant
	server.grantLeaseLocked(grant.GrantID)
	semaphore := server.serviceSemaphoreLocked(grant.GrantID)
	for range maxServiceConcurrent {
		semaphore <- struct{}{}
	}
	server.mu.Unlock()
	request := httptest.NewRequest(http.MethodGet, "/v1/services/"+grant.GrantID+"/", nil)
	request.Header.Set("Authorization", "Bearer service-secret")
	recorder := httptest.NewRecorder()
	server.ServiceHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("service concurrency status=%d", recorder.Code)
	}

	var destination bytes.Buffer
	written, err := copyWebSocketBounded(&destination, strings.NewReader("12345"), 4)
	if err != nil || written != 4 || destination.String() != "1234" {
		t.Fatalf("bounded copy written=%d destination=%q err=%v", written, destination.String(), err)
	}
	if got := webSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("RFC 6455 accept=%q", got)
	}
}

func TestServiceWebSocketUsesTheGrantUnixSocket(t *testing.T) {
	dummy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer dummy.Close()
	server, config := testGateway(t, dummy.URL)
	grant := Grant{
		GrantID: GrantID("tenant", "unix-websocket", 1), TenantID: "tenant", InstanceID: "unix-websocket", Generation: 1,
		Service: true,
	}
	grant.ServiceURL = ServiceSocketURL(config.GrantRoot, grant.GrantID)
	controlRequest(t, server, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
	listener, err := net.Listen("unix", serviceSocketPath(config.GrantRoot, grant.GrantID))
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/socket" || !websocketUpgrade(r) {
			http.Error(w, "bad upgrade", http.StatusBadRequest)
			return
		}
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Accept: " + webSocketAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		_, _ = io.Copy(connection, buffer)
	})}
	defer func() {
		_ = upstream.Close()
		_ = listener.Close()
	}()
	go func() { _ = upstream.Serve(listener) }()
	controlRequest(t, server, http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil, http.StatusOK)
	front := httptest.NewServer(server.ServiceHandler())
	defer front.Close()

	connection, reader, _ := openServiceWebSocket(t, front.URL, grant.GrantID)
	defer connection.Close()
	if _, err := connection.Write([]byte("unix-ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len("unix-ping"))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "unix-ping" {
		t.Fatalf("echo=%q err=%v", echo, err)
	}
}

func openServiceWebSocket(t *testing.T, serviceURL, grantID string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	address := strings.TrimPrefix(serviceURL, "http://")
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := "GET /v1/services/" + grantID + "/socket?channel=one HTTP/1.1\r\n" +
		"Host: " + address + "\r\nAuthorization: Bearer service-secret\r\n" +
		"Proxy-Authorization: Bearer outer-proxy\r\nCookie: outer=secret\r\n" +
		"Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		connection.Close()
		t.Fatalf("upgrade status=%d body=%s", response.StatusCode, body)
	}
	return connection, reader, response
}
