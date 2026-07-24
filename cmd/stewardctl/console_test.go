package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
)

func TestConsoleProxyVerifiesTLSAndNeverInjectsBearer(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamRequests.Add(1)
		if request.Host != request.Context().Value(http.LocalAddrContextKey).(net.Addr).String() {
			http.Error(writer, "wrong upstream Host", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, request.Header.Get("Authorization"))
	}))
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	upstream.StartTLS()
	defer upstream.Close()

	certificate := upstream.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	target, transport, err := controlclient.NewProxyTarget(upstream.URL, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenConsoleLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serveConsoleProxy(ctx, listener, target.String(), transport, &output)
	}()
	localURL := "http://" + listener.Addr().String()

	response := consoleProxyRequest(t, http.MethodGet, localURL+"/console/", "", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", response.StatusCode)
	}
	raw, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(raw) != "" {
		t.Fatalf("proxy injected Authorization = %q", raw)
	}

	response = consoleProxyRequest(t, http.MethodGet, localURL+"/v1/operations/summary", "Bearer browser-token", "")
	raw, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(raw) != "Bearer browser-token" {
		t.Fatalf("proxy changed browser Authorization = %q", raw)
	}
	if !strings.Contains(output.String(), localURL+"/console/") ||
		!strings.Contains(output.String(), "Control TLS is verified locally") {
		t.Fatalf("console output = %q", output.String())
	}

	request, err := http.NewRequest(http.MethodGet, localURL+"/console/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "attacker.example"
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid Host status = %d", response.StatusCode)
	}
	var payload map[string]string
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if payload["error"] != "invalid_host" {
		t.Fatalf("invalid Host response = %#v", payload)
	}

	beforeOversized := upstreamRequests.Load()
	response = consoleProxyRequest(t, http.MethodPost, localURL+"/v1/test", "",
		strings.Repeat("x", maxConsoleProxyRequestBytes+1))
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if upstreamRequests.Load() != beforeOversized {
		t.Fatal("oversized request reached Control")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("console proxy did not stop")
	}
}

func TestConsoleProxyRejectsRemoteAndNamedListeners(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "localhost:0", "127.0.0.1", "bad"} {
		if listener, err := listenConsoleLoopback(address); err == nil {
			_ = listener.Close()
			t.Fatalf("listenConsoleLoopback(%q) succeeded", address)
		}
	}
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		listener, err := listenConsoleLoopback(address)
		if err != nil {
			t.Fatalf("listenConsoleLoopback(%q): %v", address, err)
		}
		_ = listener.Close()
	}
}

func consoleProxyRequest(t *testing.T, method, requestURL, authorization, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, requestURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
