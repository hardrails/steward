package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestConsoleCommandValidatesBeforeListening(t *testing.T) {
	contextPath := filepath.Join(t.TempDir(), "contexts.json")
	t.Setenv("STEWARD_CONTEXT_FILE", contextPath)

	var help bytes.Buffer
	if err := consoleCommand([]string{"-help"}, &help); !errors.Is(err, flag.ErrHelp) ||
		!strings.Contains(help.String(), "-control-url") {
		t.Fatalf("console -help error=%v output=%q", err, help.String())
	}
	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{"missing context", nil, "no Steward CLI context is selected"},
		{"no-context needs URL", []string{"-no-context"}, "requires -control-url"},
		{"positional argument", []string{"-no-context", "-control-url", "https://127.0.0.1:8443", "extra"}, "named flags only"},
		{"remote plaintext", []string{"-no-context", "-control-url", "http://control.example:8443"}, "remote control URL must use HTTPS"},
		{"invalid URL", []string{"-no-context", "-control-url", "not-a-url"}, "absolute HTTPS origin"},
		{"missing CA", []string{"-no-context", "-control-url", "https://127.0.0.1:8443", "-ca-file", filepath.Join(t.TempDir(), "missing.pem")}, "read Control CA"},
		{"remote listener", []string{"-no-context", "-control-url", "https://127.0.0.1:8443", "-listen", "0.0.0.0:8443"}, "literal loopback IP"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := consoleCommand(test.arguments, io.Discard)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("consoleCommand(%q) error = %v, want %q", test.arguments, err, test.want)
			}
		})
	}
}

func TestConsoleCommandUsesSelectedContextBeforeBinding(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("test-operator-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := contextSet([]string{
		"dev",
		"-control-url", "https://127.0.0.1:8443",
		"-token-file", tokenPath,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
	err := consoleCommand([]string{"-listen", "0.0.0.0:0"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "literal loopback IP") {
		t.Fatalf("selected-context console error = %v", err)
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
