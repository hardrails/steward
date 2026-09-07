package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskIssuerHTTPRejectsInvalidRequestsWithoutIssuing(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	valid, err := json.Marshal(issuerRequest(fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, path, contentType, origin, body string
		status                                        int
	}{
		{"method", "GET", "/v1/tasks", "application/json", "", string(valid), 405},
		{"route", "POST", "/other", "application/json", "", string(valid), 404},
		{"query", "POST", "/v1/tasks?key=secret", "application/json", "", string(valid), 404},
		{"browser", "POST", "/v1/tasks", "application/json", "https://example.test", string(valid), 400},
		{"content-type", "POST", "/v1/tasks", "text/plain", "", string(valid), 400},
		{"unknown-field", "POST", "/v1/tasks", "application/json", "", `{"key":"secret"}`, 400},
		{"duplicate-field", "POST", "/v1/tasks", "application/json", "", `{"task_id":"one","task_id":"two"}`, 400},
		{"empty", "POST", "/v1/tasks", "application/json", "", `{}`, 422},
		{"oversized", "POST", "/v1/tasks", "application/json", "", strings.Repeat("s", maxTaskBundleBytes+1), 413},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Origin", test.origin)
			recorder := httptest.NewRecorder()
			issuer.serveHTTP(recorder, request)
			var response map[string]string
			if recorder.Code != test.status || json.Unmarshal(recorder.Body.Bytes(), &response) != nil ||
				len(response) != 2 || response["error"] == "" || response["message"] == "" ||
				recorder.Header().Get("Cache-Control") != "no-store" ||
				strings.Contains(recorder.Body.String(), "secret") || issuer.count != 0 {
				t.Fatalf("invalid error contract or issuance: status=%d count=%d", recorder.Code, issuer.count)
			}
		})
	}
}

func TestTaskIssuerCommandIsDiscoverableAndRequiresPrivateConfiguration(t *testing.T) {
	candidates := stewardctlCompletionCandidates([]string{"task", "serve-"})
	if len(candidates) != 1 || candidates[0] != "serve-issuer" {
		t.Fatalf("station is absent from completion: %v", candidates)
	}
	candidates = stewardctlCompletionCandidates([]string{"task", "serve-issuer", "-sock"})
	if len(candidates) != 1 || candidates[0] != "-socket" {
		t.Fatalf("station socket flag is absent: %v", candidates)
	}
	if err := taskCommand([]string{"serve-issuer"}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "absolute private socket") {
		t.Fatalf("station command did not enforce configuration: %v", err)
	}
}

func issuerSocketDirectory(t *testing.T) string {
	t.Helper()
	// macOS has a short Unix socket pathname bound; Go's test path can exceed it.
	directory, err := os.MkdirTemp("/tmp", "issuer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestTaskIssuerUnixHTTPReturnsExactBundleAndShutsDown(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	socket := filepath.Join(issuerSocketDirectory(t), "station.sock")
	listener, err := listenTaskIssuer(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- runTaskIssuerServer(ctx, listener, issuer) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	intent := issuerRequest(fixture)
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	for attempt := 0; attempt < 2; attempt++ {
		response, err := client.Post("http://station/v1/tasks", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTaskBundleBytes+1))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || len(body) > maxTaskBundleBytes ||
			response.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("invalid task response: %d %v", response.StatusCode, readErr)
		}
		if err = issuer.match(body, intent, fixture.request); err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			original = body
		} else if !bytes.Equal(original, body) {
			t.Fatal("socket replay changed exact signed authority")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("signing station did not shut down")
	}
}

func TestTaskIssuerSocketRefusesUnsafeOrActivePathsAndRecoversStaleSocket(t *testing.T) {
	directory := issuerSocketDirectory(t)
	socket := filepath.Join(directory, "station.sock")
	if err := os.WriteFile(socket, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenTaskIssuer(socket); err == nil {
		t.Fatal("regular file was replaced")
	}
	if raw, err := os.ReadFile(socket); err != nil || string(raw) != "keep" {
		t.Fatalf("regular file changed: %v", err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	listener, err := listenTaskIssuer(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if info, err := os.Lstat(socket); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe socket mode: %v", err)
	}
	if _, err := listenTaskIssuer(socket); err == nil {
		t.Fatal("active socket was replaced")
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := listenTaskIssuer(socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err = listenTaskIssuer(socket); err == nil {
		t.Fatal("public socket parent accepted")
	}
}
