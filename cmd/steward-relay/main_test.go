package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if code := run(context.Background(), []string{"-service-target", "https://agent:8080"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "http://agent:PORT") {
		t.Fatalf("target code=%d stderr=%q", code, stderr.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := run(ctx, []string{
		"-inference-socket", filepath.Join(t.TempDir(), "i.sock"), "-inference-addr", "127.0.0.1:0",
		"-service-target", "http://agent:8080", "-service-addr", "127.0.0.1:0",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("shutdown code=%d stderr=%q", code, stderr.String())
	}
	if code := run(context.Background(), []string{"-bad-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid flag code=%d", code)
	}
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
