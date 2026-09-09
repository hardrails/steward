package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

func responseIssuerHTTP(issuer *taskIssuer, method, path, raw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	issuer.serveHTTP(w, r)
	return w
}

func TestResponseIssuerUnixSocketServesTasksAndAnswers(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	socket := filepath.Join(issuerSocketDirectory(t), "station.sock")
	listener, err := listenTaskIssuer(socket, issuerTestClientGID())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- runTaskIssuerServer(ctx, listener, issuer) }()
	defer func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("signing station did not shut down")
		}
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for path, intent := range map[string]any{"/v1/tasks": issuerRequest(f), "/v1/responses": issuerResponse(f)} {
		raw, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		var first []byte
		for attempt := 0; attempt < 2; attempt++ {
			response, err := client.Post("http://station"+path, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTaskBundleBytes+1))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/octet-stream" {
				t.Fatalf("native socket response failed: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
			}
			if attempt == 0 {
				first = body
			} else if !bytes.Equal(first, body) {
				t.Fatal("socket replay changed authority")
			}
		}
	}
}

func TestResponseIssuerHTTPRejectsUnsafeRequestsAndDefaultsOff(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	raw, err := json.Marshal(issuerResponse(f))
	if err != nil {
		t.Fatal(err)
	}
	if w := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(raw)); w.Code != 404 || issuer.count != 0 {
		t.Fatal("disabled endpoint issued response authority")
	}
	// Only this test mutates configuration; restart binding is tested separately.
	issuer.config.AllowResponses = true
	for _, test := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"method", "GET", "/v1/responses", string(raw), 405},
		{"query", "POST", "/v1/responses?", string(raw), 404},
		{"encoded", "POST", "/v1/%72esponses", string(raw), 404},
		{"absolute", "POST", "http://station/v1/responses", string(raw), 404},
		{"missing", "POST", "/v1/responses", `{}`, 422},
		{"unknown", "POST", "/v1/responses", `{"key":"secret"}`, 400},
		{"duplicate", "POST", "/v1/responses", `{"response_base64":"a","response_base64":"b"}`, 400},
		{"oversize", "POST", "/v1/responses", strings.Repeat("s", (64<<10)+1), 413},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := responseIssuerHTTP(issuer, test.method, test.path, test.body)
			var body map[string]string
			if w.Code != test.status || issuer.count != 0 || json.Unmarshal(w.Body.Bytes(), &body) != nil ||
				len(body) != 2 || body["error"] == "" || body["message"] == "" ||
				w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("invalid response boundary: status=%d count=%d", w.Code, issuer.count)
			}
		})
	}
	for header, value := range map[string]string{"Origin": "https://example.test", "Content-Type": "text/plain"} {
		r := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(header, value)
		w := httptest.NewRecorder()
		issuer.serveHTTP(w, r)
		if w.Code != 400 || issuer.count != 0 {
			t.Fatal("browser or non-JSON request signed")
		}
	}
}

func TestResponseIssuerHTTPPreservesReplayAndPrivateFailureBoundary(t *testing.T) {
	f, config := newTaskIssuerFixture(t)
	config.AllowResponses = true
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	intent := issuerResponse(f)
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	first := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(raw))
	if first.Code != 200 || first.Header().Get("Content-Type") != "application/octet-stream" || first.Body.Len() > 16<<10 {
		t.Fatalf("failed response signing: %d", first.Code)
	}
	keyPath := filepath.Join(issuer.snapshots, "key")
	backup := filepath.Join(t.TempDir(), "key")
	if err = os.Rename(keyPath, backup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Rename(backup, keyPath) })
	// Recovery of already-retained authority needs no signing key.
	replayed := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(raw))
	if replayed.Code != 200 || !bytes.Equal(first.Body.Bytes(), replayed.Body.Bytes()) {
		t.Fatal("replay needs private preparation")
	}
	intent.Interaction.IdempotencyKey = "new-question"
	refreshIssuerQuestion(&intent.Interaction)
	newRaw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	failed := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(newRaw))
	var failure map[string]string
	if failed.Code != 500 || json.Unmarshal(failed.Body.Bytes(), &failure) != nil || failure["error"] != "preparation_failed" ||
		strings.Contains(failed.Body.String(), keyPath) || strings.Contains(failed.Body.String(), "Only read") || issuer.count != 1 {
		t.Fatalf("private failure leaked or changed authority: %d", failed.Code)
	}
	if err = os.Rename(backup, keyPath); err != nil {
		t.Fatal(err)
	}
	repaired := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(newRaw))
	if repaired.Code != 200 || issuer.count != 2 {
		t.Fatalf("same request failed after repair: %d", repaired.Code)
	}
	intent.ResponseBase64 = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"other"}`))
	changed, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if w := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(changed)); w.Code != 409 {
		t.Fatalf("changed replay status=%d", w.Code)
	}
	issuer.mu.Lock()
	busy := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(raw))
	issuer.mu.Unlock()
	if busy.Code != 503 {
		t.Fatalf("busy status=%d", busy.Code)
	}
	intent.Interaction.IdempotencyKey = "third-question"
	refreshIssuerQuestion(&intent.Interaction)
	third, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if w := responseIssuerHTTP(issuer, "POST", "/v1/responses", string(third)); w.Code != 503 {
		t.Fatalf("capacity status=%d", w.Code)
	}
}
