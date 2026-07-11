package executoruplink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollerExecutesAuthenticatedCommandAndReports(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"tenant-a","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reported := make(chan report, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/executor-uplink/poll":
			_ = json.NewEncoder(w).Encode(pollResponse{Commands: []command{{
				CommandID: "c1", TenantID: "tenant-a", NodeID: "node-1",
				RuntimeRef: "uplink:6:node-1:agent-1", Kind: "provision",
				Payload:         json.RawMessage(`{"profile_id":"p","image":"registry/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":{"memory_bytes":1,"cpu_millis":1,"pids":1},"egress":{}}`),
				ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
			}}})
		case "/executor-uplink/report":
			var rep report
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Fatal(err)
			}
			reported <- rep
			_ = json.NewEncoder(w).Encode(reportResponse{Applied: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"runtime_ref":"executor-x","status":"created"}`))
	})
	store, _ := LoadStateStore(filepath.Join(t.TempDir(), "state.json"))
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: local, LocalToken: "local", State: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case rep := <-reported:
		if rep.Status != "done" || rep.ReportedStatus != "stopped" {
			t.Fatalf("report = %#v", rep)
		}
	default:
		t.Fatal("no report received")
	}
}

func TestNewPollerRefusesRemotePlainHTTPByDefault(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	_ = os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"c"}`), 0o600)
	store, _ := LoadStateStore(filepath.Join(t.TempDir(), "state.json"))
	_, err := NewPoller(Config{
		BaseURL: "http://192.0.2.10", CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), LocalToken: "x", State: store,
	})
	if err == nil {
		t.Fatal("remote plaintext uplink was accepted without acknowledgement")
	}
}

func TestPollerRunBacksOffAfterFailureAndStopsWithContext(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	_ = os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"c"}`), 0o600)
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if polls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"temporarily unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer server.Close()
	store, _ := LoadStateStore(filepath.Join(t.TempDir(), "state.json"))
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Millisecond,
		Handler:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "x", State: store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { poller.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for polls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Poller.Run did not stop after context cancellation")
	}
	if polls.Load() < 2 {
		t.Fatalf("poll count=%d, want a failed poll and retry", polls.Load())
	}
}

func TestReadBoundedRejectsOversizedResponse(t *testing.T) {
	if _, err := readBounded(strings.NewReader(strings.Repeat("x", 9)), 8); err == nil {
		t.Fatal("oversized response was accepted")
	}
}
