package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestHermesRunDispatchesExactBundleOnceAndWaitsToTerminal(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.issue(t)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runID := "run_0123456789abcdef0123456789abcdef"
	var posts, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer gateway-secret" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("User-Agent") != "stewardctl" ||
			request.Header.Get("Cookie") != "" {
			t.Errorf("unexpected fixed headers: %#v", request.Header)
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == strings.TrimSuffix(fixture.admitted.ServicePath, "/")+"/v1/runs":
			posts.Add(1)
			if request.Header.Get("Content-Type") != "application/json" || len(request.Header.Values("X-Steward-Task-Permit")) != 1 {
				t.Errorf("invalid dispatch headers: %#v", request.Header)
			}
			permitRaw, err := taskpermit.DecodeHeader(request.Header.Get("X-Steward-Task-Permit"))
			if err != nil || len(permitRaw) == 0 {
				t.Errorf("invalid task permit header: %v", err)
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(body, fixture.request) || request.ContentLength != int64(len(fixture.request)) {
				t.Errorf("dispatch body=%q length=%d err=%v", body, request.ContentLength, err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Steward-Task-Receipt", "recorded")
			w.Header().Set("X-Steward-Service-Grant", "active")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"run_id":%q}`, runID)
		case request.Method == http.MethodGet && request.URL.Path == strings.TrimSuffix(fixture.admitted.ServicePath, "/")+"/v1/runs/"+runID:
			count := gets.Add(1)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if count == 1 {
				fmt.Fprintf(w, `{"run_id":%q,"status":"running"}`, runID)
				return
			}
			fmt.Fprintf(w, `{"run_id":%q,"status":"completed","output":"skill performed real work"}`, runID)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run([]string{
		"hermes", "run", "-bundle", fixture.bundlePath, "-gateway-url", server.URL, "-token-file", tokenPath,
		"-wait", "-wait-timeout", "2s", "-poll-interval", "10ms",
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 || gets.Load() != 2 || !strings.Contains(output.String(), `"status":"completed"`) ||
		!strings.Contains(output.String(), "skill performed real work") {
		t.Fatalf("posts=%d gets=%d output=%q", posts.Load(), gets.Load(), output.String())
	}
}

func TestHermesRunWithoutWaitReturnsOnlyRecordedRunID(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.issue(t)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Steward-Task-Receipt", "replayed")
		w.Header().Set("X-Steward-Service-Grant", "active")
		fmt.Fprint(w, `{"run_id":"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := run([]string{"hermes", "run", "-bundle", fixture.bundlePath, "-gateway-url", server.URL,
		"-token-file", tokenPath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || output.String() != `{"run_id":"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`+"\n" {
		t.Fatalf("calls=%d output=%q", calls.Load(), output.String())
	}
}

func TestHermesRunRejectsUnsafeTransportAndUntrustedResponses(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.issue(t)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"http://localhost:8091", "http://192.0.2.1:8091", "https://127.0.0.1:8091", "http://127.0.0.1", "http://127.0.0.1:8091/path"} {
		if _, err := newHermesClient(value, tokenPath); err == nil {
			t.Fatalf("unsafe Gateway URL accepted: %s", value)
		}
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newHermesClient("http://127.0.0.1:8091", tokenPath); err == nil || !strings.Contains(err.Error(), "permission policy") {
		t.Fatalf("loose token error=%v", err)
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		handler  http.HandlerFunc
		contains string
	}{
		"missing receipt": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"run_id":"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
		}, "receipt response"},
		"invalid run id": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Steward-Task-Receipt", "recorded")
			w.Header().Set("X-Steward-Service-Grant", "active")
			fmt.Fprint(w, `{"run_id":"other"}`)
		}, "invalid Hermes run ID"},
		"redirect": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "http://127.0.0.1:1/stolen")
			w.WriteHeader(http.StatusTemporaryRedirect)
			fmt.Fprint(w, `{"error":"redirect","message":"no"}`)
		}, "Gateway HTTP 307"},
		"compressed": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			fmt.Fprint(w, "compressed")
		}, "encoding or length"},
		"terminal escape in error": {func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"policy_denied","message":"\u001b[31mowned"}`)
		}, "invalid error response"},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			if err := run([]string{"hermes", "run", "-bundle", fixture.bundlePath, "-gateway-url", server.URL,
				"-token-file", tokenPath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestHermesAPIErrorQuotesUntrustedUnicodeAndBoundsFields(t *testing.T) {
	err := hermesAPIError(http.StatusForbidden, []byte(`{"error":"policy_denied","message":"caf\u00e9"}`))
	if err == nil || strings.Contains(err.Error(), "café") || !strings.Contains(err.Error(), `"caf\u00e9"`) {
		t.Fatalf("safely rendered error=%v", err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"error":"bad code","message":"denied"}`),
		[]byte(`{"error":"denied","message":"line\nbreak"}`),
		[]byte(`{"error":"denied","message":"` + strings.Repeat("x", 4097) + `"}`),
	} {
		if err := hermesAPIError(http.StatusForbidden, raw); err == nil || !strings.Contains(err.Error(), "invalid error response") {
			t.Fatalf("untrusted error accepted: %q => %v", raw, err)
		}
	}
}

func TestHermesStatusBindsRunAndKnownState(t *testing.T) {
	runID := "run_0123456789abcdef0123456789abcdef"
	for _, status := range []string{"queued", "running", "completed", "failed", "cancelled"} {
		raw := []byte(fmt.Sprintf(`{"run_id":%q,"status":%q,"output":"untrusted"}`, runID, status))
		got, err := hermesStatus(raw, 4096, runID)
		if err != nil || got != status {
			t.Fatalf("status %q => %q, %v", status, got, err)
		}
	}
	for name, raw := range map[string][]byte{
		"missing run":    []byte(`{"status":"completed"}`),
		"different run":  []byte(`{"run_id":"run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"completed"}`),
		"unknown status": []byte(fmt.Sprintf(`{"run_id":%q,"status":"finished"}`, runID)),
		"duplicate":      []byte(fmt.Sprintf(`{"run_id":%q,"run_id":%q,"status":"completed"}`, runID, runID)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := hermesStatus(raw, 4096, runID); err == nil {
				t.Fatal("unbound Hermes status accepted")
			}
		})
	}
}

func TestHermesRunRejectsExpiredOrNonHermesBundleBeforeNetwork(t *testing.T) {
	fixture := newTaskCLIFixture(t)
	fixture.issue(t)
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.now.Add(time.Hour) }
	if err := run([]string{"hermes", "run", "-bundle", fixture.bundlePath, "-gateway-url", server.URL,
		"-token-file", tokenPath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired bundle error=%v", err)
	}
	timeNow = priorNow
	if calls.Load() != 0 {
		t.Fatalf("expired bundle reached network %d times", calls.Load())
	}

	raw, err := os.ReadFile(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle taskBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Operation.ID = "other.run"
	bundle.Operation.PolicyDigest = gatewayOperationDigestForTest(bundle.Operation)
	changed, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	changedPath := filepath.Join(fixture.directory, "non-hermes.bundle.json")
	if err := os.WriteFile(changedPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"hermes", "run", "-bundle", changedPath, "-gateway-url", server.URL,
		"-token-file", tokenPath}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("non-Hermes bundle accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("non-Hermes bundle reached network %d times", calls.Load())
	}
}

func gatewayOperationDigestForTest(operation serviceTrustOperation) string {
	return gateway.ServiceOperationDigest(operation.gatewayOperation())
}
