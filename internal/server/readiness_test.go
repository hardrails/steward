package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hardrails/steward/internal/runtime"
)

func decodeReadiness(t *testing.T, rec *httptest.ResponseRecorder) readinessResponse {
	t.Helper()
	var got readinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode readiness: %v (body=%s)", err, rec.Body.String())
	}
	return got
}

// TestReadinessReadyByDefault: an in-memory tracker with no uplink passes every
// gate (tracker initialized, no uplink to check, no state file to probe), so
// GET /v1/readiness is a 200 {"status":"ready"}.
func TestReadinessReadyByDefault(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodGet, "/v1/readiness", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q, want application/json", ct)
	}
	if got := decodeReadiness(t, rec); got.Status != "ready" || got.Check != "" || got.Detail != "" {
		t.Fatalf("body=%+v, want {ready, no check/detail}", got)
	}
}

// TestReadinessUplinkNotReady: when the uplink source reports not-ready, the
// probe is a 503 naming the "uplink" check and carrying the source's detail.
func TestReadinessUplinkNotReady(t *testing.T) {
	fake := fakeUplinkMetrics{ready: false, readyDetail: "uplink credential was rejected"}
	h := NewWithTracker(metricsTestLogger(), runtime.NewTracker(0), 0, false, fake).Handler()

	rec := do(h, http.MethodGet, "/v1/readiness", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness: status=%d want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeReadiness(t, rec)
	if got.Status != "not_ready" || got.Check != "uplink" {
		t.Fatalf("body=%+v, want not_ready/uplink", got)
	}
	if got.Detail == "" {
		t.Fatal("a not_ready body must carry a detail naming why the check failed")
	}
}

// TestReadinessUplinkReady: when the uplink source reports ready (and there is
// no state file to probe), the probe is a 200.
func TestReadinessUplinkReady(t *testing.T) {
	fake := fakeUplinkMetrics{ready: true}
	h := NewWithTracker(metricsTestLogger(), runtime.NewTracker(0), 0, false, fake).Handler()

	rec := do(h, http.MethodGet, "/v1/readiness", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := decodeReadiness(t, rec); got.Status != "ready" {
		t.Fatalf("body=%+v, want ready", got)
	}
}

// TestReadinessStateFileNotWritable: a durable tracker whose state directory
// does not exist cannot persist a mutation, so the probe is a 503 naming the
// "state_file" check — the gate the liveness probe deliberately does not run.
func TestReadinessStateFileNotWritable(t *testing.T) {
	// A missing state file is a valid first run, so LoadTracker succeeds; the
	// missing parent directory only bites when a write is attempted.
	badPath := filepath.Join(t.TempDir(), "does-not-exist", "state.json")
	tr, err := runtime.LoadTracker(0, badPath)
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	h := NewWithTracker(metricsTestLogger(), tr, 0, false, nil).Handler()

	rec := do(h, http.MethodGet, "/v1/readiness", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness: status=%d want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeReadiness(t, rec)
	if got.Status != "not_ready" || got.Check != "state_file" {
		t.Fatalf("body=%+v, want not_ready/state_file", got)
	}
	if got.Detail == "" {
		t.Fatal("a not_ready body must carry a detail naming why the check failed")
	}
}

// TestReadinessNilTrackerFailsClosed exercises the defensive first gate: a
// Server with no tracker (never reachable through New/NewWithTracker, but a
// fail-closed guard against a future wiring path) reports not_ready naming the
// tracker check rather than panicking.
func TestReadinessNilTracker(t *testing.T) {
	s := &Server{logger: metricsTestLogger()}
	rec := httptest.NewRecorder()
	s.handleReadiness(rec, httptest.NewRequest(http.MethodGet, "/v1/readiness", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil tracker: status=%d want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := decodeReadiness(t, rec); got.Status != "not_ready" || got.Check != "tracker" {
		t.Fatalf("body=%+v, want not_ready/tracker", got)
	}
}

// TestReadinessDurableWritableIsReady: a durable tracker with a writable state
// directory passes the state-file gate, so the probe is a 200.
func TestReadinessDurableWritableIsReady(t *testing.T) {
	tr, err := runtime.LoadTracker(0, filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("LoadTracker: %v", err)
	}
	h := NewWithTracker(metricsTestLogger(), tr, 0, false, nil).Handler()

	rec := do(h, http.MethodGet, "/v1/readiness", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("readiness: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := decodeReadiness(t, rec); got.Status != "ready" {
		t.Fatalf("body=%+v, want ready", got)
	}
}
