package server

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/uplink"
)

// fakeUplinkMetrics is a test double for UplinkMetrics: it returns a fixed
// snapshot without driving a real poll loop over HTTP.
type fakeUplinkMetrics struct {
	snap uplink.Snapshot
}

func (f fakeUplinkMetrics) MetricsSnapshot() uplink.Snapshot { return f.snap }

func metricsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMetricsEndpointAbsentByDefault proves /metrics is off unless
// -enable-metrics (here, the enableMetrics constructor argument) is true: the
// route is never registered, so a request 404s exactly like any other unknown
// path — the same JSON error shape jsonErrors gives every unrouted request,
// not a special case.
func TestMetricsEndpointAbsentByDefault(t *testing.T) {
	h := New(metricsTestLogger(), 0, 0, false, nil).Handler()
	rec := do(h, http.MethodGet, "/metrics", "")
	assertJSONError(t, rec, http.StatusNotFound)
}

// TestMetricsEndpointServesInstanceCounts proves the enabled endpoint reports
// the tracker's live instance counts (broken down by status) and the
// configured capacity cap, in Prometheus text exposition format, and that
// the uplink_* series are entirely absent when no UplinkMetrics source is
// wired (the uplink disabled case).
func TestMetricsEndpointServesInstanceCounts(t *testing.T) {
	h := New(metricsTestLogger(), 5, 0, true, nil).Handler()

	provisionID(t, h, "agent-1", "")
	ref2 := provisionID(t, h, "agent-2", "")
	do(h, http.MethodPost, "/v1/instances/"+ref2+"/start", "")

	rec := do(h, http.MethodGet, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want a text/plain exposition format", ct)
	}
	body := rec.Body.String()

	for _, want := range []string{
		"# TYPE steward_instances gauge",
		`steward_instances{status="PENDING"} 1`,
		`steward_instances{status="RUNNING"} 1`,
		"# TYPE steward_max_instances gauge",
		"steward_max_instances 5",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "steward_uplink_") {
		t.Errorf("body must omit every steward_uplink_* series when no UplinkMetrics is wired:\n%s", body)
	}

	// It flows through the same middleware chain every other route uses (see
	// Handler): a request-id header proves withLogging wraps it too, not a
	// bespoke path around the shared chain.
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("GET /metrics is missing X-Request-Id; it must flow through the same middleware chain as every other route")
	}
}

// TestMetricsEndpointIncludesUplinkSeriesWhenWired proves the uplink_* series
// render from whatever UplinkMetrics.MetricsSnapshot returns, using a fake
// double rather than a real Poller (which would need an HTTP-mocked control
// plane to drive).
func TestMetricsEndpointIncludesUplinkSeriesWhenWired(t *testing.T) {
	fake := fakeUplinkMetrics{snap: uplink.Snapshot{
		PollLatencyMin:    10 * time.Millisecond,
		PollLatencyMax:    50 * time.Millisecond,
		PollLatencyLast:   20 * time.Millisecond,
		PollCount:         7,
		CommandsSucceeded: 3,
		CommandsFailed:    1,
		CurrentBackoff:    2 * time.Second,
	}}
	h := New(metricsTestLogger(), 0, 0, true, fake).Handler()

	rec := do(h, http.MethodGet, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	for _, want := range []string{
		`steward_uplink_poll_latency_seconds{stat="min"} 0.01`,
		`steward_uplink_poll_latency_seconds{stat="max"} 0.05`,
		`steward_uplink_poll_latency_seconds{stat="last"} 0.02`,
		"steward_uplink_polls_total 7",
		`steward_uplink_commands_total{status="success"} 3`,
		`steward_uplink_commands_total{status="failure"} 1`,
		"steward_uplink_backoff_seconds 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q:\n%s", want, body)
		}
	}
}

// TestMetricsEndpointMethodNotAllowed proves the route is registered GET-only,
// matching every other endpoint's convention.
func TestMetricsEndpointMethodNotAllowed(t *testing.T) {
	h := New(metricsTestLogger(), 0, 0, true, nil).Handler()
	rec := do(h, http.MethodPost, "/metrics", "")
	assertJSONError(t, rec, http.StatusMethodNotAllowed)
}
