package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/runtime"
	"github.com/hardrails/steward/internal/uplink"
)

// UplinkMetrics is the subset of the uplink poll loop's live state the server
// observes — for the /metrics endpoint (MetricsSnapshot) and the /v1/readiness
// gate (Ready). It is an interface — satisfied by *uplink.Poller — rather than
// a direct *uplink.Poller field, so a test can inject a fake without driving a
// real poll loop over HTTP. A nil UplinkMetrics (the uplink is disabled, e.g.
// no -uplink-url) is expected: handleMetrics then omits the uplink_* series and
// handleReadiness skips the uplink readiness gate entirely.
type UplinkMetrics interface {
	MetricsSnapshot() uplink.Snapshot
	// Ready reports whether the uplink poll loop is ready to serve traffic — it
	// has completed at least one successful poll, or is not in a
	// persistent-failure state — and, when not, a human detail naming why (see
	// uplink.Poller.Ready).
	Ready() (ready bool, detail string)
}

// handleMetrics renders Steward's operational state in the Prometheus text
// exposition format
// (https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md),
// built with only the standard library (fmt/strings and this handler's own
// http.ResponseWriter) — see AGENTS.md's zero-dependency invariant. The
// format itself is simple enough — `# HELP`/`# TYPE` comment lines followed
// by `metric_name{labels} value` lines — that pulling in the official
// prometheus/client_golang library would buy nothing over a handful of
// fmt.Fprintf calls; see plan.md for the explicit buy-vs-build note.
//
// It is registered only when -enable-metrics is set (see Handler and New):
// unlike every other endpoint, /metrics is OFF by default, matching
// ARCHITECTURE.md's "intentionally minimal" posture — an operator opts in
// deliberately rather than this unauthenticated-by-design service exposing
// operational detail (instance counts, uplink health) to any caller that can
// reach it, by default. When reachable at all, it is reachable only through
// the same inbound listener, rate limiter, and logging/recovery middleware
// every other endpoint uses (see Handler) — there is no second listener.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder

	counts := s.tracker.StatusCounts()
	statuses := make([]string, 0, len(counts))
	for status := range counts {
		statuses = append(statuses, string(status))
	}
	sort.Strings(statuses)

	// steward_instances (not steward_instances_total): Prometheus naming
	// convention reserves the _total suffix for counter metric families
	// (monotonically increasing); this is a gauge (instance counts rise and
	// fall), so it must not carry that suffix, unlike the genuine counters
	// below (steward_uplink_polls_total, steward_uplink_commands_total).
	fmt.Fprintln(&b, "# HELP steward_instances Current number of tracked instances, by status.")
	fmt.Fprintln(&b, "# TYPE steward_instances gauge")
	for _, status := range statuses {
		fmt.Fprintf(&b, "steward_instances{status=%q} %d\n", status, counts[runtime.Status(status)])
	}

	fmt.Fprintln(&b, "# HELP steward_max_instances Configured instance capacity cap (Provision returns 503 beyond it).")
	fmt.Fprintln(&b, "# TYPE steward_max_instances gauge")
	fmt.Fprintf(&b, "steward_max_instances %d\n", s.tracker.MaxInstances())

	if s.uplinkMetrics != nil {
		snap := s.uplinkMetrics.MetricsSnapshot()

		fmt.Fprintln(&b, "# HELP steward_uplink_poll_latency_seconds Uplink /uplink/poll round-trip latency.")
		fmt.Fprintln(&b, "# TYPE steward_uplink_poll_latency_seconds gauge")
		fmt.Fprintf(&b, "steward_uplink_poll_latency_seconds{stat=\"min\"} %s\n", formatSeconds(snap.PollLatencyMin))
		fmt.Fprintf(&b, "steward_uplink_poll_latency_seconds{stat=\"max\"} %s\n", formatSeconds(snap.PollLatencyMax))
		fmt.Fprintf(&b, "steward_uplink_poll_latency_seconds{stat=\"last\"} %s\n", formatSeconds(snap.PollLatencyLast))

		fmt.Fprintln(&b, "# HELP steward_uplink_polls_total Total uplink polls attempted (success and failure alike).")
		fmt.Fprintln(&b, "# TYPE steward_uplink_polls_total counter")
		fmt.Fprintf(&b, "steward_uplink_polls_total %d\n", snap.PollCount)

		fmt.Fprintln(&b, "# HELP steward_uplink_commands_total Uplink commands executed, by outcome.")
		fmt.Fprintln(&b, "# TYPE steward_uplink_commands_total counter")
		fmt.Fprintf(&b, "steward_uplink_commands_total{status=\"success\"} %d\n", snap.CommandsSucceeded)
		fmt.Fprintf(&b, "steward_uplink_commands_total{status=\"failure\"} %d\n", snap.CommandsFailed)

		fmt.Fprintln(&b, "# HELP steward_uplink_backoff_seconds Current uplink poll interval/backoff (excludes jitter).")
		fmt.Fprintln(&b, "# TYPE steward_uplink_backoff_seconds gauge")
		fmt.Fprintf(&b, "steward_uplink_backoff_seconds %s\n", formatSeconds(snap.CurrentBackoff))
	}

	// text/plain with an explicit exposition-format version is what a real
	// Prometheus scraper (and client_golang's own HTTP handler) sends; an
	// operator's scrape config Content-Type check should see the same value
	// whether the exposing process used the official client library or not.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// formatSeconds renders d as a decimal-seconds float the way Prometheus
// expects durations (e.g. "0.021" for 21ms), matching client_golang's own
// convention so a real Prometheus scraper parses it identically to a
// client_golang-exposed gauge.
func formatSeconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64)
}
