package uplink

import (
	"testing"
	"time"
)

// TestMetricsReadiness pins the readiness rule (see Metrics.readiness and
// Poller.Ready): ready if a poll has succeeded OR the loop is not in a
// persistent-failure state; not ready only when it has never succeeded AND is
// stuck (credential rejected, or >= threshold consecutive failures). Each case
// is exactly assertable, so a mutant that flips a comparison or drops a branch
// is caught here rather than in a timing-dependent integration run.
func TestMetricsReadiness(t *testing.T) {
	const threshold = 3

	t.Run("fresh with no failures is ready", func(t *testing.T) {
		if ready, _ := (&Metrics{}).readiness(threshold); !ready {
			t.Fatal("a fresh metrics with no failures must be ready")
		}
	})

	t.Run("one success stays ready despite later failure signals", func(t *testing.T) {
		m := &Metrics{}
		m.recordPollSuccess()
		m.setConsecutiveFailures(threshold + 100)
		m.setCredentialRejected(true)
		if ready, _ := m.readiness(threshold); !ready {
			t.Fatal("a poller that has succeeded once must stay ready across a later blip")
		}
	})

	t.Run("credential rejected with no success is not ready", func(t *testing.T) {
		m := &Metrics{}
		m.setCredentialRejected(true)
		ready, detail := m.readiness(threshold)
		if ready {
			t.Fatal("a credential-rejected loop with no success must not be ready")
		}
		if detail == "" {
			t.Fatal("a not-ready result must carry a detail naming why")
		}
	})

	t.Run("failures at threshold with no success is not ready", func(t *testing.T) {
		m := &Metrics{}
		m.setConsecutiveFailures(threshold)
		ready, detail := m.readiness(threshold)
		if ready {
			t.Fatal("sustained failures (>= threshold) with no success must not be ready")
		}
		if detail == "" {
			t.Fatal("a not-ready result must carry a detail naming why")
		}
	})

	t.Run("failures below threshold with no success is still ready", func(t *testing.T) {
		m := &Metrics{}
		m.setConsecutiveFailures(threshold - 1)
		if ready, _ := m.readiness(threshold); !ready {
			t.Fatal("a brief blip below the threshold must not flip readiness")
		}
	})

	t.Run("nil metrics is defensively ready and its setters are inert", func(t *testing.T) {
		var m *Metrics
		// Mirrors AuditLogger's nil-safety: a *dispatcher built directly in tests
		// bypasses NewPoller, so a nil *Metrics must be an inert no-op, never a
		// nil-pointer panic.
		m.recordPollSuccess()
		m.setCredentialRejected(true)
		if ready, _ := m.readiness(threshold); !ready {
			t.Fatal("a nil metrics has no failure to report and must be ready")
		}
	})
}

// TestMetricsRecordPollLatencyTracksMinMaxLastAndCount pins recordPollLatency's
// exact min/max/last/count arithmetic directly (rather than through a real,
// timing-nondeterministic HTTP round trip — see
// TestPollerMetricsSnapshotTracksPollCountLatencyAndBackoff for that
// end-to-end proof), so a wrong comparison operator or an off-by-one boundary
// produces a wrong, exactly-assertable value here.
func TestMetricsRecordPollLatencyTracksMinMaxLastAndCount(t *testing.T) {
	m := &Metrics{}

	m.recordPollLatency(50 * time.Millisecond)
	if snap := m.snapshot(time.Second); snap.PollLatencyMin != 50*time.Millisecond || snap.PollLatencyMax != 50*time.Millisecond || snap.PollLatencyLast != 50*time.Millisecond || snap.PollCount != 1 {
		t.Fatalf("after one 50ms sample: snapshot = %+v, want min=max=last=50ms count=1", snap)
	}

	m.recordPollLatency(10 * time.Millisecond) // a new minimum
	if snap := m.snapshot(time.Second); snap.PollLatencyMin != 10*time.Millisecond {
		t.Errorf("PollLatencyMin = %s, want 10ms (the new minimum)", snap.PollLatencyMin)
	}

	m.recordPollLatency(100 * time.Millisecond) // a new maximum
	if snap := m.snapshot(time.Second); snap.PollLatencyMax != 100*time.Millisecond {
		t.Errorf("PollLatencyMax = %s, want 100ms (the new maximum)", snap.PollLatencyMax)
	}

	m.recordPollLatency(30 * time.Millisecond) // neither min nor max, but the new last
	snap := m.snapshot(time.Second)
	if snap.PollLatencyMin != 10*time.Millisecond {
		t.Errorf("PollLatencyMin = %s, want unchanged 10ms", snap.PollLatencyMin)
	}
	if snap.PollLatencyMax != 100*time.Millisecond {
		t.Errorf("PollLatencyMax = %s, want unchanged 100ms", snap.PollLatencyMax)
	}
	if snap.PollLatencyLast != 30*time.Millisecond {
		t.Errorf("PollLatencyLast = %s, want 30ms (the most recent sample, even though it set neither min nor max)", snap.PollLatencyLast)
	}
	if snap.PollCount != 4 {
		t.Errorf("PollCount = %d, want 4", snap.PollCount)
	}
}

// TestMetricsRecordCommandOutcomeCounters pins the success/failure counters
// directly.
func TestMetricsRecordCommandOutcomeCounters(t *testing.T) {
	m := &Metrics{}
	m.recordCommandOutcome(true)
	m.recordCommandOutcome(true)
	m.recordCommandOutcome(false)

	snap := m.snapshot(time.Second)
	if snap.CommandsSucceeded != 2 {
		t.Errorf("CommandsSucceeded = %d, want 2", snap.CommandsSucceeded)
	}
	if snap.CommandsFailed != 1 {
		t.Errorf("CommandsFailed = %d, want 1", snap.CommandsFailed)
	}
}

// TestMetricsSnapshotCurrentBackoffTracksConsecutiveFailures pins the
// translation from the stored failure count to CurrentBackoff via the same
// backoffDuration function the poll loop itself uses.
func TestMetricsSnapshotCurrentBackoffTracksConsecutiveFailures(t *testing.T) {
	m := &Metrics{}
	const base = 10 * time.Second

	if snap := m.snapshot(base); snap.CurrentBackoff != base {
		t.Errorf("CurrentBackoff with no failures = %s, want the base interval %s", snap.CurrentBackoff, base)
	}

	m.setConsecutiveFailures(2)
	want := backoffDuration(base, 2)
	if snap := m.snapshot(base); snap.CurrentBackoff != want {
		t.Errorf("CurrentBackoff after 2 failures = %s, want %s (backoffDuration(base, 2))", snap.CurrentBackoff, want)
	}

	m.setConsecutiveFailures(0) // a success resets the run
	if snap := m.snapshot(base); snap.CurrentBackoff != base {
		t.Errorf("CurrentBackoff after failures reset to 0 = %s, want the base interval %s", snap.CurrentBackoff, base)
	}
}

// TestMetricsNilIsInertNoOp proves every *Metrics method tolerates a nil
// receiver: internal/uplink's own dispatcher tests construct a *dispatcher
// directly (bypassing NewPoller, which always supplies a real *Metrics — see
// metrics.go's doc comment), so a nil metrics field must never panic.
func TestMetricsNilIsInertNoOp(t *testing.T) {
	var m *Metrics
	m.recordPollLatency(time.Second)
	m.setConsecutiveFailures(3)
	m.recordCommandOutcome(true)

	snap := m.snapshot(10 * time.Second)
	if snap.CurrentBackoff != 10*time.Second {
		t.Errorf("nil Metrics snapshot CurrentBackoff = %s, want the base interval 10s (backoffDuration(base, 0))", snap.CurrentBackoff)
	}
	if snap.PollCount != 0 || snap.CommandsSucceeded != 0 || snap.CommandsFailed != 0 {
		t.Errorf("nil Metrics snapshot = %+v, want every counter at its zero value", snap)
	}
}
