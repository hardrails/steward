package uplink

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics is a Poller's live operational counters and gauges, read by the
// optional /metrics HTTP endpoint (see internal/server's metrics handler) from
// a goroutine other than the one Poller.Run drives. NewPoller always
// constructs one (whether or not -enable-metrics is set: counting is a
// handful of atomic increments and a small mutex-guarded update, cheap enough
// to always do, so the /metrics gate only needs to decide whether to RENDER
// these numbers, never whether to collect them). Every method is additionally
// nil-safe — mirroring AuditLogger's nil-safety in audit.go — as a defensive
// belt-and-braces: internal/uplink's own tests build a *dispatcher directly,
// bypassing NewPoller, and a nil *Metrics there must be an inert no-op, not a
// nil-pointer panic on the first executed command.
//
// The three poll-latency gauges (min/max/last) are guarded by their own mutex
// rather than being independent atomics, because a caller must read all three
// as one coherent triple (see Snapshot) — three independent atomic reads could
// observe min/max/last from three different polls. The two command counters
// and the failure count need no such coherency (each is read and reported
// standalone), so they are plain atomics.
type Metrics struct {
	mu              sync.Mutex
	pollLatencyMin  time.Duration
	pollLatencyMax  time.Duration
	pollLatencyLast time.Duration
	pollCount       int64

	commandsSucceeded   atomic.Int64
	commandsFailed      atomic.Int64
	consecutiveFailures atomic.Int64

	// pollsSucceeded and credentialRejected back the readiness gate (see
	// readiness and Poller.Ready), read by the /v1/readiness HTTP handler from a
	// goroutine other than the one Poller.Run drives. pollsSucceeded counts polls
	// that returned commands cleanly (classOK); once it is non-zero the node has
	// proven it can reach its control plane, so a later transient blip never flips
	// readiness back. credentialRejected is true only while the loop is paused on
	// a fatal 401/403 waiting for a new credential (a persistent-failure state the
	// consecutive-failure count alone does not capture, since a first-poll
	// rejection leaves that count at 0).
	pollsSucceeded     atomic.Int64
	credentialRejected atomic.Bool
}

// Snapshot is a point-in-time, race-free copy of a Poller's metrics, shaped
// for /metrics rendering.
type Snapshot struct {
	PollLatencyMin    time.Duration
	PollLatencyMax    time.Duration
	PollLatencyLast   time.Duration
	PollCount         int64
	CommandsSucceeded int64
	CommandsFailed    int64
	// CurrentBackoff is the wait duration the poll loop would use for its next
	// poll at the current consecutive-failure count: the base interval when
	// there have been no recent failures, or the exponential backoff otherwise
	// (see backoffDuration). It does not include jitter, matching how an
	// operator reasons about backoff state ("roughly how long until the next
	// retry"), not the exact jittered value of any one wait.
	CurrentBackoff time.Duration
}

// recordPollLatency updates the min/max/last poll-latency gauges and the poll
// counter with one round-trip duration. Called once per poll attempt
// (success or failure alike — latency is round-trip time, not an outcome
// judgment), from the single goroutine Poller.Run drives.
func (m *Metrics) recordPollLatency(d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pollCount == 0 || d < m.pollLatencyMin {
		m.pollLatencyMin = d
	}
	if d > m.pollLatencyMax {
		m.pollLatencyMax = d
	}
	m.pollLatencyLast = d
	m.pollCount++
}

// setConsecutiveFailures records the poll loop's current run length of
// consecutive poll failures, mirroring the `failures` local variable
// Poller.Run already tracks. It is stored separately (rather than read
// directly off Run's stack) precisely because the /metrics handler reads it
// from a different goroutine.
func (m *Metrics) setConsecutiveFailures(n int) {
	if m == nil {
		return
	}
	m.consecutiveFailures.Store(int64(n))
}

// recordPollSuccess records that a poll returned cleanly (classOK). Called from
// the single goroutine Poller.Run drives, once per successful poll. It is the
// "has the node ever reached its control plane" signal the readiness gate keys
// on; it never decrements, so one success makes the node durably ready across a
// later transient failure.
func (m *Metrics) recordPollSuccess() {
	if m == nil {
		return
	}
	m.pollsSucceeded.Add(1)
}

// setCredentialRejected records whether the poll loop is currently paused on a
// fatal 401/403 waiting for a new credential (see Poller.Run's classFatal arm).
// Called from the single goroutine Poller.Run drives; read by the readiness
// gate from the HTTP goroutine.
func (m *Metrics) setCredentialRejected(rejected bool) {
	if m == nil {
		return
	}
	m.credentialRejected.Store(rejected)
}

// readiness reports whether the uplink poll loop is ready to serve traffic and,
// when not, a human detail naming why. The rule (see Poller.Ready and
// GET /v1/readiness) is: ready if it has completed at least one successful poll
// OR is not in a persistent-failure state. So a node is NOT ready only when it
// has never polled successfully AND is currently stuck — its credential was
// rejected, or it has failed at least persistentFailureThreshold times in a row
// (a sustained inability to reach the control plane, not a single blip). A
// freshly started node with no failures yet is ready; a node that has proven it
// can reach its control plane stays ready across a later transient blip.
func (m *Metrics) readiness(persistentFailureThreshold int64) (ready bool, detail string) {
	if m == nil {
		return true, "" // defensive: a nil metrics has no failure to report.
	}
	if m.pollsSucceeded.Load() > 0 {
		return true, ""
	}
	if m.credentialRejected.Load() {
		return false, "uplink credential was rejected and no poll has succeeded yet; waiting for a valid credential"
	}
	if m.consecutiveFailures.Load() >= persistentFailureThreshold {
		return false, "uplink has not completed a successful poll and is in sustained failure"
	}
	return true, ""
}

// recordCommandOutcome increments the success or failure counter for one
// command's terminal (reported) outcome. Called from dispatcher.execute; see
// its doc comment for why this fires exactly once per reported command,
// never for a fenced or deferred-retry outcome.
func (m *Metrics) recordCommandOutcome(succeeded bool) {
	if m == nil {
		return
	}
	if succeeded {
		m.commandsSucceeded.Add(1)
	} else {
		m.commandsFailed.Add(1)
	}
}

// snapshot builds a Snapshot from the live metrics. baseInterval is the
// Poller's configured base poll interval, needed to translate the stored
// consecutive-failure count into a CurrentBackoff duration via the same
// backoffDuration function the poll loop itself uses.
func (m *Metrics) snapshot(baseInterval time.Duration) Snapshot {
	if m == nil {
		return Snapshot{CurrentBackoff: backoffDuration(baseInterval, 0)}
	}
	m.mu.Lock()
	min, max, last, count := m.pollLatencyMin, m.pollLatencyMax, m.pollLatencyLast, m.pollCount
	m.mu.Unlock()

	failures := int(m.consecutiveFailures.Load())
	return Snapshot{
		PollLatencyMin:    min,
		PollLatencyMax:    max,
		PollLatencyLast:   last,
		PollCount:         count,
		CommandsSucceeded: m.commandsSucceeded.Load(),
		CommandsFailed:    m.commandsFailed.Load(),
		CurrentBackoff:    backoffDuration(baseInterval, failures),
	}
}
