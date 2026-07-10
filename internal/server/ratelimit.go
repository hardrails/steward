package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Inbound per-source rate limiting is the same defensive class as the request-body
// and instance-count caps: this listener is unauthenticated by design, so a flood of
// requests from one source is a cheap denial-of-service unless it is shed early. The
// limiter is a hand-rolled token bucket per source IP — stdlib only (a mutex, a map,
// and time math; no third-party rate-limiter, so the zero-dependency invariant
// holds) — mirroring the hand-rolled backoff/jitter in internal/uplink/poller.go.
//
// Budget rationale for the defaults below: Steward is a control-plane-facing
// LIFECYCLE API. Railyard drives provision/start/stop/hibernate/destroy/status/list
// at reconciler-and-human pace, not high-frequency traffic. A default of 20 requests
// per second sustained with a burst of 40 (rateBurstFactor) comfortably covers normal
// operation with headroom: a fleet reconciliation sweep or a batch of lifecycle
// changes across this node's instances is a short spike well inside the 40-token
// burst, steady control traffic sits far below 20/s, and even a liveness probe
// polling several times a second is unaffected. Meanwhile an unauthenticated flood
// (thousands of requests/second from one source) drains the bucket in well under a
// second and is shed with 429s. The budget is per-source, so one abusive IP cannot
// degrade service for the legitimate control plane arriving from another IP.
//
// A rare bulk operation (cold-provisioning hundreds of instances back to back, one
// Railyard replica, one source IP, no client-side throttle) CAN exceed the 40-token
// burst and get some items shed with 429 -- whether that lands as smooth
// rate-shaping or a hard per-item failure depends entirely on whether the CALLER
// retries a 429 with Retry-After. This listener sheds the request before any
// handler work runs, so a 429 is always safe to retry -- but that is a property the
// caller must act on, not something this limiter can guarantee on its own. An
// operator who needs more headroom can raise -max-requests-per-second, or disable
// the limiter with 0 when Steward already sits behind their own rate-limiting
// gateway.

const (
	// rateBurstFactor sets the token-bucket depth as a multiple of the per-second
	// rate (burst = factor * rate). Two seconds' worth of tokens absorbs a normal
	// reconciliation spike without letting a sustained flood through.
	rateBurstFactor = 2

	// maxTrackedSources caps how many per-source buckets the limiter holds at once,
	// bounding memory against a DISTRIBUTED slow-drip flood from many source IPs
	// (rate-limiting one IP does nothing about a million distinct IPs each sending a
	// few requests — that is a memory-DoS, not a rate-DoS). At a few tens of bytes per
	// entry this ceiling is ~1-2 MiB worst case: thousands of times more sources than a
	// single-node control-plane API ever sees legitimately, so reaching it is itself an
	// attack signal. When the map is full and the periodic sweep frees nothing (every
	// tracked source is active), a brand-new source is refused with 429 rather than
	// allocated — an already-tracked (legitimate, long-lived) client keeps its bucket
	// and is unaffected. This is the memory-DoS counterpart to the instance-count cap.
	maxTrackedSources = 16384

	// sweepInterval bounds how often the O(n) idle-bucket reclamation sweep runs: at
	// most once per interval, triggered lazily by an incoming request, so its cost is
	// amortized to negligible. It is the reclamation cadence — a source that goes quiet
	// has its bucket dropped within roughly this interval past its idle TTL.
	sweepInterval = time.Minute

	// idleTTL is how long a source must go unseen before the sweep evicts its bucket. A
	// bucket unseen this long has fully refilled (a fresh bucket starts full, so
	// recreating it on the source's next request is behaviorally identical to keeping
	// it), which is why evicting it loses no rate-limit state. The sweep never evicts a
	// still-depleted bucket — that would hand its source a free token reset — so
	// sweepLocked extends this floor past the full-refill time for very low rates.
	idleTTL = 2 * time.Minute
)

// bucket is one source's token-bucket state. tokens is held in [0, burst] and
// lastSeen is the time of its last refill; both are mutated only under rateLimiter.mu.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// rateLimiter is a per-source token-bucket limiter behind a single mutex. All map and
// bucket access happens under mu; the configuration fields (ratePerSec, burst,
// maxSources, sweepEvery, idleAfter, now) are set at construction and never mutated
// afterward, so they need no lock.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time

	ratePerSec float64
	burst      float64
	maxSources int
	sweepEvery time.Duration
	idleAfter  time.Duration

	// now returns the current time; nil means time.Now. It is injected in tests so
	// the refill and eviction behavior can be exercised on a deterministic clock.
	now func() time.Time
}

// newRateLimiter builds a limiter allowing ratePerSecond sustained requests per
// source with a burst of rateBurstFactor times that. ratePerSecond must be positive
// (the caller only builds a limiter when rate limiting is enabled).
func newRateLimiter(ratePerSecond int) *rateLimiter {
	return &rateLimiter{
		buckets:    make(map[string]*bucket),
		ratePerSec: float64(ratePerSecond),
		burst:      float64(ratePerSecond * rateBurstFactor),
		maxSources: maxTrackedSources,
		sweepEvery: sweepInterval,
		idleAfter:  idleTTL,
	}
}

func (l *rateLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// allow reports whether a request from the given source key is permitted now. When it
// denies, retryAfterSeconds is the whole-second Retry-After hint (always >= 1).
func (l *rateLimiter) allow(key string) (allowed bool, retryAfterSeconds int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()

	// Amortized reclamation: at most once per sweepEvery, drop idle (fully refilled)
	// buckets so a burst of many distinct sources does not retain memory indefinitely.
	if now.Sub(l.lastSweep) >= l.sweepEvery {
		l.sweepLocked(now)
		l.lastSweep = now
	}

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxSources {
			// Ceiling reached and the sweep reclaimed nothing (every tracked source is
			// active): refuse to allocate a new bucket. This bounds memory under a
			// distributed many-source flood; existing sources keep their buckets.
			return false, l.tableFullRetryAfterSeconds()
		}
		b = &bucket{tokens: l.burst, lastSeen: now}
		l.buckets[key] = b
	} else {
		// Refill by the time elapsed since this source was last seen, capped at burst.
		b.tokens += now.Sub(b.lastSeen).Seconds() * l.ratePerSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastSeen = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, retryAfterForTokens(b.tokens, l.ratePerSec)
}

// sweepLocked drops every bucket unseen for the idle threshold. The threshold is at
// least idleAfter and never less than the full-refill time, so an evicted bucket has
// always refilled to full: recreating it fresh on the source's next request is then
// behaviorally identical to having kept it, and an active (still-depleted) source's
// bucket is never dropped out from under it. The caller holds l.mu.
func (l *rateLimiter) sweepLocked(now time.Time) {
	threshold := l.idleAfter
	if refill := l.fullRefill(); refill > threshold {
		threshold = refill
	}
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) >= threshold {
			delete(l.buckets, key)
		}
	}
}

// fullRefill is the time for an empty bucket to refill to burst at the configured
// rate.
func (l *rateLimiter) fullRefill() time.Duration {
	return time.Duration(l.burst / l.ratePerSec * float64(time.Second))
}

// tableFullRetryAfterSeconds advises a source refused because the tracking table is
// full to retry once the reclamation sweep has had a chance to run. It returns the
// remaining time until the next sweep (sweepEvery - elapsed since lastSweep), floored
// at 1s, rather than always the full interval — the caller holds l.mu, so lastSweep
// is current.
func (l *rateLimiter) tableFullRetryAfterSeconds() int {
	remaining := l.sweepEvery - l.clock().Sub(l.lastSweep)
	if remaining < 0 {
		remaining = 0
	}
	secs := int(math.Ceil(remaining.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return secs
}

// retryAfterForTokens is the whole seconds until a depleted bucket (tokens in [0,1))
// has one token again, rounded up and floored at 1 — Retry-After is delta-seconds, and
// a sub-second wait still advises at least 1s.
func retryAfterForTokens(tokens, ratePerSec float64) int {
	secs := int(math.Ceil((1 - tokens) / ratePerSec))
	if secs < 1 {
		secs = 1
	}
	return secs
}

// rateLimit sheds inbound requests that exceed the per-source token-bucket budget with
// a 429 and a Retry-After hint, in the same JSON error shape every other response
// uses. It sits below withLogging in the chain, so a shed request still gets its
// X-Request-Id header and its structured log line, and above the mux, so a flood is
// rejected before any routing or handler work.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed, retryAfter := s.limiter.allow(sourceKey(r.RemoteAddr)); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeError(w, http.StatusTooManyRequests, codeRateLimited,
				"too many requests from your source address; retry after the Retry-After interval")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sourceKey is the per-source limiter key: the client IP with its port stripped, so
// every ephemeral connection from one host shares one bucket. It keys on the real TCP
// peer (r.RemoteAddr) and deliberately NOT on any client-supplied header such as
// X-Forwarded-For: this listener is unauthenticated by design, so a client-controlled
// key would let an attacker rotate it to dodge the limit — the same untrusted-input
// reasoning that makes the server mint its own request id rather than echo a
// client-supplied one. An operator running Steward behind a trusted proxy should
// rate-limit at that proxy (and may disable this limiter with -max-requests-per-second
// 0).
func sourceKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// No host:port to split (unusual for a real TCP peer): key on the raw value
		// rather than dropping the request onto an unmetered path.
		return remoteAddr
	}
	return host
}
