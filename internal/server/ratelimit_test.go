package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// frozenLimiter builds a rate limiter driven by a caller-controlled clock so the
// refill and eviction behavior can be exercised deterministically. cur is the time
// the limiter reads via l.now; advance it between calls to simulate elapsed time.
func frozenLimiter(rate, burst float64, maxSources int, cur *time.Time) *rateLimiter {
	return &rateLimiter{
		buckets:    make(map[string]*bucket),
		lastSweep:  *cur,
		ratePerSec: rate,
		burst:      burst,
		maxSources: maxSources,
		sweepEvery: time.Minute,
		idleAfter:  2 * time.Minute,
		now:        func() time.Time { return *cur },
	}
}

func trackedSources(l *rateLimiter) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func bucketExists(l *rateLimiter, key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.buckets[key]
	return ok
}

// doFrom drives one request through h from a specific source address, so the
// per-source limiter keying (r.RemoteAddr) can be exercised.
func doFrom(h http.Handler, method, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewRateLimiterDefaults(t *testing.T) {
	l := newRateLimiter(20)
	if l.ratePerSec != 20 {
		t.Errorf("ratePerSec = %v, want 20", l.ratePerSec)
	}
	if l.burst != 40 {
		t.Errorf("burst = %v, want 40 (rateBurstFactor x rate)", l.burst)
	}
	if l.maxSources != maxTrackedSources {
		t.Errorf("maxSources = %d, want %d", l.maxSources, maxTrackedSources)
	}
	if l.sweepEvery != sweepInterval {
		t.Errorf("sweepEvery = %v, want %v", l.sweepEvery, sweepInterval)
	}
	if l.idleAfter != idleTTL {
		t.Errorf("idleAfter = %v, want %v", l.idleAfter, idleTTL)
	}
	if l.buckets == nil {
		t.Error("buckets map must be initialized")
	}
}

// TestRateLimiterAllowsBurstThenDenies pins the core throttle: exactly burst requests
// pass from a source with no elapsed time, and the next is denied with a positive
// Retry-After.
func TestRateLimiterAllowsBurstThenDenies(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(5, 10, maxTrackedSources, &cur)

	for i := 0; i < 10; i++ {
		if allowed, _ := l.allow("k"); !allowed {
			t.Fatalf("burst request %d (within burst 10) should be allowed", i)
		}
	}
	allowed, retryAfter := l.allow("k")
	if allowed {
		t.Fatal("request 11 exceeds the burst and must be denied")
	}
	if retryAfter < 1 {
		t.Fatalf("Retry-After = %d, want >= 1", retryAfter)
	}
}

// TestRateLimiterSteadyRateNeverTrips proves a client holding the sustained rate is
// never throttled, however long it runs: at exactly one request per 1/rate, each
// consumed token is refilled before the next request.
func TestRateLimiterSteadyRateNeverTrips(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(10, 20, maxTrackedSources, &cur)

	step := time.Second / 10 // 1/rate at rate 10
	for i := 0; i < 300; i++ {
		allowed, retryAfter := l.allow("steady")
		if !allowed {
			t.Fatalf("request %d at the sustained rate was denied (retryAfter=%d)", i, retryAfter)
		}
		cur = cur.Add(step)
	}
}

// TestRateLimiterRefillsAfterDepletion proves the bucket refills at the configured
// rate: after the burst is drained, ~rate tokens return per elapsed second.
func TestRateLimiterRefillsAfterDepletion(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(5, 10, maxTrackedSources, &cur)

	for i := 0; i < 10; i++ {
		if allowed, _ := l.allow("k"); !allowed {
			t.Fatalf("burst request %d should be allowed", i)
		}
	}
	if allowed, retryAfter := l.allow("k"); allowed || retryAfter < 1 {
		t.Fatalf("after draining the burst, want denial with a positive Retry-After; allowed=%v retryAfter=%d", allowed, retryAfter)
	}

	// One second later, exactly rate (5) tokens have refilled: 5 pass, the 6th does not.
	cur = cur.Add(time.Second)
	for i := 0; i < 5; i++ {
		if allowed, _ := l.allow("k"); !allowed {
			t.Fatalf("post-refill request %d should be allowed (5 tokens refilled in 1s)", i)
		}
	}
	if allowed, _ := l.allow("k"); allowed {
		t.Fatal("only ~5 tokens refill in 1s at rate 5; the 6th must be denied")
	}
}

// TestRateLimiterRefillCapsAtBurst proves the refill never exceeds burst: after a
// long idle (but short of the eviction threshold, so the same bucket survives), the
// source gets exactly a fresh burst back — not an unbounded credit for the idle time.
func TestRateLimiterRefillCapsAtBurst(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(5, 10, maxTrackedSources, &cur)

	for i := 0; i < 10; i++ {
		if allowed, _ := l.allow("k"); !allowed {
			t.Fatalf("burst request %d should be allowed", i)
		}
	}
	if allowed, _ := l.allow("k"); allowed {
		t.Fatal("bucket should be drained")
	}

	// Idle 30s: under sweepEvery (1m) so the bucket survives, but far past the 2s
	// full-refill time — an uncapped refill would credit ~150 tokens. Tokens must cap
	// at burst (10): exactly 10 requests pass, the 11th does not.
	cur = cur.Add(30 * time.Second)
	for i := 0; i < 10; i++ {
		if allowed, _ := l.allow("k"); !allowed {
			t.Fatalf("post-idle request %d should be allowed (refill caps at burst)", i)
		}
	}
	if allowed, _ := l.allow("k"); allowed {
		t.Fatal("tokens must cap at burst; the 11th request after a long idle must be denied")
	}
}

// TestTableFullRetryAfterSeconds pins the table-full Retry-After hint: whole seconds of
// the sweep interval, rounded up and floored at 1.
func TestTableFullRetryAfterSeconds(t *testing.T) {
	if got := (&rateLimiter{sweepEvery: 90 * time.Second}).tableFullRetryAfterSeconds(); got != 90 {
		t.Errorf("tableFullRetryAfterSeconds(90s) = %d, want 90", got)
	}
	if got := (&rateLimiter{sweepEvery: 89500 * time.Millisecond}).tableFullRetryAfterSeconds(); got != 90 {
		t.Errorf("tableFullRetryAfterSeconds(89.5s) = %d, want 90 (rounded up)", got)
	}
	if got := (&rateLimiter{sweepEvery: 0}).tableFullRetryAfterSeconds(); got != 1 {
		t.Errorf("tableFullRetryAfterSeconds(0) = %d, want 1 (floored)", got)
	}
}

// TestRateLimiterPerSourceIsolation proves one source's flood does not touch another:
// A is drained to exhaustion while B, keyed separately, keeps its full budget.
func TestRateLimiterPerSourceIsolation(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(5, 10, maxTrackedSources, &cur)

	for i := 0; i < 10; i++ {
		if allowed, _ := l.allow("A"); !allowed {
			t.Fatalf("A burst request %d should be allowed", i)
		}
	}
	if allowed, _ := l.allow("A"); allowed {
		t.Fatal("A should be exhausted after its burst")
	}
	if allowed, _ := l.allow("B"); !allowed {
		t.Fatal("B must not be affected by A's exhaustion (per-source isolation)")
	}
}

// TestRateLimiterEvictsIdleBuckets proves the map does not grow without bound under a
// distributed drip: idle buckets are reclaimed by the periodic sweep, so a burst of
// many distinct sources does not retain memory forever.
func TestRateLimiterEvictsIdleBuckets(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(10, 20, maxTrackedSources, &cur)

	for i := 0; i < 500; i++ {
		if allowed, _ := l.allow(fmt.Sprintf("src-%d", i)); !allowed {
			t.Fatalf("src-%d should be allowed on first contact", i)
		}
	}
	if got := trackedSources(l); got != 500 {
		t.Fatalf("tracked sources = %d, want 500 before any idle time", got)
	}

	// Advance past idleAfter (2m) + sweepEvery (1m); the next request triggers a sweep
	// that reclaims every source now idle.
	cur = cur.Add(5 * time.Minute)
	if allowed, _ := l.allow("fresh"); !allowed {
		t.Fatal("fresh source should be allowed")
	}
	if got := trackedSources(l); got != 1 {
		t.Fatalf("tracked sources = %d after the idle sweep, want 1 (only the fresh source)", got)
	}
}

// TestRateLimiterBoundedUnderManyActiveSources proves the hard ceiling: once the map
// holds maxSources active buckets, a brand-new source is refused (429 with a positive
// Retry-After) and no bucket is allocated for it, so a distributed many-IP flood
// cannot grow the map. An already-tracked source stays served.
func TestRateLimiterBoundedUnderManyActiveSources(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := frozenLimiter(10, 20, 5, &cur)
	l.sweepEvery = time.Hour // keep the sweep out of the way; every source stays active

	for i := 0; i < 5; i++ {
		if allowed, _ := l.allow(fmt.Sprintf("active-%d", i)); !allowed {
			t.Fatalf("active-%d should be allowed", i)
		}
	}
	if got := trackedSources(l); got != 5 {
		t.Fatalf("tracked = %d, want 5 (at the cap)", got)
	}

	allowed, retryAfter := l.allow("overflow")
	if allowed {
		t.Fatal("a new source must be refused once the tracking table is full")
	}
	if retryAfter < 1 {
		t.Fatalf("table-full Retry-After = %d, want >= 1", retryAfter)
	}
	if got := trackedSources(l); got != 5 {
		t.Fatalf("tracked = %d after refusing a new source, want the map bounded at 5", got)
	}
	if bucketExists(l, "overflow") {
		t.Fatal("no bucket may be allocated for a source refused at the table cap")
	}
	if allowed, _ := l.allow("active-0"); !allowed {
		t.Fatal("an already-tracked source must keep being served while the table is full")
	}
}

// TestRateLimiterSweepRespectsFullRefillFloor proves the sweep never evicts a
// still-depleted bucket (which would hand its source a free token reset): for a very
// low rate whose full-refill time exceeds idleAfter, a depleted bucket survives past
// idleAfter until it would actually have refilled.
func TestRateLimiterSweepRespectsFullRefillFloor(t *testing.T) {
	cur := time.Unix(1000, 0)
	// burst 4 at 0.01/s => full refill takes 400s, far beyond idleAfter (120s).
	l := frozenLimiter(0.01, 4, maxTrackedSources, &cur)

	for i := 0; i < 4; i++ {
		l.allow("slow")
	}
	// 3 minutes: past idleAfter (2m) but well short of the 400s full-refill time.
	cur = cur.Add(3 * time.Minute)
	l.allow("trigger") // crosses sweepEvery, so the sweep runs

	if !bucketExists(l, "slow") {
		t.Fatal("a still-depleted bucket must survive the sweep — the threshold floors at the full-refill time")
	}
}

func TestRetryAfterForTokens(t *testing.T) {
	cases := []struct {
		tokens, rate float64
		want         int
	}{
		{0, 1, 1},     // ceil(1/1) = 1
		{0, 20, 1},    // ceil(1/20) = 1 after the floor
		{0.5, 1, 1},   // ceil(0.5/1) = 1
		{0, 0.5, 2},   // ceil(1/0.5) = 2
		{0, 0.25, 4},  // ceil(1/0.25) = 4
		{0.2, 0.2, 4}, // ceil(0.8/0.2) = 4
		{2, 1, 1},     // tokens already >= 1: ceil(-1) = -1, floored to 1
	}
	for _, c := range cases {
		if got := retryAfterForTokens(c.tokens, c.rate); got != c.want {
			t.Errorf("retryAfterForTokens(%v, %v) = %d, want %d", c.tokens, c.rate, got, c.want)
		}
	}
}

func TestSourceKey(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":      "1.2.3.4",
		"[2001:db8::1]:443": "2001:db8::1",
		"[::1]:8080":        "::1",
		"noport":            "noport", // SplitHostPort fails -> raw fallback, never unmetered
	}
	for in, want := range cases {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRateLimitMiddlewareSheds429WithRetryAfter drives the throttle through the real
// middleware chain: the third near-instant request from one source at rate=1/burst=2
// is shed with a 429, a Retry-After header, the shared JSON error shape, and — because
// the limiter sits below withLogging — an X-Request-Id.
func TestRateLimitMiddlewareSheds429WithRetryAfter(t *testing.T) {
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, 1).Handler()
	const src = "203.0.113.5:44444"

	for i := 0; i < 2; i++ {
		if rec := doFrom(h, http.MethodGet, "/v1/healthz", src); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst: status=%d want 200", i, rec.Code)
		}
	}

	rec := doFrom(h, http.MethodGet, "/v1/healthz", src)
	assertJSONError(t, rec, http.StatusTooManyRequests)

	var er errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatalf("429 body not JSON: %v (body=%s)", err, rec.Body.String())
	}
	if er.Error != "rate_limited" {
		t.Errorf("error code = %q, want rate_limited", er.Error)
	}

	ra := rec.Header().Get("Retry-After")
	if secs, err := strconv.Atoi(ra); err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer number of seconds", ra)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("a rate-limited 429 must still carry X-Request-Id (it flows through withLogging)")
	}
}

// TestRateLimitMiddlewarePerSourceIsolation proves the HTTP path keys on the source IP:
// a flood from one address does not throttle another.
func TestRateLimitMiddlewarePerSourceIsolation(t *testing.T) {
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, 1).Handler()
	const a = "198.51.100.1:1111"
	const b = "198.51.100.2:2222"

	doFrom(h, http.MethodGet, "/v1/healthz", a)
	doFrom(h, http.MethodGet, "/v1/healthz", a)
	if rec := doFrom(h, http.MethodGet, "/v1/healthz", a); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("A third request: status=%d want 429", rec.Code)
	}
	if rec := doFrom(h, http.MethodGet, "/v1/healthz", b); rec.Code != http.StatusOK {
		t.Fatalf("B first request: status=%d want 200 — A's flood must not affect B", rec.Code)
	}
}

// TestRateLimitDisabledAllowsUnthrottled proves rate<=0 disables the limiter entirely:
// a heavy burst from one source is never shed.
func TestRateLimitDisabledAllowsUnthrottled(t *testing.T) {
	h := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, 0).Handler()
	const src = "192.0.2.7:9999"
	for i := 0; i < 100; i++ {
		if rec := doFrom(h, http.MethodGet, "/v1/healthz", src); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status=%d want 200 with the limiter disabled", i, rec.Code)
		}
	}
}
