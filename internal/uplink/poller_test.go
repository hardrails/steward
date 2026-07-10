package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

func TestNewPollerRejectsBadConfig(t *testing.T) {
	tr := runtime.NewTracker(0)
	base := Config{BaseURL: "http://cp", Credential: "tok", NodeID: "node-7", PollInterval: time.Second}

	cases := map[string]Config{
		"missing url":           {Credential: "tok", NodeID: "node-7", PollInterval: time.Second},
		"missing credential":    {BaseURL: "http://cp", NodeID: "node-7", PollInterval: time.Second},
		"missing node_id":       {BaseURL: "http://cp", Credential: "tok", PollInterval: time.Second},
		"non-positive interval": {BaseURL: "http://cp", Credential: "tok", NodeID: "node-7", PollInterval: 0},
		// A bare hostname (the plausible forgot-"http://" operator typo) parses
		// without error and with an empty scheme and host — it must be rejected here
		// rather than succeeding silently and failing every poll forever.
		"bare hostname, no scheme": {BaseURL: "control-plane.example", Credential: "tok", NodeID: "node-7", PollInterval: time.Second},
		"scheme with no host":      {BaseURL: "http://", Credential: "tok", NodeID: "node-7", PollInterval: time.Second},
		"non-http(s) scheme":       {BaseURL: "ftp://cp", Credential: "tok", NodeID: "node-7", PollInterval: time.Second},
	}
	for name, cfg := range cases {
		if _, err := NewPoller(tr, cfg); err == nil {
			t.Errorf("NewPoller(%s): got nil err, want a validation error", name)
		}
	}
	if _, err := NewPoller(tr, base); err != nil {
		t.Fatalf("NewPoller(valid http): unexpected err %v", err)
	}
	if _, err := NewPoller(tr, Config{BaseURL: "https://cp", Credential: "tok", NodeID: "node-7", PollInterval: time.Second}); err != nil {
		t.Fatalf("NewPoller(valid https): unexpected err %v", err)
	}
}

func TestPollerExecutesAndReportsCommand(t *testing.T) {
	tr := runtime.NewTracker(0)
	reportCh := make(chan report, 4)
	var mu sync.Mutex
	polls := 0
	var pollAuth string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		n := polls
		pollAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = io.WriteString(w, `{"commands":[{"command_id":"cmd-1","node_id":"node-7","runtime_ref":"uplink:6:node-7:agent-1","kind":"provision","payload":{"model":"opus"},"claim_generation":7}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"commands":[]}`)
	})
	mux.HandleFunc("POST /uplink/report", func(w http.ResponseWriter, r *http.Request) {
		var rep report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("decode report: %v", err)
		}
		reportCh <- rep
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applied":true}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := mustPoller(t, tr, Config{BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := run(p, ctx)

	select {
	case rep := <-reportCh:
		if rep.CommandID != "cmd-1" {
			t.Errorf("report command_id = %q, want cmd-1 (echoed verbatim)", rep.CommandID)
		}
		if rep.ClaimGeneration != 7 {
			t.Errorf("report claim_generation = %d, want 7 (echoed verbatim)", rep.ClaimGeneration)
		}
		if rep.Status != statusDone || rep.ReportedStatus != "provisioning" {
			t.Errorf("report status=%q reported=%q, want done/provisioning", rep.Status, rep.ReportedStatus)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the command report")
	}

	cancel()
	waitDone(t, done)

	mu.Lock()
	gotAuth := pollAuth
	mu.Unlock()
	if gotAuth != "Bearer tok" {
		t.Errorf("poll Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if tr.Len() != 1 {
		t.Errorf("tracker holds %d instances, want 1 (the provisioned command)", tr.Len())
	}
}

func TestPollerBacksOffAndRetriesOn5xx(t *testing.T) {
	var mu sync.Mutex
	polls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		n := polls
		mu.Unlock()
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"commands":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := run(p, ctx)

	// It must poll past the two 503s (proving it backed off and retried rather than
	// stopping or wedging).
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := polls
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d polls after 2s; expected retries past the two 503s", n)
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()
	waitDone(t, done)
}

func TestPollerStopsOnCredentialRejection(t *testing.T) {
	var mu sync.Mutex
	polls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7",
		PollInterval: 5 * time.Millisecond, Logger: logger,
	})

	// No cancel: a 403 must stop the loop on its own.
	done := run(p, context.Background())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop after a 403")
	}

	// The goroutine has returned, so reading polls and logBuf is race-free.
	mu.Lock()
	n := polls
	mu.Unlock()
	if n != 1 {
		t.Errorf("polled %d times, want exactly 1 (stop on the first 403, no retry)", n)
	}
	logs := logBuf.String()
	if c := strings.Count(logs, "credential rejected"); c != 1 {
		t.Errorf("logged the credential rejection %d times, want exactly once:\n%s", c, logs)
	}
	if !strings.Contains(logs, "re-enroll") || !strings.Contains(logs, "restart") {
		t.Errorf("credential-rejection log does not name the remedy (re-enroll/restart):\n%s", logs)
	}
}

func TestPollerReturnsPromptlyOnCancelWhileWaiting(t *testing.T) {
	// The common shutdown case: the loop is asleep between polls. A long interval
	// keeps it in the inter-poll wait, and cancellation must return it at once.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"commands":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := run(p, ctx)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after cancellation during the inter-poll wait")
	}
}

func TestPollerReturnsPromptlyOnCancelDuringRequest(t *testing.T) {
	// The other shutdown case: a poll is in flight. The client aborts the request on
	// ctx cancellation without waiting for the server, so Run returns promptly. The
	// handler blocks only briefly and with a hard cap, so the deferred srv.Close
	// never hangs even if the server-side request-context cancellation is delayed on
	// this platform — the assertion depends only on the reliable client-side path.
	var once sync.Once
	inFlight := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(inFlight) })
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := run(p, ctx)

	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		t.Fatal("poller never issued its first poll")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after cancellation of an in-flight request")
	}
}

func TestBackoffDuration(t *testing.T) {
	cases := []struct {
		base     time.Duration
		failures int
		want     time.Duration
	}{
		{10 * time.Second, 0, 10 * time.Second},
		{10 * time.Second, 1, 20 * time.Second},
		{10 * time.Second, 2, 40 * time.Second},
		{10 * time.Second, 5, 5 * time.Minute}, // 320s clamps to the 5m cap
		{10 * time.Second, 1000, 5 * time.Minute},
		{10 * time.Minute, 0, 5 * time.Minute}, // base already past the cap
		{time.Second, skewFailures, 5 * time.Minute},
	}
	for _, c := range cases {
		if got := backoffDuration(c.base, c.failures); got != c.want {
			t.Errorf("backoffDuration(%s, %d) = %s, want %s", c.base, c.failures, got, c.want)
		}
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	const d = 100 * time.Millisecond
	lo := time.Duration(float64(d) * (1 - jitterFraction))
	hi := time.Duration(float64(d) * (1 + jitterFraction))
	for i := 0; i < 10_000; i++ {
		got := jitter(d)
		if got < lo || got > hi {
			t.Fatalf("jitter(%s) = %s, outside [%s, %s]", d, got, lo, hi)
		}
		if got <= 0 {
			t.Fatalf("jitter(%s) = %s, must stay positive", d, got)
		}
	}
}

// TestExecuteBatchReplaceDestroyThenProvision is the regression test for the
// "batch reordering inverts replace" review finding: a poll carrying
// destroy(agent-1) then provision(agent-1) (the control plane replacing an
// instance) must run in the server's order and end with agent-1 EXISTING. The old
// "provisions first" reordering ran provision (an idempotent no-op) then destroy,
// leaving agent-1 gone.
func TestExecuteBatchReplaceDestroyThenProvision(t *testing.T) {
	tr := runtime.NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 0, nil); err != nil {
		t.Fatalf("seed the instance being replaced: %v", err)
	}
	p, sink := batchPoller(t, tr)

	p.executeBatch(context.Background(), []command{
		cmd("c-destroy", "node-7", "agent-1", kindDestroy, "", 1),
		cmd("c-provision", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 2),
	})

	if _, ok := tr.RefForInstance("agent-1"); !ok {
		t.Fatal("after a destroy-then-provision replace, agent-1 must exist (the replace succeeded)")
	}
	if rep, ok := sink.byID("c-destroy"); !ok || rep.Status != statusDone {
		t.Fatalf("destroy report = %+v (found=%v), want done", rep, ok)
	}
	if rep, ok := sink.byID("c-provision"); !ok || rep.Status != statusDone || rep.ReportedStatus != "provisioning" {
		t.Fatalf("provision report = %+v (found=%v), want done/provisioning", rep, ok)
	}
	if n := sink.count(); n != 2 {
		t.Fatalf("got %d reports, want 2 (destroy + provision, each once)", n)
	}
}

// TestExecuteBatchStartBeforeProvisionRetries proves the retry pass still closes
// the original out-of-order concern the blanket reordering was meant to solve: a
// poll carrying start(agent-1) BEFORE its own provision ends with agent-1 RUNNING —
// the start is deferred on the first pass and retried after the provision runs.
func TestExecuteBatchStartBeforeProvisionRetries(t *testing.T) {
	tr := runtime.NewTracker(0)
	p, sink := batchPoller(t, tr)

	p.executeBatch(context.Background(), []command{
		cmd("c-start", "node-7", "agent-1", kindStart, "", 1),
		cmd("c-provision", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 2),
	})

	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("agent-1 must exist after its provision ran")
	}
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != runtime.StatusRunning {
		t.Fatalf("agent-1 status = %v, want RUNNING (the deferred start retried after the provision)", inst.Status)
	}
	if rep, ok := sink.byID("c-start"); !ok || rep.Status != statusDone || rep.ReportedStatus != "running" {
		t.Fatalf("start report = %+v (found=%v), want done/running", rep, ok)
	}
	if rep, ok := sink.byID("c-provision"); !ok || rep.Status != statusDone {
		t.Fatalf("provision report = %+v (found=%v), want done", rep, ok)
	}
	if n := sink.count(); n != 2 {
		t.Fatalf("got %d reports, want 2 (start reported once, after its retry)", n)
	}
}

// TestExecuteBatchStartNeverProvisionedReportsFailedOnce proves the retry pass is
// bounded: a start whose instance is never provisioned anywhere in the batch is
// deferred once, retried once, and then reported failed for real — exactly one
// report, never an infinite loop.
func TestExecuteBatchStartNeverProvisionedReportsFailedOnce(t *testing.T) {
	tr := runtime.NewTracker(0)
	p, sink := batchPoller(t, tr)

	p.executeBatch(context.Background(), []command{
		cmd("c-start", "node-7", "agent-1", kindStart, "", 1),
	})

	if _, ok := tr.RefForInstance("agent-1"); ok {
		t.Fatal("agent-1 must not exist; it was never provisioned")
	}
	rep, ok := sink.byID("c-start")
	if !ok {
		t.Fatal("the start must be reported (failed) after the bounded retry pass")
	}
	if rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("start report = %+v, want failed/failed", rep)
	}
	if n := sink.count(); n != 1 {
		t.Fatalf("got %d reports, want exactly 1 (bounded: reported failed once, not looped)", n)
	}
}

// TestExecuteBatchStopBeforeProvisionFailsImmediately pins the second, narrower
// hosted review finding: a batch carrying stop(agent-1) BEFORE agent-1's own
// provision must NOT defer the stop and retry it after the provision runs — that
// would stop the instance the provision just created, which is the wrong outcome.
// The stop must report failed on the very first pass, and the provision must still
// succeed with agent-1 left un-stopped (still PENDING, not STOPPED).
func TestExecuteBatchStopBeforeProvisionFailsImmediately(t *testing.T) {
	tr := runtime.NewTracker(0)
	p, sink := batchPoller(t, tr)

	p.executeBatch(context.Background(), []command{
		cmd("c-stop", "node-7", "agent-1", kindStop, "", 1),
		cmd("c-provision", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 2),
	})

	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("agent-1 must exist after its provision ran")
	}
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != runtime.StatusPending {
		t.Fatalf("agent-1 status = %v, want PENDING (the stop must not act on the sibling provision's instance)", inst.Status)
	}
	if rep, ok := sink.byID("c-stop"); !ok || rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("stop report = %+v (found=%v), want failed/failed on the first pass", rep, ok)
	}
	if rep, ok := sink.byID("c-provision"); !ok || rep.Status != statusDone {
		t.Fatalf("provision report = %+v (found=%v), want done", rep, ok)
	}
	if n := sink.count(); n != 2 {
		t.Fatalf("got %d reports, want 2 (stop failed once on the first pass, no retry; provision done once)", n)
	}
}

// TestExecuteBatchHibernateBeforeProvisionFailsImmediately mirrors
// TestExecuteBatchStopBeforeProvisionFailsImmediately for hibernate.
func TestExecuteBatchHibernateBeforeProvisionFailsImmediately(t *testing.T) {
	tr := runtime.NewTracker(0)
	p, sink := batchPoller(t, tr)

	p.executeBatch(context.Background(), []command{
		cmd("c-hibernate", "node-7", "agent-1", kindHibernate, "", 1),
		cmd("c-provision", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 2),
	})

	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("agent-1 must exist after its provision ran")
	}
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != runtime.StatusPending {
		t.Fatalf("agent-1 status = %v, want PENDING (the hibernate must not act on the sibling provision's instance)", inst.Status)
	}
	if rep, ok := sink.byID("c-hibernate"); !ok || rep.Status != statusFailed || rep.ReportedStatus != "failed" {
		t.Fatalf("hibernate report = %+v (found=%v), want failed/failed on the first pass", rep, ok)
	}
	if rep, ok := sink.byID("c-provision"); !ok || rep.Status != statusDone {
		t.Fatalf("provision report = %+v (found=%v), want done", rep, ok)
	}
	if n := sink.count(); n != 2 {
		t.Fatalf("got %d reports, want 2 (hibernate failed once on the first pass, no retry; provision done once)", n)
	}
}

// TestExecuteBatchFencedCommandProducesNoReport pins task 5's central acceptance
// check: a batch containing one stale (fenced) command and one normal command
// must report exactly the non-stale command — the fenced one produces no report
// POST at all — and must not mutate the fenced command's target instance.
func TestExecuteBatchFencedCommandProducesNoReport(t *testing.T) {
	tr := runtime.NewTracker(0)
	if _, _, err := tr.Provision("agent-1", 5, nil); err != nil {
		t.Fatalf("seed agent-1 at generation 5: %v", err)
	}
	if _, _, err := tr.Provision("agent-2", 0, nil); err != nil {
		t.Fatalf("seed agent-2: %v", err)
	}
	p, sink := batchPoller(t, tr)

	stale := cmdGen("c-stale", "node-7", "agent-1", kindStop, "", 1, 2) // 2 < tracked 5: fenced
	good := cmdGen("c-good", "node-7", "agent-2", kindStop, "", 2, 0)   // 0: never fenced

	p.executeBatch(context.Background(), []command{stale, good})

	if _, ok := sink.byID("c-stale"); ok {
		t.Fatal("a fenced command must produce no report POST")
	}
	if rep, ok := sink.byID("c-good"); !ok || rep.Status != statusDone {
		t.Fatalf("good command report = %+v (found=%v), want done", rep, ok)
	}
	if n := sink.count(); n != 1 {
		t.Fatalf("got %d reports, want exactly 1 (the fenced command sent none)", n)
	}

	// The fenced stop must not have mutated agent-1's status.
	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("agent-1 must still exist (the fenced stop must not have destroyed/altered it)")
	}
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != runtime.StatusPending {
		t.Fatalf("agent-1 status = %v, want PENDING (the fenced stop must not have acted)", inst.Status)
	}
}

// TestExecuteBatchDeferredStartFencedAfterSiblingProvisionBumpsGeneration proves
// fencing composes correctly with the one-pass start-retry mechanism: a start
// deferred on the first pass (its instance is not yet known) is re-checked
// against the fence on the retry pass too. If its own carried
// instance_generation is now stale relative to the generation a sibling
// provision just adopted earlier in the SAME batch, the retried start must be
// fenced — not reported done, not reported failed, and not applied — rather
// than blindly starting an instance whose lineage has already moved on.
func TestExecuteBatchDeferredStartFencedAfterSiblingProvisionBumpsGeneration(t *testing.T) {
	tr := runtime.NewTracker(0)
	p, sink := batchPoller(t, tr)

	// The start's own instance_generation (3) predates the sibling provision's
	// generation (10) landing later in the same batch.
	start := cmdGen("c-start", "node-7", "agent-1", kindStart, "", 1, 3)
	provision := cmdGen("c-provision", "node-7", "agent-1", kindProvision, `{"model":"opus"}`, 2, 10)

	p.executeBatch(context.Background(), []command{start, provision})

	if _, ok := sink.byID("c-start"); ok {
		t.Fatal("the deferred start must be fenced on retry (its own instance_generation is now stale), producing no report")
	}
	if rep, ok := sink.byID("c-provision"); !ok || rep.Status != statusDone {
		t.Fatalf("provision report = %+v (found=%v), want done", rep, ok)
	}
	if n := sink.count(); n != 1 {
		t.Fatalf("got %d reports, want exactly 1 (provision only; the deferred start was fenced, not reported)", n)
	}

	// agent-1 must exist (from the provision) but must NOT be RUNNING: the
	// fenced start must never have reached the tracker's Start mutator.
	ref, ok := tr.RefForInstance("agent-1")
	if !ok {
		t.Fatal("agent-1 must exist after its provision ran")
	}
	inst, err := tr.Status(ref)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if inst.Status != runtime.StatusPending {
		t.Fatalf("agent-1 status = %v, want PENDING (the fenced start must not have run)", inst.Status)
	}
}

// reportSink captures the reports an executeBatch run POSTs so a test can assert
// each command's terminal outcome by command_id. It is concurrency-safe because
// the httptest handler records from a server goroutine.
type reportSink struct {
	mu   sync.Mutex
	reps []report
}

func (s *reportSink) add(r report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reps = append(s.reps, r)
}

func (s *reportSink) byID(id string) (report, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.reps {
		if r.CommandID == id {
			return r, true
		}
	}
	return report{}, false
}

func (s *reportSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reps)
}

// batchPoller builds a Poller whose /uplink/report endpoint records every report
// into the returned sink, so a test can drive p.executeBatch directly and assert
// the per-command outcomes. The /uplink/poll endpoint is unused by executeBatch.
func batchPoller(t *testing.T, tr Tracker) (*Poller, *reportSink) {
	t.Helper()
	sink := &reportSink{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/report", func(w http.ResponseWriter, r *http.Request) {
		var rep report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("decode report: %v", err)
		}
		sink.add(rep)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applied":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return mustPoller(t, tr, Config{BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second}), sink
}

// mustPoller builds a Poller with a discard logger unless cfg supplies one.
func mustPoller(t *testing.T, tr Tracker, cfg Config) *Poller {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = discardLogger()
	}
	p, err := NewPoller(tr, cfg)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	return p
}

// run starts p.Run in a goroutine and returns a channel closed when it returns.
func run(p *Poller, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	return done
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("poll loop did not return within the deadline")
	}
}
