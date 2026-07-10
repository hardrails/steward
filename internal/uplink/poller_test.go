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
	}
	for name, cfg := range cases {
		if _, err := NewPoller(tr, cfg); err == nil {
			t.Errorf("NewPoller(%s): got nil err, want a validation error", name)
		}
	}
	if _, err := NewPoller(tr, base); err != nil {
		t.Fatalf("NewPoller(valid): unexpected err %v", err)
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
