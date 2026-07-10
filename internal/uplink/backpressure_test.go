package uplink

import (
	"context"
	"encoding/json"
	"fmt"
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

// pendingControlPlane is a fake control-plane poll/report server for the backpressure
// integration tests. It holds a fixed set of commands and, on each poll, returns the
// ones not yet reported done — in a stable order — so a redelivered-until-acknowledged
// batch is modelled faithfully. It is concurrency-safe: /uplink/poll is hit from the
// poll loop's producer goroutine and /uplink/report from its consumer goroutine.
type pendingControlPlane struct {
	mu       sync.Mutex
	order    []string
	cmds     map[string]command
	doneSeen map[string]int
}

func newPendingControlPlane(cmds ...command) *pendingControlPlane {
	s := &pendingControlPlane{
		cmds:     make(map[string]command, len(cmds)),
		doneSeen: make(map[string]int),
	}
	for _, c := range cmds {
		s.order = append(s.order, c.CommandID)
		s.cmds[c.CommandID] = c
	}
	return s
}

func (s *pendingControlPlane) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /uplink/poll", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		var pending []command
		for _, id := range s.order {
			if s.doneSeen[id] == 0 {
				pending = append(pending, s.cmds[id])
			}
		}
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pollResponse{Commands: pending}); err != nil {
			t.Errorf("encode poll response: %v", err)
		}
	})
	mux.HandleFunc("POST /uplink/report", func(w http.ResponseWriter, r *http.Request) {
		var rep report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			t.Errorf("decode report: %v", err)
		}
		if rep.Status == statusDone {
			s.mu.Lock()
			s.doneSeen[rep.CommandID]++
			s.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applied":true}`)
	})
	return mux
}

func (s *pendingControlPlane) allDone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.order {
		if s.doneSeen[id] == 0 {
			return false
		}
	}
	return true
}

// blockingTracker is a Tracker whose FIRST Provision call blocks until release is
// closed, and which counts every Provision call. It lets a test hold one command
// in-flight (so the queue stays occupied) while it observes what happens to the
// commands that pile up behind it. Every other method delegates to a real tracker.
type blockingTracker struct {
	*runtime.Tracker
	release       chan struct{}
	mu            sync.Mutex
	provisionByID map[string]int
	blockedFirst  bool
}

func newBlockingTracker() *blockingTracker {
	return &blockingTracker{
		Tracker:       runtime.NewTracker(0),
		release:       make(chan struct{}),
		provisionByID: make(map[string]int),
	}
}

func (b *blockingTracker) Provision(instanceID string, generation int64, spec json.RawMessage) (*runtime.Instance, bool, error) {
	b.mu.Lock()
	b.provisionByID[instanceID]++
	first := !b.blockedFirst
	b.blockedFirst = true
	b.mu.Unlock()

	if first {
		<-b.release // hold the very first provision in-flight until the test releases it.
	}
	return b.Tracker.Provision(instanceID, generation, spec)
}

func (b *blockingTracker) provisionCalls(instanceID string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.provisionByID[instanceID]
}

// TestPollerRejectsBurstExceedingQueueDepthAndRedelivers is the core backpressure
// proof: a single poll returning more commands than the queue depth has its excess
// rejected (not silently dropped, not a crash, not a block) with the rejected
// commands' identities logged under a grep-able prefix — and, because a rejected
// command is never reported, the control plane redelivers it on a later cycle until
// every command is eventually executed.
func TestPollerRejectsBurstExceedingQueueDepthAndRedelivers(t *testing.T) {
	cp := newPendingControlPlane(
		cmd("c-1", "node-7", "agent-1", kindProvision, `{"model":"x"}`, 1),
		cmd("c-2", "node-7", "agent-2", kindProvision, `{"model":"x"}`, 1),
		cmd("c-3", "node-7", "agent-3", kindProvision, `{"model":"x"}`, 1),
		cmd("c-4", "node-7", "agent-4", kindProvision, `{"model":"x"}`, 1),
		cmd("c-5", "node-7", "agent-5", kindProvision, `{"model":"x"}`, 1),
	)
	srv := httptest.NewServer(cp.handler(t))
	defer srv.Close()

	tr := runtime.NewTracker(0)
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := mustPoller(t, tr, Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7",
		PollInterval: 5 * time.Millisecond, Logger: logger,
		CommandQueueDepth: 2, // 5 commands, depth 2: at least 3 rejected on the first cycle.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := run(p, ctx)

	// Every command must eventually be executed and reported done, proving the
	// rejected excess was redelivered, not lost.
	deadline := time.After(3 * time.Second)
	for !cp.allDone() {
		select {
		case <-deadline:
			t.Fatalf("not every command was executed within the deadline; tracker has %d instances", tr.Len())
		case <-time.After(2 * time.Millisecond):
		}
	}
	if tr.Len() != 5 {
		t.Errorf("tracker holds %d instances, want 5 (all commands executed exactly once each)", tr.Len())
	}

	cancel()
	waitDone(t, done)

	// The rejection must have been logged with the grep-able prefix and must have
	// named the excess commands' identities. The first cycle deterministically
	// rejects the tail (the queue starts empty, so it admits c-1/c-2 and rejects
	// c-3/c-4/c-5), so c-5's id must appear in a rejection log.
	logs := logBuf.String()
	if !strings.Contains(logs, "uplink command queue full") {
		t.Errorf("no grep-able queue-full rejection log; got:\n%s", logs)
	}
	if !strings.Contains(logs, "rejected_command_ids") || !strings.Contains(logs, "c-5") {
		t.Errorf("rejection log does not name the rejected commands' identities (expected c-5 among rejected_command_ids); got:\n%s", logs)
	}

	// The rejection must also be counted in the metrics for an operator's dashboard.
	if snap := p.MetricsSnapshot(); snap.CommandsRejected == 0 {
		t.Errorf("CommandsRejected = 0, want > 0 (the burst exceeded the queue depth)")
	}
}

// TestPollerDeduplicatesRedeliveredCommandInFlight proves the cross-cycle dedup guard
// end to end: while one command is still executing (held in-flight), the control plane
// redelivers the SAME command_id on every subsequent poll, and those redeliveries must
// NOT drive a second execution. It uses a tracker that blocks the first provision so
// the command stays in-flight across many polls.
func TestPollerDeduplicatesRedeliveredCommandInFlight(t *testing.T) {
	cp := newPendingControlPlane(
		cmd("cmd-dup", "node-7", "agent-dup", kindProvision, `{"model":"x"}`, 1),
	)
	srv := httptest.NewServer(cp.handler(t))
	defer srv.Close()

	bt := newBlockingTracker()
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := mustPoller(t, bt, Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7",
		PollInterval: 5 * time.Millisecond, Logger: logger,
		CommandQueueDepth: 16, // ample capacity: dedup, not capacity, is what must stop re-execution.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := run(p, ctx)

	// Wait until the first provision is reached (now blocked, holding cmd-dup in-flight).
	deadline := time.After(2 * time.Second)
	for bt.provisionCalls("agent-dup") == 0 {
		select {
		case <-deadline:
			t.Fatal("the first provision was never reached")
		case <-time.After(2 * time.Millisecond):
		}
	}

	// Let many polls redeliver cmd-dup while it is still executing. None may reach a
	// second Provision call — the queue must skip each redelivery as a duplicate.
	time.Sleep(20 * p.baseInterval)
	if n := bt.provisionCalls("agent-dup"); n != 1 {
		t.Fatalf("Provision(agent-dup) called %d times while the command was in-flight, want exactly 1 (redeliveries must be deduplicated)", n)
	}
	if !strings.Contains(logBuf.String(), "skipping redelivered") {
		t.Errorf("expected a DEBUG log naming the skipped redelivered duplicates; got:\n%s", logBuf.String())
	}

	// Stop the producer FIRST so no further poll can admit a copy, THEN release the
	// blocked provision so the consumer can finish and Run can return. Ordering
	// matters: releasing first could let one more poll re-admit cmd-dup after it
	// completed — the benign, idempotent at-least-once re-execution — which is correct
	// behavior but would make this strict count==1 assertion racy. With the producer
	// already stopped, the single in-flight copy is the only one that ever runs.
	cancel()
	close(bt.release)
	waitDone(t, done)

	if n := bt.provisionCalls("agent-dup"); n != 1 {
		t.Errorf("Provision(agent-dup) called %d times overall, want exactly 1 (deduplicated, never double-executed)", n)
	}
}

// TestPollerReadinessFlipsOnSustainedQueueBackpressureAndRecovers exercises both
// backpressure-readiness paths in one run: while a command is stuck in-flight and a
// depth-1 queue keeps rejecting the backlog, sustained rejections flip readiness to
// not-ready (naming the backlog); once the stuck command releases and the queue drains,
// a clean poll cycle resets the streak and the node reports ready again.
func TestPollerReadinessFlipsOnSustainedQueueBackpressureAndRecovers(t *testing.T) {
	cp := newPendingControlPlane(
		cmd("c-block", "node-7", "agent-block", kindProvision, `{"model":"x"}`, 1),
		cmd("c-extra", "node-7", "agent-extra", kindProvision, `{"model":"x"}`, 1),
	)
	srv := httptest.NewServer(cp.handler(t))
	defer srv.Close()

	bt := newBlockingTracker()
	p := mustPoller(t, bt, Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7",
		PollInterval:      5 * time.Millisecond,
		CommandQueueDepth: 1, // agent-block occupies the only slot; agent-extra is rejected every cycle.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := run(p, ctx)

	// A single over-full cycle must NOT flip readiness (no flapping); only a sustained
	// streak does. Wait for the sustained backup to be reported not-ready.
	var lastDetail string
	deadline := time.After(3 * time.Second)
	for {
		ready, detail := p.Ready()
		if !ready {
			lastDetail = detail
			break
		}
		select {
		case <-deadline:
			t.Fatal("readiness never flipped to not-ready under sustained queue backpressure")
		case <-time.After(2 * time.Millisecond):
		}
	}
	if !strings.Contains(lastDetail, "queue") || !strings.Contains(lastDetail, "backlog") {
		t.Errorf("not-ready detail %q does not name the command-queue backlog", lastDetail)
	}

	// Release the stuck command; it completes and is acknowledged, the queue drains,
	// and a subsequent clean poll cycle (admitting agent-extra without rejection)
	// resets the streak — so the node becomes ready again.
	close(bt.release)
	deadline = time.After(3 * time.Second)
	for {
		if ready, _ := p.Ready(); ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("readiness never recovered after the queue drained")
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()
	waitDone(t, done)
}

// TestPollerStaysReadyWhenQueueHealthy is the healthy-path companion: under normal load
// (commands well within the queue depth), no cycle ever rejects, so the backpressure
// gate never fires and the node stays ready throughout.
func TestPollerStaysReadyWhenQueueHealthy(t *testing.T) {
	var cmds []command
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("c-%d", i)
		cmds = append(cmds, cmd(id, "node-7", "agent-"+id, kindProvision, `{"model":"x"}`, 1))
	}
	cp := newPendingControlPlane(cmds...)
	srv := httptest.NewServer(cp.handler(t))
	defer srv.Close()

	tr := runtime.NewTracker(0)
	p := mustPoller(t, tr, Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7",
		PollInterval:      5 * time.Millisecond,
		CommandQueueDepth: 64, // far above the 4-command batch: nothing is ever rejected.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := run(p, ctx)

	// Let it complete the whole batch, then confirm it is (still) ready and never
	// counted a rejection.
	deadline := time.After(3 * time.Second)
	for !cp.allDone() {
		select {
		case <-deadline:
			t.Fatal("healthy batch was not fully executed within the deadline")
		case <-time.After(2 * time.Millisecond):
		}
	}
	if ready, detail := p.Ready(); !ready {
		t.Fatalf("a node keeping up with a healthy queue must stay ready, got not-ready (%q)", detail)
	}
	if snap := p.MetricsSnapshot(); snap.CommandsRejected != 0 {
		t.Errorf("CommandsRejected = %d, want 0 (the queue was never full)", snap.CommandsRejected)
	}

	cancel()
	waitDone(t, done)
}
