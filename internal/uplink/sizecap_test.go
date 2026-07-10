package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

// TestReadCappedBody pins the exact cap boundary the poll-response guard turns on:
// a body of exactly maxUplinkBodyBytes is not over the cap, one byte more is, and
// the returned prefix is always bounded to the cap. This kills the off-by-one
// (> vs >=) and the truncation-length mutants directly, without an HTTP round-trip.
func TestReadCappedBody(t *testing.T) {
	t.Run("exactly at the cap is accepted", func(t *testing.T) {
		in := bytes.Repeat([]byte("x"), maxUplinkBodyBytes)
		data, tooLarge, err := readCappedBody(bytes.NewReader(in))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if tooLarge {
			t.Error("a body of exactly the cap must not be reported as too large")
		}
		if len(data) != maxUplinkBodyBytes {
			t.Errorf("len(data) = %d, want %d (the whole body)", len(data), maxUplinkBodyBytes)
		}
	})

	t.Run("one byte over the cap is rejected", func(t *testing.T) {
		in := bytes.Repeat([]byte("x"), maxUplinkBodyBytes+1)
		data, tooLarge, err := readCappedBody(bytes.NewReader(in))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !tooLarge {
			t.Error("a body one byte over the cap must be reported as too large")
		}
		// The read is bounded: at most the cap is returned, never the extra byte.
		if len(data) != maxUplinkBodyBytes {
			t.Errorf("len(data) = %d, want the truncated prefix of %d", len(data), maxUplinkBodyBytes)
		}
	})

	t.Run("a small body is returned whole", func(t *testing.T) {
		data, tooLarge, err := readCappedBody(strings.NewReader("hello"))
		if err != nil || tooLarge || string(data) != "hello" {
			t.Errorf("readCappedBody(small) = (%q, %v, %v), want (\"hello\", false, nil)", data, tooLarge, err)
		}
	})
}

// TestPollRejectsOversizedResponse pins Feature 2's poll-side rejection: a 2xx
// poll response whose body exceeds the cap is dropped as classTransient (this
// cycle is retried next) with a clear message, never parsed from a truncated
// prefix and never read unbounded.
func TestPollRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A valid-looking prefix followed by padding that pushes the whole body
		// well past the 1 MiB cap. The guard must reject on size before ever
		// trying to decode it.
		_, _ = io.WriteString(w, `{"commands":[]}`)
		_, _ = io.WriteString(w, strings.Repeat(" ", maxUplinkBodyBytes+64))
	}))
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second,
	})

	commands, class, err := p.poll(context.Background())
	if class != classTransient {
		t.Errorf("class = %v, want classTransient (%v) so the poll is dropped and retried", class, classTransient)
	}
	if commands != nil {
		t.Errorf("commands = %v, want nil: an oversized response must yield no commands", commands)
	}
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v, want one naming the exceeded cap", err)
	}
}

// TestPollAcceptsResponseUnderCap is the paired happy path: a normal, under-cap
// poll response still decodes to its commands, proving the cap rejects only
// oversized bodies rather than breaking the ordinary path.
func TestPollAcceptsResponseUnderCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"commands":[{"command_id":"cmd-1","node_id":"node-7","runtime_ref":"rt-1","kind":"provision"}]}`)
	}))
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second,
	})

	commands, class, err := p.poll(context.Background())
	if err != nil {
		t.Fatalf("unexpected err on an under-cap response: %v", err)
	}
	if class != classOK {
		t.Errorf("class = %v, want classOK", class)
	}
	if len(commands) != 1 || commands[0].CommandID != "cmd-1" {
		t.Errorf("commands = %v, want the single decoded cmd-1", commands)
	}
}

// TestSendReportRefusesOversizedBody pins Feature 2's report-side rejection: a
// report whose marshaled body exceeds the cap is refused before it is sent, so
// Steward never pushes an unbounded body at the control plane. The server must
// never be contacted; the caller (executeBatch) logs the returned error at WARN
// and the server redelivers via its claim lease.
func TestSendReportRefusesOversizedBody(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applied":true}`)
	}))
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second,
	})

	// A valid JSON string field large enough to push the whole report past the cap.
	huge := json.RawMessage(`"` + strings.Repeat("a", maxUplinkBodyBytes+64) + `"`)
	err := p.sendReport(context.Background(), report{CommandID: "cmd-big", Result: huge})
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Errorf("err = %v, want one naming the exceeded cap", err)
	}
	if hit.Load() {
		t.Error("an oversized report must not be sent; the server was contacted")
	}
}

// TestSendReportRejectsOversizedResponse pins that the report-response read
// enforces the cap the same way the poll response does: a 2xx report response
// whose body exceeds the cap is rejected (not silently accepted from a bounded
// LimitReader that ignores the padded tail). sendReport returns an error, which
// the caller logs at WARN; the server redelivers via its claim lease.
func TestSendReportRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A valid applied:true prefix followed by padding past the cap. A bare
		// LimitReader would decode the prefix and drop the tail; readCappedBody
		// rejects the whole over-cap body.
		_, _ = io.WriteString(w, `{"applied":true}`)
		_, _ = io.WriteString(w, strings.Repeat(" ", maxUplinkBodyBytes+64))
	}))
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second,
	})

	err := p.sendReport(context.Background(), report{CommandID: "cmd-ok", Status: "success"})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v, want one naming the exceeded response cap", err)
	}
}

// TestSendReportSendsUnderCapBody is the paired happy path: a normal report is
// marshaled, passes the cap, and is delivered.
func TestSendReportSendsUnderCapBody(t *testing.T) {
	got := make(chan report, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep report
		_ = json.NewDecoder(r.Body).Decode(&rep)
		got <- rep
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"applied":true}`)
	}))
	defer srv.Close()

	p := mustPoller(t, runtime.NewTracker(0), Config{
		BaseURL: srv.URL, Credential: "tok", NodeID: "node-7", PollInterval: time.Second,
	})

	if err := p.sendReport(context.Background(), report{CommandID: "cmd-ok", Status: "success"}); err != nil {
		t.Fatalf("unexpected err on an under-cap report: %v", err)
	}
	select {
	case rep := <-got:
		if rep.CommandID != "cmd-ok" {
			t.Errorf("server received command_id %q, want cmd-ok", rep.CommandID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("under-cap report was never delivered")
	}
}
