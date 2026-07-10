package server

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

// execHandler builds a handler over an exec-enabled tracker (rate limiting and
// metrics off, matching newTestHandler), so the process-exec HTTP surface can be
// exercised end to end.
func execHandler(t *testing.T) http.Handler {
	t.Helper()
	tr := runtime.NewTracker(0, runtime.WithExec(runtime.ExecConfig{
		Enabled:         true,
		StopGracePeriod: time.Second,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}))
	return NewWithTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), tr, 0, false, nil).Handler()
}

// TestProvisionCommandSpecRejectedWhenExecDisabled proves the opt-in gate: a
// command-bearing spec provisioned against a default (exec-disabled) Steward is a
// 400 process_exec_disabled, not a silently-stored instance.
func TestProvisionCommandSpecRejectedWhenExecDisabled(t *testing.T) {
	h := newTestHandler(0) // exec disabled

	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"a","spec":{"command":"/bin/echo"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if er := decodeError(t, rec); er.Error != "process_exec_disabled" {
		t.Fatalf("error code=%q, want process_exec_disabled", er.Error)
	}
	// It must not have been created.
	list := do(h, http.MethodGet, "/v1/instances", "")
	if got := decodeInstances(t, list); len(got.Instances) != 0 {
		t.Fatalf("a rejected provision created %d instances, want 0", len(got.Instances))
	}
}

// TestProvisionOpaqueSpecUnaffectedWhenExecDisabled is the backward-compat
// regression guard: a spec WITHOUT a command field is provisioned exactly as
// before, whether or not process exec is enabled.
func TestProvisionOpaqueSpecUnaffectedWhenExecDisabled(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"a","spec":{"owner":"a"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if inst := decodeInstance(t, rec); inst.Status != runtime.StatusPending {
		t.Fatalf("status=%q, want PENDING", inst.Status)
	}
}

// TestProvisionMalformedCommandSpecWhenExecEnabled: an intent-expressing spec that
// is malformed is a 400 invalid_spec, caught at provision time.
func TestProvisionMalformedCommandSpecWhenExecEnabled(t *testing.T) {
	h := execHandler(t)
	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"a","spec":{"command":""}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if er := decodeError(t, rec); er.Error != "invalid_spec" {
		t.Fatalf("error code=%q, want invalid_spec", er.Error)
	}
}

// TestStartFailedCommandReturns400 proves a valid /start whose configured command
// cannot be spawned returns 400 process_start_failed and leaves the instance in its
// prior status (not a false RUNNING).
func TestStartFailedCommandReturns400(t *testing.T) {
	h := execHandler(t)
	ref := provisionID(t, h, "a", `{"command":"/nonexistent/steward-no-such-binary"}`)

	rec := do(h, http.MethodPost, "/v1/instances/"+ref+"/start", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("start status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if er := decodeError(t, rec); er.Error != "process_start_failed" {
		t.Fatalf("error code=%q, want process_start_failed", er.Error)
	}
	// The instance must still be PENDING, not falsely RUNNING.
	got := do(h, http.MethodGet, "/v1/instances/"+ref, "")
	if inst := decodeInstance(t, got); inst.Status != runtime.StatusPending {
		t.Fatalf("status=%q after failed start, want PENDING", inst.Status)
	}
}
