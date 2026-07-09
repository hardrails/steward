package server

import (
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/runtime"
)

// stateHandler builds a server whose tracker persists to path, mirroring how
// cmd/steward wires the opt-in durable-state mode via NewWithTracker.
func stateHandler(t *testing.T, path string) http.Handler {
	t.Helper()
	tr, err := runtime.LoadTracker(0, path)
	if err != nil {
		t.Fatalf("LoadTracker(%q): %v", path, err)
	}
	return NewWithTracker(slog.New(slog.NewTextHandler(io.Discard, nil)), tr).Handler()
}

// TestDurableStateSurvivesRestart drives the full HTTP surface, then rebuilds a
// fresh server pointed at the same state file (a process "restart") and confirms
// the tracked instances — and their statuses and specs — are still there, while a
// destroyed instance stays gone.
func TestDurableStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	h1 := stateHandler(t, path)

	const specA = `{"model":"opus","memory_mb":512}`
	refA := provisionID(t, h1, "agent-a", specA)
	refB := provisionID(t, h1, "agent-b", "")
	refGone := provisionID(t, h1, "agent-gone", `{"tmp":true}`)

	// Mutate: A running, B hibernated, gone destroyed.
	if rec := do(h1, http.MethodPost, "/v1/instances/"+refA+"/start", ""); rec.Code != http.StatusOK {
		t.Fatalf("start A: status=%d", rec.Code)
	}
	if rec := do(h1, http.MethodPost, "/v1/instances/"+refB+"/hibernate", ""); rec.Code != http.StatusOK {
		t.Fatalf("hibernate B: status=%d", rec.Code)
	}
	if rec := do(h1, http.MethodDelete, "/v1/instances/"+refGone, ""); rec.Code != http.StatusOK {
		t.Fatalf("destroy gone: status=%d", rec.Code)
	}

	// "Restart": a brand-new server + tracker over the same file.
	h2 := stateHandler(t, path)

	getA := do(h2, http.MethodGet, "/v1/instances/"+refA, "")
	if getA.Code != http.StatusOK {
		t.Fatalf("A after restart: status=%d (body=%s)", getA.Code, getA.Body.String())
	}
	if inst := decodeInstance(t, getA); inst.Status != runtime.StatusRunning || string(inst.Spec) != specA {
		t.Fatalf("A after restart: status=%q spec=%s, want RUNNING and %s", inst.Status, inst.Spec, specA)
	}

	getB := do(h2, http.MethodGet, "/v1/instances/"+refB, "")
	if getB.Code != http.StatusOK {
		t.Fatalf("B after restart: status=%d", getB.Code)
	}
	if inst := decodeInstance(t, getB); inst.Status != runtime.StatusHibernated {
		t.Fatalf("B after restart: status=%q, want HIBERNATED", inst.Status)
	}

	// The destroyed instance did not come back.
	assertJSONError(t, do(h2, http.MethodGet, "/v1/instances/"+refGone, ""), http.StatusNotFound)

	// Idempotency key survives the restart: re-provisioning agent-a returns the
	// same runtime_ref with 200, proving the byID index was rebuilt.
	reprov := do(h2, http.MethodPost, "/v1/instances", `{"instance_id":"agent-a"}`)
	if reprov.Code != http.StatusOK {
		t.Fatalf("reprovision after restart: status=%d want 200 (body=%s)", reprov.Code, reprov.Body.String())
	}
	if decodeInstance(t, reprov).RuntimeRef != refA {
		t.Fatal("reprovision after restart returned a different runtime_ref")
	}
}

// TestCapabilitiesReportsDurableState proves the durable_state bit in
// /v1/capabilities flips to true when a state file is configured (the in-memory
// case is covered by TestCapabilities), and that advertising it never leaks the
// configured filesystem path into the response body.
func TestCapabilitiesReportsDurableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	h := stateHandler(t, path)

	rec := do(h, http.MethodGet, "/v1/capabilities", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !decodeCapabilities(t, rec).DurableState {
		t.Fatal("durable_state = false, want true when a state file is configured")
	}
	if body := rec.Body.String(); strings.Contains(body, path) || strings.Contains(body, filepath.Dir(path)) {
		t.Fatalf("capabilities body leaked the state-file path: %s", body)
	}
}
