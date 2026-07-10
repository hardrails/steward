package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestProvisionResponseIncludesCreatedAt pins that every Instance response
// carries a `created_at` key with a valid, parseable RFC3339 timestamp — the
// wire field the `created_since` filter is built on. It is asserted at the
// raw-JSON level (not just via the decoded Go struct) because CreatedAt has no
// `omitempty` (a zero time.Time is never "empty" to encoding/json, unlike
// Generation's int64), so the key must always be present, never silently
// dropped.
func TestProvisionResponseIncludesCreatedAt(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"agent-1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision: status=%d want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw body: %v", err)
	}
	createdAtRaw, ok := raw["created_at"]
	if !ok {
		t.Fatalf("response is missing the created_at key entirely (body=%s)", rec.Body.String())
	}
	var createdAt string
	if err := json.Unmarshal(createdAtRaw, &createdAt); err != nil {
		t.Fatalf("created_at is not a JSON string: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, createdAt); err != nil {
		t.Fatalf("created_at = %q is not a valid RFC3339 timestamp: %v", createdAt, err)
	}
}

// TestListFilterByStatusAlone pins the `status` filter used on its own.
func TestListFilterByStatusAlone(t *testing.T) {
	h := newTestHandler(0)
	runningRef := provisionID(t, h, "running-1", "")
	if rec := do(h, http.MethodPost, "/v1/instances/"+runningRef+"/start", ""); rec.Code != http.StatusOK {
		t.Fatalf("start running-1: status=%d (body=%s)", rec.Code, rec.Body.String())
	}
	provisionID(t, h, "pending-1", "")

	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances?status=RUNNING", ""))
	if len(got.Instances) != 1 || got.Instances[0].InstanceID != "running-1" {
		t.Fatalf("GET ?status=RUNNING = %+v, want exactly running-1", got.Instances)
	}
}

// TestListFilterByInstanceIDPrefixAlone pins the `instance_id_prefix` filter
// used on its own.
func TestListFilterByInstanceIDPrefixAlone(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "web-1", "")
	provisionID(t, h, "web-2", "")
	provisionID(t, h, "worker-1", "")

	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances?instance_id_prefix=web-", ""))
	if len(got.Instances) != 2 {
		t.Fatalf("GET ?instance_id_prefix=web- returned %d instances, want 2: %+v", len(got.Instances), got.Instances)
	}
	for _, inst := range got.Instances {
		if inst.InstanceID != "web-1" && inst.InstanceID != "web-2" {
			t.Fatalf("GET ?instance_id_prefix=web- returned unexpected instance_id %q", inst.InstanceID)
		}
	}
}

// TestListFilterByCreatedSinceAlone pins the `created_since` filter used on
// its own: instances created at or after the RFC3339 timestamp are returned;
// earlier ones are excluded.
func TestListFilterByCreatedSinceAlone(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "old-1", "")
	time.Sleep(2 * time.Millisecond)
	boundary := time.Now().UTC()
	time.Sleep(2 * time.Millisecond)
	provisionID(t, h, "new-1", "")

	q := url.Values{"created_since": {boundary.Format(time.RFC3339Nano)}}
	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances?"+q.Encode(), ""))
	if len(got.Instances) != 1 || got.Instances[0].InstanceID != "new-1" {
		t.Fatalf("GET ?created_since=boundary = %+v, want exactly new-1", got.Instances)
	}
}

// TestListFilterCombinedComposesViaAND pins that multiple filters given
// together narrow the result with AND semantics, not OR.
func TestListFilterCombinedComposesViaAND(t *testing.T) {
	h := newTestHandler(0)
	webRunningRef := provisionID(t, h, "web-1", "")
	if rec := do(h, http.MethodPost, "/v1/instances/"+webRunningRef+"/start", ""); rec.Code != http.StatusOK {
		t.Fatalf("start web-1: status=%d", rec.Code)
	}
	provisionID(t, h, "web-2", "") // wrong status (PENDING)
	workerRunningRef := provisionID(t, h, "worker-1", "")
	if rec := do(h, http.MethodPost, "/v1/instances/"+workerRunningRef+"/start", ""); rec.Code != http.StatusOK {
		t.Fatalf("start worker-1: status=%d", rec.Code)
	}

	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances?status=RUNNING&instance_id_prefix=web-", ""))
	if len(got.Instances) != 1 || got.Instances[0].InstanceID != "web-1" {
		t.Fatalf("GET ?status=RUNNING&instance_id_prefix=web- = %+v, want exactly web-1", got.Instances)
	}
}

// TestListFilterEmptyResult pins that a filter matching nothing returns 200
// with an empty (never null) instances array, not an error.
func TestListFilterEmptyResult(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "agent-1", "")

	rec := do(h, http.MethodGet, "/v1/instances?instance_id_prefix=does-not-exist-", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeInstances(t, rec)
	if got.Instances == nil {
		t.Fatal("instances = null, want a non-nil empty array")
	}
	if len(got.Instances) != 0 {
		t.Fatalf("instances has %d entries, want 0", len(got.Instances))
	}
}

// TestListNoFiltersUnchanged pins backward compatibility: omitting all three
// filters returns exactly what the endpoint always returned (every tracked
// instance, unfiltered).
func TestListNoFiltersUnchanged(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "agent-1", "")
	provisionID(t, h, "agent-2", "")

	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances", ""))
	if len(got.Instances) != 2 {
		t.Fatalf("GET /v1/instances (no filters) returned %d instances, want 2", len(got.Instances))
	}
}

// TestListFilterInvalidCreatedSinceReturns400 pins that an unparseable
// created_since is a 400, never a silently-ignored filter and never a 500.
func TestListFilterInvalidCreatedSinceReturns400(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "agent-1", "")

	cases := []string{"not-a-timestamp", "2024-01-01", "12345"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			q := url.Values{"created_since": {raw}}
			assertJSONError(t, do(h, http.MethodGet, "/v1/instances?"+q.Encode(), ""), http.StatusBadRequest)
		})
	}
}

// TestListFilterInvalidStatusReturns400 pins that an unknown status value is
// a 400 rather than a silently-empty result.
func TestListFilterInvalidStatusReturns400(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "agent-1", "")

	assertJSONError(t, do(h, http.MethodGet, "/v1/instances?status=BOGUS", ""), http.StatusBadRequest)
}

// TestListFilterStatusExactMatchNoCaseFolding pins that the status filter is
// an exact match against the enum's wire casing.
func TestListFilterStatusExactMatchNoCaseFolding(t *testing.T) {
	h := newTestHandler(0)
	provisionID(t, h, "agent-1", "")

	// Lowercase "pending" is not a recognized enum member, so it is a 400 (not
	// a case-insensitive match against PENDING).
	assertJSONError(t, do(h, http.MethodGet, "/v1/instances?status=pending", ""), http.StatusBadRequest)
}

// TestListFilterDestroyedNeverMatches pins that a destroyed instance can never
// appear via a status filter — Destroy removes it from the tracker entirely.
func TestListFilterDestroyedNeverMatches(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", "")
	if rec := do(h, http.MethodDelete, "/v1/instances/"+ref, ""); rec.Code != http.StatusOK {
		t.Fatalf("destroy: status=%d", rec.Code)
	}

	got := decodeInstances(t, do(h, http.MethodGet, "/v1/instances?status=DESTROYED", ""))
	if len(got.Instances) != 0 {
		t.Fatalf("GET ?status=DESTROYED = %+v, want empty", got.Instances)
	}
}
