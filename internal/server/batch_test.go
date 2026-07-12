package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/runtime"
)

func decodeBatch(t *testing.T, rec *httptest.ResponseRecorder) batchResponse {
	t.Helper()
	var got batchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode batch response: %v (body=%s)", err, rec.Body.String())
	}
	return got
}

// TestBatchAllSucceed pins the happy path: every operation succeeds and the
// results array reports each in order with the same status/body a single-op
// call would have produced.
func TestBatchAllSucceed(t *testing.T) {
	h := newTestHandler(0)
	body := `{"operations":[
		{"op":"provision","instance_id":"agent-1","spec":{"k":"v"}},
		{"op":"provision","instance_id":"agent-2"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeBatch(t, rec)
	if len(got.Results) != 2 {
		t.Fatalf("results has %d entries, want 2: %+v", len(got.Results), got.Results)
	}
	for i, r := range got.Results {
		if r.Status != http.StatusCreated {
			t.Fatalf("result %d: status=%d want 201 (result=%+v)", i, r.Status, r)
		}
		if r.Error != nil {
			t.Fatalf("result %d: unexpected error %+v", i, r.Error)
		}
		if r.Instance == nil {
			t.Fatalf("result %d: instance is nil", i)
		}
	}
	if got.Results[0].Instance.InstanceID != "agent-1" || string(got.Results[0].Instance.Spec) != `{"k":"v"}` {
		t.Fatalf("result 0 instance = %+v, want agent-1 with spec {\"k\":\"v\"}", got.Results[0].Instance)
	}
	if got.Results[1].Instance.InstanceID != "agent-2" {
		t.Fatalf("result 1 instance = %+v, want agent-2", got.Results[1].Instance)
	}
}

// TestBatchInvalidStateTransitionReturns409PerOperation pins that a rejected
// transition inside a batch surfaces per-operation exactly as the single-op
// endpoint does: a stop of a freshly-provisioned (PENDING) instance is a 409
// with the invalid_state_transition code at its own index, while sibling
// operations still run and the batch call itself is 200.
func TestBatchInvalidStateTransitionReturns409PerOperation(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", "") // PENDING

	body := `{"operations":[
		{"op":"stop","runtime_ref":"` + ref + `"},
		{"op":"start","runtime_ref":"` + ref + `"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (per-op failure is not an overall error)", rec.Code)
	}
	got := decodeBatch(t, rec)
	if len(got.Results) != 2 {
		t.Fatalf("results has %d entries, want 2", len(got.Results))
	}
	if got.Results[0].Status != http.StatusConflict || got.Results[0].Error == nil ||
		got.Results[0].Error.Error != "invalid_state_transition" {
		t.Fatalf("result 0 = %+v, want 409 invalid_state_transition (stop of a PENDING instance)", got.Results[0])
	}
	// The sibling start still ran (PENDING→RUNNING), proving the batch did not
	// stop on the failure.
	if got.Results[1].Status != http.StatusOK || got.Results[1].Instance == nil ||
		got.Results[1].Instance.Status != runtime.StatusRunning {
		t.Fatalf("result 1 = %+v, want 200 RUNNING (the sibling start must still run)", got.Results[1])
	}
}

// TestBatchPartialFailureReportsEachResultIndependently pins the core
// partial-success contract: operation 3 of 5 failing does not prevent 1, 2, 4,
// 5 from running, and every result — success or failure — is reported at its
// original index. The batch call itself still returns 200: failure is
// reported per-operation, not as an overall HTTP error.
func TestBatchPartialFailureReportsEachResultIndependently(t *testing.T) {
	h := newTestHandler(0)
	body := `{"operations":[
		{"op":"provision","instance_id":"a"},
		{"op":"provision","instance_id":"b"},
		{"op":"start","runtime_ref":"rt_does_not_exist"},
		{"op":"provision","instance_id":"c"},
		{"op":"provision","instance_id":"d"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeBatch(t, rec)
	if len(got.Results) != 5 {
		t.Fatalf("results has %d entries, want 5", len(got.Results))
	}

	wantIDs := []string{"a", "b", "", "c", "d"}
	for i, r := range got.Results {
		if i == 2 {
			if r.Status != http.StatusNotFound {
				t.Fatalf("result 2 (the failing op): status=%d want 404 (result=%+v)", r.Status, r)
			}
			if r.Error == nil || r.Error.Error != "unknown_runtime_ref" {
				t.Fatalf("result 2: error=%+v want unknown_runtime_ref", r.Error)
			}
			if r.Instance != nil {
				t.Fatalf("result 2: instance should be nil on failure, got %+v", r.Instance)
			}
			continue
		}
		if r.Status != http.StatusCreated {
			t.Fatalf("result %d: status=%d want 201 (result=%+v)", i, r.Status, r)
		}
		if r.Instance == nil || r.Instance.InstanceID != wantIDs[i] {
			t.Fatalf("result %d: instance=%+v want instance_id %q", i, r.Instance, wantIDs[i])
		}
	}

	// The successful operations actually took effect on the live tracker.
	list := decodeInstances(t, do(h, http.MethodGet, "/v1/instances", ""))
	if len(list.Instances) != 4 {
		t.Fatalf("tracker holds %d instances after the batch, want 4 (a,b,c,d)", len(list.Instances))
	}
}

// TestBatchOrderingDestroyThenReprovision pins that operations run strictly in
// request order against the live tracker: destroying an instance_id and
// re-provisioning it within the SAME batch must work, because the destroy's
// effect (releasing the instance_id) is visible to the later provision.
func TestBatchOrderingDestroyThenReprovision(t *testing.T) {
	h := newTestHandler(0)
	originalRef := provisionID(t, h, "agent-1", "")

	body := `{"operations":[
		{"op":"destroy","runtime_ref":"` + originalRef + `"},
		{"op":"provision","instance_id":"agent-1","spec":{"reprovisioned":true}}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeBatch(t, rec)
	if len(got.Results) != 2 {
		t.Fatalf("results has %d entries, want 2", len(got.Results))
	}

	destroyResult := got.Results[0]
	if destroyResult.Status != http.StatusOK || destroyResult.Instance == nil || destroyResult.Instance.Status != runtime.StatusDestroyed {
		t.Fatalf("destroy result = %+v, want 200 DESTROYED", destroyResult)
	}

	reprovisionResult := got.Results[1]
	if reprovisionResult.Status != http.StatusCreated {
		t.Fatalf("reprovision result: status=%d want 201 (a genuinely NEW instance, not idempotent-200) — got %+v",
			reprovisionResult.Status, reprovisionResult)
	}
	if reprovisionResult.Instance == nil || reprovisionResult.Instance.RuntimeRef == originalRef {
		t.Fatalf("reprovision result must carry a fresh runtime_ref distinct from the destroyed one, got %+v", reprovisionResult.Instance)
	}
	if string(reprovisionResult.Instance.Spec) != `{"reprovisioned":true}` {
		t.Fatalf("reprovisioned spec = %s, want {\"reprovisioned\":true}", reprovisionResult.Instance.Spec)
	}

	// The tracker now holds exactly the new instance, addressable by its new ref.
	getNew := do(h, http.MethodGet, "/v1/instances/"+reprovisionResult.Instance.RuntimeRef, "")
	if getNew.Code != http.StatusOK {
		t.Fatalf("GET new ref: status=%d", getNew.Code)
	}
	getOld := do(h, http.MethodGet, "/v1/instances/"+originalRef, "")
	if getOld.Code != http.StatusNotFound {
		t.Fatalf("GET old (destroyed) ref: status=%d want 404", getOld.Code)
	}
}

// TestBatchEmptyOperationsList pins that an empty operations array is valid
// input, not an error: the response is 200 with an empty (non-null) results
// array.
func TestBatchEmptyOperationsList(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances/batch", `{"operations":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeBatch(t, rec)
	if got.Results == nil {
		t.Fatal("results = null, want a non-nil empty array")
	}
	if len(got.Results) != 0 {
		t.Fatalf("results has %d entries, want 0", len(got.Results))
	}
}

// TestBatchUnknownOpReturns400PerOperation pins that an unrecognized op value
// is reported as a 400 in that operation's own result, not a top-level error
// or a panic, and does not block sibling operations.
func TestBatchUnknownOpReturns400PerOperation(t *testing.T) {
	h := newTestHandler(0)
	body := `{"operations":[
		{"op":"hibernate","runtime_ref":"rt_whatever"},
		{"op":"provision","instance_id":"a"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	got := decodeBatch(t, rec)
	if got.Results[0].Status != http.StatusBadRequest || got.Results[0].Error == nil ||
		got.Results[0].RuntimeRef != "rt_whatever" {
		t.Fatalf("result 0 (unknown op): %+v, want 400 with an error", got.Results[0])
	}
	if got.Results[1].Status != http.StatusCreated {
		t.Fatalf("result 1 (sibling op): status=%d want 201 — an unknown op must not block siblings", got.Results[1].Status)
	}
}

// TestBatchProvisionMissingInstanceIDReturns400PerOperation pins the
// per-operation validation for "provision": a missing instance_id is a 400 in
// that result, mirroring handleProvision's own validation.
func TestBatchProvisionMissingInstanceIDReturns400PerOperation(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances/batch", `{"operations":[{"op":"provision"}]}`)
	got := decodeBatch(t, rec)
	if got.Results[0].Status != http.StatusBadRequest || got.Results[0].Error == nil || got.Results[0].Error.Error != "invalid_request" {
		t.Fatalf("result 0 = %+v, want 400 invalid_request", got.Results[0])
	}
}

// TestBatchTransitionMissingRuntimeRefReturns400PerOperation pins the
// per-operation validation for "start"/"stop"/"destroy": a missing
// runtime_ref is a 400 in that result.
func TestBatchTransitionMissingRuntimeRefReturns400PerOperation(t *testing.T) {
	h := newTestHandler(0)
	for _, op := range []string{"start", "stop", "destroy"} {
		t.Run(op, func(t *testing.T) {
			rec := do(h, http.MethodPost, "/v1/instances/batch", `{"operations":[{"op":"`+op+`"}]}`)
			got := decodeBatch(t, rec)
			if got.Results[0].Status != http.StatusBadRequest || got.Results[0].Error == nil {
				t.Fatalf("result 0 = %+v, want 400", got.Results[0])
			}
		})
	}
}

// TestBatchProvisionInvalidSpecReturns400PerOperation mirrors
// handleProvision's spec-must-be-an-object validation inside a batch
// operation.
func TestBatchProvisionInvalidSpecReturns400PerOperation(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances/batch", `{"operations":[{"op":"provision","instance_id":"a","spec":[1,2,3]}]}`)
	got := decodeBatch(t, rec)
	if got.Results[0].Status != http.StatusBadRequest || got.Results[0].Error == nil {
		t.Fatalf("result 0 = %+v, want 400", got.Results[0])
	}
}

// TestBatchStartStopWorkOnRuntimeRef pins that "start"/"stop" batch operations
// address instances by runtime_ref — the same identifier the single-instance
// routes use — and produce the same status transition.
func TestBatchStartStopWorkOnRuntimeRef(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", "")

	body := `{"operations":[
		{"op":"start","runtime_ref":"` + ref + `"},
		{"op":"stop","runtime_ref":"` + ref + `"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	got := decodeBatch(t, rec)
	if got.Results[0].Instance == nil || got.Results[0].Instance.Status != runtime.StatusRunning {
		t.Fatalf("result 0 (start) = %+v, want RUNNING", got.Results[0])
	}
	if got.Results[1].Instance == nil || got.Results[1].Instance.Status != runtime.StatusStopped {
		t.Fatalf("result 1 (stop) = %+v, want STOPPED", got.Results[1])
	}
}

// TestBatchProvisionIsIdempotentAcrossRetriedBatch pins the idempotency
// discussion from the design: a batch is not itself a transaction with a
// dedup token, but a "provision" operation inside it calls straight into
// Tracker.Provision, so retrying the SAME batch body (as a caller would after
// a timeout that left the outcome ambiguous) does not double-provision — the
// second call's provision result comes back 200 (existing instance, same
// runtime_ref) instead of 201/a duplicate.
func TestBatchProvisionIsIdempotentAcrossRetriedBatch(t *testing.T) {
	h := newTestHandler(0)
	body := `{"operations":[{"op":"provision","instance_id":"agent-1","spec":{"a":1}}]}`

	first := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))
	second := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))

	if first.Results[0].Status != http.StatusCreated {
		t.Fatalf("first batch: status=%d want 201", first.Results[0].Status)
	}
	if second.Results[0].Status != http.StatusOK {
		t.Fatalf("retried batch: status=%d want 200 (idempotent re-provision, not a duplicate)", second.Results[0].Status)
	}
	if first.Results[0].Instance.RuntimeRef != second.Results[0].Instance.RuntimeRef {
		t.Fatal("runtime_ref changed between the original batch and its retry; provision idempotency was lost")
	}

	list := decodeInstances(t, do(h, http.MethodGet, "/v1/instances", ""))
	if len(list.Instances) != 1 {
		t.Fatalf("tracker holds %d instances after retrying the batch, want exactly 1 (no duplicate)", len(list.Instances))
	}
}

// TestBatchStartIsIdempotentAcrossRetriedBatch mirrors the provision
// idempotency test for "start": Start's transition is naturally idempotent
// (repeated calls converge on the same RUNNING state and 200 response), so
// retrying a batch containing a start op is safe.
func TestBatchStartIsIdempotentAcrossRetriedBatch(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", "")
	body := `{"operations":[{"op":"start","runtime_ref":"` + ref + `"}]}`

	first := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))
	second := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))

	if first.Results[0].Status != http.StatusOK || first.Results[0].Instance.Status != runtime.StatusRunning {
		t.Fatalf("first batch start = %+v, want 200 RUNNING", first.Results[0])
	}
	if second.Results[0].Status != http.StatusOK || second.Results[0].Instance.Status != runtime.StatusRunning {
		t.Fatalf("retried batch start = %+v, want 200 RUNNING (idempotent)", second.Results[0])
	}
}

// TestBatchDestroyIsNotIdempotentAcrossRetriedBatch documents the one
// constituent operation that is NOT safely retriable at the batch level:
// Destroy releases the instance_id/runtime_ref, so retrying a batch that
// already destroyed an instance gets a 404 unknown_runtime_ref on that
// operation the second time — the batch endpoint does not (and cannot,
// without changing Destroy's own semantics) paper over this. This is the same
// behavior a single DELETE /v1/instances/{id} retry would see; batching does
// not make it worse.
func TestBatchDestroyIsNotIdempotentAcrossRetriedBatch(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", "")
	body := `{"operations":[{"op":"destroy","runtime_ref":"` + ref + `"}]}`

	first := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))
	if first.Results[0].Status != http.StatusOK || first.Results[0].Instance.Status != runtime.StatusDestroyed {
		t.Fatalf("first batch destroy = %+v, want 200 DESTROYED", first.Results[0])
	}

	second := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body))
	if second.Results[0].Status != http.StatusNotFound {
		t.Fatalf("retried batch destroy: status=%d want 404 (the runtime_ref was released by the first destroy)", second.Results[0].Status)
	}
}

// TestBatchMalformedBodyReturns400 pins the top-level request validation: a
// body that is not a JSON object at all is a 400, not a 500 and not an empty
// results array.
func TestBatchMalformedBodyReturns400(t *testing.T) {
	h := newTestHandler(0)
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"operations":`},
		{"not an object", `[1,2,3]`},
		{"missing operations", `{}`},
		{"null operations", `{"operations":null}`},
		{"trailing value", `{"operations":[]} {}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertJSONError(t, do(h, http.MethodPost, "/v1/instances/batch", c.body), http.StatusBadRequest)
		})
	}
}

func TestBatchRejectsTooManyOperations(t *testing.T) {
	h := newTestHandler(0)
	operations := make([]string, maxBatchOperations+1)
	for i := range operations {
		operations[i] = `{"op":"provision","instance_id":"a"}`
	}
	body := `{"operations":[` + strings.Join(operations, ",") + `]}`
	assertJSONError(t, do(h, http.MethodPost, "/v1/instances/batch", body), http.StatusBadRequest)
}

func TestBatchProvisionMirrorsSingleEndpointProcessErrors(t *testing.T) {
	tests := []struct {
		name string
		h    http.Handler
		spec string
		code string
	}{
		{name: "execution disabled", h: newTestHandler(0), spec: `{"command":"/bin/echo"}`, code: codeProcessExecDisabled},
		{name: "invalid process spec", h: execHandler(t), spec: `{"command":""}`, code: codeInvalidSpec},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `{"operations":[{"op":"provision","instance_id":"a","spec":` + test.spec + `}]}`
			result := decodeBatch(t, do(test.h, http.MethodPost, "/v1/instances/batch", body)).Results[0]
			if result.Status != http.StatusBadRequest || result.Error == nil || result.Error.Error != test.code {
				t.Fatalf("result=%+v", result)
			}
		})
	}
	t.Run("process start failure", func(t *testing.T) {
		h := execHandler(t)
		provisioned := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"start-fails","spec":{"command":"/nonexistent/steward-no-such-binary"}}`)
		if provisioned.Code != http.StatusCreated {
			t.Fatalf("provision status=%d body=%s", provisioned.Code, provisioned.Body.String())
		}
		ref := decodeInstance(t, provisioned).RuntimeRef
		body := `{"operations":[{"op":"start","runtime_ref":"` + ref + `"}]}`
		result := decodeBatch(t, do(h, http.MethodPost, "/v1/instances/batch", body)).Results[0]
		if result.Status != http.StatusBadRequest || result.Error == nil || result.Error.Error != codeProcessStartFailed {
			t.Fatalf("result=%+v", result)
		}
	})
}

// TestBatchOversizedBodyReturns413 mirrors TestOversizedBodyRejected for the
// batch endpoint: the same 1 MiB MaxBytesReader bound applies.
func TestBatchOversizedBodyReturns413(t *testing.T) {
	h := newTestHandler(0)
	huge := strings.Repeat("A", 2<<20)
	body := `{"operations":[{"op":"provision","instance_id":"big","spec":{"blob":"` + huge + `"}}]}`
	assertJSONError(t, do(h, http.MethodPost, "/v1/instances/batch", body), http.StatusRequestEntityTooLarge)
}

// TestBatchCapacityExceededReturns503PerOperation pins that a capacity-full
// tracker reports 503 on the individual provision op that overflows it,
// leaving earlier/later successful operations unaffected.
func TestBatchCapacityExceededReturns503PerOperation(t *testing.T) {
	h := newTestHandler(1)
	body := `{"operations":[
		{"op":"provision","instance_id":"a"},
		{"op":"provision","instance_id":"b"}
	]}`
	rec := do(h, http.MethodPost, "/v1/instances/batch", body)
	got := decodeBatch(t, rec)
	if got.Results[0].Status != http.StatusCreated {
		t.Fatalf("result 0 = %+v, want 201", got.Results[0])
	}
	if got.Results[1].Status != http.StatusServiceUnavailable || got.Results[1].Error == nil || got.Results[1].Error.Error != "capacity_exceeded" {
		t.Fatalf("result 1 = %+v, want 503 capacity_exceeded", got.Results[1])
	}
}

// TestBatchWrongMethodReturnsJSON405 pins that a method registered nowhere on
// this path (batch is POST-only) is rejected with a JSON 405.
//
// This deliberately uses PUT, not GET/DELETE: those two methods ARE
// registered on the sibling wildcard route GET/DELETE /v1/instances/{id}, so
// (by plain net/http.ServeMux path-matching — the mux resolves per method
// across all registered patterns, and "batch" is, syntactically, a valid
// {id} value) a GET or DELETE to this exact literal path resolves to that
// route instead, addressing an instance literally named "batch" and getting
// a 404 unknown_runtime_ref — not a 405. That is expected, not a routing
// bug: a real runtime_ref is always "rt_"+32 hex chars, so no live instance
// can ever collide with the literal path segment "batch", and only POST is
// documented for this endpoint in openapi/steward.v1.yaml.
func TestBatchWrongMethodReturnsJSON405(t *testing.T) {
	h := newTestHandler(0)
	assertJSONError(t, do(h, http.MethodPut, "/v1/instances/batch", ""), http.StatusMethodNotAllowed)
}
