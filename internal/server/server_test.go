package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/runtime"
)

func newTestHandler(maxInstances int) http.Handler {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), maxInstances).Handler()
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeInstance(t *testing.T, rec *httptest.ResponseRecorder) runtime.Instance {
	t.Helper()
	var inst runtime.Instance
	if err := json.Unmarshal(rec.Body.Bytes(), &inst); err != nil {
		t.Fatalf("decode instance: %v (body=%s)", err, rec.Body.String())
	}
	return inst
}

// provisionID provisions an instance and returns its runtime_ref.
func provisionID(t *testing.T, h http.Handler, id, spec string) string {
	t.Helper()
	body := `{"instance_id":"` + id + `"`
	if spec != "" {
		body += `,"spec":` + spec
	}
	body += `}`
	rec := do(h, http.MethodPost, "/v1/instances", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision %q: status=%d want 201 (body=%s)", id, rec.Code, rec.Body.String())
	}
	return decodeInstance(t, rec).RuntimeRef
}

func decodeCapabilities(t *testing.T, rec *httptest.ResponseRecorder) capabilitiesResponse {
	t.Helper()
	var got capabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode capabilities: %v (body=%s)", err, rec.Body.String())
	}
	return got
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, wantStatus, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json (body=%s)", ct, rec.Body.String())
	}
	var er errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil {
		t.Fatalf("error body not JSON: %v (body=%s)", err, rec.Body.String())
	}
	if er.Error == "" || er.Message == "" {
		t.Fatalf("error body missing fields: %+v", er)
	}
}

func TestProvisionHappyPathAndSpecRoundTrip(t *testing.T) {
	h := newTestHandler(0)
	const spec = `{"model":"opus","memory_mb":512}`

	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"agent-1","spec":`+spec+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision: status=%d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	inst := decodeInstance(t, rec)
	if inst.InstanceID != "agent-1" || inst.RuntimeRef == "" || inst.Status != runtime.StatusPending {
		t.Fatalf("unexpected instance %+v", inst)
	}
	if string(inst.Spec) != spec {
		t.Fatalf("spec = %s, want verbatim %s", inst.Spec, spec)
	}

	// Status round-trip: GET returns the same spec unchanged.
	get := do(h, http.MethodGet, "/v1/instances/"+inst.RuntimeRef, "")
	if get.Code != http.StatusOK {
		t.Fatalf("status get: %d want 200 (body=%s)", get.Code, get.Body.String())
	}
	if got := decodeInstance(t, get); string(got.Spec) != spec {
		t.Fatalf("round-trip spec = %s, want %s", got.Spec, spec)
	}
}

func TestLifecycleEndpoints(t *testing.T) {
	h := newTestHandler(0)
	ref := provisionID(t, h, "agent-1", `{"k":"v"}`)

	cases := []struct {
		route string
		want  runtime.Status
	}{
		{"/start", runtime.StatusRunning},
		{"/stop", runtime.StatusStopped},
		{"/hibernate", runtime.StatusHibernated},
	}
	for _, c := range cases {
		rec := do(h, http.MethodPost, "/v1/instances/"+ref+c.route, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status=%d want 200 (body=%s)", c.route, rec.Code, rec.Body.String())
		}
		if got := decodeInstance(t, rec).Status; got != c.want {
			t.Fatalf("%s: status=%q want %q", c.route, got, c.want)
		}
	}

	del := do(h, http.MethodDelete, "/v1/instances/"+ref, "")
	if del.Code != http.StatusOK || decodeInstance(t, del).Status != runtime.StatusDestroyed {
		t.Fatalf("destroy: status=%d body=%s", del.Code, del.Body.String())
	}
	// After destroy the ref is gone.
	assertJSONError(t, do(h, http.MethodGet, "/v1/instances/"+ref, ""), http.StatusNotFound)
}

func TestCapabilities(t *testing.T) {
	h := newTestHandler(7)
	rec := do(h, http.MethodGet, "/v1/capabilities", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("capabilities: status=%d want 200", rec.Code)
	}
	got := decodeCapabilities(t, rec)
	if len(got.Skills) != 0 {
		t.Fatalf("skills = %v, want empty", got.Skills)
	}
	if got.Version == "" {
		t.Fatal("version is empty; capabilities must advertise a build/version string")
	}
	if got.MaxInstances != 7 {
		t.Fatalf("max_instances = %d, want 7 (the configured cap)", got.MaxInstances)
	}
	if got.DurableState {
		t.Fatal("durable_state = true, want false for an in-memory tracker")
	}
	if got.InstanceCount != 0 {
		t.Fatalf("instance_count = %d, want 0 before any provision", got.InstanceCount)
	}

	// instance_count reflects live provisions.
	provisionID(t, h, "agent-1", "")
	if c := decodeCapabilities(t, do(h, http.MethodGet, "/v1/capabilities", "")).InstanceCount; c != 1 {
		t.Fatalf("instance_count = %d after one provision, want 1", c)
	}
}

func TestHealthz(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodGet, "/v1/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json (body=%s)", ct, rec.Body.String())
	}
	var got healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode health: %v (body=%s)", err, rec.Body.String())
	}
	if got.Status != "ok" {
		t.Fatalf("status = %q, want ok", got.Status)
	}
}

func TestIdempotentProvisionReturns200(t *testing.T) {
	h := newTestHandler(0)

	first := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"agent-1","spec":{"a":1}}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first provision: status=%d want 201", first.Code)
	}
	second := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"agent-1","spec":{"b":2}}`)
	if second.Code != http.StatusOK {
		t.Fatalf("repeat provision: status=%d want 200 (body=%s)", second.Code, second.Body.String())
	}
	if decodeInstance(t, first).RuntimeRef != decodeInstance(t, second).RuntimeRef {
		t.Fatal("runtime_ref changed on idempotent re-provision")
	}
	// The second spec is ignored; original is retained.
	if string(decodeInstance(t, second).Spec) != `{"a":1}` {
		t.Fatalf("spec = %s, want original {\"a\":1}", decodeInstance(t, second).Spec)
	}
}

func TestProvisionSpecNullTreatedAsAbsent(t *testing.T) {
	h := newTestHandler(0)
	rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"agent-1","spec":null}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision spec:null: status=%d want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if inst := decodeInstance(t, rec); len(inst.Spec) != 0 {
		t.Fatalf("spec = %s, want omitted", inst.Spec)
	}
}

func TestBadRequests(t *testing.T) {
	h := newTestHandler(0)
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{"instance_id":`},
		{"not an object", `[1,2,3]`},
		{"missing instance_id", `{"spec":{"k":"v"}}`},
		{"empty instance_id", `{"instance_id":""}`},
		{"spec is array", `{"instance_id":"x","spec":[1,2,3]}`},
		{"spec is string", `{"instance_id":"x","spec":"nope"}`},
		{"spec is number", `{"instance_id":"x","spec":42}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertJSONError(t, do(h, http.MethodPost, "/v1/instances", c.body), http.StatusBadRequest)
		})
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	h := newTestHandler(0)
	// A spec well past the 1 MiB cap; the body must be rejected before it is
	// buffered whole, yielding a clean 413 rather than a 201 or 500.
	huge := strings.Repeat("A", (2 << 20))
	body := `{"instance_id":"big","spec":{"blob":"` + huge + `"}}`
	assertJSONError(t, do(h, http.MethodPost, "/v1/instances", body), http.StatusRequestEntityTooLarge)
}

func TestUnknownRuntimeRefReturns404(t *testing.T) {
	h := newTestHandler(0)
	const unknown = "rt_missing"
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/instances/" + unknown},
		{http.MethodDelete, "/v1/instances/" + unknown},
		{http.MethodPost, "/v1/instances/" + unknown + "/start"},
		{http.MethodPost, "/v1/instances/" + unknown + "/stop"},
		{http.MethodPost, "/v1/instances/" + unknown + "/hibernate"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			assertJSONError(t, do(h, c.method, c.path, ""), http.StatusNotFound)
		})
	}
}

func TestUnknownPathReturnsJSON404(t *testing.T) {
	h := newTestHandler(0)
	assertJSONError(t, do(h, http.MethodGet, "/v1/nope", ""), http.StatusNotFound)
	assertJSONError(t, do(h, http.MethodGet, "/", ""), http.StatusNotFound)
}

func TestWrongMethodReturnsJSON405(t *testing.T) {
	h := newTestHandler(0)
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/instances"},       // provision is POST-only
		{http.MethodPut, "/v1/instances"},       // unsupported verb
		{http.MethodDelete, "/v1/capabilities"}, // capabilities is GET-only
		{http.MethodPost, "/v1/healthz"},        // healthz is GET-only
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			assertJSONError(t, do(h, c.method, c.path, ""), http.StatusMethodNotAllowed)
		})
	}
}

func TestCapacityExceededReturns503(t *testing.T) {
	h := newTestHandler(1)
	if rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"a"}`); rec.Code != http.StatusCreated {
		t.Fatalf("first provision: status=%d want 201", rec.Code)
	}
	assertJSONError(t, do(h, http.MethodPost, "/v1/instances", `{"instance_id":"b"}`), http.StatusServiceUnavailable)

	// Re-provisioning the existing instance at capacity still succeeds (200).
	if rec := do(h, http.MethodPost, "/v1/instances", `{"instance_id":"a"}`); rec.Code != http.StatusOK {
		t.Fatalf("reprovision at capacity: status=%d want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestRecoverMiddlewareReturnsJSON500(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
	h := s.recoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	assertJSONError(t, rec, http.StatusInternalServerError)
}
