// Package server wires Steward's lifecycle operations to REST endpoints.
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/hardrails/steward/internal/runtime"
)

// maxRequestBodyBytes caps every request body. spec is meant to be small opaque
// config, not a blob store, so 1 MiB is generous; anything larger is rejected
// with 413 before it is buffered into memory.
const maxRequestBodyBytes = 1 << 20

// Version is the Steward build/version string advertised by GET /v1/capabilities.
// It lives here (not in cmd/steward) because the capabilities handler needs it
// and the command package cannot be imported by this internal package. It is a
// plain hardcoded string on purpose: Steward has no build-info system today, and
// adding one is not warranted for a single advertised field.
const Version = "0.1.0"

type Server struct {
	tracker *runtime.Tracker
	logger  *slog.Logger
}

// New builds a Server whose tracker holds at most maxInstances instances in
// memory only (no persistence). A non-positive maxInstances falls back to
// runtime.DefaultMaxInstances. For durable state, build a tracker with
// runtime.LoadTracker and pass it to NewWithTracker.
func New(logger *slog.Logger, maxInstances int) *Server {
	return NewWithTracker(logger, runtime.NewTracker(maxInstances))
}

// NewWithTracker builds a Server around a caller-provided tracker. It lets the
// caller inject a tracker bound to a state file (see runtime.LoadTracker) so the
// same wiring serves both the in-memory default and the opt-in durable-state
// mode.
func NewWithTracker(logger *slog.Logger, tracker *runtime.Tracker) *Server {
	return &Server{
		tracker: tracker,
		logger:  logger,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/instances", s.handleProvision)
	mux.HandleFunc("GET /v1/instances/{id}", s.handleStatus)
	mux.HandleFunc("DELETE /v1/instances/{id}", s.handleDestroy)
	mux.HandleFunc("POST /v1/instances/{id}/start", s.handleStart)
	mux.HandleFunc("POST /v1/instances/{id}/stop", s.handleStop)
	mux.HandleFunc("POST /v1/instances/{id}/hibernate", s.handleHibernate)
	mux.HandleFunc("GET /v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /v1/healthz", s.handleHealthz)
	// Order (outermost first): recover so a panic still yields a clean JSON 500;
	// logging so every response is recorded; jsonErrors so the mux's stdlib
	// plain-text 404/405 become our JSON error shape.
	return s.recoverMiddleware(s.withLogging(s.jsonErrors(mux)))
}

type provisionRequest struct {
	InstanceID string          `json:"instance_id"`
	Spec       json.RawMessage `json:"spec"`
}

// capabilitiesResponse advertises what this Steward can do plus a small slice of
// operational state useful to a control-plane dashboard. The change from the v1
// static {"skills": []} is strictly additive: skills keeps its shape and
// meaning, and the new fields are appended, so a consumer that only reads skills
// (or ignores unknown fields) is unaffected.
type capabilitiesResponse struct {
	Skills []any `json:"skills"`
	// Version is the Steward build/version string.
	Version string `json:"version"`
	// InstanceCount is the number of instances currently tracked.
	InstanceCount int `json:"instance_count"`
	// MaxInstances is the configured capacity cap (Provision returns 503 beyond it).
	MaxInstances int `json:"max_instances"`
	// DurableState reports whether durable state is enabled. It is a bool, never
	// the configured file path, so this response never leaks a local filesystem
	// path.
	DurableState bool `json:"durable_state"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req provisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				"request body exceeds the 1MiB limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	if req.InstanceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "instance_id is required")
		return
	}

	// An explicit null spec is treated as no spec; any other present value must
	// be a JSON object, matching the documented ProvisionRequest.spec schema.
	spec := req.Spec
	if bytes.Equal(bytes.TrimSpace(spec), []byte("null")) {
		spec = nil
	}
	if len(spec) > 0 && !isJSONObject(spec) {
		writeError(w, http.StatusBadRequest, "invalid_request", "spec must be a JSON object")
		return
	}

	inst, created, err := s.tracker.Provision(req.InstanceID, spec)
	if err != nil {
		if errors.Is(err, runtime.ErrCapacityExceeded) {
			writeError(w, http.StatusServiceUnavailable, "capacity_exceeded",
				"instance capacity reached; retry later")
			return
		}
		s.logger.Error("provision failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "operation failed")
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, inst)
}

// isJSONObject reports whether raw (already-validated JSON) is a JSON object. The
// decoder guarantees raw is well-formed JSON, so inspecting the first
// non-whitespace byte is sufficient.
func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	inst, err := s.tracker.Status(r.PathValue("id"))
	s.respond(w, inst, err)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	inst, err := s.tracker.Start(r.PathValue("id"))
	s.respond(w, inst, err)
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	inst, err := s.tracker.Stop(r.PathValue("id"))
	s.respond(w, inst, err)
}

func (s *Server) handleHibernate(w http.ResponseWriter, r *http.Request) {
	inst, err := s.tracker.Hibernate(r.PathValue("id"))
	s.respond(w, inst, err)
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	inst, err := s.tracker.Destroy(r.PathValue("id"))
	s.respond(w, inst, err)
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, capabilitiesResponse{
		Skills:        []any{},
		Version:       Version,
		InstanceCount: s.tracker.Len(),
		MaxInstances:  s.tracker.MaxInstances(),
		DurableState:  s.tracker.Durable(),
	})
}

// handleHealthz is a liveness probe: a 200 with {"status":"ok"} proves the
// process is up and the HTTP server is serving. It deliberately does NOT probe
// the durable-state file, even when -state-file is configured, for three reasons:
//   - health is a hot, frequently-polled path, and per-poll disk I/O is wasted work;
//   - an active write-probe would churn temp files and could race the
//     atomic-rename persistence discipline in internal/runtime;
//   - durable state is already fail-closed elsewhere — LoadTracker refuses to
//     start on an unreadable or corrupt file, and every mutation rolls back and
//     returns an error if its persist write fails — so a broken state file
//     surfaces as a startup failure or a 5xx on the actual write, never as a
//     healthy liveness probe masking a doomed node. Adding a filesystem probe
//     here would duplicate that guarantee at a cost, not add a new one.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func (s *Server) respond(w http.ResponseWriter, inst *runtime.Instance, err error) {
	if err != nil {
		if errors.Is(err, runtime.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown_runtime_ref", "no instance with that runtime_ref")
			return
		}
		s.logger.Error("lifecycle operation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "operation failed")
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// recoverMiddleware turns a handler panic into a clean JSON 500 instead of a
// dropped connection.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered", "err", rec, "method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", "operation failed")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// jsonErrors rewrites the ServeMux's built-in plain-text 404/405 responses into
// the same JSON error shape every handler uses, so every error status the
// service returns is consistent.
func (s *Server) jsonErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&jsonErrorWriter{ResponseWriter: w}, r)
	})
}

// jsonErrorWriter intercepts a 404/405 written by the stdlib mux (which sets a
// text/plain Content-Type) and replaces it with JSON. A handler-written error
// sets Content-Type application/json first, so it is left untouched.
type jsonErrorWriter struct {
	http.ResponseWriter
	swallow bool
}

func (w *jsonErrorWriter) WriteHeader(code int) {
	if (code == http.StatusNotFound || code == http.StatusMethodNotAllowed) &&
		w.Header().Get("Content-Type") != "application/json" {
		w.swallow = true
		body := errorResponse{Error: "not_found", Message: "no route matches that path"}
		if code == http.StatusMethodNotAllowed {
			body = errorResponse{Error: "method_not_allowed", Message: "that method is not allowed on this path"}
		}
		w.Header().Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(code)
		_ = json.NewEncoder(w.ResponseWriter).Encode(body)
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *jsonErrorWriter) Write(b []byte) (int, error) {
	if w.swallow {
		// Discard the stdlib error handler's plain-text body; JSON already sent.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}
