package executor

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

const maxBodyBytes = 1 << 20

// Server is the authenticated control boundary in front of the local Docker API.
// The bearer token is a host-control credential; tenant authorization belongs in the
// upstream control plane and must never be inferred from a caller-supplied label.
type Server struct {
	docker    Docker
	tokenHash [sha256.Size]byte
	policy    HostPolicy
	logger    *slog.Logger

	// provisionMu makes the count-then-create admission check atomic within the
	// one Docker-socket-bearing executor process. Docker inventory makes the
	// counts restart-safe; this lock prevents concurrent HTTP calls from racing
	// past the same ceiling.
	provisionMu sync.Mutex
}

func NewServer(docker Docker, token string, logger *slog.Logger) (*Server, error) {
	return NewServerWithPolicy(docker, token, DefaultHostPolicy(), logger)
}

func NewServerWithPolicy(
	docker Docker, token string, policy HostPolicy, logger *slog.Logger,
) (*Server, error) {
	if docker == nil {
		return nil, errors.New("docker client is required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("executor token is required")
	}
	if len(token) > 4096 {
		return nil, errors.New("executor token must not exceed 4096 bytes")
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid host policy: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		docker: docker, tokenHash: sha256.Sum256([]byte("Bearer " + token)),
		policy: policy, logger: logger,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/workloads", s.provision)
	mux.HandleFunc("POST /v1/workloads/{id}/start", s.start)
	mux.HandleFunc("POST /v1/workloads/{id}/stop", s.stop)
	mux.HandleFunc("DELETE /v1/workloads/{id}", s.destroy)
	mux.HandleFunc("GET /v1/workloads/{id}", s.status)
	mux.HandleFunc("GET /v1/workloads/{id}/logs", s.logs)
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return recoverMiddleware(jsonErrors(s.auth(mux), s.logger), s.logger)
}

type jsonErrorWriter struct {
	http.ResponseWriter
	replaced bool
}

func (w *jsonErrorWriter) WriteHeader(status int) {
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
		w.replaced = true
		code := "not_found"
		message := "resource not found"
		if status == http.StatusMethodNotAllowed {
			code, message = "method_not_allowed", "method not allowed"
		}
		writeError(w.ResponseWriter, status, code, message)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *jsonErrorWriter) Write(p []byte) (int, error) {
	if w.replaced {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

func jsonErrors(next http.Handler, _ *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&jsonErrorWriter{ResponseWriter: w}, r)
	})
}

func recoverMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("executor request panic", "method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		presented := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(presented[:], s.tokenHash[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "valid executor bearer credential required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) provision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var workload Workload
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&workload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain exactly one JSON object")
		return
	}
	if err := workload.Validate(); err != nil {
		var policy *PolicyError
		if errors.As(err, &policy) {
			writeError(w, http.StatusBadRequest, "policy_rejected", policy.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	if err := s.policy.ValidateWorkload(workload); err != nil {
		writeError(w, http.StatusBadRequest, "policy_rejected", err.Error())
		return
	}
	name := RuntimeRef(workload.TenantID, workload.InstanceID)
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	observed, err := s.docker.Inspect(r.Context(), name)
	if err == nil {
		if !observed.Managed || !observed.Hardened ||
			observed.Fingerprint != workloadFingerprint(workload) {
			writeError(w, http.StatusConflict, "workload_conflict", "runtime_ref already belongs to a different workload definition")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
		return
	}
	if !errors.Is(err, ErrNotFound) {
		writeDockerError(w, err)
		return
	}
	total, tenant, err := s.docker.WorkloadCounts(r.Context(), workload.TenantID)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if total >= s.policy.MaxWorkloads {
		writeCapacityError(w, "host workload capacity is exhausted")
		return
	}
	if tenant >= s.policy.MaxWorkloadsPerTenant {
		writeCapacityError(w, "tenant workload capacity is exhausted")
		return
	}
	if err := s.docker.Create(r.Context(), name, workload); err != nil {
		writeDockerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"runtime_ref": name, "status": "created"})
}

func writeCapacityError(w http.ResponseWriter, message string) {
	writeError(w, http.StatusServiceUnavailable, "capacity_exceeded", message)
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) { s.transition(w, r, "start") }
func (s *Server) stop(w http.ResponseWriter, r *http.Request)  { s.transition(w, r, "stop") }
func (s *Server) transition(w http.ResponseWriter, r *http.Request, action string) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	status := observed.Status
	if (action == "start" && status == "running") || (action == "stop" && status != "running") {
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": status})
		return
	}
	if action == "start" {
		err = s.docker.Start(r.Context(), name)
	} else {
		err = s.docker.Stop(r.Context(), name)
	}
	if err != nil {
		writeDockerError(w, err)
		return
	}
	observed, err = s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
}
func (s *Server) destroy(w http.ResponseWriter, r *http.Request) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	if _, err := s.managed(r.Context(), name); errors.Is(err, ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	} else if err != nil {
		writeDockerError(w, err)
		return
	}
	if err := s.docker.Remove(r.Context(), name); err != nil && !errors.Is(err, ErrNotFound) {
		writeDockerError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	if _, err := s.managed(r.Context(), name); err != nil {
		writeDockerError(w, err)
		return
	}
	logs, err := s.docker.Logs(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "logs": logs})
}

func (s *Server) managed(ctx context.Context, name string) (ObservedWorkload, error) {
	observed, err := s.docker.Inspect(ctx, name)
	if err != nil {
		return ObservedWorkload{}, err
	}
	if !observed.Managed {
		return ObservedWorkload{}, ErrNotFound
	}
	if !observed.Hardened {
		return ObservedWorkload{}, ErrWorkloadDrift
	}
	return observed, nil
}

// RuntimeRef deterministically maps one tenant-scoped instance to the only Docker
// name the executor may operate. It is exported within the internal tree so the
// outbound uplink dispatcher can drive the exact same lifecycle boundary.
func RuntimeRef(tenantID, instanceID string) string {
	// The runtime ref must be unique across a shared host. Do not derive it from
	// instance_id alone: distinct tenants may legitimately use the same id.
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID))
	return "executor-" + hex.EncodeToString(sum[:])
}

func runtimeRef(value string) (string, bool) {
	// Lifecycle calls accept only an opaque executor-issued ref. Refusing arbitrary
	// Docker names keeps the host socket from becoming a general container control API.
	if strings.HasPrefix(value, "executor-") && len(value) == len("executor-")+64 {
		if _, err := hex.DecodeString(strings.TrimPrefix(value, "executor-")); err == nil {
			return value, true
		}
	}
	return "", false
}
func writeDockerError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown_runtime_ref", "unknown workload")
		return
	}
	if errors.Is(err, ErrWorkloadDrift) {
		writeError(w, http.StatusConflict, "workload_drift", err.Error())
		return
	}
	writeError(w, http.StatusBadGateway, "docker_error", fmt.Sprintf("Docker operation failed: %v", err))
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
