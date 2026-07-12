package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const maxProxyBody = 4 << 20
const maxProxyResponse = 32 << 20

type Grant struct {
	GrantID        string   `json:"grant_id"`
	TenantID       string   `json:"tenant_id"`
	InstanceID     string   `json:"instance_id"`
	Generation     uint64   `json:"generation"`
	RouteID        string   `json:"route_id,omitempty"`
	ModelAlias     string   `json:"model_alias,omitempty"`
	Service        bool     `json:"service"`
	ServiceURL     string   `json:"service_url,omitempty"`
	EgressRouteIDs []string `json:"egress_route_ids,omitempty"`
	Active         bool     `json:"active"`
}

type grantResponse struct {
	GrantID         string `json:"grant_id"`
	InferenceSocket string `json:"inference_socket,omitempty"`
	ServicePath     string `json:"service_path,omitempty"`
	EgressSocket    string `json:"egress_socket,omitempty"`
	Active          bool   `json:"active"`
}

type snapshot struct {
	Version int     `json:"version"`
	Grants  []Grant `json:"grants"`
}

type egressLease struct {
	context context.Context
	cancel  context.CancelFunc
}

type Server struct {
	mu               sync.Mutex
	config           Config
	routes           map[string]loadedRoute
	egressRoutes     map[string]loadedEgressRoute
	semaphores       map[string]chan struct{}
	egressSemaphores map[string]chan struct{}
	grants           map[string]Grant
	listeners        map[string]net.Listener
	egressListeners  map[string]net.Listener
	egressStats      map[string]EgressStats
	egressLeases     map[string]egressLease
	audit            *auditLog
	tokenHash        [sha256.Size]byte
	client           *http.Client
}

func Open(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, serviceToken string) (*Server, error) {
	if serviceToken == "" {
		return nil, errors.New("gateway service token is required")
	}
	audit, err := openAuditLog(config.EgressAuditFile, config.EgressAuditFile != "")
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
	}
	server := &Server{
		config: config, routes: routes, egressRoutes: egressRoutes, semaphores: make(map[string]chan struct{}, len(routes)),
		egressSemaphores: make(map[string]chan struct{}, len(egressRoutes)),
		grants:           make(map[string]Grant), listeners: make(map[string]net.Listener), egressListeners: make(map[string]net.Listener),
		egressStats: make(map[string]EgressStats), egressLeases: make(map[string]egressLease), audit: audit,
		tokenHash: sha256.Sum256([]byte("Bearer " + serviceToken)),
		client: &http.Client{Transport: transport, Timeout: 2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	for id, route := range routes {
		server.semaphores[id] = make(chan struct{}, route.MaxConcurrent)
	}
	for id, route := range egressRoutes {
		server.egressSemaphores[id] = make(chan struct{}, route.MaxConcurrent)
	}
	if err := server.load(); err != nil {
		_ = audit.Close()
		return nil, err
	}
	return server, nil
}

// Reload atomically replaces operator-owned route policy and the service token.
// Socket, identity, state, and audit paths are immutable for the process lifetime.
// Existing grants fence route removal so a successful reload cannot orphan an
// admitted workload. Narrowing or widening destinations within an existing route
// ID is an explicit host-operator policy change and takes effect on the next request.
func (s *Server) Reload(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, serviceToken string) error {
	if serviceToken == "" || !sameRuntimeConfig(s.config, config) {
		return errors.New("gateway reload may change only routes and service token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, grant := range s.grants {
		if grant.RouteID != "" {
			if _, ok := routes[grant.RouteID]; !ok {
				return fmt.Errorf("reload removes inference route %q used by grant %s", grant.RouteID, grant.GrantID)
			}
		}
		for _, id := range grant.EgressRouteIDs {
			if _, ok := egressRoutes[id]; !ok {
				return fmt.Errorf("reload removes egress route %q used by grant %s", id, grant.GrantID)
			}
		}
	}
	semaphores := make(map[string]chan struct{}, len(routes))
	for id, route := range routes {
		current := s.semaphores[id]
		if current != nil && cap(current) == route.MaxConcurrent {
			semaphores[id] = current
			continue
		}
		if len(current) > 0 {
			return fmt.Errorf("reload changes concurrency for busy inference route %q", id)
		}
		semaphores[id] = make(chan struct{}, route.MaxConcurrent)
	}
	egressSemaphores := make(map[string]chan struct{}, len(egressRoutes))
	for id, route := range egressRoutes {
		current := s.egressSemaphores[id]
		if current != nil && cap(current) == route.MaxConcurrent {
			egressSemaphores[id] = current
			continue
		}
		if len(current) > 0 {
			return fmt.Errorf("reload changes concurrency for busy egress route %q", id)
		}
		egressSemaphores[id] = make(chan struct{}, route.MaxConcurrent)
	}
	s.config.Routes, s.config.EgressRoutes = config.Routes, config.EgressRoutes
	s.routes, s.egressRoutes = routes, egressRoutes
	s.semaphores, s.egressSemaphores = semaphores, egressSemaphores
	s.tokenHash = sha256.Sum256([]byte("Bearer " + serviceToken))
	return nil
}

func sameRuntimeConfig(left, right Config) bool {
	return left.Version == right.Version && left.ControlSocket == right.ControlSocket &&
		left.ServiceAddress == right.ServiceAddress && left.ServiceTokenFile == right.ServiceTokenFile &&
		left.StateFile == right.StateFile && left.GrantRoot == right.GrantRoot &&
		left.ExecutorGID == right.ExecutorGID && left.RelayGID == right.RelayGID &&
		left.EgressAuditFile == right.EgressAuditFile
}

func (s *Server) Start(ctx context.Context) error {
	defer s.audit.Close()
	defer s.closeGrantListeners()
	s.mu.Lock()
	for id, grant := range s.grants {
		if grant.RouteID != "" {
			if err := s.listenGrantLocked(id); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("restore inference grant %q: %w", id, err)
			}
		}
		if len(grant.EgressRouteIDs) > 0 {
			if err := s.listenEgressGrantLocked(id); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("restore egress grant %q: %w", id, err)
			}
		}
	}
	s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.config.ControlSocket), 0o750); err != nil {
		return err
	}
	_ = os.Remove(s.config.ControlSocket)
	controlListener, err := net.Listen("unix", s.config.ControlSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.config.ControlSocket, 0o660); err != nil {
		_ = controlListener.Close()
		return err
	}
	if err := os.Chown(s.config.ControlSocket, -1, s.config.ExecutorGID); err != nil {
		_ = controlListener.Close()
		return err
	}
	control := &http.Server{Handler: s.ControlHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	service := &http.Server{Addr: s.config.ServiceAddress, Handler: s.ServiceHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- control.Serve(controlListener) }()
	go func() { errorsCh <- service.ListenAndServe() }()
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errorsCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = control.Shutdown(shutdown)
	_ = service.Shutdown(shutdown)
	_ = os.Remove(s.config.ControlSocket)
	return runErr
}

func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/grants", s.register)
	mux.HandleFunc("POST /v1/grants/{id}/activate", s.activate)
	mux.HandleFunc("POST /v1/grants/{id}/deactivate", s.deactivate)
	mux.HandleFunc("GET /v1/grants/{id}", s.getGrant)
	mux.HandleFunc("GET /v1/grants/{id}/egress", s.getEgressStats)
	mux.HandleFunc("DELETE /v1/grants/{id}", s.unregister)
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func (s *Server) getGrant(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	grant, ok := s.grants[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeGatewayError(w, http.StatusNotFound, "grant_not_found", "gateway grant not found")
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (s *Server) ServiceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		s.mu.Lock()
		tokenHash := s.tokenHash
		s.mu.Unlock()
		if subtle.ConstantTimeCompare(presented[:], tokenHash[:]) != 1 {
			writeGatewayError(w, http.StatusUnauthorized, "unauthorized", "valid gateway bearer credential required")
			return
		}
		const prefix = "/v1/services/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			writeGatewayError(w, http.StatusNotFound, "not_found", "service grant not found")
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		separator := strings.IndexByte(rest, '/')
		grantID := rest
		path := "/"
		if separator >= 0 {
			grantID, path = rest[:separator], rest[separator:]
		}
		s.mu.Lock()
		grant, ok := s.grants[grantID]
		s.mu.Unlock()
		if !ok || !grant.Active || grant.ServiceURL == "" {
			writeGatewayError(w, http.StatusNotFound, "service_unavailable", "active service grant not found")
			return
		}
		s.proxyService(w, r, grant, path)
	})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "grant request exceeds limit")
		return
	}
	var grant Grant
	if err := dsse.DecodeStrictInto(raw, maxConfigBytes, &grant); err != nil || grant.Active {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "grant request is invalid")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validGrant(grant) {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "grant request is invalid")
		return
	}
	current, hadCurrent := s.grants[grant.GrantID]
	if hadCurrent {
		if grant.Generation < current.Generation {
			writeGatewayError(w, http.StatusConflict, "generation_rollback", "gateway grant generation rollback")
			return
		}
		grant.Active = false
		if grant.Generation == current.Generation && !grantsEqual(grant, current) && !validServiceEnrichment(current, grant) {
			writeGatewayError(w, http.StatusConflict, "grant_conflict", "equal generation identifies a different gateway grant")
			return
		}
	}
	grant.Active = false
	hadInferenceListener := s.listeners[grant.GrantID] != nil
	hadEgressListener := s.egressListeners[grant.GrantID] != nil
	rollback := func() {
		if hadCurrent {
			s.grants[grant.GrantID] = current
		} else {
			delete(s.grants, grant.GrantID)
		}
		if !hadInferenceListener && s.listeners[grant.GrantID] != nil {
			_ = s.listeners[grant.GrantID].Close()
			delete(s.listeners, grant.GrantID)
			_ = os.Remove(inferenceSocketPath(s.config.GrantRoot, grant.GrantID))
		}
		if !hadEgressListener && s.egressListeners[grant.GrantID] != nil {
			_ = s.egressListeners[grant.GrantID].Close()
			delete(s.egressListeners, grant.GrantID)
			_ = os.Remove(egressSocketPath(s.config.GrantRoot, grant.GrantID))
		}
		_ = s.persistLocked()
	}
	s.grants[grant.GrantID] = grant
	if err := s.persistLocked(); err != nil {
		rollback()
		writeGatewayError(w, http.StatusServiceUnavailable, "state_unavailable", err.Error())
		return
	}
	if grant.RouteID != "" {
		if err := s.listenGrantLocked(grant.GrantID); err != nil {
			rollback()
			writeGatewayError(w, http.StatusServiceUnavailable, "socket_unavailable", err.Error())
			return
		}
	}
	if len(grant.EgressRouteIDs) > 0 {
		if err := s.listenEgressGrantLocked(grant.GrantID); err != nil {
			rollback()
			writeGatewayError(w, http.StatusServiceUnavailable, "socket_unavailable", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusCreated, s.response(grant))
}

// validServiceEnrichment permits the Executor to reserve an inference socket,
// create and inspect the relay's loopback publication, then bind that exact
// observed address to the same inactive grant. No identity, route, model, or
// generation field can change in this operation.
func validServiceEnrichment(current, next Grant) bool {
	return !current.Active && !next.Active && current.ServiceURL == "" && next.ServiceURL != "" &&
		current.GrantID == next.GrantID && current.TenantID == next.TenantID &&
		current.InstanceID == next.InstanceID && current.Generation == next.Generation &&
		current.RouteID == next.RouteID && current.ModelAlias == next.ModelAlias && current.Service == next.Service &&
		slices.Equal(current.EgressRouteIDs, next.EgressRouteIDs)
}

func grantsEqual(left, right Grant) bool {
	return left.GrantID == right.GrantID && left.TenantID == right.TenantID &&
		left.InstanceID == right.InstanceID && left.Generation == right.Generation &&
		left.RouteID == right.RouteID && left.ModelAlias == right.ModelAlias &&
		left.Service == right.Service && left.ServiceURL == right.ServiceURL &&
		left.Active == right.Active && slices.Equal(left.EgressRouteIDs, right.EgressRouteIDs)
}

func GrantsEqual(left, right Grant) bool { return grantsEqual(left, right) }

func (s *Server) activate(w http.ResponseWriter, r *http.Request) {
	s.setActive(w, r.PathValue("id"), true)
}
func (s *Server) deactivate(w http.ResponseWriter, r *http.Request) {
	s.setActive(w, r.PathValue("id"), false)
}

func (s *Server) setActive(w http.ResponseWriter, id string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok {
		writeGatewayError(w, http.StatusNotFound, "grant_not_found", "gateway grant not found")
		return
	}
	current := grant
	grant.Active = active
	s.grants[id] = grant
	if err := s.persistLocked(); err != nil {
		s.grants[id] = current
		writeGatewayError(w, http.StatusServiceUnavailable, "state_unavailable", err.Error())
		return
	}
	if active && len(grant.EgressRouteIDs) > 0 {
		s.egressLeaseLocked(id)
	} else {
		s.revokeEgressLocked(id)
	}
	writeJSON(w, http.StatusOK, s.response(grant))
}

func (s *Server) unregister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	delete(s.grants, id)
	if err := s.persistLocked(); err != nil {
		s.grants[id] = grant
		writeGatewayError(w, http.StatusServiceUnavailable, "state_unavailable", err.Error())
		return
	}
	s.revokeEgressLocked(id)
	if listener := s.listeners[id]; listener != nil {
		_ = listener.Close()
		delete(s.listeners, id)
	}
	if listener := s.egressListeners[id]; listener != nil {
		_ = listener.Close()
		delete(s.egressListeners, id)
	}
	delete(s.egressStats, id)
	_ = os.RemoveAll(GrantDirectory(s.config.GrantRoot, id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validGrant(grant Grant) bool {
	if !validGrantID(grant.GrantID) || !bounded(grant.TenantID, 128) || !bounded(grant.InstanceID, 256) || grant.Generation == 0 ||
		(grant.RouteID == "" && !grant.Service && len(grant.EgressRouteIDs) == 0) || len(grant.ModelAlias) > 256 || (grant.ServiceURL != "" && !grant.Service) {
		return false
	}
	if grant.RouteID != "" {
		if _, ok := s.routes[grant.RouteID]; !ok || !bounded(grant.ModelAlias, 256) {
			return false
		}
	}
	if len(grant.EgressRouteIDs) > 32 {
		return false
	}
	for index, id := range grant.EgressRouteIDs {
		if !routeID(id) {
			return false
		}
		if _, ok := s.egressRoutes[id]; !ok {
			return false
		}
		if index > 0 && grant.EgressRouteIDs[index-1] >= id {
			return false
		}
	}
	if grant.ServiceURL != "" && !validLoopbackServiceURL(grant.ServiceURL) {
		return false
	}
	return true
}

func validGrantID(id string) bool {
	if !strings.HasPrefix(id, "grant-") || len(id) != len("grant-")+64 {
		return false
	}
	for _, char := range strings.TrimPrefix(id, "grant-") {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func validLoopbackServiceURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	address := net.ParseIP(parsed.Hostname())
	return address != nil && (address.IsLoopback() || address.IsPrivate()) && parsed.Port() != ""
}

func (s *Server) response(grant Grant) grantResponse {
	result := grantResponse{GrantID: grant.GrantID, Active: grant.Active}
	if grant.RouteID != "" {
		result.InferenceSocket = inferenceSocketPath(s.config.GrantRoot, grant.GrantID)
	}
	if grant.Service {
		result.ServicePath = "/v1/services/" + grant.GrantID + "/"
	}
	if len(grant.EgressRouteIDs) > 0 {
		result.EgressSocket = egressSocketPath(s.config.GrantRoot, grant.GrantID)
	}
	return result
}

func (s *Server) listenGrantLocked(id string) error {
	if listener := s.listeners[id]; listener != nil {
		return nil
	}
	directory := GrantDirectory(s.config.GrantRoot, id)
	path := inferenceSocketPath(s.config.GrantRoot, id)
	listener, err := openGrantListener(directory, path, s.config.RelayGID)
	if err != nil {
		return err
	}
	s.listeners[id] = listener
	server := &http.Server{Handler: s.inferenceHandler(id), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (s *Server) inferenceHandler(id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		grant, ok := s.grants[id]
		route := s.routes[grant.RouteID]
		semaphore := s.semaphores[grant.RouteID]
		if !ok || !grant.Active || grant.RouteID == "" {
			s.mu.Unlock()
			writeGatewayError(w, http.StatusServiceUnavailable, "grant_inactive", "inference grant is not active")
			return
		}
		select {
		case semaphore <- struct{}{}:
			s.mu.Unlock()
			defer func() { <-semaphore }()
		default:
			s.mu.Unlock()
			writeGatewayError(w, http.StatusTooManyRequests, "route_busy", "inference route concurrency limit reached")
			return
		}
		s.proxyInference(w, r, route)
	})
}

var inferencePaths = map[string]string{
	"/v1/chat/completions": http.MethodPost,
	"/v1/completions":      http.MethodPost,
	"/v1/embeddings":       http.MethodPost,
	"/v1/responses":        http.MethodPost,
	"/v1/models":           http.MethodGet,
}

func (s *Server) proxyInference(w http.ResponseWriter, incoming *http.Request, route loadedRoute) {
	if inferencePaths[incoming.URL.Path] != incoming.Method || incoming.URL.RawQuery != "" {
		writeGatewayError(w, http.StatusForbidden, "route_denied", "inference method or path is not allowed")
		return
	}
	s.proxy(w, incoming, route.base, incoming.URL.Path, route.credential, false)
}

func (s *Server) proxyService(w http.ResponseWriter, incoming *http.Request, grant Grant, path string) {
	if incoming.Method == http.MethodConnect || !safeServicePath(path) {
		writeGatewayError(w, http.StatusForbidden, "service_denied", "service method or path is not allowed")
		return
	}
	base, _ := url.Parse(grant.ServiceURL)
	s.proxy(w, incoming, base, path, "", true)
}

// safeServicePath rejects both direct and nested-encoded traversal syntax.
// net/http has already decoded one layer into URL.Path, so a remaining percent
// sign is a second decoding opportunity for an agent framework or its router.
// Literal percent characters are deliberately outside the v1 service contract.
func safeServicePath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "%\\\x00") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (s *Server) proxy(w http.ResponseWriter, incoming *http.Request, base *url.URL, path, credential string, service bool) {
	incoming.Body = http.MaxBytesReader(w, incoming.Body, maxProxyBody)
	target := *base
	if base.Path == "/v1" || base.Path == "/v1/" {
		target.Path = path
	} else {
		target.Path = path
	}
	target.RawQuery = incoming.URL.RawQuery
	request, err := http.NewRequestWithContext(incoming.Context(), incoming.Method, target.String(), incoming.Body)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "cannot construct upstream request")
		return
	}
	copyHeaders(request.Header, incoming.Header)
	request.Header.Del("Authorization")
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Cookie")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := s.client.Do(request)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured upstream request failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeGatewayError(w, http.StatusBadGateway, "redirect_denied", "configured upstream returned a redirect")
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Set-Cookie")
	w.Header().Del("Location")
	if service {
		w.Header().Set("X-Steward-Service-Grant", "active")
	}
	w.WriteHeader(response.StatusCode)
	limited := io.LimitReader(response.Body, maxProxyResponse+1)
	written, copyErr := io.Copy(w, limited)
	if copyErr != nil || written > maxProxyResponse {
		return
	}
}

func copyHeaders(destination, source http.Header) {
	connectionHeaders := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = http.CanonicalHeaderKey(strings.TrimSpace(token)); token != "" {
				connectionHeaders[token] = struct{}{}
			}
		}
	}
	for key, values := range source {
		if hopHeader(key) {
			continue
		}
		if _, connected := connectionHeaders[http.CanonicalHeaderKey(key)]; connected {
			continue
		}
		for _, value := range values {
			if len(value) <= 8192 {
				destination.Add(key, value)
			}
		}
	}
}

func hopHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func (s *Server) load() error {
	if err := os.MkdirAll(filepath.Dir(s.config.StateFile), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(s.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return s.persistLocked()
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConfigBytes {
		return errors.New("gateway state must be a bounded owner-only regular file")
	}
	raw, err := os.ReadFile(s.config.StateFile)
	if err != nil {
		return err
	}
	var state snapshot
	if err := dsse.DecodeStrictInto(raw, maxConfigBytes, &state); err != nil || state.Version != 1 || len(state.Grants) > 4096 {
		return errors.New("gateway state is invalid")
	}
	for _, grant := range state.Grants {
		grant.Active = false
		if !s.validGrant(grant) {
			return errors.New("gateway state contains an invalid grant")
		}
		if _, exists := s.grants[grant.GrantID]; exists {
			return errors.New("gateway state contains a duplicate grant")
		}
		s.grants[grant.GrantID] = grant
	}
	return nil
}

func (s *Server) persistLocked() error {
	grants := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, grant)
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].GrantID < grants[j].GrantID })
	raw, err := json.Marshal(snapshot{Version: 1, Grants: grants})
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.config.StateFile)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gateway-state-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.config.StateFile); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (s *Server) closeGrantListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.egressLeases {
		s.revokeEgressLocked(id)
	}
	for id, listener := range s.listeners {
		_ = listener.Close()
		delete(s.listeners, id)
	}
	for id, listener := range s.egressListeners {
		_ = listener.Close()
		delete(s.egressListeners, id)
	}
}

func (s *Server) egressLeaseLocked(id string) context.Context {
	if lease, ok := s.egressLeases[id]; ok {
		return lease.context
	}
	if s.egressLeases == nil {
		s.egressLeases = make(map[string]egressLease)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.egressLeases[id] = egressLease{context: ctx, cancel: cancel}
	return ctx
}

func (s *Server) revokeEgressLocked(id string) {
	if lease, ok := s.egressLeases[id]; ok {
		lease.cancel()
		delete(s.egressLeases, id)
	}
}

func GrantID(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "grant-" + fmt.Sprintf("%x", sum[:])
}

// GrantDirectory retains 128 bits of the already-cryptographic grant ID. This
// keeps Linux Unix-socket paths below sockaddr_un's 108-byte ceiling while the
// public/fencing identity remains the full 256-bit GrantID.
func GrantDirectory(root, grantID string) string {
	digest := strings.TrimPrefix(grantID, "grant-")
	if len(digest) >= 32 {
		digest = digest[:32]
	}
	return filepath.Join(root, digest)
}

func inferenceSocketPath(root, grantID string) string {
	return filepath.Join(GrantDirectory(root, grantID), "i.sock")
}

func egressSocketPath(root, grantID string) string {
	return filepath.Join(GrantDirectory(root, grantID), "e.sock")
}

func openGrantListener(directory, path string, relayGID int) (net.Listener, error) {
	if err := os.MkdirAll(directory, 0o710); err != nil {
		return nil, err
	}
	if err := os.Chown(directory, -1, relayGID); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Chown(path, -1, relayGID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func writeGatewayError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
