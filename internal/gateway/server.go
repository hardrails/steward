package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
)

const maxProxyBody = 4 << 20
const maxProxyResponse = 32 << 20
const maxHTTPHeaderBytes = 64 << 10
const maxServiceConcurrent = 16
const maxServiceLifetime = 2 * time.Minute
const streamStatusTrailer = "X-Steward-Stream-Status"
const maxConnectorGlobalConcurrent = 32
const maxConnectorGrantConcurrent = 4
const connectorReceiptStatusTrailer = "X-Steward-Connector-Receipt"
const maxConnectorAttemptsPerMinute = 60
const maxEgressDeniedAttemptsPerGrantMinute = 30
const maxEgressDeniedAttemptsPerTenantMinute = 120
const maxEgressDeniedAttemptsHostMinute = 480

type Grant struct {
	GrantID         string          `json:"grant_id"`
	TenantID        string          `json:"tenant_id"`
	NodeID          string          `json:"node_id,omitempty"`
	InstanceID      string          `json:"instance_id"`
	Generation      uint64          `json:"generation"`
	RuntimeRef      string          `json:"runtime_ref,omitempty"`
	CapsuleDigest   string          `json:"capsule_digest,omitempty"`
	PolicyDigest    string          `json:"policy_digest,omitempty"`
	RouteID         string          `json:"route_id,omitempty"`
	ModelAlias      string          `json:"model_alias,omitempty"`
	Service         bool            `json:"service"`
	ServiceID       string          `json:"service_id,omitempty"`
	ServiceURL      string          `json:"service_url,omitempty"`
	TaskAuthorities []TaskAuthority `json:"task_authorities,omitempty"`
	EgressRouteIDs  []string        `json:"egress_route_ids,omitempty"`
	ConnectorIDs    []string        `json:"connector_ids,omitempty"`
	Active          bool            `json:"active"`
}

// TaskAuthority is non-secret tenant authority authenticated by the signed
// site policy and carried to Gateway by Executor. Gateway configuration never
// supplies or widens this tenant-owned key set.
type TaskAuthority struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type grantResponse struct {
	GrantID           string `json:"grant_id"`
	InferenceSocket   string `json:"inference_socket,omitempty"`
	ServicePath       string `json:"service_path,omitempty"`
	EgressSocket      string `json:"egress_socket,omitempty"`
	ConnectorSocket   string `json:"connector_socket,omitempty"`
	RoutePolicyDigest string `json:"route_policy_digest,omitempty"`
	Active            bool   `json:"active"`
}

// GrantInspection reports a retained grant and the non-secret policy identity
// durably pinned to its inference and egress route references. Open refuses to
// serve the grant when current route semantics do not match this commitment.
type GrantInspection struct {
	Grant
	RoutePolicyDigest string `json:"route_policy_digest,omitempty"`
}

type retainedGrant struct {
	GrantID                 string                  `json:"grant_id"`
	TenantID                string                  `json:"tenant_id"`
	NodeID                  string                  `json:"node_id,omitempty"`
	InstanceID              string                  `json:"instance_id"`
	Generation              uint64                  `json:"generation"`
	RuntimeRef              string                  `json:"runtime_ref,omitempty"`
	CapsuleDigest           string                  `json:"capsule_digest,omitempty"`
	PolicyDigest            string                  `json:"policy_digest,omitempty"`
	RouteID                 string                  `json:"route_id,omitempty"`
	ModelAlias              string                  `json:"model_alias,omitempty"`
	Service                 bool                    `json:"service"`
	ServiceID               string                  `json:"service_id,omitempty"`
	ServiceURL              string                  `json:"service_url,omitempty"`
	TaskAuthorities         []TaskAuthority         `json:"task_authorities,omitempty"`
	EgressRouteIDs          []string                `json:"egress_route_ids,omitempty"`
	ConnectorIDs            []string                `json:"connector_ids,omitempty"`
	Active                  bool                    `json:"active"`
	RoutePolicyDigest       string                  `json:"route_policy_digest,omitempty"`
	CredentialBindingDigest string                  `json:"credential_binding_digest,omitempty"`
	ConnectorCalls          []retainedConnectorCall `json:"connector_calls,omitempty"`
}

type retainedConnectorCall struct {
	ConnectorID string `json:"connector_id"`
	Sequence    int    `json:"sequence"`
	Digest      string `json:"digest"`
}

func retainGrant(grant Grant, policyDigest, credentialDigest string, callMaps ...map[string][]string) retainedGrant {
	retained := retainedGrant{
		GrantID: grant.GrantID, TenantID: grant.TenantID, NodeID: grant.NodeID, InstanceID: grant.InstanceID, Generation: grant.Generation,
		RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest, PolicyDigest: grant.PolicyDigest,
		RouteID: grant.RouteID, ModelAlias: grant.ModelAlias, Service: grant.Service, ServiceID: grant.ServiceID, ServiceURL: grant.ServiceURL,
		TaskAuthorities: append([]TaskAuthority(nil), grant.TaskAuthorities...),
		EgressRouteIDs:  append([]string(nil), grant.EgressRouteIDs...), Active: grant.Active,
		ConnectorIDs:      append([]string(nil), grant.ConnectorIDs...),
		RoutePolicyDigest: policyDigest, CredentialBindingDigest: credentialDigest,
	}
	if len(callMaps) > 0 {
		connectorIDs := make([]string, 0, len(callMaps[0]))
		for connectorID := range callMaps[0] {
			connectorIDs = append(connectorIDs, connectorID)
		}
		sort.Strings(connectorIDs)
		for _, connectorID := range connectorIDs {
			for index, digest := range callMaps[0][connectorID] {
				retained.ConnectorCalls = append(retained.ConnectorCalls, retainedConnectorCall{
					ConnectorID: connectorID, Sequence: index + 1, Digest: digest,
				})
			}
		}
	}
	return retained
}

func (retained retainedGrant) grant() Grant {
	return Grant{
		GrantID: retained.GrantID, TenantID: retained.TenantID, NodeID: retained.NodeID, InstanceID: retained.InstanceID, Generation: retained.Generation,
		RuntimeRef: retained.RuntimeRef, CapsuleDigest: retained.CapsuleDigest, PolicyDigest: retained.PolicyDigest,
		RouteID: retained.RouteID, ModelAlias: retained.ModelAlias, Service: retained.Service, ServiceID: retained.ServiceID, ServiceURL: retained.ServiceURL,
		TaskAuthorities: append([]TaskAuthority(nil), retained.TaskAuthorities...),
		EgressRouteIDs:  append([]string(nil), retained.EgressRouteIDs...),
		ConnectorIDs:    append([]string(nil), retained.ConnectorIDs...), Active: retained.Active,
	}
}

type snapshot struct {
	Version int             `json:"version"`
	Grants  []retainedGrant `json:"grants"`
}

type grantLease struct {
	context context.Context
	cancel  context.CancelFunc
}

type connectorAttemptWindow struct {
	started time.Time
	count   int
}

type egressDeniedAttemptWindow struct {
	started time.Time
	count   int
}

type connectorReceiptLog interface {
	Begin(connectorledger.Event) (connectorledger.Head, error)
	Finish(connectorledger.Event) (connectorledger.Head, error)
	Failed() bool
	Close() error
}

type Server struct {
	mu                       sync.Mutex
	serviceTaskBeginMu       sync.Mutex
	config                   Config
	routes                   map[string]loadedRoute
	egressRoutes             map[string]loadedEgressRoute
	connectors               map[string]loadedConnector
	serviceOperations        map[string]map[string]ServiceOperation
	semaphores               map[string]chan struct{}
	egressSemaphores         map[string]chan struct{}
	connectorSemaphores      map[string]chan struct{}
	connectorGlobalSemaphore chan struct{}
	connectorGrantSemaphores map[string]chan struct{}
	serviceSemaphores        map[string]chan struct{}
	grants                   map[string]Grant
	policyDigests            map[string]string
	credentialDigests        map[string]string
	listeners                map[string]net.Listener
	egressListeners          map[string]net.Listener
	connectorListeners       map[string]net.Listener
	egressStats              map[string]EgressStats
	connectorCalls           map[string]map[string][]string
	connectorSpends          map[string]connectorSpendOwner
	serviceTasks             map[string]serviceTaskReceipt
	serviceTaskPermits       map[string]string
	connectorCallCounts      map[string]map[string]int
	connectorAttempts        map[string]connectorAttemptWindow
	egressDeniedAttempts     map[string]egressDeniedAttemptWindow
	egressTenantDenials      map[string]egressDeniedAttemptWindow
	egressHostDenials        egressDeniedAttemptWindow
	grantLeases              map[string]grantLease
	egressLeases             map[string]grantLease
	audit                    *auditLog
	connectorLedger          connectorReceiptLog
	now                      func() time.Time
	tokenHash                [sha256.Size]byte
	client                   *http.Client
}

func Open(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, serviceToken string) (*Server, error) {
	if serviceToken == "" {
		return nil, errors.New("gateway service token is required")
	}
	connectors, err := config.connectorMap()
	if err != nil {
		return nil, err
	}
	config.loadedConnectors = connectors
	serviceOperations, err := config.serviceOperationMap()
	if err != nil {
		return nil, err
	}
	config.loadedServiceOperations = serviceOperations
	receiptKey, err := config.connectorReceiptPrivateKey()
	if err != nil {
		return nil, err
	}
	config.connectorReceiptKey = receiptKey
	audit, err := openAuditLog(config.EgressAuditFile, config.EgressAuditFile != "")
	if err != nil {
		return nil, err
	}
	receiptLog, receiptIndex, err := openConnectorReceiptLedger(config, receiptKey)
	if err != nil {
		_ = audit.Close()
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		IdleConnTimeout:        60 * time.Second,
	}
	var receiptWriter connectorReceiptLog
	if receiptLog != nil {
		receiptWriter = receiptLog
	}
	server := &Server{
		config: config, routes: routes, egressRoutes: egressRoutes, connectors: connectors,
		serviceOperations:        serviceOperations,
		semaphores:               make(map[string]chan struct{}, len(routes)),
		egressSemaphores:         make(map[string]chan struct{}, len(egressRoutes)),
		connectorSemaphores:      make(map[string]chan struct{}, len(connectors)),
		connectorGlobalSemaphore: make(chan struct{}, maxConnectorGlobalConcurrent),
		connectorGrantSemaphores: make(map[string]chan struct{}),
		grants:                   make(map[string]Grant), policyDigests: make(map[string]string), credentialDigests: make(map[string]string),
		listeners: make(map[string]net.Listener), egressListeners: make(map[string]net.Listener), connectorListeners: make(map[string]net.Listener),
		serviceSemaphores: make(map[string]chan struct{}), egressStats: make(map[string]EgressStats),
		connectorCalls:  make(map[string]map[string][]string),
		connectorSpends: receiptIndex.spends, serviceTasks: receiptIndex.tasks, serviceTaskPermits: receiptIndex.permits,
		connectorCallCounts:  receiptIndex.counts,
		connectorAttempts:    make(map[string]connectorAttemptWindow),
		egressDeniedAttempts: make(map[string]egressDeniedAttemptWindow),
		egressTenantDenials:  make(map[string]egressDeniedAttemptWindow),
		grantLeases:          make(map[string]grantLease), egressLeases: make(map[string]grantLease), audit: audit,
		connectorLedger: receiptWriter, now: time.Now,
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
	for id, connector := range connectors {
		server.connectorSemaphores[id] = make(chan struct{}, connector.MaxConcurrent)
	}
	if err := server.load(); err != nil {
		_ = audit.Close()
		if receiptLog != nil {
			_ = receiptLog.Close()
		}
		return nil, err
	}
	if err := server.mergeRetainedConnectorSpends(); err != nil {
		_ = audit.Close()
		if receiptLog != nil {
			_ = receiptLog.Close()
		}
		return nil, err
	}
	return server, nil
}

// StateSummary identifies the retained-state compatibility boundary without
// exposing grant contents.
type StateSummary struct {
	Present        bool `json:"present"`
	FormatVersion  int  `json:"format_version"`
	RetainedGrants int  `json:"retained_grants"`
}

// Validate checks the retained Gateway state and audit sink without creating
// files, directories, sockets, or listeners. Missing state and audit files are
// valid prospective paths; normal startup creates them. Existing files must
// satisfy the same bounds, permissions, and state-policy bindings as Open.
func Validate(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, serviceToken string) (StateSummary, error) {
	if serviceToken == "" {
		return StateSummary{}, errors.New("gateway service token is required")
	}
	connectors, err := config.connectorMap()
	if err != nil {
		return StateSummary{}, err
	}
	config.loadedConnectors = connectors
	serviceOperations, err := config.serviceOperationMap()
	if err != nil {
		return StateSummary{}, err
	}
	config.loadedServiceOperations = serviceOperations
	receiptKey, err := config.connectorReceiptPrivateKey()
	if err != nil {
		return StateSummary{}, err
	}
	config.connectorReceiptKey = receiptKey
	if err := validateAuditLog(config.EgressAuditFile, config.EgressAuditFile != ""); err != nil {
		return StateSummary{}, err
	}
	if receiptKey != nil {
		limits, err := config.connectorReceiptLimits()
		if err != nil {
			return StateSummary{}, err
		}
		if _, err := connectorledger.ValidateWithLimits(config.ConnectorReceiptFile, receiptKey, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch, limits); err != nil {
			return StateSummary{}, err
		}
	}
	return InspectState(config, routes, egressRoutes)
}

// InspectState verifies retained grants against the loaded route policy and
// reports the on-disk format boundary without creating a prospective state
// file. Activation tooling can use the summary to require an explicit drain or
// migration before changing formats.
func InspectState(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute) (StateSummary, error) {
	connectors, err := config.connectorMap()
	if err != nil {
		return StateSummary{}, err
	}
	serviceOperations, err := config.serviceOperationMap()
	if err != nil {
		return StateSummary{}, err
	}
	validator := &Server{
		config: config, routes: routes, egressRoutes: egressRoutes, connectors: connectors,
		serviceOperations: serviceOperations,
		grants:            make(map[string]Grant), policyDigests: make(map[string]string), credentialDigests: make(map[string]string),
		connectorCalls: make(map[string]map[string][]string),
	}
	return validator.loadExisting()
}

// Reload atomically replaces operator-owned route and connector policy and the service token.
// Socket, identity, state, and audit paths are immutable for the process lifetime.
// Existing retained grants pin the complete effective route, including concurrency
// and loaded credentials. A route may be added or changed only while no retained
// grant refers to its ID, preventing a reload from silently changing signed authority.
func (s *Server) Reload(config Config, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, serviceToken string) error {
	if serviceToken == "" || !sameRuntimeConfig(s.config, config) {
		return errors.New("gateway reload may change only routes, connectors, and service token")
	}
	connectors, err := config.connectorMap()
	if err != nil {
		return err
	}
	config.loadedConnectors = connectors
	serviceOperations, err := config.serviceOperationMap()
	if err != nil {
		return err
	}
	config.loadedServiceOperations = serviceOperations
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, grant := range s.grants {
		if len(grant.TaskAuthorities) > 0 && !sameServiceOperations(s.serviceOperations[grant.ServiceID], serviceOperations[grant.ServiceID]) {
			return fmt.Errorf("reload changes task operations used by retained grant %s", grant.GrantID)
		}
		if grant.RouteID != "" {
			next, ok := routes[grant.RouteID]
			if !ok {
				return fmt.Errorf("reload removes inference route %q used by grant %s", grant.RouteID, grant.GrantID)
			}
			if !sameLoadedRoute(s.routes[grant.RouteID], next) {
				return fmt.Errorf("reload changes inference route %q used by retained grant %s", grant.RouteID, grant.GrantID)
			}
		}
		for _, id := range grant.EgressRouteIDs {
			next, ok := egressRoutes[id]
			if !ok {
				return fmt.Errorf("reload removes egress route %q used by grant %s", id, grant.GrantID)
			}
			if !sameLoadedEgressRoute(s.egressRoutes[id], next) {
				return fmt.Errorf("reload changes egress route %q used by retained grant %s", id, grant.GrantID)
			}
		}
		for _, connectorID := range grant.ConnectorIDs {
			next, ok := connectors[connectorID]
			if !ok {
				return fmt.Errorf("reload removes connector %q used by grant %s", connectorID, grant.GrantID)
			}
			if !sameLoadedConnector(s.connectors[connectorID], next) {
				return fmt.Errorf("reload changes connector %q used by retained grant %s", connectorID, grant.GrantID)
			}
		}
		budget, _ := config.connectorReceiptBudget(grant.TenantID)
		if routePolicyDigest(grant, routes, egressRoutes, connectors, serviceOperations, budget) != s.policyDigests[id] ||
			routeCredentialBindingDigest(grant, routes, connectors) != s.credentialDigests[id] {
			return fmt.Errorf("reload changes route policy used by retained grant %s", grant.GrantID)
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
	connectorSemaphores := make(map[string]chan struct{}, len(connectors))
	for id, connector := range connectors {
		current := s.connectorSemaphores[id]
		if current != nil && cap(current) == connector.MaxConcurrent {
			connectorSemaphores[id] = current
			continue
		}
		if len(current) > 0 {
			return fmt.Errorf("reload changes concurrency for busy connector %q", id)
		}
		connectorSemaphores[id] = make(chan struct{}, connector.MaxConcurrent)
	}
	s.config.Routes, s.config.EgressRoutes, s.config.Connectors, s.config.ServiceOperations = config.Routes, config.EgressRoutes, config.Connectors, config.ServiceOperations
	s.config.loadedConnectors = connectors
	s.config.loadedServiceOperations = serviceOperations
	s.routes, s.egressRoutes, s.connectors, s.serviceOperations = routes, egressRoutes, connectors, serviceOperations
	s.semaphores, s.egressSemaphores, s.connectorSemaphores = semaphores, egressSemaphores, connectorSemaphores
	s.tokenHash = sha256.Sum256([]byte("Bearer " + serviceToken))
	return nil
}

func sameRuntimeConfig(left, right Config) bool {
	return left.Version == right.Version && left.ControlSocket == right.ControlSocket &&
		left.ServiceAddress == right.ServiceAddress && left.ServiceTokenFile == right.ServiceTokenFile &&
		left.StateFile == right.StateFile && left.GrantRoot == right.GrantRoot &&
		left.ExecutorGID == right.ExecutorGID && left.RelayGID == right.RelayGID &&
		left.EgressAuditFile == right.EgressAuditFile &&
		left.ConnectorReceiptFile == right.ConnectorReceiptFile &&
		left.ConnectorReceiptKeyFile == right.ConnectorReceiptKeyFile &&
		left.ConnectorReceiptNodeID == right.ConnectorReceiptNodeID &&
		left.ConnectorReceiptEpoch == right.ConnectorReceiptEpoch &&
		sameConnectorReceiptTenantBudgets(left.ConnectorReceiptTenantBudgets, right.ConnectorReceiptTenantBudgets) &&
		connectorReceiptKeyID(left) == connectorReceiptKeyID(right)
}

func sameConnectorReceiptTenantBudgets(left, right []ConnectorReceiptTenantBudget) bool {
	if len(left) != len(right) {
		return false
	}
	rightByTenant := make(map[string]int64, len(right))
	for _, budget := range right {
		rightByTenant[budget.TenantID] = budget.Bytes
	}
	for _, budget := range left {
		if bytes, ok := rightByTenant[budget.TenantID]; !ok || bytes != budget.Bytes {
			return false
		}
	}
	return true
}

func (s *Server) Start(ctx context.Context) error {
	defer s.audit.Close()
	if s.connectorLedger != nil {
		defer s.connectorLedger.Close()
	}
	defer s.closeGrantListeners()
	s.mu.Lock()
	for id, grant := range s.grants {
		if grant.Service {
			if err := prepareGrantDirectory(GrantDirectory(s.config.GrantRoot, id), s.config.RelayGID); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("restore service grant %q: %w", id, err)
			}
		}
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
		if len(grant.ConnectorIDs) > 0 {
			if err := s.listenConnectorGrantLocked(id); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("restore connector grant %q: %w", id, err)
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
	control := &http.Server{Handler: s.ControlHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes}
	service := &http.Server{Addr: s.config.ServiceAddress, Handler: s.ServiceHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes}
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
	digest := s.policyDigests[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeGatewayError(w, http.StatusNotFound, "grant_not_found", "gateway grant not found")
		return
	}
	writeJSON(w, http.StatusOK, GrantInspection{Grant: grant, RoutePolicyDigest: digest})
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
		var lease context.Context
		var semaphore chan struct{}
		if ok && grant.Active && grant.ServiceURL != "" {
			lease = s.grantLeaseLocked(grantID)
			semaphore = s.serviceSemaphoreLocked(grantID)
		}
		s.mu.Unlock()
		if !ok || !grant.Active || grant.ServiceURL == "" {
			writeGatewayError(w, http.StatusNotFound, "service_unavailable", "active service grant not found")
			return
		}
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
		default:
			writeGatewayError(w, http.StatusTooManyRequests, "service_busy", "service grant concurrency limit reached")
			return
		}
		requestContext, cancel := context.WithTimeout(r.Context(), maxServiceLifetime)
		defer cancel()
		stopRevocation := context.AfterFunc(lease, cancel)
		defer stopRevocation()
		s.proxyService(w, r.WithContext(requestContext), grant, path)
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
	currentPolicyDigest, hadPolicyDigest := s.policyDigests[grant.GrantID]
	currentCredentialDigest, hadCredentialDigest := s.credentialDigests[grant.GrantID]
	policyDigest := s.routePolicyDigestLocked(grant)
	credentialDigest := routeCredentialBindingDigest(grant, s.routes, s.connectors)
	if hadCurrent {
		if current.Active {
			writeGatewayError(w, http.StatusConflict, "grant_active", "active gateway grant must be deactivated before replacement")
			return
		}
		if grant.Generation < current.Generation {
			writeGatewayError(w, http.StatusConflict, "generation_rollback", "gateway grant generation rollback")
			return
		}
		grant.Active = false
		if grant.Generation == current.Generation && !grantsEqual(grant, current) && !validServiceEnrichment(current, grant) {
			writeGatewayError(w, http.StatusConflict, "grant_conflict", "equal generation identifies a different gateway grant")
			return
		}
		if !hadPolicyDigest || !hadCredentialDigest || policyDigest != currentPolicyDigest || credentialDigest != currentCredentialDigest {
			writeGatewayError(w, http.StatusConflict, "grant_conflict", "retained gateway grant route policy does not match current configuration")
			return
		}
	}
	grant.Active = false
	hadInferenceListener := s.listeners[grant.GrantID] != nil
	hadEgressListener := s.egressListeners[grant.GrantID] != nil
	hadConnectorListener := s.connectorListeners[grant.GrantID] != nil
	grantDirectory := GrantDirectory(s.config.GrantRoot, grant.GrantID)
	_, directoryErr := os.Stat(grantDirectory)
	hadGrantDirectory := directoryErr == nil
	rollback := func() {
		if hadCurrent {
			s.grants[grant.GrantID] = current
			if hadPolicyDigest {
				s.policyDigests[grant.GrantID] = currentPolicyDigest
			}
			if hadCredentialDigest {
				s.credentialDigests[grant.GrantID] = currentCredentialDigest
			}
		} else {
			delete(s.grants, grant.GrantID)
			delete(s.policyDigests, grant.GrantID)
			delete(s.credentialDigests, grant.GrantID)
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
		if !hadConnectorListener && s.connectorListeners[grant.GrantID] != nil {
			_ = s.connectorListeners[grant.GrantID].Close()
			delete(s.connectorListeners, grant.GrantID)
			_ = os.Remove(connectorSocketPath(s.config.GrantRoot, grant.GrantID))
		}
		if !hadGrantDirectory {
			_ = os.RemoveAll(grantDirectory)
		}
		_ = s.persistLocked()
	}
	s.grants[grant.GrantID] = grant
	s.policyDigests[grant.GrantID] = policyDigest
	s.credentialDigests[grant.GrantID] = credentialDigest
	if err := s.persistLocked(); err != nil {
		rollback()
		writeGatewayError(w, http.StatusServiceUnavailable, "state_unavailable", err.Error())
		return
	}
	if grant.Service {
		if err := prepareGrantDirectory(grantDirectory, s.config.RelayGID); err != nil {
			rollback()
			writeGatewayError(w, http.StatusServiceUnavailable, "socket_unavailable", err.Error())
			return
		}
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
	if len(grant.ConnectorIDs) > 0 {
		if err := s.listenConnectorGrantLocked(grant.GrantID); err != nil {
			rollback()
			writeGatewayError(w, http.StatusServiceUnavailable, "socket_unavailable", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusCreated, s.response(grant))
}

// validServiceEnrichment permits the Executor to reserve a grant, create the
// relay, then bind that grant's deterministic service socket. No identity,
// route, model, or generation field can change in this operation.
func validServiceEnrichment(current, next Grant) bool {
	return !current.Active && !next.Active && current.ServiceURL == "" && next.ServiceURL != "" &&
		current.GrantID == next.GrantID && current.TenantID == next.TenantID &&
		current.NodeID == next.NodeID &&
		current.InstanceID == next.InstanceID && current.Generation == next.Generation &&
		current.RuntimeRef == next.RuntimeRef && current.CapsuleDigest == next.CapsuleDigest && current.PolicyDigest == next.PolicyDigest &&
		current.RouteID == next.RouteID && current.ModelAlias == next.ModelAlias && current.Service == next.Service &&
		current.ServiceID == next.ServiceID && slices.Equal(current.TaskAuthorities, next.TaskAuthorities) &&
		slices.Equal(current.EgressRouteIDs, next.EgressRouteIDs) && slices.Equal(current.ConnectorIDs, next.ConnectorIDs)
}

func grantsEqual(left, right Grant) bool {
	return left.GrantID == right.GrantID && left.TenantID == right.TenantID &&
		left.NodeID == right.NodeID &&
		left.InstanceID == right.InstanceID && left.Generation == right.Generation &&
		left.RuntimeRef == right.RuntimeRef && left.CapsuleDigest == right.CapsuleDigest && left.PolicyDigest == right.PolicyDigest &&
		left.RouteID == right.RouteID && left.ModelAlias == right.ModelAlias &&
		left.Service == right.Service && left.ServiceID == right.ServiceID && left.ServiceURL == right.ServiceURL &&
		slices.Equal(left.TaskAuthorities, right.TaskAuthorities) &&
		left.Active == right.Active && slices.Equal(left.EgressRouteIDs, right.EgressRouteIDs) && slices.Equal(left.ConnectorIDs, right.ConnectorIDs)
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
	if active {
		s.grantLeaseLocked(id)
	} else {
		s.revokeGrantLocked(id)
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
	connectorCalls, hadConnectorCalls := s.connectorCalls[id]
	delete(s.connectorCalls, id)
	policyDigest, hadPolicyDigest := s.policyDigests[id]
	credentialDigest, hadCredentialDigest := s.credentialDigests[id]
	delete(s.policyDigests, id)
	delete(s.credentialDigests, id)
	if err := s.persistLocked(); err != nil {
		s.grants[id] = grant
		if hadConnectorCalls {
			s.connectorCalls[id] = connectorCalls
		}
		if hadPolicyDigest {
			s.policyDigests[id] = policyDigest
		}
		if hadCredentialDigest {
			s.credentialDigests[id] = credentialDigest
		}
		writeGatewayError(w, http.StatusServiceUnavailable, "state_unavailable", err.Error())
		return
	}
	s.revokeEgressLocked(id)
	s.revokeGrantLocked(id)
	if listener := s.listeners[id]; listener != nil {
		_ = listener.Close()
		delete(s.listeners, id)
	}
	if listener := s.egressListeners[id]; listener != nil {
		_ = listener.Close()
		delete(s.egressListeners, id)
	}
	if listener := s.connectorListeners[id]; listener != nil {
		_ = listener.Close()
		delete(s.connectorListeners, id)
	}
	delete(s.egressStats, id)
	delete(s.serviceSemaphores, id)
	delete(s.connectorGrantSemaphores, id)
	delete(s.connectorAttempts, id)
	delete(s.egressDeniedAttempts, id)
	_ = os.RemoveAll(GrantDirectory(s.config.GrantRoot, id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validGrant(grant Grant) bool {
	if !validGrantID(grant.GrantID) || !bounded(grant.TenantID, 128) || !bounded(grant.InstanceID, 256) || grant.Generation == 0 ||
		grant.GrantID != GrantID(grant.TenantID, grant.InstanceID, grant.Generation) ||
		(grant.RouteID == "" && !grant.Service && len(grant.EgressRouteIDs) == 0 && len(grant.ConnectorIDs) == 0) ||
		len(grant.ModelAlias) > 256 || (grant.ServiceURL != "" && !grant.Service) ||
		(!grant.Service && (grant.ServiceID != "" || len(grant.TaskAuthorities) != 0)) || !validGrantEvidenceContext(grant) {
		return false
	}
	if grant.ServiceID != "" && !routeID(grant.ServiceID) {
		return false
	}
	if len(grant.TaskAuthorities) == 0 && (grant.NodeID != "" || grant.ServiceID != "") {
		return false
	}
	if len(grant.TaskAuthorities) > 0 {
		if grant.ServiceID == "" || !bounded(grant.NodeID, 128) || grant.RuntimeRef == "" || len(s.serviceOperations[grant.ServiceID]) == 0 ||
			s.config.ConnectorReceiptNodeID != ServiceTaskReceiptNodeID(grant.NodeID) || !validTaskAuthorities(grant.TaskAuthorities) {
			return false
		}
		if _, budgeted := s.config.connectorReceiptBudget(grant.TenantID); !budgeted {
			return false
		}
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
	if len(grant.ConnectorIDs) > 32 {
		return false
	}
	for index, id := range grant.ConnectorIDs {
		if !routeID(id) {
			return false
		}
		connector, ok := s.connectors[id]
		if !ok {
			return false
		}
		if len(connector.authorities) > 0 {
			tenantAuthorized := false
			for keyID := range connector.authorities {
				if connector.authorityTenants[keyID] == grant.TenantID {
					tenantAuthorized = true
					break
				}
			}
			if !tenantAuthorized {
				return false
			}
		}
		if index > 0 && grant.ConnectorIDs[index-1] >= id {
			return false
		}
	}
	if len(grant.ConnectorIDs) > 0 && grant.RuntimeRef == "" {
		return false
	}
	if len(grant.ConnectorIDs) > 0 {
		if _, budgeted := s.config.connectorReceiptBudget(grant.TenantID); !budgeted {
			return false
		}
	}
	if grant.ServiceURL != "" && !validServiceURL(grant.ServiceURL, s.config.GrantRoot, grant.GrantID) {
		return false
	}
	return true
}

func validTaskAuthorities(authorities []TaskAuthority) bool {
	if len(authorities) == 0 || len(authorities) > 8 {
		return false
	}
	seenKeys := make(map[string]struct{}, len(authorities))
	for index, authority := range authorities {
		if !routeID(authority.KeyID) || index > 0 && authorities[index-1].KeyID >= authority.KeyID {
			return false
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(public) != authority.PublicKey {
			return false
		}
		if _, duplicate := seenKeys[string(public)]; duplicate {
			return false
		}
		seenKeys[string(public)] = struct{}{}
	}
	return true
}

// TaskAuthoritiesValid exposes the exact grant-shape validation to Executor,
// which persists the same authority in its workload fingerprint.
func TaskAuthoritiesValid(authorities []TaskAuthority) bool { return validTaskAuthorities(authorities) }

func validGrantEvidenceContext(grant Grant) bool {
	present := grant.RuntimeRef != "" || grant.CapsuleDigest != "" || grant.PolicyDigest != ""
	if !present {
		return true
	}
	return validExecutorRuntimeRef(grant.RuntimeRef) && validSHA256Digest(grant.CapsuleDigest) && validSHA256Digest(grant.PolicyDigest)
}

func validExecutorRuntimeRef(value string) bool {
	return strings.HasPrefix(value, "executor-") && len(value) == len("executor-")+64 && lowerHex(value[len("executor-"):])
}

func validSHA256Digest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == len("sha256:")+64 && lowerHex(value[len("sha256:"):])
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
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

func validServiceURL(value, grantRoot, grantID string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "unix" {
		return parsed.Host == "" && parsed.Path == serviceSocketPath(grantRoot, grantID)
	}
	if parsed.Scheme != "http" || parsed.Path != "" {
		return false
	}
	address := net.ParseIP(parsed.Hostname())
	return address != nil && address.IsLoopback() && parsed.Port() != ""
}

func (s *Server) response(grant Grant) grantResponse {
	result := grantResponse{GrantID: grant.GrantID, RoutePolicyDigest: s.policyDigests[grant.GrantID], Active: grant.Active}
	if grant.RouteID != "" {
		result.InferenceSocket = inferenceSocketPath(s.config.GrantRoot, grant.GrantID)
	}
	if grant.Service {
		result.ServicePath = "/v1/services/" + grant.GrantID + "/"
	}
	if len(grant.EgressRouteIDs) > 0 {
		result.EgressSocket = egressSocketPath(s.config.GrantRoot, grant.GrantID)
	}
	if len(grant.ConnectorIDs) > 0 {
		result.ConnectorSocket = connectorSocketPath(s.config.GrantRoot, grant.GrantID)
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
	server := &http.Server{Handler: s.inferenceHandler(id), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes}
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
		lease := s.grantLeaseLocked(id)
		select {
		case semaphore <- struct{}{}:
			s.mu.Unlock()
			defer func() { <-semaphore }()
		default:
			s.mu.Unlock()
			writeGatewayError(w, http.StatusTooManyRequests, "route_busy", "inference route concurrency limit reached")
			return
		}
		requestContext, cancel := context.WithCancel(r.Context())
		defer cancel()
		stopRevocation := context.AfterFunc(lease, cancel)
		defer stopRevocation()
		s.proxyInference(w, r.WithContext(requestContext), grant, route)
	})
}

var inferencePaths = map[string]string{
	"/v1/chat/completions": http.MethodPost,
	"/v1/completions":      http.MethodPost,
	"/v1/embeddings":       http.MethodPost,
	"/v1/responses":        http.MethodPost,
	"/v1/models":           http.MethodGet,
}

func (s *Server) proxyInference(w http.ResponseWriter, incoming *http.Request, grant Grant, route loadedRoute) {
	if inferencePaths[incoming.URL.Path] != incoming.Method || incoming.URL.RawQuery != "" {
		writeGatewayError(w, http.StatusForbidden, "route_denied", "inference method or path is not allowed")
		return
	}
	if incoming.URL.Path == "/v1/models" {
		writeJSON(w, http.StatusOK, map[string]any{
			"object": "list",
			"data":   []map[string]any{{"id": grant.ModelAlias, "object": "model", "created": 0, "owned_by": "steward"}},
		})
		return
	}
	raw, model, err := inspectInferenceModel(w, incoming)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if model != grant.ModelAlias {
		writeGatewayError(w, http.StatusForbidden, "model_denied", "request model does not match the active inference grant")
		return
	}
	incoming.Body = io.NopCloser(bytes.NewReader(raw))
	incoming.ContentLength = int64(len(raw))
	s.proxy(w, incoming, route.base, incoming.URL.Path, route.credential, false, s.client)
}

func (s *Server) proxyService(w http.ResponseWriter, incoming *http.Request, grant Grant, path string) {
	if incoming.Method == http.MethodConnect || !safeServicePath(path) {
		writeGatewayError(w, http.StatusForbidden, "service_denied", "service method or path is not allowed")
		return
	}
	operation, routePolicyDigest, protected := s.serviceTaskOperation(grant, incoming.Method, path)
	permitPresented := len(incoming.Header.Values(taskPermitHeader)) != 0
	if protected {
		s.proxyServiceTask(w, incoming, grant, operation, routePolicyDigest)
		return
	}
	if permitPresented || len(grant.TaskAuthorities) > 0 && incoming.Method != http.MethodGet && incoming.Method != http.MethodHead {
		writeGatewayError(w, http.StatusForbidden, "service_task_denied", "task-enabled service methods require one configured exact operation and task permit")
		return
	}
	base, client, transport, err := s.serviceUpstream(grant.ServiceURL)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured service transport is unavailable")
		return
	}
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	if websocketAttempt(incoming) {
		if !websocketUpgrade(incoming) {
			writeGatewayError(w, http.StatusForbidden, "service_denied", "only a valid WebSocket upgrade is allowed")
			return
		}
		s.proxyWebSocket(w, incoming, base, path, client.Transport)
		return
	}
	s.proxy(w, incoming, base, path, "", true, client)
}

func (s *Server) serviceUpstream(value string) (*url.URL, *http.Client, *http.Transport, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, nil, nil, err
	}
	if parsed.Scheme != "unix" {
		return parsed, s.client, nil, nil
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", parsed.Path)
		},
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
	}
	base, _ := url.Parse("http://steward-relay")
	return base, &http.Client{
		Transport: transport, Timeout: maxServiceLifetime,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, transport, nil
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

func (s *Server) proxy(w http.ResponseWriter, incoming *http.Request, base *url.URL, path, credential string, service bool, client *http.Client) {
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
	if incoming.ContentLength > 0 && incoming.ContentLength <= maxProxyBody {
		request.ContentLength = incoming.ContentLength
	}
	copyHeaders(request.Header, incoming.Header)
	request.Header.Del("Authorization")
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Cookie")
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := client.Do(request)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "upstream_unavailable", "configured upstream request failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeGatewayError(w, http.StatusBadGateway, "redirect_denied", "configured upstream returned a redirect")
		return
	}
	s.relayHTTPResponse(w, response, service)
}

func (s *Server) relayHTTPResponse(w http.ResponseWriter, response *http.Response, service bool) {
	relayHTTPResponseBounded(w, response, service, maxProxyResponse)
}

func relayHTTPResponseBounded(w http.ResponseWriter, response *http.Response, service bool, maximum int64) {
	if response.ContentLength > maximum {
		writeGatewayError(w, http.StatusBadGateway, "response_too_large", "configured upstream response exceeds the byte limit")
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.Header().Del("Set-Cookie")
	w.Header().Del("Location")
	unknownLength := prepareBoundedHTTPResponse(w, response.ContentLength)
	if service {
		w.Header().Set("X-Steward-Service-Grant", "active")
	}
	w.WriteHeader(response.StatusCode)
	result := copyHTTPResponseBody(w, response.Body, maximum, unknownLength)
	if result.abort {
		panic(http.ErrAbortHandler)
	}
}

type boundedHTTPResponseResult struct {
	written int64
	reason  string
	abort   bool
}

// prepareBoundedHTTPResponse advertises an integrity trailer for responses
// whose size is not known before streaming starts. A clean terminal trailer
// distinguishes a complete stream from a connection that disappeared before
// Steward could finish it.
func prepareBoundedHTTPResponse(w http.ResponseWriter, contentLength int64) bool {
	if contentLength >= 0 {
		return false
	}
	w.Header().Del("Content-Length")
	w.Header().Add("Trailer", streamStatusTrailer)
	return true
}

func copyHTTPResponseBody(w http.ResponseWriter, body io.Reader, maximum int64, unknownLength bool) boundedHTTPResponseResult {
	destination := io.Writer(w)
	if unknownLength {
		// Flush each copied chunk so inference token streams and long-running
		// service responses retain their streaming behavior.
		destination = flushingResponseWriter{writer: w, controller: http.NewResponseController(w)}
	}
	written, copyErr := io.Copy(destination, io.LimitReader(body, maximum))
	result := boundedHTTPResponseResult{written: written, reason: "completed"}
	if copyErr != nil {
		result.reason, result.abort = "stream_failed", true
	} else if unknownLength && written == maximum {
		var probe [1]byte
		count, probeErr := io.ReadFull(body, probe[:])
		switch {
		case count > 0:
			result.reason, result.abort = "response_too_large", true
		case probeErr != nil && !errors.Is(probeErr, io.EOF) && !errors.Is(probeErr, io.ErrUnexpectedEOF):
			result.reason, result.abort = "stream_failed", true
		}
	}
	if unknownLength {
		w.Header().Set(streamStatusTrailer, result.reason)
	}
	return result
}

type flushingResponseWriter struct {
	writer     io.Writer
	controller *http.ResponseController
}

func (w flushingResponseWriter) Write(value []byte) (int, error) {
	written, err := w.writer.Write(value)
	if err != nil || written == 0 {
		return written, err
	}
	if flushErr := w.controller.Flush(); flushErr != nil {
		return written, flushErr
	}
	return written, nil
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
	summary, err := s.loadExisting()
	if err != nil {
		return err
	}
	if !summary.Present {
		return s.persistLocked()
	}
	return nil
}

func (s *Server) loadExisting() (StateSummary, error) {
	info, err := os.Lstat(s.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return StateSummary{}, nil
	}
	if err != nil {
		return StateSummary{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConfigBytes {
		return StateSummary{}, errors.New("gateway state must be a bounded owner-only regular file")
	}
	file, err := os.Open(s.config.StateFile)
	if err != nil {
		return StateSummary{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return StateSummary{}, err
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 || openedInfo.Size() > maxConfigBytes {
		return StateSummary{}, errors.New("gateway state changed while it was opened for validation")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return StateSummary{}, err
	}
	if len(raw) > maxConfigBytes {
		return StateSummary{}, errors.New("gateway state must be a bounded owner-only regular file")
	}
	var state snapshot
	if err := dsse.DecodeStrictInto(raw, maxConfigBytes, &state); err != nil ||
		(state.Version != 1 && state.Version != 2 && state.Version != 3 && state.Version != 4) || len(state.Grants) > 4096 {
		return StateSummary{}, errors.New("gateway state is invalid")
	}
	for _, retained := range state.Grants {
		grant := retained.grant()
		grant.Active = false
		if !s.validGrant(grant) {
			return StateSummary{}, errors.New("gateway state contains an invalid grant")
		}
		if _, exists := s.grants[grant.GrantID]; exists {
			return StateSummary{}, errors.New("gateway state contains a duplicate grant")
		}
		effectivePolicyDigest := s.routePolicyDigestLocked(grant)
		effectiveCredentialDigest := routeCredentialBindingDigest(grant, s.routes, s.connectors)
		policyBearing := effectivePolicyDigest != ""
		credentialBearing := grant.RouteID != "" || len(grant.ConnectorIDs) > 0
		if policyBearing && (state.Version < 2 || retained.RoutePolicyDigest == "") ||
			credentialBearing && retained.CredentialBindingDigest == "" {
			return StateSummary{}, errors.New("gateway state contains a retained grant without a durable route policy binding")
		}
		if len(grant.ConnectorIDs) > 0 && state.Version != 3 {
			if state.Version != 4 {
				return StateSummary{}, errors.New("gateway state contains a connector grant without durable call accounting")
			}
		}
		if len(grant.TaskAuthorities) > 0 && state.Version != 4 {
			return StateSummary{}, errors.New("gateway state contains task authority without its durable state format")
		}
		if retained.RoutePolicyDigest != effectivePolicyDigest || retained.CredentialBindingDigest != effectiveCredentialDigest {
			return StateSummary{}, errors.New("gateway state route policy does not match current configuration")
		}
		calls, err := s.validateRetainedConnectorCalls(grant, retained.ConnectorCalls)
		if err != nil {
			return StateSummary{}, fmt.Errorf("gateway state connector calls are invalid: %w", err)
		}
		s.grants[grant.GrantID] = grant
		s.policyDigests[grant.GrantID] = retained.RoutePolicyDigest
		s.credentialDigests[grant.GrantID] = retained.CredentialBindingDigest
		if len(calls) > 0 {
			s.connectorCalls[grant.GrantID] = calls
		}
	}
	return StateSummary{Present: true, FormatVersion: state.Version, RetainedGrants: len(state.Grants)}, nil
}

func (s *Server) persistLocked() error {
	grants := make([]retainedGrant, 0, len(s.grants))
	for _, grant := range s.grants {
		grants = append(grants, retainGrant(
			grant, s.policyDigests[grant.GrantID], s.credentialDigests[grant.GrantID], s.connectorCalls[grant.GrantID],
		))
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].GrantID < grants[j].GrantID })
	raw, err := json.Marshal(snapshot{Version: 4, Grants: grants})
	if err != nil {
		return err
	}
	if len(raw) > maxConfigBytes {
		return errors.New("gateway state capacity exceeded")
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

func (s *Server) validateRetainedConnectorCalls(grant Grant, retained []retainedConnectorCall) (map[string][]string, error) {
	if len(retained) == 0 {
		return nil, nil
	}
	calls := make(map[string][]string)
	seenDigests := make(map[string]struct{}, len(retained))
	previousConnector := ""
	for _, call := range retained {
		if !slices.Contains(grant.ConnectorIDs, call.ConnectorID) || !validSHA256Digest(call.Digest) {
			return nil, errors.New("call does not belong to the retained connector grant")
		}
		if previousConnector > call.ConnectorID {
			return nil, errors.New("calls are not in canonical connector order")
		}
		previousConnector = call.ConnectorID
		current := calls[call.ConnectorID]
		if call.Sequence != len(current)+1 || len(current) >= s.connectors[call.ConnectorID].MaxCallsPerGrant {
			return nil, errors.New("call sequence or budget is invalid")
		}
		if _, duplicate := seenDigests[call.Digest]; duplicate {
			return nil, errors.New("duplicate call digest")
		}
		seenDigests[call.Digest] = struct{}{}
		calls[call.ConnectorID] = append(current, call.Digest)
	}
	return calls, nil
}

func (s *Server) closeGrantListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.grantLeases {
		s.revokeGrantLocked(id)
	}
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
	for id, listener := range s.connectorListeners {
		_ = listener.Close()
		delete(s.connectorListeners, id)
	}
}

func (s *Server) egressLeaseLocked(id string) context.Context {
	if lease, ok := s.egressLeases[id]; ok {
		return lease.context
	}
	if s.egressLeases == nil {
		s.egressLeases = make(map[string]grantLease)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.egressLeases[id] = grantLease{context: ctx, cancel: cancel}
	return ctx
}

func (s *Server) revokeEgressLocked(id string) {
	if lease, ok := s.egressLeases[id]; ok {
		lease.cancel()
		delete(s.egressLeases, id)
	}
}

func (s *Server) grantLeaseLocked(id string) context.Context {
	if lease, ok := s.grantLeases[id]; ok {
		return lease.context
	}
	if s.grantLeases == nil {
		s.grantLeases = make(map[string]grantLease)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.grantLeases[id] = grantLease{context: ctx, cancel: cancel}
	return ctx
}

func (s *Server) revokeGrantLocked(id string) {
	if lease, ok := s.grantLeases[id]; ok {
		lease.cancel()
		delete(s.grantLeases, id)
	}
}

func (s *Server) serviceSemaphoreLocked(id string) chan struct{} {
	if s.serviceSemaphores == nil {
		s.serviceSemaphores = make(map[string]chan struct{})
	}
	if semaphore := s.serviceSemaphores[id]; semaphore != nil {
		return semaphore
	}
	semaphore := make(chan struct{}, maxServiceConcurrent)
	s.serviceSemaphores[id] = semaphore
	return semaphore
}

func GrantID(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "grant-" + fmt.Sprintf("%x", sum[:])
}

// ServiceTaskReceiptNodeID derives the only Gateway receipt identity accepted
// for task authority admitted on a node. This binds the signed permit's node to
// the outer signed receipt chain without copying node identity into every event.
func ServiceTaskReceiptNodeID(nodeID string) string { return nodeID + "/gateway" }

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

func connectorSocketPath(root, grantID string) string {
	return filepath.Join(GrantDirectory(root, grantID), "c.sock")
}

func serviceSocketPath(root, grantID string) string {
	return filepath.Join(GrantDirectory(root, grantID), "s.sock")
}

// ServiceSocketURL returns the only Unix service origin valid for a grant.
func ServiceSocketURL(root, grantID string) string {
	return (&url.URL{Scheme: "unix", Path: serviceSocketPath(root, grantID)}).String()
}

func openGrantListener(directory, path string, relayGID int) (net.Listener, error) {
	if err := prepareGrantDirectory(directory, relayGID); err != nil {
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

func prepareGrantDirectory(directory string, relayGID int) error {
	if err := os.MkdirAll(directory, 0o730); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o730); err != nil {
		return err
	}
	return os.Chown(directory, -1, relayGID)
}

func writeGatewayError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
