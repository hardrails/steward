// Package controlplane exposes the bounded HTTP contract for Steward's bundled
// controller. The service transports exact tenant-signed commands but never
// receives tenant private keys or executes agent operations itself.
package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	maxRequestBytes           = 1 << 20
	maxResponseBytes          = 1 << 20
	defaultPageSize           = 100
	maxPageSize               = 500
	evidenceChallengeLifetime = 2 * time.Minute
	maxEvidenceExportAttempts = 3
	evidenceExportRetryAfter  = 1
)

var errBodyTooLarge = errors.New("request body exceeds 1 MiB")

type Config struct {
	Store                *controlstore.Store
	Auth                 *controlauth.Manager
	WitnessPrivateKey    ed25519.PrivateKey
	LeaseDuration        time.Duration
	MaxPoll              int
	EnableMetrics        bool
	OperationsThresholds controlstore.OperationsThresholds
	Now                  func() time.Time
	Logger               *slog.Logger
}

type Server struct {
	store                *controlstore.Store
	auth                 *controlauth.Manager
	witnessKey           ed25519.PrivateKey
	lease                time.Duration
	maxPoll              int
	enableMetrics        bool
	operationsThresholds controlstore.OperationsThresholds
	now                  func() time.Time
	logger               *slog.Logger
	mux                  *http.ServeMux
}

func New(config Config) (*Server, error) {
	if config.Store == nil || config.Auth == nil || config.LeaseDuration <= 0 ||
		config.LeaseDuration > controlstore.MaxDeliveryLease || config.MaxPoll <= 0 ||
		config.MaxPoll > controlprotocol.MaxExecutorDeliveries || len(config.WitnessPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("control server requires store, auth, an Ed25519 witness key, a lease no greater than 10 minutes, and a bounded poll batch")
	}
	operationsThresholds, err := resolveOperationsThresholds(config.OperationsThresholds)
	if err != nil {
		return nil, fmt.Errorf("control server operations thresholds: %w", err)
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		store: config.Store, auth: config.Auth, witnessKey: append(ed25519.PrivateKey(nil), config.WitnessPrivateKey...), lease: config.LeaseDuration,
		maxPoll: config.MaxPoll, enableMetrics: config.EnableMetrics, operationsThresholds: operationsThresholds,
		now: now, logger: logger, mux: http.NewServeMux(),
	}
	server.routes()
	return server, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			server.logger.Error("control HTTP panic recovered", "panic", recovered, "method", request.Method, "path", request.URL.Path)
			writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not complete the request")
		}
	}()
	server.mux.ServeHTTP(writer, request)
}

func (server *Server) routes() {
	server.mux.HandleFunc("/console", server.console)
	server.mux.HandleFunc("/console/", server.console)
	server.mux.HandleFunc("/v1/healthz", server.health)
	server.mux.HandleFunc("/v1/readiness", server.readiness)
	server.mux.HandleFunc("/v1/tenants", server.tenants)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}", server.tenant)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/freeze", server.tenantOperationalFreeze)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/quota", server.tenantResourceQuota)
	server.mux.HandleFunc("/v1/operators", server.operators)
	server.mux.HandleFunc("/v1/operators/{credential_id}", server.operator)
	server.mux.HandleFunc("/v1/enrollments", server.enrollments)
	server.mux.HandleFunc("/v1/enroll", server.enroll)
	server.mux.HandleFunc("/v1/node-credentials/{credential_id}", server.nodeCredential)
	server.mux.HandleFunc("/v1/nodes/{node_id}", server.nodeAdministration)
	server.mux.HandleFunc("/v1/nodes/{node_id}/placement", server.nodePlacement)
	server.mux.HandleFunc("/v1/nodes/{node_id}/drain", server.nodeDrain)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence", server.evidenceAdministration)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence/export", server.evidenceExport)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence/captures", server.evidenceCaptures)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence/captures/{capture_id}", server.evidenceCapture)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence/captures/{capture_id}/seal", server.evidenceCaptureSeal)
	server.mux.HandleFunc("/v1/nodes/{node_id}/evidence/captures/{capture_id}/export", server.evidenceCaptureExport)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/nodes", server.nodes)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/nodes/{node_id}", server.node)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/nodes/{node_id}/snapshots/{snapshot_id}/quarantine", server.snapshotQuarantine)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/nodes/{node_id}/commands", server.commands)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/nodes/{node_id}/commands/{command_id}", server.command)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/deployments", server.deployments)
	server.mux.HandleFunc("/v1/tenants/{tenant_id}/deployments/{deployment_id}", server.deployment)
	server.mux.HandleFunc("/v1/operations/summary", server.operationsSummary)
	server.mux.HandleFunc("/v1/operations/freeze", server.siteOperationalFreeze)
	server.mux.HandleFunc("/v1/operations/attention", server.operationsAttention)
	server.mux.HandleFunc("/v1/operations/agents", server.operationsAgents)
	server.mux.HandleFunc("/v1/operations/commands", server.operationsCommands)
	server.mux.HandleFunc("/v1/operations/credentials", server.operationsCredentials)
	server.mux.HandleFunc("/executor-uplink/poll", server.executorPoll)
	server.mux.HandleFunc("/executor-uplink/report", server.executorReport)
	server.mux.HandleFunc("/executor-uplink/scheduling", server.executorScheduling)
	server.mux.HandleFunc("/evidence-uplink/poll", server.evidencePoll)
	server.mux.HandleFunc("/evidence-uplink/report", server.evidenceReport)
	if server.enableMetrics {
		server.mux.HandleFunc("/metrics", server.metrics)
	}
	server.mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		writeError(writer, http.StatusNotFound, "not_found", "the requested control-plane route does not exist")
	})
}

func (server *Server) health(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) readiness(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	if _, err := server.store.Status(); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "not_ready", "durable control state is unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (server *Server) tenants(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodGet, http.MethodPost)
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPost:
		if !noQuery(writer, request) {
			return
		}
		var input struct {
			TenantID string `json:"tenant_id"`
		}
		if !server.decode(writer, request, &input) {
			return
		}
		tenant, created, err := server.store.CreateTenant(identity, input.TenantID, server.now())
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(writer, status, tenantView(tenant))
	case http.MethodGet:
		page, ok := parsePage(writer, request)
		if !ok {
			return
		}
		tenants, err := server.store.ListTenants(identity)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		selected, next := pageTenants(tenants, page)
		views := make([]tenantResponse, 0, len(selected))
		for _, tenant := range selected {
			views = append(views, tenantView(tenant))
		}
		writeJSON(writer, http.StatusOK, struct {
			Tenants   []tenantResponse `json:"tenants"`
			NextAfter string           `json:"next_after,omitempty"`
		}{Tenants: views, NextAfter: next})
	}
}

func (server *Server) tenant(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenant, found, err := server.store.GetTenant(identity, request.PathValue("tenant_id"))
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "not_found", "tenant was not found")
		return
	}
	writeJSON(writer, http.StatusOK, tenantView(tenant))
}

func (server *Server) operators(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		RequestID string           `json:"request_id"`
		Role      controlauth.Role `json:"role"`
		TenantID  string           `json:"tenant_id,omitempty"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	raw, credential, created, err := server.store.IssueOperator(identity, server.auth, input.RequestID, input.Role, input.TenantID, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(writer, status, struct {
		CredentialID string           `json:"credential_id"`
		Role         controlauth.Role `json:"role"`
		TenantID     string           `json:"tenant_id,omitempty"`
		Token        string           `json:"token"`
		CreatedAt    string           `json:"created_at"`
	}{credential.ID, credential.Role, credential.TenantID, raw, credential.CreatedAt})
}

func (server *Server) operator(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodDelete) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	revoked, err := server.store.RevokeOperator(identity, request.PathValue("credential_id"), server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	if !revoked {
		writeError(writer, http.StatusNotFound, "not_found", "operator credential was not found")
		return
	}
	writeNoContent(writer)
}

func (server *Server) enrollments(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		RequestID  string   `json:"request_id"`
		NodeID     string   `json:"node_id"`
		TenantIDs  []string `json:"tenant_ids"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	now := server.now()
	if input.TTLSeconds <= 0 || input.TTLSeconds > int64((24*time.Hour)/time.Second) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "ttl_seconds must be between 1 and 86400")
		return
	}
	raw, enrollment, _, created, err := server.store.CreateEnrollmentForRequest(
		identity, server.auth, input.RequestID, input.NodeID, input.TenantIDs,
		now.Add(time.Duration(input.TTLSeconds)*time.Second), now,
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(writer, status, struct {
		ControllerInstanceID string   `json:"controller_instance_id"`
		EnrollmentID         string   `json:"enrollment_id"`
		EnrollmentToken      string   `json:"enrollment_token"`
		NodeID               string   `json:"node_id"`
		TenantIDs            []string `json:"tenant_ids"`
		ExpiresAt            string   `json:"expires_at"`
	}{
		server.auth.InstanceID(), enrollment.ID, raw, enrollment.NodeID,
		append([]string(nil), enrollment.TenantIDs...), enrollment.ExpiresAt,
	})
}

func (server *Server) enroll(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	var input struct {
		EnrollmentToken       string                                          `json:"enrollment_token"`
		RequestID             string                                          `json:"request_id"`
		EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	credential, err := server.store.ExchangeEnrollment(
		server.auth, input.EnrollmentToken, input.RequestID, input.EvidenceIdentityProof, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusCreated, credential)
}

func (server *Server) nodeCredential(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodDelete) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	credentialID := request.PathValue("credential_id")
	nodeID, revoked, err := server.store.RevokeNodeCredential(identity, credentialID, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		CredentialID string `json:"credential_id"`
		NodeID       string `json:"node_id"`
		Revoked      bool   `json:"revoked"`
	}{CredentialID: credentialID, NodeID: nodeID, Revoked: revoked})
}

func (server *Server) nodeAdministration(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodDelete) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	revoked, err := server.store.RevokeNode(identity, request.PathValue("node_id"), server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		NodeID             string `json:"node_id"`
		RevokedCredentials int    `json:"revoked_credentials"`
	}{request.PathValue("node_id"), revoked})
}

func (server *Server) nodePlacement(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		Action controlstore.NodePlacementAction `json:"action"`
		Reason string                           `json:"reason,omitempty"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	node, changed, err := server.store.ChangeNodePlacement(
		identity, request.PathValue("node_id"), input.Action, input.Reason, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Node    nodeResponse `json:"node"`
		Changed bool         `json:"changed"`
	}{Node: nodeView(node), Changed: changed})
}

func (server *Server) nodeDrain(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPut && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodPut, http.MethodDelete)
		return
	}
	if !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason,omitempty"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	var node controlstore.Node
	var changed bool
	var err error
	if request.Method == http.MethodPut {
		node, changed, err = server.store.StartNodeDrain(
			identity, request.PathValue("node_id"), input.RequestID, input.Reason, server.now(),
		)
	} else {
		if input.Reason != "" {
			writeError(writer, http.StatusBadRequest, "invalid_request", "drain cancellation does not accept a reason")
			return
		}
		node, changed, err = server.store.CancelNodeDrain(
			identity, request.PathValue("node_id"), input.RequestID, server.now(),
		)
	}
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Node    nodeResponse `json:"node"`
		Changed bool         `json:"changed"`
	}{Node: nodeView(node), Changed: changed})
}

func (server *Server) evidenceAdministration(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	inspection, err := server.store.InspectExecutorEvidence(identity, request.PathValue("node_id"))
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	response := server.evidenceInspection(request.PathValue("node_id"), inspection)
	if err := response.Validate(); err != nil {
		server.logger.Error("retained Executor evidence inspection is invalid", "error", err, "node_id", request.PathValue("node_id"))
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode valid evidence state")
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) evidenceExport(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	nodeID := request.PathValue("node_id")
	for attempt := 0; attempt < maxEvidenceExportAttempts; attempt++ {
		snapshot, err := server.store.SnapshotExecutorEvidence(identity, nodeID)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		inspection := snapshot.Inspection
		if inspection.IdentityProof == nil {
			server.storeError(writer, controlstore.ErrConflict, false)
			return
		}
		statement := controlprotocol.ExecutorEvidenceExportStatementV1{
			ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: server.auth.InstanceID(),
			ControlNodeID: nodeID, IdentityProof: *inspection.IdentityProof, Status: inspection.Status,
			ExportedAt: server.now().UTC().Format(time.RFC3339Nano),
		}
		export, err := controlprotocol.SignExecutorEvidenceExportV1(statement, server.witnessKey)
		if err != nil {
			server.logger.Error("sign Executor evidence export", "error", err, "node_id", nodeID)
			writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not sign a valid evidence export")
			return
		}
		current, err := server.store.ExecutorEvidenceSnapshotCurrent(identity, nodeID, snapshot)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		if current {
			writeJSON(writer, http.StatusOK, export)
			return
		}
	}
	writer.Header().Set("Retry-After", strconv.Itoa(evidenceExportRetryAfter))
	writeError(
		writer,
		http.StatusConflict,
		"conflict",
		"evidence changed while the export was being signed; retry after the indicated delay",
	)
}

func (server *Server) evidenceCaptures(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		CaptureID             string `json:"capture_id"`
		RequestID             string `json:"request_id"`
		TenantID              string `json:"tenant_id"`
		RuntimeRef            string `json:"runtime_ref"`
		Generation            uint64 `json:"generation"`
		ActivationID          string `json:"activation_id"`
		ActivationBeginDigest string `json:"activation_begin_digest"`
		TTLSeconds            int64  `json:"ttl_seconds"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	if input.TTLSeconds < int64(controlstore.MinEvidenceCaptureTTL/time.Second) ||
		input.TTLSeconds > int64(controlstore.MaxEvidenceCaptureTTL/time.Second) {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			"ttl_seconds must be between 1 and 3600",
		)
		return
	}
	now := server.now().UTC()
	capture, created, err := server.store.ArmEvidenceCapture(
		identity,
		controlstore.EvidenceCaptureArmRequest{
			CaptureID: input.CaptureID, RequestID: input.RequestID,
			NodeID: request.PathValue("node_id"), TenantID: input.TenantID,
			RuntimeRef: input.RuntimeRef, Generation: input.Generation,
			ActivationID: input.ActivationID, ActivationBeginDigest: input.ActivationBeginDigest,
			TTL: time.Duration(input.TTLSeconds) * time.Second,
		},
		now,
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(writer, status, capture)
}

func (server *Server) evidenceCapture(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodGet, http.MethodDelete)
		return
	}
	if !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	if request.Method == http.MethodGet {
		capture, found, err := server.store.GetEvidenceCapture(
			identity,
			request.PathValue("capture_id"),
			server.now(),
		)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		if !found || capture.NodeID != request.PathValue("node_id") {
			writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
			return
		}
		writeJSON(writer, http.StatusOK, capture)
		return
	}
	deleted, err := server.store.DeleteEvidenceCapture(
		identity,
		request.PathValue("node_id"),
		request.PathValue("capture_id"),
		server.now(),
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	if !deleted {
		writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
		return
	}
	writeNoContent(writer)
}

func (server *Server) evidenceCaptureSeal(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		CanaryCommandID string `json:"canary_command_id"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	capture, _, err := server.store.SealEvidenceCapture(
		identity,
		request.PathValue("node_id"),
		request.PathValue("capture_id"),
		input.CanaryCommandID,
		server.now(),
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, capture)
}

func (server *Server) evidenceCaptureExport(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	nodeID := request.PathValue("node_id")
	captureID := request.PathValue("capture_id")
	for attempt := 0; attempt < maxEvidenceExportAttempts; attempt++ {
		now := server.now().UTC()
		snapshot, found, err := server.store.SnapshotEvidenceCaptureExport(
			identity,
			captureID,
			now,
		)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		if !found || snapshot.Capture.NodeID != nodeID {
			writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
			return
		}
		statement, err := snapshot.Statement(server.auth.InstanceID(), now)
		if err != nil {
			server.logger.Error(
				"construct evidence capture export",
				"error", err,
				"node_id", nodeID,
				"capture_id", captureID,
			)
			writeError(
				writer,
				http.StatusInternalServerError,
				"internal_error",
				"the control plane could not construct a valid evidence capture export",
			)
			return
		}
		export, err := controlprotocol.SignControllerEvidenceCaptureV1(
			statement,
			snapshot.Frames,
			server.witnessKey,
		)
		if err != nil {
			server.logger.Error(
				"sign evidence capture export",
				"error", err,
				"node_id", nodeID,
				"capture_id", captureID,
			)
			writeError(
				writer,
				http.StatusInternalServerError,
				"internal_error",
				"the control plane could not sign a valid evidence capture export",
			)
			return
		}
		current, err := server.store.EvidenceCaptureSnapshotCurrent(
			identity,
			snapshot,
			server.now(),
		)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		if current {
			writeJSON(writer, http.StatusOK, export)
			return
		}
	}
	writer.Header().Set("Retry-After", strconv.Itoa(evidenceExportRetryAfter))
	writeError(
		writer,
		http.StatusConflict,
		"conflict",
		"evidence capture changed while the export was being signed; retry after the indicated delay",
	)
}

func (server *Server) evidenceInspection(nodeID string, inspection controlstore.ExecutorEvidenceInspection) controlprotocol.ExecutorEvidenceInspectionV1 {
	return controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: server.auth.InstanceID(),
		ControlNodeID: nodeID, IdentityProof: inspection.IdentityProof, Status: inspection.Status,
	}
}

func (server *Server) nodes(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenantID := request.PathValue("tenant_id")
	nodes, err := server.store.ListNodes(identity, tenantID)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	views, next, err := pageNodeViews(nodes, page)
	if err != nil {
		server.logger.Error("control node page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded node page")
		return
	}
	writeJSON(writer, http.StatusOK, nodeListResponse{Nodes: views, NextAfter: next})
}

func (server *Server) node(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	node, found, err := server.store.GetNode(identity, request.PathValue("tenant_id"), request.PathValue("node_id"))
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "not_found", "node was not found")
		return
	}
	writeJSON(writer, http.StatusOK, nodeView(node))
}

func (server *Server) commands(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		CommandDSSEBase64 string `json:"command_dsse_base64"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	commandRaw, err := base64.StdEncoding.DecodeString(input.CommandDSSEBase64)
	if err != nil || base64.StdEncoding.EncodeToString(commandRaw) != input.CommandDSSEBase64 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "command_dsse_base64 must be canonical base64")
		return
	}
	command, created, err := server.store.SubmitCommand(
		identity, request.PathValue("tenant_id"), request.PathValue("node_id"), commandRaw, server.now(),
	)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(writer, status, commandView(command))
}

func (server *Server) command(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	command, found, err := server.store.GetCommand(identity, request.PathValue("tenant_id"), request.PathValue("node_id"), request.PathValue("command_id"))
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "not_found", "command was not found")
		return
	}
	writeJSON(writer, http.StatusOK, commandView(command))
}

func (server *Server) executorPoll(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	version, err := executorProtocolVersion(raw)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request body must contain one supported executor protocol version")
		return
	}
	switch version {
	case controlprotocol.ExecutorProtocolV3:
		var input controlprotocol.ExecutorPollRequestV3
		if err := dsse.DecodeStrictInto(raw, maxRequestBytes, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request body must be one strict JSON object")
			return
		}
		if input.CredentialScope != "node" || input.NodeID != identity.NodeID {
			writeError(writer, http.StatusBadRequest, "invalid_request", "poll identity or protocol does not match the authenticated node")
			return
		}
		deliveries, err := server.store.Poll(identity, input.Capabilities, server.now(), server.lease, server.maxPoll)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			ProtocolVersion int                                  `json:"protocol_version"`
			Deliveries      []controlprotocol.ExecutorDeliveryV3 `json:"deliveries"`
		}{ProtocolVersion: controlprotocol.ExecutorProtocolV3, Deliveries: deliveries})
	case controlprotocol.ExecutorProtocolV4:
		var input controlprotocol.ExecutorPollRequestV4
		if err := dsse.DecodeStrictInto(raw, maxRequestBytes, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request body must be one strict JSON object")
			return
		}
		if input.CredentialScope != "node" || input.NodeID != identity.NodeID {
			writeError(writer, http.StatusBadRequest, "invalid_request", "poll identity or protocol does not match the authenticated node")
			return
		}
		deliveries, err := server.store.PollV4(identity, input.Capabilities, server.now(), server.lease, server.maxPoll)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			ProtocolVersion int                                  `json:"protocol_version"`
			Deliveries      []controlprotocol.ExecutorDeliveryV4 `json:"deliveries"`
		}{ProtocolVersion: controlprotocol.ExecutorProtocolV4, Deliveries: deliveries})
	default:
		writeError(writer, http.StatusBadRequest, "invalid_request", "poll identity or protocol does not match the authenticated node")
	}
}

func (server *Server) executorScheduling(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	var observation controlprotocol.ExecutorSchedulingObservationV1
	if len(raw) > controlprotocol.MaxExecutorSchedulingBytes ||
		dsse.DecodeStrictInto(raw, controlprotocol.MaxExecutorSchedulingBytes, &observation) != nil ||
		observation.Validate() != nil || observation.NodeID != identity.NodeID {
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor scheduling observation is invalid")
		return
	}
	node, applied, err := server.store.ObserveNodeScheduling(identity, observation, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Applied    bool   `json:"applied"`
		ObservedAt string `json:"observed_at"`
	}{Applied: applied, ObservedAt: node.Scheduling.ObservedAt})
}

func (server *Server) executorReport(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	version, err := executorProtocolVersion(raw)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request body must contain one supported executor protocol version")
		return
	}
	switch version {
	case controlprotocol.ExecutorProtocolV3:
		var report controlprotocol.ExecutorReportV3
		if err := dsse.DecodeStrictInto(raw, maxRequestBytes, &report); err != nil || report.Validate() != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "executor report is invalid")
			return
		}
		applied, err := server.store.ApplyReport(identity, report, server.now())
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeJSON(writer, http.StatusOK, controlprotocol.ExecutorReportResponseV3{
			ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: applied,
		})
	case controlprotocol.ExecutorProtocolV4:
		report, err := controlprotocol.DecodeExecutorReportV4(raw)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "executor report is invalid")
			return
		}
		applied, err := server.store.ApplyReportV4(identity, report, server.now())
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeJSON(writer, http.StatusOK, controlprotocol.ExecutorReportResponseV4{
			ProtocolVersion: controlprotocol.ExecutorProtocolV4, Applied: applied,
		})
	default:
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor report protocol is unsupported")
	}
}

func (server *Server) evidencePoll(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	var input controlprotocol.ExecutorEvidencePollRequestV1
	if !server.decode(writer, request, &input) {
		return
	}
	now := server.now()
	response, err := server.store.PollExecutorEvidence(server.auth, identity, input, now, now.Add(evidenceChallengeLifetime))
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) evidenceReport(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	var report controlprotocol.ExecutorEvidenceReportV1
	if !server.decode(writer, request, &report) {
		return
	}
	response, err := server.store.ApplyExecutorEvidenceReport(server.auth, identity, report, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) operatorIdentity(writer http.ResponseWriter, request *http.Request) (controlauth.Identity, bool) {
	token, ok := bearer(writer, request)
	if !ok {
		return controlauth.Identity{}, false
	}
	identity, err := server.store.AuthenticateOperator(server.auth, token)
	if err != nil {
		server.storeError(writer, err, false)
		return controlauth.Identity{}, false
	}
	return identity, true
}

func (server *Server) nodeIdentity(writer http.ResponseWriter, request *http.Request) (controlauth.NodeIdentity, bool) {
	token, ok := bearer(writer, request)
	if !ok {
		return controlauth.NodeIdentity{}, false
	}
	identity, err := server.store.AuthenticateNode(server.auth, token)
	if err != nil {
		server.storeError(writer, err, false)
		return controlauth.NodeIdentity{}, false
	}
	return identity, true
}

func bearer(writer http.ResponseWriter, request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "one bearer credential is required")
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "one bearer credential is required")
		return "", false
	}
	if token == "" || len(token) > 4096 || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n\x00") {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "bearer credential is invalid")
		return "", false
	}
	return token, true
}

func (server *Server) decode(writer http.ResponseWriter, request *http.Request, destination any) bool {
	raw, ok := server.readBody(writer, request)
	if !ok {
		return false
	}
	if err := dsse.DecodeStrictInto(raw, maxRequestBytes, destination); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request body must be one strict JSON object")
		return false
	}
	return true
}

func (server *Server) readBody(writer http.ResponseWriter, request *http.Request) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return nil, false
	}
	reader := http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(writer, http.StatusRequestEntityTooLarge, "payload_too_large", errBodyTooLarge.Error())
		} else {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request body could not be read")
		}
		return nil, false
	}
	return raw, true
}

func executorProtocolVersion(raw []byte) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return 0, errors.New("executor request must be one JSON object")
	}
	seen := make(map[string]struct{})
	version := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return 0, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return 0, errors.New("executor request field name is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return 0, fmt.Errorf("executor request contains duplicate field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return 0, err
		}
		if key == "protocol_version" {
			if err := json.Unmarshal(value, &version); err != nil || version <= 0 {
				return 0, errors.New("executor protocol version is invalid")
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return 0, errors.New("executor request object is not terminated")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return 0, errors.New("executor request contains trailing JSON")
	}
	if version == 0 {
		return 0, errors.New("executor protocol version is missing")
	}
	return version, nil
}

func (server *Server) storeError(writer http.ResponseWriter, err error, hideForbidden bool) {
	switch {
	case errors.Is(err, controlauth.ErrUnauthorized):
		writeError(writer, http.StatusUnauthorized, "unauthorized", "control credential is invalid or revoked")
	case errors.Is(err, controlauth.ErrEnrollmentConsumed), errors.Is(err, controlstore.ErrConflict):
		writeError(writer, http.StatusConflict, "conflict", "request conflicts with retained control state")
	case errors.Is(err, controlauth.ErrEnrollmentExpired):
		writeError(writer, http.StatusGone, "enrollment_expired", "enrollment capability has expired")
	case errors.Is(err, controlstore.ErrForbidden):
		if hideForbidden {
			writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
		} else {
			writeError(writer, http.StatusForbidden, "forbidden", "credential does not authorize this operation")
		}
	case errors.Is(err, controlstore.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, controlstore.ErrInvalid):
		writeError(writer, http.StatusBadRequest, "invalid_request", "request does not satisfy the control-plane contract")
	case errors.Is(err, controlstore.ErrCapacityExceeded):
		writeError(writer, http.StatusServiceUnavailable, "capacity_exceeded", "bounded control-plane capacity is exhausted")
	case errors.Is(err, controlstore.ErrOperationallyFrozen):
		writeError(writer, http.StatusLocked, "operationally_frozen", "new command delivery is frozen for this scope")
	case errors.Is(err, controlstore.ErrSnapshotQuarantined):
		writeError(writer, http.StatusLocked, "snapshot_quarantined", "snapshot is quarantined and cannot seed a new fork")
	case errors.Is(err, controlstore.ErrUnavailable):
		writeError(writer, http.StatusServiceUnavailable, "not_ready", "durable control state requires recovery")
	default:
		server.logger.Error("control store operation failed", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not complete the request")
	}
}

type tenantResponse struct {
	TenantID string `json:"tenant_id"`
	State    string `json:"state"`
	Created  string `json:"created_at"`
}

func tenantView(tenant controlstore.Tenant) tenantResponse {
	state := "inactive"
	if tenant.Active {
		state = "active"
	}
	return tenantResponse{TenantID: tenant.ID, State: state, Created: tenant.CreatedAt}
}

type nodeResponse struct {
	NodeID       string                       `json:"node_id"`
	TenantIDs    []string                     `json:"tenant_ids"`
	Capabilities []string                     `json:"capabilities"`
	State        string                       `json:"state"`
	CreatedAt    string                       `json:"created_at"`
	LastSeenAt   string                       `json:"last_seen_at,omitempty"`
	RevokedAt    string                       `json:"revoked_at,omitempty"`
	Scheduling   *controlstore.NodeScheduling `json:"scheduling,omitempty"`
	Placement    controlstore.NodePlacement   `json:"placement"`
	Drain        *controlstore.NodeDrain      `json:"drain,omitempty"`
}

type nodeListResponse struct {
	Nodes     []nodeResponse `json:"nodes"`
	NextAfter string         `json:"next_after,omitempty"`
}

func nodeView(node controlstore.Node) nodeResponse {
	state := "revoked"
	if node.Active {
		state = "active"
	}
	return nodeResponse{
		NodeID: node.ID, TenantIDs: append([]string(nil), node.TenantIDs...),
		Capabilities: append([]string{}, node.Capabilities...), State: state,
		CreatedAt: node.CreatedAt, LastSeenAt: node.LastSeenAt, RevokedAt: node.RevokedAt,
		Scheduling: node.Scheduling,
		Placement:  controlstore.EffectiveNodePlacement(node),
		Drain:      node.Drain,
	}
}

type commandResponse struct {
	CommandID                       string                 `json:"command_id"`
	DeliveryID                      string                 `json:"delivery_id"`
	TenantID                        string                 `json:"tenant_id"`
	NodeID                          string                 `json:"node_id"`
	CommandDigest                   string                 `json:"command_digest"`
	CommandKind                     string                 `json:"command_kind,omitempty"`
	SignedRuntimeRef                string                 `json:"signed_runtime_ref,omitempty"`
	SignedClaimGeneration           uint64                 `json:"signed_claim_generation,omitempty"`
	SignedInstanceGeneration        uint64                 `json:"signed_instance_generation,omitempty"`
	State                           string                 `json:"state"`
	DeliveryProtocol                int                    `json:"delivery_protocol,omitempty"`
	DeliveryGeneration              uint64                 `json:"delivery_generation,omitempty"`
	LeaseExpiresAt                  string                 `json:"lease_expires_at,omitempty"`
	TerminalStatus                  string                 `json:"terminal_status,omitempty"`
	ReportedStatus                  string                 `json:"reported_status,omitempty"`
	ErrorCode                       string                 `json:"error_code,omitempty"`
	ClaimGeneration                 *uint64                `json:"claim_generation,omitempty"`
	AdmissionProjectionState        string                 `json:"admission_projection_state,omitempty"`
	ActivationCanaryProjectionState string                 `json:"activation_canary_projection_state,omitempty"`
	Result                          *commandResultResponse `json:"result,omitempty"`
}

type commandResultResponse struct {
	RuntimeRef       string                                            `json:"runtime_ref,omitempty"`
	Error            string                                            `json:"error,omitempty"`
	Replayed         bool                                              `json:"replayed,omitempty"`
	Absent           bool                                              `json:"absent,omitempty"`
	Admission        *controlprotocol.ExecutorAdmissionProjectionV1    `json:"admission,omitempty"`
	ActivationCanary *controlprotocol.ExecutorActivationCanaryResultV1 `json:"activation_canary,omitempty"`
}

func commandView(command controlstore.Command) commandResponse {
	response := commandResponse{
		CommandID: command.ID, DeliveryID: command.DeliveryID, TenantID: command.TenantID,
		NodeID: command.NodeID, CommandDigest: command.Digest,
		CommandKind: command.CommandKind, SignedRuntimeRef: command.SignedRuntimeRef,
		SignedClaimGeneration:    command.SignedClaimGeneration,
		SignedInstanceGeneration: command.SignedInstanceGeneration,
		State:                    string(command.State), DeliveryProtocol: command.DeliveryProtocol,
		DeliveryGeneration: command.DeliveryGeneration, LeaseExpiresAt: command.LeaseUntil,
	}
	if command.Terminal != nil {
		claimGeneration := command.Terminal.Report.ClaimGeneration
		retained := command.Terminal.Report.Result
		result := commandResultResponse{
			RuntimeRef: retained.RuntimeRef, Error: retained.Error,
			Replayed: retained.Replayed, Absent: retained.Absent,
			Admission:        command.Terminal.Admission,
			ActivationCanary: command.Terminal.ActivationCanary,
		}
		response.TerminalStatus = command.Terminal.Report.Status
		response.ReportedStatus = command.Terminal.Report.ReportedStatus
		response.ErrorCode = command.Terminal.Report.ErrorCode
		response.ClaimGeneration = &claimGeneration
		response.Result = &result
		if command.CommandKind == "admit" && command.Terminal.Report.Status == controlprotocol.ExecutorStatusDone {
			response.AdmissionProjectionState = "missing"
			if command.Terminal.Admission != nil {
				response.AdmissionProjectionState = "present"
			}
		}
		if command.CommandKind == "activation-canary" &&
			command.Terminal.Report.Status == controlprotocol.ExecutorStatusDone {
			response.ActivationCanaryProjectionState = "missing"
			if command.Terminal.ActivationCanary != nil {
				response.ActivationCanaryProjectionState = "present"
			}
		}
	}
	return response
}

type pageRequest struct {
	after string
	limit int
}

func parsePage(writer http.ResponseWriter, request *http.Request) (pageRequest, bool) {
	for key, values := range request.URL.Query() {
		if (key != "after" && key != "limit") || len(values) != 1 {
			writeError(writer, http.StatusBadRequest, "invalid_request", "pagination accepts one after and one limit value")
			return pageRequest{}, false
		}
	}
	page := pageRequest{after: request.URL.Query().Get("after"), limit: defaultPageSize}
	if value := request.URL.Query().Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 || limit > maxPageSize {
			writeError(writer, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 500")
			return pageRequest{}, false
		}
		page.limit = limit
	}
	if len(page.after) > 128 || strings.ContainsAny(page.after, "\r\n\x00") {
		writeError(writer, http.StatusBadRequest, "invalid_request", "after cursor is invalid")
		return pageRequest{}, false
	}
	return page, true
}

func pageTenants(values []controlstore.Tenant, page pageRequest) ([]controlstore.Tenant, string) {
	start := sort.Search(len(values), func(index int) bool { return values[index].ID > page.after })
	end := start + page.limit
	if end >= len(values) {
		return values[start:], ""
	}
	return values[start:end], values[end-1].ID
}

func pageNodeViews(values []controlstore.Node, page pageRequest) ([]nodeResponse, string, error) {
	start := sort.Search(len(values), func(index int) bool { return values[index].ID > page.after })
	views := make([]nodeResponse, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(views) < page.limit; index++ {
		candidate := append(append([]nodeResponse(nil), views...), nodeView(values[index]))
		next := ""
		if index+1 < len(values) {
			next = values[index].ID
		}
		raw, err := json.Marshal(nodeListResponse{Nodes: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(views) == 0 {
				return nil, "", errors.New("one valid node cannot fit the response limit")
			}
			break
		}
		views = candidate
	}
	next := ""
	if start+len(views) < len(values) {
		next = views[len(views)-1].NodeID
	}
	return views, next, nil
}

func method(writer http.ResponseWriter, request *http.Request, expected string) bool {
	if request.Method == expected {
		return true
	}
	methodNotAllowed(writer, expected)
	return false
}

func methodNotAllowed(writer http.ResponseWriter, allowed ...string) {
	writer.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "HTTP method is not allowed for this route")
}

func noQuery(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery == "" {
		return true
	}
	writeError(writer, http.StatusBadRequest, "invalid_request", "query parameters are not accepted on this route")
	return false
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > maxResponseBytes {
		writeError(writer, http.StatusInternalServerError, "internal_error", "response could not be encoded within its limit")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(raw, '\n'))
}

func writeNoContent(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusNoContent)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	raw, err := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{Error: code, Message: message})
	if err != nil {
		raw = []byte(`{"error":"internal_error","message":"error response could not be encoded"}`)
		status = http.StatusInternalServerError
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, "%s\n", raw)
}
