package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
)

const (
	maxBodyBytes                      = 1 << 20
	activationAdmissionRequestSchema  = "steward.executor-activation-admission.v1"
	activationCanaryPreflightSchema   = "steward.executor-activation-canary-preflight.v1"
	activationCheckpointRequestSchema = "steward.executor-activation-checkpoint.v1"
)

// Server is the authenticated control boundary in front of the local Docker API.
// The bearer token is a host-control credential; tenant authorization belongs in the
// upstream control plane and must never be inferred from a caller-supplied label.
type Server struct {
	docker           Docker
	localCredentials []localCredentialVerifier
	policy           HostPolicy
	logger           *slog.Logger
	secure           *secureAdmission

	// provisionMu makes the count-then-create admission check atomic within the
	// one Docker-socket-bearing executor process. Docker inventory makes the
	// counts restart-safe; this lock prevents concurrent HTTP calls from racing
	// past the same ceiling.
	provisionMu sync.Mutex

	reconcileMu        sync.RWMutex
	reconcileAttempted bool
	reconcileAt        time.Time
	reconcileReport    ReconcileReport
}

type secureAdmission struct {
	policyEnvelope      []byte
	siteRoots           map[string]ed25519.PublicKey
	nodeID              string
	fences              *admission.FenceStore
	journal             *journal.Journal
	evidence            *evidence.Log
	allowHostAdmin      bool
	allowUnquotaedState bool
	topology            TopologyDocker
	gateway             GatewayControl
	relayImage          string
	grantRoot           string
	relayGID            int
}

type GatewayControl interface {
	Register(context.Context, gateway.Grant) error
	Inspect(context.Context, string) (gateway.Grant, error)
	InspectWithPolicy(context.Context, string) (gateway.GrantInspection, error)
	Activate(context.Context, string) error
	Deactivate(context.Context, string) error
	Unregister(context.Context, string) error
	EgressStats(context.Context, string) (gateway.EgressStats, error)
}

// SecureAdmissionConfig enables the signed admission path. All fields are
// mandatory because a partially configured authority chain must fail closed.
type SecureAdmissionConfig struct {
	PolicyEnvelope []byte
	SiteRoots      map[string]ed25519.PublicKey
	NodeID         string
	Fences         *admission.FenceStore
	Journal        *journal.Journal
	Evidence       *evidence.Log
	// AllowHostAdminIntent permits the host-wide loopback bearer credential to
	// select a tenant. Leave false when tenant identity must come from an
	// authenticated uplink principal.
	AllowHostAdminIntent bool
	// AllowUnquotaedStateOnDedicatedHost enables Docker local-volume state even
	// though it has no portable hard byte or inode quota. It must remain false on
	// shared multi-tenant hosts.
	AllowUnquotaedStateOnDedicatedHost bool
	// Positive-capability topology is optional as a complete unit. When absent,
	// inference, service, and egress fail closed. State also fails closed unless
	// the dedicated-host-only unquotaed compatibility flag is explicit.
	Topology   TopologyDocker
	Gateway    GatewayControl
	RelayImage string
	GrantRoot  string
	RelayGID   int
}

type admissionPrincipal struct {
	tenantID   string
	nodeID     string
	generation uint64
}

type admissionPrincipalKey struct{}

// WithAdmissionPrincipal carries identity already authenticated by the
// Executor uplink into the in-process HTTP handler. Network callers cannot
// manufacture this context value with headers or request JSON.
func WithAdmissionPrincipal(ctx context.Context, tenantID, nodeID string, generation uint64) context.Context {
	return context.WithValue(ctx, admissionPrincipalKey{}, admissionPrincipal{
		tenantID: tenantID, nodeID: nodeID, generation: generation,
	})
}

func NewServer(docker Docker, token string, logger *slog.Logger) (*Server, error) {
	return NewServerWithPolicy(docker, token, DefaultHostPolicy(), logger)
}

// EnableSecureAdmission installs the signed local authority chain before the
// server begins serving. A recovered pending journal operation is accepted so
// the process can expose liveness, readiness, inspection, and authenticated
// fail-closed containment. Expansive or irreversible mutations remain blocked
// until an operator resolves the ambiguous operation and reconciliation passes.
func (s *Server) EnableSecureAdmission(config SecureAdmissionConfig) error {
	if len(config.PolicyEnvelope) == 0 || len(config.SiteRoots) == 0 ||
		strings.TrimSpace(config.NodeID) == "" || config.Fences == nil ||
		config.Journal == nil || config.Evidence == nil {
		return errors.New("complete secure admission configuration is required")
	}
	if config.Fences.Count() > 0 && config.Evidence.NextSequence() == 1 {
		return errors.New("evidence chain is empty but admission fences exist; restore the prior chain")
	}
	topologyRequested := config.Topology != nil || config.Gateway != nil || config.RelayImage != "" || config.GrantRoot != "" || config.RelayGID != 0
	if topologyRequested && (config.Topology == nil || config.Gateway == nil || !relayImageDigest.MatchString(config.RelayImage) ||
		!filepath.IsAbs(config.GrantRoot) || filepath.Clean(config.GrantRoot) != config.GrantRoot || config.RelayGID <= 0) {
		return errors.New("positive-capability topology requires Docker topology, gateway, immutable relay image, clean grant root, and relay GID")
	}
	// Verify policy authenticity and shape now, then verify it again as part of
	// every admission. Startup validation catches bad key/config deployment early.
	policyPayload, _, err := dsse.Verify(config.PolicyEnvelope, admission.PolicyPayloadType, config.SiteRoots)
	if err != nil {
		return fmt.Errorf("verify site policy: %w", err)
	}
	var policy admission.SitePolicy
	if err := dsse.DecodeStrictInto(policyPayload, dsse.DefaultMaxEnvelopeBytes, &policy); err != nil {
		return fmt.Errorf("decode site policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("validate site policy: %w", err)
	}
	if config.AllowUnquotaedStateOnDedicatedHost && len(policy.Tenants) != 1 {
		return errors.New("unquotaed persistent state requires a signed site policy with exactly one tenant")
	}
	s.secure = &secureAdmission{
		policyEnvelope:      append([]byte(nil), config.PolicyEnvelope...),
		siteRoots:           clonePublicKeys(config.SiteRoots),
		nodeID:              config.NodeID,
		fences:              config.Fences,
		journal:             config.Journal,
		evidence:            config.Evidence,
		allowHostAdmin:      config.AllowHostAdminIntent,
		allowUnquotaedState: config.AllowUnquotaedStateOnDedicatedHost,
		topology:            config.Topology, gateway: config.Gateway, relayImage: config.RelayImage,
		grantRoot: config.GrantRoot, relayGID: config.RelayGID,
	}
	s.reconcileMu.Lock()
	s.reconcileAttempted = false
	s.reconcileAt = time.Time{}
	s.reconcileReport = ReconcileReport{}
	s.reconcileMu.Unlock()
	return nil
}

func NewServerWithPolicy(
	docker Docker, token string, policy HostPolicy, logger *slog.Logger,
) (*Server, error) {
	return NewServerWithLocalCredentials(docker, []LocalCredential{{
		ID: "host-admin", Role: LocalRoleHostAdmin, Token: token,
	}}, policy, logger)
}

// NewServerWithLocalCredentials configures explicit role-scoped identities for
// the loopback API. Exactly one host administrator is required so recovery and
// configuration operations cannot become unreachable through partial setup.
func NewServerWithLocalCredentials(
	docker Docker, credentials []LocalCredential, policy HostPolicy, logger *slog.Logger,
) (*Server, error) {
	if docker == nil {
		return nil, errors.New("docker client is required")
	}
	verifiers, err := buildLocalCredentialVerifiers(credentials)
	if err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid host policy: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		docker: docker, localCredentials: verifiers, policy: policy, logger: logger,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/workloads", requireLocalRole(LocalRoleHostAdmin, s.provision))
	mux.HandleFunc("POST /v1/admissions", requireLocalRole(LocalRoleHostAdmin, s.secureProvision))
	mux.HandleFunc("GET /v1/local-principal", requireLocalRole(LocalRoleObserver, s.localPrincipal))
	mux.HandleFunc("GET /v1/maintenance", requireLocalRole(LocalRoleObserver, s.maintenanceStatus))
	mux.HandleFunc("POST /v1/maintenance/enter", requireLocalRole(LocalRoleOperator, s.maintenanceEnter))
	mux.HandleFunc("POST /v1/maintenance/exit", requireLocalRole(LocalRoleOperator, s.maintenanceExit))
	mux.HandleFunc("POST /v1/state/purge", requireLocalRole(LocalRoleHostAdmin, s.purgeState))
	mux.HandleFunc(
		"POST /v1/workloads/{id}/activation-canary-preflight",
		requireLocalRole(LocalRoleHostAdmin, s.activationCanaryPreflight),
	)
	mux.HandleFunc(
		"POST /v1/workloads/{id}/activation-checkpoints",
		requireLocalRole(LocalRoleHostAdmin, s.activationCheckpoint),
	)
	mux.HandleFunc("POST /v1/workloads/{id}/start", requireLocalRole(LocalRoleOperator, s.start))
	mux.HandleFunc("POST /v1/workloads/{id}/stop", requireLocalRole(LocalRoleOperator, s.stop))
	mux.HandleFunc("DELETE /v1/workloads/{id}", requireLocalRole(LocalRoleOperator, s.destroy))
	mux.HandleFunc("GET /v1/workloads/{id}", requireLocalRole(LocalRoleObserver, s.status))
	mux.HandleFunc("GET /v1/workloads/{id}/logs", requireLocalRole(LocalRoleObserver, s.logs))
	mux.HandleFunc("GET /v1/workloads/{id}/egress", requireLocalRole(LocalRoleObserver, s.egressStats))
	mux.HandleFunc("GET /v1/readiness", requireLocalRole(LocalRoleObserver, s.readiness))
	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return recoverMiddleware(jsonErrors(s.auth(mux), s.logger), s.logger)
}

func (s *Server) readiness(w http.ResponseWriter, _ *http.Request) {
	if s.secure == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready", "secure_admission": false,
		})
		return
	}
	s.reconcileMu.RLock()
	attempted, at, report := s.reconcileAttempted, s.reconcileAt, s.reconcileReport
	s.reconcileMu.RUnlock()
	status, code := "reconciling", http.StatusServiceUnavailable
	if attempted && report.Ready {
		status, code = "ready", http.StatusOK
	} else if attempted {
		status = "degraded"
	}
	response := map[string]any{
		"status": status, "secure_admission": true, "reconciliation": report,
	}
	if !at.IsZero() {
		response["last_attempt"] = at.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, code, response)
}

type secureProvisionRequest struct {
	CapsuleDSSEBase64 string                      `json:"capsule_dsse_base64"`
	Intent            admission.InstanceIntent    `json:"intent"`
	Activation        *activationAdmissionRequest `json:"activation,omitempty"`
}

type activationAdmissionRequest struct {
	SchemaVersion string `json:"schema_version"`
	ActivationID  string `json:"activation_id"`
	BeginDigest   string `json:"begin_digest"`
}

type secureProvisionResponse struct {
	RuntimeRef              string                         `json:"runtime_ref"`
	Status                  string                         `json:"status"`
	CapsuleDigest           string                         `json:"capsule_digest"`
	PolicyDigest            string                         `json:"policy_digest"`
	Generation              uint64                         `json:"generation"`
	EvidenceKeyID           string                         `json:"evidence_key_id"`
	GrantID                 string                         `json:"grant_id,omitempty"`
	ServicePath             string                         `json:"service_path,omitempty"`
	ServiceID               string                         `json:"service_id,omitempty"`
	TaskAuthorities         []gateway.TaskAuthority        `json:"task_authorities,omitempty"`
	EgressProxy             string                         `json:"egress_proxy,omitempty"`
	EgressRouteIDs          []string                       `json:"egress_route_ids,omitempty"`
	ConnectorURL            string                         `json:"connector_url,omitempty"`
	ConnectorIDs            []string                       `json:"connector_ids,omitempty"`
	EffectMode              string                         `json:"effect_mode,omitempty"`
	ActionApprovalThreshold int                            `json:"action_approval_threshold,omitempty"`
	ActionContextRequired   bool                           `json:"action_context_required,omitempty"`
	ActionAuthorities       []gateway.GrantActionAuthority `json:"action_authorities,omitempty"`
	RoutePolicyDigest       string                         `json:"route_policy_digest,omitempty"`
	ActivationID            string                         `json:"activation_id,omitempty"`
	ActivationBeginDigest   string                         `json:"activation_begin_digest,omitempty"`
}

type purgeStateRequest struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
}

type activationCheckpointRequest struct {
	SchemaVersion    string `json:"schema_version"`
	ActivationID     string `json:"activation_id"`
	CheckpointDigest string `json:"checkpoint_digest"`
}

type activationCanaryPreflightRequest struct {
	SchemaVersion         string `json:"schema_version"`
	ActivationID          string `json:"activation_id"`
	ActivationBeginDigest string `json:"activation_begin_digest"`
}

func (s *Server) secureProvision(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the admission limit")
		return
	}
	var request secureProvisionRequest
	if err := dsse.DecodeStrictInto(raw, maxBodyBytes, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one strict admission object")
		return
	}
	if request.Activation != nil &&
		(request.Activation.SchemaVersion != activationAdmissionRequestSchema ||
			!activationCheckpointID(request.Activation.ActivationID) ||
			!imageConfigDigest.MatchString(request.Activation.BeginDigest)) {
		writeError(w, http.StatusBadRequest, "invalid_request", "activation admission metadata is invalid")
		return
	}
	capsuleEnvelope, err := base64.StdEncoding.DecodeString(request.CapsuleDSSEBase64)
	if err != nil || len(capsuleEnvelope) == 0 || len(capsuleEnvelope) > dsse.DefaultMaxEnvelopeBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "capsule_dsse_base64 must contain one bounded DSSE envelope")
		return
	}
	if request.Intent.NodeID != s.secure.nodeID {
		writeError(w, http.StatusForbidden, "admission_denied", "instance intent is not bound to this node")
		return
	}
	principal, authenticated := r.Context().Value(admissionPrincipalKey{}).(admissionPrincipal)
	if !authenticated {
		if !s.secure.allowHostAdmin {
			writeError(w, http.StatusForbidden, "tenant_identity_required", "signed admission requires an authenticated uplink principal")
			return
		}
		principal = admissionPrincipal{tenantID: request.Intent.TenantID, nodeID: s.secure.nodeID, generation: request.Intent.Generation}
	}
	if principal.generation != request.Intent.Generation {
		writeError(w, http.StatusForbidden, "admission_denied", "instance intent generation does not match the authenticated command")
		return
	}
	fences := s.secure.fences.Fences(request.Intent.TenantID, request.Intent.InstanceID)
	effective, err := admission.VerifyAndAdmit(
		capsuleEnvelope, s.secure.policyEnvelope, s.secure.siteRoots, request.Intent,
		admission.AuthenticatedIdentity{TenantID: principal.tenantID, NodeID: principal.nodeID},
		fences, time.Now().UTC(), admission.DefaultProfiles(),
	)
	if err != nil {
		writeError(w, http.StatusForbidden, "admission_denied", err.Error())
		return
	}
	workload := Workload{
		InstanceID: effective.Intent.InstanceID,
		TenantID:   effective.Intent.TenantID,
		ProfileID:  effective.Profile.Ref.ID + "@" + effective.Profile.Ref.Version,
		Image:      effective.Capsule.Image.Repository + "@" + effective.Capsule.Image.ManifestDigest,
		Command:    append([]string(nil), effective.Capsule.Command...),
		Resources: Resources{
			MemoryBytes: effective.EffectiveResources.MemoryBytes,
			CPUMillis:   effective.EffectiveResources.CPUMillis,
			PIDs:        effective.EffectiveResources.PIDs,
		},
		Egress: Egress{},
	}
	imageDocker, ok := s.docker.(ImageDocker)
	if !ok {
		writeError(w, http.StatusNotImplemented, "capability_unavailable", "signed image inspection is unavailable with this Docker backend")
		return
	}
	imageReference := effective.Capsule.Image.Repository + "@" + effective.Capsule.Image.ManifestDigest
	observedImage, err := imageDocker.InspectSignedImage(r.Context(), imageReference, effective.Capsule.Image.ConfigDigest)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusConflict, "image_unavailable", "the exact signed image is not loaded on this node")
		return
	}
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if err := ValidateImage(observedImage, ImageRequirement{
		ManifestDigest: effective.Capsule.Image.ManifestDigest,
		ConfigDigest:   effective.Capsule.Image.ConfigDigest,
		OS:             effective.Capsule.Image.Platform.OS,
		Architecture:   effective.Capsule.Image.Platform.Architecture,
		Variant:        effective.Capsule.Image.Platform.Variant,
	}); err != nil {
		writeError(w, http.StatusConflict, "image_rejected", err.Error())
		return
	}
	// Docker create uses this exact verified local content ID. The signed
	// repository@manifest value remains attached as provenance, but is not used
	// as an offline lookup alias because docker load may not preserve it.
	workload.ImageConfigDigest = effective.Capsule.Image.ConfigDigest
	workload.ImageRuntimeDigest = observedImage.ID
	// Every mount, network and grant identifier is Executor-derived. The signed
	// request selects only finite capabilities already authorized by capsule and
	// site policy; it never supplies a host path or Docker topology primitive.
	if effective.Intent.Capabilities.Inference || effective.Intent.Capabilities.Service || effective.Intent.Capabilities.Egress || effective.Intent.Capabilities.Connector {
		if s.secure.topology == nil || s.secure.gateway == nil {
			writeError(w, http.StatusNotImplemented, "capability_unavailable", "inference, service, egress, and connector capabilities require the configured gateway topology")
			return
		}
		workload.Runtime = &RuntimeGrant{
			NetworkName: NetworkName(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation),
			GrantID:     gateway.GrantID(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation),
			Generation:  effective.Intent.Generation,
			Inference:   effective.Intent.Capabilities.Inference, ModelAlias: effective.Intent.ModelAlias,
			RouteID:        effective.Intent.InferenceRouteID,
			EgressRouteIDs: admission.CanonicalRouteIDs(effective.Intent.EgressRouteIDs),
			ConnectorIDs:   admission.CanonicalConnectorIDs(effective.Intent.ConnectorIDs),
			EffectMode:     effective.Intent.EffectMode,
			CapsuleDigest:  effective.CapsuleDigest, PolicyDigest: effective.PolicyDigest,
		}
		if effective.Intent.EffectMode == admission.EffectModeAuthorized {
			workload.Runtime.NodeID = effective.Intent.NodeID
			approvalThreshold, err := effective.AuthorizedActionApprovalThreshold()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "enforcement_failed", "signed action approval threshold could not be projected into the runtime grant")
				return
			}
			workload.Runtime.ActionApprovalThreshold = approvalThreshold
			contextRequired, err := effective.AuthorizedActionContextRequired()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "enforcement_failed", "signed action context policy could not be projected into the runtime grant")
				return
			}
			workload.Runtime.ActionContextRequired = contextRequired
			actionAuthorities, err := admittedActionAuthorities(effective)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "enforcement_failed", "signed action authority could not be projected into the runtime grant")
				return
			}
			workload.Runtime.ActionAuthorities = actionAuthorities
		}
		if effective.Intent.Capabilities.Service {
			workload.Runtime.ServicePort = effective.Capsule.Service.Port
			taskAuthorities, err := admittedTaskAuthorities(effective)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "enforcement_failed", "signed task authority could not be projected into the runtime grant")
				return
			}
			if len(taskAuthorities) > 0 {
				workload.Runtime.NodeID = effective.Intent.NodeID
				workload.Runtime.ServiceID = effective.Intent.ServiceID
				workload.Runtime.TaskAuthorities = taskAuthorities
			}
		}
	}
	if request.Activation != nil {
		if workload.Runtime == nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "activation admission requires a signed runtime capability topology")
			return
		}
		workload.Runtime.ActivationID = request.Activation.ActivationID
		workload.Runtime.ActivationBeginDigest = request.Activation.BeginDigest
	}
	if effective.Intent.Capabilities.State {
		if !s.secure.allowUnquotaedState {
			writeError(w, http.StatusNotImplemented, "capability_unavailable", "persistent state is disabled because the configured Docker volume has no hard byte or inode quota")
			return
		}
		if _, ok := s.docker.(StateDocker); !ok {
			writeError(w, http.StatusNotImplemented, "capability_unavailable", "persistent state is unavailable with this Docker backend")
			return
		}
		workload.State = &StateMount{
			VolumeName: StateVolumeName(effective.Intent.TenantID, effective.Intent.LineageID),
			Path:       effective.Capsule.State.Path,
		}
	}
	if err := workload.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "policy_rejected", err.Error())
		return
	}
	if err := s.policy.ValidateWorkload(workload); err != nil {
		writeError(w, http.StatusBadRequest, "policy_rejected", err.Error())
		return
	}
	s.provisionSecureWorkload(w, r, workload, effective, request.Activation)
}

func (s *Server) purgeState(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	docker, ok := s.docker.(StateDocker)
	if !ok {
		writeError(w, http.StatusNotImplemented, "capability_unavailable", "persistent state is unavailable with this Docker backend")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the state purge limit")
		return
	}
	var request purgeStateRequest
	if err := dsse.DecodeStrictInto(raw, maxBodyBytes, &request); err != nil ||
		!boundedRuntimeText(request.TenantID, 128) || !boundedRuntimeText(request.NodeID, 128) ||
		!boundedRuntimeText(request.LineageID, 256) || request.Generation == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded state purge object")
		return
	}
	if request.NodeID != s.secure.nodeID {
		writeError(w, http.StatusForbidden, "admission_denied", "state purge is not bound to this node")
		return
	}
	principal, authenticated := r.Context().Value(admissionPrincipalKey{}).(admissionPrincipal)
	if !authenticated {
		if !s.secure.allowHostAdmin {
			writeError(w, http.StatusForbidden, "tenant_identity_required", "state purge requires an authenticated uplink principal")
			return
		}
		principal = admissionPrincipal{tenantID: request.TenantID, nodeID: request.NodeID, generation: request.Generation}
	}
	if principal.tenantID != request.TenantID || principal.nodeID != request.NodeID || principal.generation != request.Generation {
		writeError(w, http.StatusForbidden, "admission_denied", "state purge does not match the authenticated command")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; state purge is blocked until reconciliation succeeds")
		return
	}
	var lineage admission.FenceRecord
	for _, record := range s.secure.fences.Records() {
		if record.TenantID != request.TenantID || record.LineageID != request.LineageID {
			continue
		}
		if record.Present {
			writeError(w, http.StatusConflict, "state_in_use", "state cannot be purged while a signed workload in the lineage is present")
			return
		}
		if record.Generation > lineage.Generation {
			lineage = record
		}
	}
	if lineage.Generation == 0 {
		writeError(w, http.StatusNotFound, "state_not_found", "state lineage is not known to this node")
		return
	}
	if lineage.Generation != request.Generation || !s.principalAuthorizesRecord(r.Context(), lineage) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "state purge is not authorized for the signed lineage generation")
		return
	}
	name := StateVolumeName(request.TenantID, request.LineageID)
	if len(s.secure.journal.Pending()) != 0 {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	observed, err := docker.InspectStateVolume(r.Context(), name)
	if errors.Is(err, ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if !stateVolumeEqual(observed, StateVolumeSpec{Name: name, TenantID: request.TenantID, LineageID: request.LineageID}) {
		writeError(w, http.StatusConflict, "state_drift", "state volume does not match the signed tenant lineage")
		return
	}
	opID, err := newOperationID("purge-"+name, request.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create state purge operation identity")
		return
	}
	if _, err := s.secure.journal.Prepare(opID, "purge:"+name, request.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
		return
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: request.TenantID, RuntimeRef: name,
		CapsuleDigest: lineage.CapsuleDigest, PolicyDigest: lineage.PolicyDigest,
		Generation: request.Generation, GrantID: "state", Outcome: evidence.Allowed,
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	removeErr := docker.RemoveStateVolume(r.Context(), name)
	_, inspectErr := docker.InspectStateVolume(r.Context(), name)
	if !errors.Is(inspectErr, ErrNotFound) {
		if inspectErr == nil {
			s.recordCompensation(opID, prepared, "state_purge")
			if removeErr == nil {
				removeErr = errors.New("state volume remained after Docker reported successful removal")
			}
			writeDockerError(w, removeErr)
		} else {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state purge result is ambiguous; operation remains prepared")
		}
		return
	}
	committed := prepared
	committed.Type, committed.Outcome = evidence.StatePurge, evidence.Committed
	if _, err := s.secure.evidence.Append(committed); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state was purged but its receipt could not be persisted")
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// activationCanaryPreflight is the read-only authorization boundary before a
// node may contact Gateway. Unlike generic status, it serializes with signed
// mutations and requires the current policy, authenticated principal, retained
// activation, and exact running topology to agree.
func (s *Server) activationCanaryPreflight(
	w http.ResponseWriter,
	r *http.Request,
) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the activation canary preflight limit")
		return
	}
	var request activationCanaryPreflightRequest
	if err := dsse.DecodeStrictInto(raw, maxBodyBytes, &request); err != nil ||
		request.SchemaVersion != activationCanaryPreflightSchema ||
		!activationCheckpointID(request.ActivationID) ||
		!imageConfigDigest.MatchString(request.ActivationBeginDigest) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded activation canary preflight")
		return
	}

	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; activation canary dispatch is blocked until reconciliation succeeds")
		return
	}
	if s.secure.fences.Maintenance().Enabled {
		writeError(w, http.StatusServiceUnavailable, "maintenance_enabled", "node maintenance blocks activation canary dispatch")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	record, ok := s.secureLifecycleRecord(observed)
	if !ok || !s.principalAuthorizesRecord(r.Context(), record) ||
		!s.currentPolicyAuthorizesRecord(record) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the current authenticated signed admission")
		return
	}
	runtime := observed.Workload.Runtime
	if name != RuntimeRef(
		observed.Workload.TenantID,
		observed.Workload.InstanceID,
	) ||
		runtime == nil ||
		runtime.ActivationID != request.ActivationID ||
		runtime.ActivationBeginDigest != request.ActivationBeginDigest {
		writeError(w, http.StatusConflict, "activation_runtime_mismatch", "workload is not bound to the requested activation admission")
		return
	}
	if !lifecycleMatches(observed.Status, true) ||
		s.proveRuntimeTopologyState(
			r.Context(),
			observed.Workload,
			true,
			record.RoutePolicyDigest,
		) != nil {
		writeError(w, http.StatusConflict, "workload_drift", "activation canary requires the exact signed runtime topology to be running")
		return
	}
	writeJSON(w, http.StatusOK, s.secureResponse(
		name,
		observed.Status,
		record.CapsuleDigest,
		record.PolicyDigest,
		record.Generation,
		runtime,
		record.RoutePolicyDigest,
	))
}

// activationCheckpoint appends a content-free causal join to the signed
// Executor receipt stream. The caller supplies only a bounded activation
// identity and digest; every lifecycle binding is derived from the current
// signed fence and re-proven running under the mutation lock.
func (s *Server) activationCheckpoint(w http.ResponseWriter, r *http.Request) {
	if s.secure == nil {
		writeError(w, http.StatusServiceUnavailable, "secure_admission_unavailable", "signed admission is not configured on this node")
		return
	}
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body exceeds the activation checkpoint limit")
		return
	}
	var request activationCheckpointRequest
	if err := dsse.DecodeStrictInto(raw, maxBodyBytes, &request); err != nil ||
		request.SchemaVersion != activationCheckpointRequestSchema ||
		!activationCheckpointID(request.ActivationID) ||
		!imageConfigDigest.MatchString(request.CheckpointDigest) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be one bounded activation checkpoint")
		return
	}

	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; activation checkpoint is blocked until reconciliation succeeds")
		return
	}
	if s.secure.fences.Maintenance().Enabled {
		writeError(w, http.StatusServiceUnavailable, "maintenance_enabled", "node maintenance blocks activation checkpoints")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	record, ok := s.secureLifecycleRecord(observed)
	if !ok || !s.principalAuthorizesRecord(r.Context(), record) ||
		!s.currentPolicyAuthorizesRecord(record) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the current authenticated signed admission")
		return
	}
	runtime := observed.Workload.Runtime
	if name != RuntimeRef(observed.Workload.TenantID, observed.Workload.InstanceID) ||
		runtime == nil ||
		runtime.ActivationID != request.ActivationID ||
		!imageConfigDigest.MatchString(runtime.ActivationBeginDigest) {
		writeError(w, http.StatusConflict, "activation_runtime_mismatch", "workload is not bound to the requested activation admission")
		return
	}
	if !lifecycleMatches(observed.Status, true) ||
		s.proveRuntimeTopologyState(
			r.Context(), observed.Workload, true, record.RoutePolicyDigest,
		) != nil {
		writeError(w, http.StatusConflict, "workload_drift", "activation checkpoint requires the exact signed runtime topology to be running")
		return
	}
	event := evidence.Event{
		Type:          evidence.ActivationCheckpoint,
		TenantID:      record.TenantID,
		RuntimeRef:    name,
		CapsuleDigest: record.CapsuleDigest,
		PolicyDigest:  record.PolicyDigest,
		Generation:    record.Generation,
		GrantID:       request.ActivationID,
		Outcome:       evidence.Committed,
		MetadataHash:  request.CheckpointDigest,
	}
	if _, err := s.secure.evidence.AppendActivationCheckpoint(event); err != nil {
		if errors.Is(err, evidence.ErrActivationInvalidated) {
			writeError(w, http.StatusConflict, "activation_invalidated", err.Error())
		} else if errors.Is(err, evidence.ErrActivationMarkerConflict) {
			writeError(w, http.StatusConflict, "activation_checkpoint_conflict", err.Error())
		} else {
			writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, request)
}

func boundedRuntimeText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func activationCheckpointID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		char := value[index]
		if !asciiAlphaNumeric(char) && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9'
}

func (s *Server) provisionSecureWorkload(
	w http.ResponseWriter,
	r *http.Request,
	workload Workload,
	effective admission.EffectiveAdmission,
	activationRequest *activationAdmissionRequest,
) {
	name := RuntimeRef(workload.TenantID, workload.InstanceID)
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; admission is blocked until reconciliation succeeds")
		return
	}
	observed, err := s.docker.Inspect(r.Context(), name)
	if err == nil {
		if workload.Runtime != nil && observed.Workload.Runtime != nil &&
			workload.Runtime.NetworkName == observed.Workload.Runtime.NetworkName &&
			workload.Runtime.GrantID == observed.Workload.Runtime.GrantID &&
			workload.Runtime.Generation == observed.Workload.Runtime.Generation {
			workload.Runtime.Subnet = observed.Workload.Runtime.Subnet
			workload.Runtime.Gateway = observed.Workload.Runtime.Gateway
			workload.Runtime.RelayIP = observed.Workload.Runtime.RelayIP
			workload.Runtime.AgentIP = observed.Workload.Runtime.AgentIP
		}
		if legacy, ok := legacyRuntimeReplay(workload, observed.Workload); ok {
			workload = legacy
		}
		committedRecord, hasCommittedRecord := s.secure.fences.Record(workload.TenantID, workload.InstanceID)
		expectedRecord := admission.FenceRecord{
			TenantID: workload.TenantID, InstanceID: workload.InstanceID,
			Generation: effective.Intent.Generation, CapsuleDigest: effective.CapsuleDigest,
			PolicyDigest: effective.PolicyDigest, LineageID: effective.Intent.LineageID,
			WorkloadDigest:    "sha256:" + workloadFingerprint(workload),
			ImageConfigDigest: effective.Capsule.Image.ConfigDigest,
			RoutePolicyDigest: committedRecord.RoutePolicyDigest, Present: true,
		}
		if !observed.Managed || !observed.Hardened ||
			observed.Fingerprint != workloadFingerprint(workload) ||
			observed.ImageID != effective.Capsule.Image.ConfigDigest ||
			!hasCommittedRecord || !s.secure.fences.Matches(expectedRecord, effective.SitePolicy.PolicyEpoch) {
			writeError(w, http.StatusConflict, "workload_conflict", "runtime_ref already belongs to a different workload definition")
			return
		}
		if workload.State != nil && !s.stateVolumeMatches(r.Context(), workload, effective.Intent.LineageID) {
			writeError(w, http.StatusConflict, "state_drift", "persistent state volume does not match the signed tenant lineage")
			return
		}
		observedRunning, lifecycleKnown := desiredStatus(observed.Status)
		if !lifecycleKnown {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "existing workload has an ambiguous Docker lifecycle state")
			return
		}
		if workload.Runtime != nil && (!s.runtimeTopologyMatches(r.Context(), workload, observedRunning) ||
			!s.gatewayRoutePolicyMatches(r.Context(), workload, committedRecord.RoutePolicyDigest)) {
			writeError(w, http.StatusConflict, "runtime_drift", "isolated runtime topology does not match the signed capability grant")
			return
		}
		s.writeSecureResponse(
			r.Context(), w, http.StatusOK, name, observed.Status, effective,
			workload.Runtime, committedRecord.RoutePolicyDigest,
		)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		writeDockerError(w, err)
		return
	}
	if s.secure.fences.Maintenance().Enabled {
		writeError(w, http.StatusServiceUnavailable, "maintenance_enabled", "node maintenance blocks new signed admissions")
		return
	}
	if persisted := s.secure.fences.Fences(workload.TenantID, workload.InstanceID); persisted.Generation >= effective.Intent.Generation {
		writeError(w, http.StatusConflict, "generation_consumed", "the committed generation is absent; submit a higher generation rather than replaying it")
		return
	}
	if workload.State != nil {
		for _, record := range s.secure.fences.Records() {
			if record.Present && record.TenantID == workload.TenantID &&
				record.LineageID == effective.Intent.LineageID && record.InstanceID != workload.InstanceID {
				writeError(w, http.StatusConflict, "state_in_use", "persistent state lineage is already leased by another live instance")
				return
			}
		}
	}
	stateDocker, stateExists, stateErr := s.prepareStateAdmission(r.Context(), workload, effective)
	if stateErr != nil {
		var admissionErr *stateAdmissionError
		if errors.As(stateErr, &admissionErr) {
			writeError(w, admissionErr.Status, admissionErr.Code, admissionErr.Message)
		} else {
			writeDockerError(w, stateErr)
		}
		return
	}
	capacityMessage, err := s.capacityMessage(r.Context(), workload)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if capacityMessage != "" {
		writeCapacityError(w, capacityMessage)
		return
	}
	opID, err := newOperationID(name, effective.Intent.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create operation identity")
		return
	}
	if activationRequest != nil {
		begin := evidence.Event{
			Type:          evidence.ActivationBegin,
			TenantID:      workload.TenantID,
			RuntimeRef:    name,
			CapsuleDigest: effective.CapsuleDigest,
			PolicyDigest:  effective.PolicyDigest,
			Generation:    effective.Intent.Generation,
			GrantID:       activationRequest.ActivationID,
			Outcome:       evidence.Allowed,
			MetadataHash:  activationRequest.BeginDigest,
		}
		if _, err := s.secure.evidence.AppendActivationBegin(begin); err != nil {
			if errors.Is(err, evidence.ErrActivationMarkerConflict) {
				writeError(w, http.StatusConflict, "activation_admission_conflict", err.Error())
			} else {
				writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
			}
			return
		}
	}
	// Persist the authorization decision after every read-only preflight but
	// before the journal or host can change. This is not a workload-success
	// receipt; JournalCommit remains the durable mutation outcome.
	grantID := "workload"
	if workload.Runtime != nil {
		grantID = workload.Runtime.GrantID
	}
	allowed := evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: workload.TenantID, RuntimeRef: name,
		CapsuleDigest: effective.CapsuleDigest, PolicyDigest: effective.PolicyDigest,
		Generation: effective.Intent.Generation, GrantID: grantID, Outcome: evidence.Allowed,
	}
	if _, err := s.secure.evidence.Append(allowed); err != nil {
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	if _, err := s.secure.journal.Prepare(opID, name, effective.Intent.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
		return
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: workload.TenantID, RuntimeRef: name,
		CapsuleDigest: effective.CapsuleDigest, PolicyDigest: effective.PolicyDigest,
		Generation: effective.Intent.Generation, GrantID: "workload", Outcome: evidence.Allowed,
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	stateCreated := false
	if workload.State != nil && !stateExists {
		spec := StateVolumeSpec{Name: workload.State.VolumeName, TenantID: workload.TenantID, LineageID: effective.Intent.LineageID}
		if err := stateDocker.CreateStateVolume(r.Context(), spec); err != nil {
			observedState, inspectErr := stateDocker.InspectStateVolume(r.Context(), spec.Name)
			if inspectErr != nil || !stateVolumeEqual(observedState, spec) {
				if errors.Is(inspectErr, ErrNotFound) {
					s.recordCompensation(opID, prepared, "state_create")
					writeDockerError(w, err)
				} else {
					writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "state creation returned an ambiguous result; operation remains prepared")
				}
				return
			}
		}
		observedState, err := stateDocker.InspectStateVolume(r.Context(), spec.Name)
		if err != nil || !stateVolumeEqual(observedState, spec) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "created state volume could not be verified; operation remains prepared")
			return
		}
		stateCreated = true
	}
	if err := s.prepareRuntimeTopology(r.Context(), workload); err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "runtime topology preparation failed and rollback is ambiguous; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "topology_prepare")
		writeError(w, http.StatusServiceUnavailable, "topology_unavailable", err.Error())
		return
	}
	if err := workload.Validate(); err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "allocated runtime topology was invalid and rollback is ambiguous; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "topology_validate")
		writeError(w, http.StatusInternalServerError, "enforcement_failed", "Docker allocated an invalid runtime topology")
		return
	}
	if err := s.docker.Create(r.Context(), name, workload); err != nil {
		if _, inspectErr := s.docker.Inspect(r.Context(), name); errors.Is(inspectErr, ErrNotFound) {
			if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
				writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker create failed and topology rollback is ambiguous; operation remains prepared")
				return
			}
			s.recordCompensation(opID, prepared, "docker_create")
			writeCreateError(w, err)
		} else {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker create returned an ambiguous result; operation remains prepared")
		}
		return
	}
	if err := s.completeRuntimeTopology(r.Context(), workload); err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "runtime topology completion failed and rollback is ambiguous; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "topology_complete")
		writeError(w, http.StatusServiceUnavailable, "topology_unavailable", err.Error())
		return
	}
	observed, err = s.docker.Inspect(r.Context(), name)
	if err != nil || !observed.Managed || !observed.Hardened ||
		observed.Fingerprint != workloadFingerprint(workload) ||
		observed.ImageID != effective.Capsule.Image.ConfigDigest {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "rejected workload could not be removed; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "inspect_failed")
		writeError(w, http.StatusInternalServerError, "enforcement_failed", "created workload did not match admitted hardened state")
		return
	}
	routePolicyDigest, err := s.gatewayRoutePolicyDigest(r.Context(), workload)
	if err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "gateway policy inspection failed and workload rollback is ambiguous; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "gateway_policy")
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "effective gateway route policy could not be verified")
		return
	}
	committed := prepared
	committed.Type = evidence.JournalCommit
	committed.Outcome = evidence.Committed
	committed.MetadataHash = routePolicyDigest
	if _, err := s.secure.evidence.Append(committed); err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "commit receipt failed and workload rollback is ambiguous; operation remains prepared")
			return
		}
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", "commit receipt could not be persisted; workload was removed")
		return
	}
	if err := s.secure.fences.Commit(admission.FenceRecord{
		TenantID: workload.TenantID, InstanceID: workload.InstanceID,
		Generation: effective.Intent.Generation, CapsuleDigest: effective.CapsuleDigest,
		PolicyDigest: effective.PolicyDigest, LineageID: effective.Intent.LineageID,
		WorkloadDigest:    "sha256:" + workloadFingerprint(workload),
		ImageConfigDigest: effective.Capsule.Image.ConfigDigest,
		RoutePolicyDigest: routePolicyDigest, Present: true,
	}, effective.SitePolicy.PolicyEpoch); err != nil {
		if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "fence commit failed and workload rollback is ambiguous; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "fence_commit")
		writeError(w, http.StatusServiceUnavailable, "fence_unavailable", err.Error())
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		// The signed receipt, fence, and Docker state are durable. Leave the
		// prepared journal entry so restart and subsequent mutations fail closed.
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	s.writeSecureResponse(
		r.Context(), w, http.StatusCreated, name, observed.Status, effective,
		workload.Runtime, routePolicyDigest,
	)
}

// legacyRuntimeReplay returns the exact external-effect-authority-free runtime
// shape retained before signed admission bindings were added to Docker labels.
// The fence and fingerprint checks that follow still have to match this
// projection, so a newly authorized runtime whose binding labels were removed
// cannot use the compatibility path.
func legacyRuntimeReplay(desired, observed Workload) (Workload, bool) {
	if desired.Runtime == nil || observed.Runtime == nil || len(desired.Runtime.ConnectorIDs) != 0 || len(observed.Runtime.ConnectorIDs) != 0 ||
		len(desired.Runtime.TaskAuthorities) != 0 || len(observed.Runtime.TaskAuthorities) != 0 ||
		desired.Runtime.EffectMode != "" || observed.Runtime.EffectMode != "" ||
		desired.Runtime.ActionApprovalThreshold != 0 || observed.Runtime.ActionApprovalThreshold != 0 ||
		desired.Runtime.ActionContextRequired || observed.Runtime.ActionContextRequired ||
		len(desired.Runtime.ActionAuthorities) != 0 || len(observed.Runtime.ActionAuthorities) != 0 ||
		!imageConfigDigest.MatchString(desired.Runtime.CapsuleDigest) || !imageConfigDigest.MatchString(desired.Runtime.PolicyDigest) ||
		observed.Runtime.CapsuleDigest != "" || observed.Runtime.PolicyDigest != "" ||
		!runtimeGrantEqualExceptAdmissionBindings(desired.Runtime, observed.Runtime) {
		return desired, false
	}
	legacy := *desired.Runtime
	legacy.CapsuleDigest, legacy.PolicyDigest = "", ""
	desired.Runtime = &legacy
	return desired, true
}

func runtimeGrantEqualExceptAdmissionBindings(left, right *RuntimeGrant) bool {
	return left.NetworkName == right.NetworkName && left.Subnet == right.Subnet && left.Gateway == right.Gateway &&
		left.GrantID == right.GrantID && left.NodeID == right.NodeID && left.Generation == right.Generation && left.Inference == right.Inference &&
		left.RouteID == right.RouteID && left.RelayIP == right.RelayIP && left.AgentIP == right.AgentIP &&
		left.ModelAlias == right.ModelAlias && left.ServicePort == right.ServicePort && left.ServiceID == right.ServiceID &&
		left.ActivationID == right.ActivationID && left.ActivationBeginDigest == right.ActivationBeginDigest &&
		left.EffectMode == right.EffectMode && left.ActionApprovalThreshold == right.ActionApprovalThreshold &&
		left.ActionContextRequired == right.ActionContextRequired &&
		slices.Equal(left.TaskAuthorities, right.TaskAuthorities) &&
		slices.EqualFunc(left.ActionAuthorities, right.ActionAuthorities, func(left, right gateway.GrantActionAuthority) bool {
			return left.KeyID == right.KeyID && left.PublicKey == right.PublicKey && slices.Equal(left.ConnectorIDs, right.ConnectorIDs)
		}) &&
		slices.Equal(left.EgressRouteIDs, right.EgressRouteIDs) && slices.Equal(left.ConnectorIDs, right.ConnectorIDs)
}

func (s *Server) recordCompensation(opID string, prepared evidence.Event, code string) {
	compensated := prepared
	compensated.Type = evidence.JournalCompensate
	compensated.Outcome = evidence.Compensated
	compensated.ErrorCode = code
	_, _ = s.secure.evidence.Append(compensated)
	_ = s.secure.journal.Compensate(opID)
}

// removeAndConfirmAbsent is used only while compensating a prepared secure
// operation. A failed or ambiguous rollback deliberately leaves the journal
// pending so restart and every later mutation fail closed for reconciliation.
func (s *Server) removeAndConfirmAbsent(ctx context.Context, name string) bool {
	removeErr := s.docker.Remove(ctx, name)
	if removeErr != nil && !errors.Is(removeErr, ErrNotFound) {
		_, inspectErr := s.docker.Inspect(ctx, name)
		return errors.Is(inspectErr, ErrNotFound)
	}
	_, inspectErr := s.docker.Inspect(ctx, name)
	return errors.Is(inspectErr, ErrNotFound)
}

type stateAdmissionError struct {
	Status  int
	Code    string
	Message string
}

func (e *stateAdmissionError) Error() string { return e.Message }

func (s *Server) prepareStateAdmission(ctx context.Context, workload Workload, effective admission.EffectiveAdmission) (StateDocker, bool, error) {
	if workload.State == nil {
		return nil, false, nil
	}
	docker, ok := s.docker.(StateDocker)
	if !ok {
		return nil, false, &stateAdmissionError{http.StatusNotImplemented, "capability_unavailable", "persistent state is unavailable with this Docker backend"}
	}
	want := StateVolumeSpec{Name: workload.State.VolumeName, TenantID: workload.TenantID, LineageID: effective.Intent.LineageID}
	observed, err := docker.InspectStateVolume(ctx, want.Name)
	if errors.Is(err, ErrNotFound) {
		if effective.Intent.StateDisposition == "resume" {
			return nil, false, &stateAdmissionError{http.StatusConflict, "state_missing", "resume requires an existing state lineage"}
		}
		return docker, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !stateVolumeEqual(observed, want) {
		return nil, false, &stateAdmissionError{http.StatusConflict, "state_drift", "existing state volume does not match the signed tenant lineage"}
	}
	if effective.Intent.StateDisposition == "new" {
		return nil, false, &stateAdmissionError{http.StatusConflict, "state_exists", "new state disposition refuses an existing lineage; use resume"}
	}
	return docker, true, nil
}

func (s *Server) stateVolumeMatches(ctx context.Context, workload Workload, lineageID string) bool {
	if workload.State == nil {
		return true
	}
	docker, ok := s.docker.(StateDocker)
	if !ok {
		return false
	}
	observed, err := docker.InspectStateVolume(ctx, workload.State.VolumeName)
	return err == nil && stateVolumeEqual(observed, StateVolumeSpec{
		Name: workload.State.VolumeName, TenantID: workload.TenantID, LineageID: lineageID,
	})
}

func stateVolumeEqual(observed ObservedStateVolume, want StateVolumeSpec) bool {
	return observed.Managed && observed.StateVolumeSpec == want
}

func (s *Server) rollbackSecureProvision(ctx context.Context, name string, stateDocker StateDocker, workload Workload, stateCreated bool) bool {
	if !s.removeAndConfirmAbsent(ctx, name) {
		return false
	}
	if !s.removeRuntimeTopology(ctx, workload) {
		return false
	}
	if stateCreated && !removeAndConfirmStateAbsent(ctx, stateDocker, workload.State.VolumeName) {
		return false
	}
	return true
}

func removeAndConfirmStateAbsent(ctx context.Context, docker StateDocker, name string) bool {
	removeErr := docker.RemoveStateVolume(ctx, name)
	if removeErr != nil && !errors.Is(removeErr, ErrNotFound) {
		_, inspectErr := docker.InspectStateVolume(ctx, name)
		return errors.Is(inspectErr, ErrNotFound)
	}
	_, inspectErr := docker.InspectStateVolume(ctx, name)
	return errors.Is(inspectErr, ErrNotFound)
}

func (s *Server) writeSecureResponse(
	ctx context.Context,
	w http.ResponseWriter,
	status int,
	runtimeRef, runtimeStatus string,
	effective admission.EffectiveAdmission,
	runtime *RuntimeGrant,
	expectedRoutePolicyDigest string,
) {
	response := s.secureResponse(
		runtimeRef, runtimeStatus, effective.CapsuleDigest, effective.PolicyDigest,
		effective.Intent.Generation, runtime, expectedRoutePolicyDigest,
	)
	if runtimeNeedsGatewayPolicy(runtime) {
		inspection, err := s.secure.gateway.InspectWithPolicy(ctx, response.GrantID)
		if err != nil || !imageConfigDigest.MatchString(expectedRoutePolicyDigest) || inspection.RoutePolicyDigest != expectedRoutePolicyDigest {
			writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "effective gateway route policy could not be verified")
			return
		}
	} else if expectedRoutePolicyDigest != "" {
		writeError(w, http.StatusServiceUnavailable, "fence_unavailable", "committed route policy binding is inconsistent with the admitted capabilities")
		return
	}
	writeJSON(w, status, response)
}

func (s *Server) secureResponse(
	runtimeRef, runtimeStatus, capsuleDigest, policyDigest string,
	generation uint64,
	runtime *RuntimeGrant,
	routePolicyDigest string,
) secureProvisionResponse {
	response := secureProvisionResponse{
		RuntimeRef: runtimeRef, Status: runtimeStatus,
		CapsuleDigest: capsuleDigest, PolicyDigest: policyDigest,
		Generation:        generation,
		EvidenceKeyID:     evidence.KeyID(s.secure.evidence.PublicKey()),
		RoutePolicyDigest: routePolicyDigest,
	}
	if runtime == nil {
		return response
	}
	response.GrantID = runtime.GrantID
	if runtime.ServicePort > 0 {
		response.ServicePath = "/v1/services/" + runtime.GrantID + "/"
		response.ServiceID = runtime.ServiceID
		response.TaskAuthorities = append(
			[]gateway.TaskAuthority(nil), runtime.TaskAuthorities...,
		)
	}
	if len(runtime.EgressRouteIDs) > 0 {
		response.EgressProxy = "http://steward-relay:8082"
		response.EgressRouteIDs = append([]string(nil), runtime.EgressRouteIDs...)
	}
	if len(runtime.ConnectorIDs) > 0 {
		response.ConnectorURL = "http://steward-relay:8081"
		response.ConnectorIDs = append([]string(nil), runtime.ConnectorIDs...)
	}
	response.EffectMode = runtime.EffectMode
	response.ActionApprovalThreshold = runtime.ActionApprovalThreshold
	response.ActionContextRequired = runtime.ActionContextRequired
	response.ActionAuthorities = cloneGrantActionAuthorities(runtime.ActionAuthorities)
	response.ActivationID = runtime.ActivationID
	response.ActivationBeginDigest = runtime.ActivationBeginDigest
	return response
}

func runtimeNeedsGatewayPolicy(runtime *RuntimeGrant) bool {
	return runtime != nil &&
		(runtime.Inference || len(runtime.EgressRouteIDs) > 0 ||
			len(runtime.ConnectorIDs) > 0 || len(runtime.TaskAuthorities) > 0 || runtime.EffectMode != "")
}

func admittedTaskAuthorities(effective admission.EffectiveAdmission) ([]gateway.TaskAuthority, error) {
	if !effective.Intent.Capabilities.Service {
		return nil, nil
	}
	keys, err := effective.SitePolicy.TrustedTaskKeys(effective.Intent.TenantID, effective.Intent.ServiceID)
	if err != nil {
		return nil, err
	}
	keyIDs := make([]string, 0, len(keys))
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID)
	}
	slices.Sort(keyIDs)
	authorities := make([]gateway.TaskAuthority, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		authorities = append(authorities, gateway.TaskAuthority{
			KeyID: keyID, PublicKey: base64.StdEncoding.EncodeToString(keys[keyID]),
		})
	}
	return authorities, nil
}

func admittedActionAuthorities(effective admission.EffectiveAdmission) ([]gateway.GrantActionAuthority, error) {
	keys, err := effective.AuthorizedActionKeys()
	if err != nil {
		return nil, err
	}
	authorities := make([]gateway.GrantActionAuthority, 0, len(keys))
	for _, key := range keys {
		authorities = append(authorities, gateway.GrantActionAuthority{
			KeyID: key.KeyID, PublicKey: key.PublicKey,
			ConnectorIDs: append([]string(nil), key.ConnectorIDs...),
		})
	}
	return authorities, nil
}

func newOperationID(runtimeRef string, generation uint64) (string, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-g%d-%x", runtimeRef, generation, nonce[:]), nil
}

func clonePublicKeys(keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		cloned[id] = append(ed25519.PublicKey(nil), key...)
	}
	return cloned
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

func (s *Server) provision(w http.ResponseWriter, r *http.Request) {
	if s.secure != nil {
		writeError(w, http.StatusForbidden, "signed_admission_required", "legacy workload provisioning is disabled while signed admission is configured")
		return
	}
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
	capacityMessage, err := s.capacityMessage(r.Context(), workload)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if capacityMessage != "" {
		writeCapacityError(w, capacityMessage)
		return
	}
	if err := s.docker.Create(r.Context(), name, workload); err != nil {
		writeCreateError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"runtime_ref": name, "status": "created"})
}

func writeCapacityError(w http.ResponseWriter, message string) {
	writeError(w, http.StatusServiceUnavailable, "capacity_exceeded", message)
}

func (s *Server) capacityMessage(ctx context.Context, workload Workload) (string, error) {
	var usage CapacityUsage
	if docker, ok := s.docker.(CapacityDocker); ok {
		observed, err := docker.CapacityUsage(ctx, workload.TenantID)
		if err != nil {
			return "", err
		}
		usage = observed
	} else {
		total, tenant, err := s.docker.WorkloadCounts(ctx, workload.TenantID)
		if err != nil {
			return "", err
		}
		usage.Host.Workloads, usage.Tenant.Workloads = total, tenant
	}
	if usage.Host.Workloads >= s.policy.MaxWorkloads {
		return "host workload capacity is exhausted", nil
	}
	if usage.Tenant.Workloads >= s.policy.MaxWorkloadsPerTenant {
		return "tenant workload capacity is exhausted", nil
	}
	prospective, err := workloadReservation(workload)
	if err != nil {
		return "", err
	}
	if exceedsCapacity(usage.Host.MemoryBytes, prospective.MemoryBytes, s.policy.MaxTotalMemoryBytes) {
		return "host memory capacity is exhausted", nil
	}
	if exceedsCapacity(usage.Host.CPUMillis, prospective.CPUMillis, s.policy.MaxTotalCPUMillis) {
		return "host CPU capacity is exhausted", nil
	}
	if exceedsCapacity(usage.Host.PIDs, prospective.PIDs, s.policy.MaxTotalPIDs) {
		return "host process capacity is exhausted", nil
	}
	if exceedsCapacity(usage.Tenant.MemoryBytes, prospective.MemoryBytes, s.policy.MaxTenantMemoryBytes) {
		return "tenant memory capacity is exhausted", nil
	}
	if exceedsCapacity(usage.Tenant.CPUMillis, prospective.CPUMillis, s.policy.MaxTenantCPUMillis) {
		return "tenant CPU capacity is exhausted", nil
	}
	if exceedsCapacity(usage.Tenant.PIDs, prospective.PIDs, s.policy.MaxTenantPIDs) {
		return "tenant process capacity is exhausted", nil
	}
	return "", nil
}

func workloadReservation(workload Workload) (CapacityReservation, error) {
	reservation := CapacityReservation{
		Workloads: 1, MemoryBytes: workload.Resources.MemoryBytes,
		CPUMillis: workload.Resources.CPUMillis, PIDs: workload.Resources.PIDs,
	}
	if workload.Runtime == nil {
		return reservation, nil
	}
	var err error
	if reservation.MemoryBytes, err = checkedCapacityAdd(reservation.MemoryBytes, defaultRelayMemory); err != nil {
		return CapacityReservation{}, err
	}
	if reservation.CPUMillis, err = checkedCapacityAdd(reservation.CPUMillis, defaultRelayCPU); err != nil {
		return CapacityReservation{}, err
	}
	if reservation.PIDs, err = checkedCapacityAdd(reservation.PIDs, defaultRelayPIDs); err != nil {
		return CapacityReservation{}, err
	}
	return reservation, nil
}

func exceedsCapacity(used, add, maximum int64) bool {
	return used < 0 || add < 0 || add > maximum || used > maximum-add
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) { s.transition(w, r, "start") }
func (s *Server) stop(w http.ResponseWriter, r *http.Request)  { s.transition(w, r, "stop") }
func (s *Server) transition(w http.ResponseWriter, r *http.Request, action string) {
	if s.secure != nil {
		s.secureTransition(w, r, action)
		return
	}
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
	state := classifyDockerLifecycle(observed.Status)
	if action == "start" && state == dockerLifecycleRunning || action == "stop" && state == dockerLifecycleStopped {
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
		return
	}
	if state == dockerLifecycleAmbiguous {
		if err := s.stopWorkloadAndConfirm(r.Context(), name, observed.Workload); err != nil {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "ambiguous Docker lifecycle state could not be confirmed stopped")
			return
		}
		if action == "start" {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "ambiguous Docker lifecycle state was contained; retry start from the confirmed stopped state")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": "exited"})
		return
	}
	if action == "start" {
		err = s.docker.Start(r.Context(), name)
	} else {
		err = s.stopWorkloadAndConfirm(r.Context(), name, observed.Workload)
	}
	final, inspectErr := s.managed(r.Context(), name)
	if inspectErr != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker lifecycle result could not be reinspected")
		return
	}
	if lifecycleMatches(final.Status, action == "start") {
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": final.Status})
		return
	}
	if err != nil && classifyDockerLifecycle(final.Status) != dockerLifecycleAmbiguous {
		writeDockerError(w, err)
		return
	}
	writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker lifecycle operation did not reach the requested exact state")
}

func (s *Server) secureTransition(w http.ResponseWriter, r *http.Request, action string) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		if action == "stop" {
			s.containSecureWorkload(w, r, name)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; start is blocked until reconciliation succeeds")
		return
	}
	if action == "start" && s.secure.fences.Maintenance().Enabled {
		writeError(w, http.StatusServiceUnavailable, "maintenance_enabled", "node maintenance blocks workload starts")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	record, ok := s.secureLifecycleRecord(observed)
	if !ok || !s.principalAuthorizesRecord(r.Context(), record) ||
		(action == "start" && !s.currentPolicyAuthorizesRecord(record)) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the authenticated signed admission")
		return
	}
	priorRunning, priorKnown := desiredStatus(observed.Status)
	containAmbiguousStart := action == "start" && !priorKnown
	if action == "start" && priorKnown && observed.Workload.Runtime != nil && s.secure.topology != nil {
		relay, relayErr := s.secure.topology.InspectRelay(r.Context(), RelayName(
			observed.Workload.TenantID, observed.Workload.InstanceID, observed.Workload.Runtime.Generation))
		if relayErr == nil && relayEqual(relay, s.desiredRelay(observed.Workload)) &&
			classifyDockerLifecycle(relay.Status) == dockerLifecycleAmbiguous {
			containAmbiguousStart = true
			priorKnown = false
		}
	}
	effectiveAction := action
	if containAmbiguousStart {
		effectiveAction = "stop"
	}
	if action == "start" && !containAmbiguousStart {
		proofErr := s.proveRuntimeTopologyState(r.Context(), observed.Workload, priorRunning, record.RoutePolicyDigest)
		if proofErr != nil {
			if priorRunning {
				s.markRuntimeTopologyDegradedLocked(name, proofErr)
				_, complete := s.containObservedSecureWorkload(r, name, record, observed)
				if complete {
					writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "an unsafe running topology was contained; reconciliation must prove the repaired runtime before it can start")
				} else {
					writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "unsafe running topology containment was attempted, but every authority boundary could not be verified inactive and stopped")
				}
				return
			}
			writeRuntimeTopologyFailure(w, proofErr)
			return
		}
		if priorRunning {
			writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
			return
		}
	}
	if lifecycleMatches(observed.Status, effectiveAction == "start") &&
		s.runtimeLifecycleMatches(r.Context(), observed.Workload, effectiveAction == "start") {
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
		return
	}
	journalAction := effectiveAction
	if containAmbiguousStart {
		journalAction = "lifecycle_containment"
	}
	opID, err := newOperationID(journalAction+"-"+name, record.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create operation identity")
		return
	}
	if _, err := s.secure.journal.Prepare(opID, journalAction+":"+name, record.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
		return
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: record.TenantID, RuntimeRef: name,
		CapsuleDigest: record.CapsuleDigest, PolicyDigest: record.PolicyDigest,
		Generation: record.Generation, GrantID: "workload", Outcome: evidence.Allowed,
		ErrorCode: journalAction,
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	err = s.applyRuntimeTransition(r.Context(), name, observed.Workload, effectiveAction == "start", record.RoutePolicyDigest)
	final, inspectErr := s.managed(r.Context(), name)
	expected := inspectErr == nil && lifecycleMatches(final.Status, effectiveAction == "start")
	if expected && effectiveAction == "start" {
		expected = s.proveRuntimeTopologyState(r.Context(), final.Workload, true, record.RoutePolicyDigest) == nil
	} else if expected {
		expected = s.runtimeLifecycleMatches(r.Context(), final.Workload, false)
	}
	var startProofFailure *runtimeStartProofFailure
	if err != nil && errors.As(err, &startProofFailure) {
		// The primitive guarantees that its precondition runs before its first
		// mutation. Compensate the journal without invoking a rollback path that
		// could widen authority on the topology it just rejected.
		s.recordCompensation(opID, prepared, "start_precondition")
		writeRuntimeTransitionFailure(w, err)
		return
	}
	var failedStart *runtimeFailedStart
	if err != nil && errors.As(err, &failedStart) {
		if failedStart.topologyReconciliation {
			s.markRuntimeTopologyDegradedLocked(name, failedStart.err)
		}
		if !failedStart.contained {
			s.markRuntimeDegradedLocked(name, "containment_incomplete", failedStart.err)
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "failed start containment could not be proven; the operation remains pending")
			return
		}
		s.recordCompensation(opID, prepared, "failed_start_contained")
		if failedStart.topologyReconciliation {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "the failed start was contained; reconciliation must prove the repaired topology")
		} else {
			writeRuntimeTransitionFailure(w, failedStart.err)
		}
		return
	}
	if err != nil && effectiveAction == "start" {
		// Defensive catch-all: every known post-precondition failure is wrapped
		// above, but a future start stage must still be monotonic by default.
		failure := s.failedRuntimeStart(r.Context(), name, observed.Workload, record.RoutePolicyDigest, err, false)
		if !failure.contained {
			s.markRuntimeDegradedLocked(name, "containment_incomplete", failure.err)
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "failed start containment could not be proven; the operation remains pending")
			return
		}
		s.recordCompensation(opID, prepared, "failed_start_contained")
		writeRuntimeTransitionFailure(w, failure.err)
		return
	}
	unchanged := inspectErr == nil && priorKnown && final.Status == observed.Status &&
		lifecycleMatches(final.Status, priorRunning) && s.runtimeLifecycleMatches(r.Context(), observed.Workload, priorRunning)
	if err != nil && unchanged {
		s.recordCompensation(opID, prepared, "docker_"+effectiveAction)
		writeRuntimeTransitionFailure(w, err)
		return
	}
	if inspectErr != nil {
		if effectiveAction == "start" {
			failure := s.failedRuntimeStart(r.Context(), name, observed.Workload, record.RoutePolicyDigest,
				fmt.Errorf("inspect started workload: %w", inspectErr), false)
			if !failure.contained {
				s.markRuntimeDegradedLocked(name, "containment_incomplete", failure.err)
				writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker start result and containment are ambiguous; the operation remains pending")
				return
			}
			s.recordCompensation(opID, prepared, "ambiguous_start_contained")
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker start result was ambiguous and the failed start was contained")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker lifecycle result is ambiguous; operation remains prepared")
		return
	}
	if !expected {
		if effectiveAction == "start" {
			failure := s.failedRuntimeStart(r.Context(), name, observed.Workload, record.RoutePolicyDigest,
				errors.New("started runtime did not reach the exact requested state"), false)
			if !failure.contained {
				s.markRuntimeDegradedLocked(name, "containment_incomplete", failure.err)
				writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "unexpected start result could not be contained; the operation remains pending")
				return
			}
			s.recordCompensation(opID, prepared, "unexpected_start_contained")
			writeError(w, http.StatusInternalServerError, "enforcement_failed", "lifecycle result did not match the requested state; the failed start was contained")
			return
		}
		if !priorKnown || !s.restoreRuntimeLifecycle(r.Context(), name, observed.Workload, priorRunning, record.RoutePolicyDigest) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "unexpected lifecycle result could not be rolled back; operation remains prepared")
			return
		}
		s.recordCompensation(opID, prepared, "inspect_failed")
		writeError(w, http.StatusInternalServerError, "enforcement_failed", "lifecycle result did not match the requested state")
		return
	}
	committed := prepared
	committed.ErrorCode = ""
	committed.Outcome = evidence.Committed
	committed.MetadataHash = record.RoutePolicyDigest
	if effectiveAction == "start" {
		committed.Type = evidence.LifecycleStart
	} else {
		committed.Type = evidence.LifecycleStop
	}
	if _, err := s.secure.evidence.Append(committed); err != nil {
		if effectiveAction == "start" {
			failure := s.failedRuntimeStart(r.Context(), name, observed.Workload, record.RoutePolicyDigest,
				fmt.Errorf("persist lifecycle receipt: %w", err), false)
			if !failure.contained {
				s.markRuntimeDegradedLocked(name, "containment_incomplete", failure.err)
				writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "lifecycle receipt failed and the started runtime could not be contained; the operation remains pending")
				return
			}
			_ = s.secure.journal.Compensate(opID)
			writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", "lifecycle receipt could not be persisted; the failed start was contained")
			return
		}
		if !priorKnown || !s.restoreRuntimeLifecycle(r.Context(), name, observed.Workload, priorRunning, record.RoutePolicyDigest) {
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "lifecycle receipt failed and prior state could not be restored; operation remains prepared")
			return
		}
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", "lifecycle receipt could not be persisted; prior state was requested")
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	if containAmbiguousStart {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "ambiguous Docker lifecycle state was contained; retry start from the confirmed stopped state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": final.Status})
}

// markRuntimeTopologyDegradedLocked publishes drift discovered between periodic
// scans before releasing provisionMu. A waiting mutation must therefore observe
// the degraded gate, even when monotonic containment completed successfully.
func (s *Server) markRuntimeTopologyDegradedLocked(runtimeRef string, err error) {
	code := "runtime_drift"
	var failure *runtimeTopologyFailure
	if errors.As(err, &failure) && failure.unavailable {
		code = "topology_unavailable"
	}
	s.markRuntimeDegradedLocked(runtimeRef, code, err)
}

func (s *Server) markRuntimeDegradedLocked(runtimeRef, code string, err error) {
	s.reconcileMu.Lock()
	report := cloneReconcileReport(s.reconcileReport)
	report.Ready = false
	report.addFailure(runtimeRef, code, err.Error())
	s.reconcileAttempted = true
	// reconcileAt remains the last actual scan time; this request discovered
	// drift but did not claim to complete a host-wide reconciliation.
	s.reconcileReport = report
	s.reconcileMu.Unlock()
}

func writeRuntimeTopologyFailure(w http.ResponseWriter, err error) {
	var failure *runtimeTopologyFailure
	if !errors.As(err, &failure) {
		writeDockerError(w, err)
		return
	}
	if !failure.unavailable {
		writeError(w, http.StatusConflict, "runtime_drift", failure.message)
		return
	}
	switch failure.component {
	case runtimeTopologyNetwork, runtimeTopologyRelay:
		if failure.cause != nil {
			writeDockerError(w, failure.cause)
			return
		}
	case runtimeTopologyGateway:
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", "Gateway topology inspection is unavailable")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "topology_unavailable", "runtime topology inspection is unavailable")
}

func writeRuntimeTransitionFailure(w http.ResponseWriter, err error) {
	var failure *runtimeTopologyFailure
	if errors.As(err, &failure) {
		writeRuntimeTopologyFailure(w, err)
		return
	}
	writeDockerError(w, err)
}

func (s *Server) destroy(w http.ResponseWriter, r *http.Request) {
	if s.secure != nil {
		s.secureDestroy(w, r)
		return
	}
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

func (s *Server) secureDestroy(w http.ResponseWriter, r *http.Request) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if s.secureMutationBlockedLocked() {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "signed runtime state is degraded; destroy is blocked until reconciliation succeeds")
		return
	}
	observed, err := s.docker.Inspect(r.Context(), name)
	if errors.Is(err, ErrNotFound) {
		for _, record := range s.secure.fences.Records() {
			if RuntimeRef(record.TenantID, record.InstanceID) == name && !record.Present && s.principalAuthorizesRecord(r.Context(), record) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeError(w, http.StatusNotFound, "not_found", "unknown signed workload")
		return
	}
	if err != nil {
		writeDockerError(w, err)
		return
	}
	if !observed.Managed || !observed.Hardened {
		writeDockerError(w, ErrWorkloadDrift)
		return
	}
	record, ok := s.secureLifecycleRecord(observed)
	if !ok || !s.principalAuthorizesRecord(r.Context(), record) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the authenticated signed admission")
		return
	}
	opID, err := newOperationID("destroy-"+name, record.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create operation identity")
		return
	}
	if _, err := s.secure.journal.Prepare(opID, "destroy:"+name, record.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
		return
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: record.TenantID, RuntimeRef: name,
		CapsuleDigest: record.CapsuleDigest, PolicyDigest: record.PolicyDigest,
		Generation: record.Generation, GrantID: "workload", Outcome: evidence.Allowed,
		ErrorCode: "destroy",
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	if removeErr := s.docker.Remove(r.Context(), name); removeErr != nil && !errors.Is(removeErr, ErrNotFound) {
		_, inspectErr := s.docker.Inspect(r.Context(), name)
		switch {
		case errors.Is(inspectErr, ErrNotFound):
			// Docker reported an error after applying the removal. Continue to
			// receipt and tombstone the observed result.
		case inspectErr == nil:
			s.recordCompensation(opID, prepared, "docker_destroy")
			writeDockerError(w, removeErr)
			return
		default:
			writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker destroy result is ambiguous; operation remains prepared")
			return
		}
	}
	if !s.removeRuntimeTopology(r.Context(), observed.Workload) {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "workload was removed but runtime topology cleanup is ambiguous; operation remains prepared")
		return
	}
	committed := prepared
	committed.Type, committed.Outcome, committed.ErrorCode = evidence.LifecycleDestroy, evidence.Committed, ""
	if _, err := s.secure.evidence.Append(committed); err != nil {
		// Destruction cannot be safely undone. Leave the prepared journal entry
		// so startup and later mutations fail closed until operator reconciliation.
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "destroy completed but its receipt could not be persisted")
		return
	}
	record.Present = false
	policyEpoch := s.secure.fences.Fences(record.TenantID, record.InstanceID).PolicyEpoch
	if err := s.secure.fences.Commit(record, policyEpoch); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "destroy completed but its tombstone could not be persisted")
		return
	}
	if err := s.secure.journal.Commit(opID); err != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) secureLifecycleRecord(observed ObservedWorkload) (admission.FenceRecord, bool) {
	record, ok := s.secure.fences.Record(observed.Workload.TenantID, observed.Workload.InstanceID)
	if !ok || !record.Present ||
		observed.Fingerprint != workloadFingerprint(observed.Workload) ||
		observed.Fingerprint != strings.TrimPrefix(record.WorkloadDigest, "sha256:") ||
		observed.ImageID != record.ImageConfigDigest ||
		RuntimeRef(record.TenantID, record.InstanceID) != RuntimeRef(observed.Workload.TenantID, observed.Workload.InstanceID) {
		return admission.FenceRecord{}, false
	}
	return record, true
}

func (s *Server) currentPolicyAuthorizesRecord(record admission.FenceRecord) bool {
	return record.PolicyDigest == dsse.Digest(s.secure.policyEnvelope)
}

// principalAuthorizesRecord authenticates cleanup authority independently from
// the current policy digest. A policy rotation may revoke permission to start a
// workload, but it must never make stop, destroy, or state cleanup impossible.
func (s *Server) principalAuthorizesRecord(ctx context.Context, record admission.FenceRecord) bool {
	principal, authenticated := ctx.Value(admissionPrincipalKey{}).(admissionPrincipal)
	if !authenticated {
		return s.secure.allowHostAdmin
	}
	return principal.tenantID == record.TenantID && principal.nodeID == s.secure.nodeID && principal.generation == record.Generation
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
	if s.secure != nil {
		record, ok := s.secureLifecycleRecord(observed)
		if !ok {
			writeError(w, http.StatusConflict, "workload_drift", "workload does not match its committed signed admission")
			return
		}
		runtime := observed.Workload.Runtime
		if runtimeNeedsGatewayPolicy(runtime) != (record.RoutePolicyDigest != "") ||
			record.RoutePolicyDigest != "" && !imageConfigDigest.MatchString(record.RoutePolicyDigest) {
			writeError(w, http.StatusConflict, "workload_drift", "workload route policy does not match its committed signed admission")
			return
		}
		writeJSON(w, http.StatusOK, s.secureResponse(
			name, observed.Status, record.CapsuleDigest, record.PolicyDigest,
			record.Generation, runtime, record.RoutePolicyDigest,
		))
		return
	}
	response := map[string]any{"runtime_ref": name, "status": observed.Status}
	if observed.Workload.Runtime != nil && len(observed.Workload.Runtime.EgressRouteIDs) > 0 {
		response["egress_proxy"] = "http://steward-relay:8082"
		response["egress_route_ids"] = observed.Workload.Runtime.EgressRouteIDs
	}
	if observed.Workload.Runtime != nil && len(observed.Workload.Runtime.ConnectorIDs) > 0 {
		response["connector_url"] = "http://steward-relay:8081"
		response["connector_ids"] = observed.Workload.Runtime.ConnectorIDs
	}
	writeJSON(w, http.StatusOK, response)
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
	encoded, err := json.Marshal(map[string]string{"runtime_ref": name, "logs": logs})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "encode workload logs")
		return
	}
	if len(encoded)+1 > maxLogBytes {
		writeError(w, http.StatusBadGateway, "docker_error", "encoded Docker log response exceeds 1 MiB limit")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(encoded, '\n'))
}

func (s *Server) egressStats(w http.ResponseWriter, r *http.Request) {
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
	if s.secure == nil || s.secure.gateway == nil || observed.Workload.Runtime == nil || len(observed.Workload.Runtime.EgressRouteIDs) == 0 {
		writeError(w, http.StatusNotFound, "egress_unavailable", "workload has no signed egress grant")
		return
	}
	stats, err := s.secure.gateway.EgressStats(r.Context(), observed.Workload.Runtime.GrantID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "gateway_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
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
func writeCreateError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusConflict, "workload_dependency_unavailable", "the requested image or prepared network is unavailable")
		return
	}
	writeDockerError(w, err)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
