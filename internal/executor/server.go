package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
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
	secure    *secureAdmission

	// provisionMu makes the count-then-create admission check atomic within the
	// one Docker-socket-bearing executor process. Docker inventory makes the
	// counts restart-safe; this lock prevents concurrent HTTP calls from racing
	// past the same ceiling.
	provisionMu sync.Mutex
}

type secureAdmission struct {
	policyEnvelope []byte
	siteRoots      map[string]ed25519.PublicKey
	nodeID         string
	fences         *admission.FenceStore
	journal        *journal.Journal
	evidence       *evidence.Log
	allowHostAdmin bool
	topology       TopologyDocker
	gateway        GatewayControl
	relayImage     string
	grantRoot      string
	relayGID       int
}

type GatewayControl interface {
	Register(context.Context, gateway.Grant) error
	Inspect(context.Context, string) (gateway.Grant, error)
	Activate(context.Context, string) error
	Deactivate(context.Context, string) error
	Unregister(context.Context, string) error
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
	// Positive-capability topology is optional as a complete unit. When absent,
	// signed state-only workloads remain available and inference/service fail
	// closed with capability_unavailable.
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
// server begins serving. Pending journal operations require explicit recovery;
// accepting fresh mutations while host state is ambiguous would be unsafe.
func (s *Server) EnableSecureAdmission(config SecureAdmissionConfig) error {
	if len(config.PolicyEnvelope) == 0 || len(config.SiteRoots) == 0 ||
		strings.TrimSpace(config.NodeID) == "" || config.Fences == nil ||
		config.Journal == nil || config.Evidence == nil {
		return errors.New("complete secure admission configuration is required")
	}
	if len(config.Journal.Pending()) != 0 {
		return errors.New("operation journal has pending work; reconcile it before startup")
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
	s.secure = &secureAdmission{
		policyEnvelope: append([]byte(nil), config.PolicyEnvelope...),
		siteRoots:      clonePublicKeys(config.SiteRoots),
		nodeID:         config.NodeID,
		fences:         config.Fences,
		journal:        config.Journal,
		evidence:       config.Evidence,
		allowHostAdmin: config.AllowHostAdminIntent,
		topology:       config.Topology, gateway: config.Gateway, relayImage: config.RelayImage,
		grantRoot: config.GrantRoot, relayGID: config.RelayGID,
	}
	return nil
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
	mux.HandleFunc("POST /v1/admissions", s.secureProvision)
	mux.HandleFunc("POST /v1/state/purge", s.purgeState)
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

type secureProvisionRequest struct {
	CapsuleDSSEBase64 string                   `json:"capsule_dsse_base64"`
	Intent            admission.InstanceIntent `json:"intent"`
}

type secureProvisionResponse struct {
	RuntimeRef    string `json:"runtime_ref"`
	Status        string `json:"status"`
	CapsuleDigest string `json:"capsule_digest"`
	PolicyDigest  string `json:"policy_digest"`
	Generation    uint64 `json:"generation"`
	EvidenceKeyID string `json:"evidence_key_id"`
	GrantID       string `json:"grant_id,omitempty"`
	ServicePath   string `json:"service_path,omitempty"`
}

type purgeStateRequest struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
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
	// Every mount, network and grant identifier is Executor-derived. The signed
	// request selects only finite capabilities already authorized by capsule and
	// site policy; it never supplies a host path or Docker topology primitive.
	if effective.Intent.Capabilities.Inference || effective.Intent.Capabilities.Service {
		if s.secure.topology == nil || s.secure.gateway == nil {
			writeError(w, http.StatusNotImplemented, "capability_unavailable", "inference and service capabilities require the configured v1.3 gateway topology")
			return
		}
		workload.Runtime = &RuntimeGrant{
			NetworkName: NetworkName(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation),
			GrantID:     gateway.GrantID(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation),
			Generation:  effective.Intent.Generation,
			Inference:   effective.Intent.Capabilities.Inference, ModelAlias: effective.Intent.ModelAlias,
			RouteID: effective.Intent.InferenceRouteID,
		}
		addresses := NetworkSpecFor(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation)
		workload.Runtime.RelayIP, workload.Runtime.AgentIP = addresses.RelayIP, addresses.AgentIP
		if effective.Intent.Capabilities.Service {
			workload.Runtime.ServicePort = effective.Capsule.Service.Port
		}
	}
	if effective.Intent.Capabilities.State {
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
	s.provisionSecureWorkload(w, r, workload, effective)
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
	if lineage.Generation != request.Generation || !s.authorizeRecord(r.Context(), lineage) {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "state purge is not authorized for the signed lineage generation")
		return
	}
	name := StateVolumeName(request.TenantID, request.LineageID)
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
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

func boundedRuntimeText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func (s *Server) provisionSecureWorkload(w http.ResponseWriter, r *http.Request, workload Workload, effective admission.EffectiveAdmission) {
	name := RuntimeRef(workload.TenantID, workload.InstanceID)
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if len(s.secure.journal.Pending()) != 0 {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	observed, err := s.docker.Inspect(r.Context(), name)
	if err == nil {
		if !observed.Managed || !observed.Hardened ||
			observed.Fingerprint != workloadFingerprint(workload) ||
			observed.ImageID != effective.Capsule.Image.ConfigDigest ||
			!s.secure.fences.Matches(admission.FenceRecord{
				TenantID: workload.TenantID, InstanceID: workload.InstanceID,
				Generation: effective.Intent.Generation, CapsuleDigest: effective.CapsuleDigest,
				PolicyDigest: effective.PolicyDigest, LineageID: effective.Intent.LineageID,
				WorkloadDigest:    "sha256:" + workloadFingerprint(workload),
				ImageConfigDigest: effective.Capsule.Image.ConfigDigest, Present: true,
			}, effective.SitePolicy.PolicyEpoch) {
			writeError(w, http.StatusConflict, "workload_conflict", "runtime_ref already belongs to a different workload definition")
			return
		}
		if workload.State != nil && !s.stateVolumeMatches(r.Context(), workload, effective.Intent.LineageID) {
			writeError(w, http.StatusConflict, "state_drift", "persistent state volume does not match the signed tenant lineage")
			return
		}
		if workload.Runtime != nil && !s.runtimeTopologyMatches(r.Context(), workload, observed.Status == "running") {
			writeError(w, http.StatusConflict, "runtime_drift", "isolated runtime topology does not match the signed capability grant")
			return
		}
		s.writeSecureResponse(w, http.StatusOK, name, observed.Status, effective)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		writeDockerError(w, err)
		return
	}
	if persisted := s.secure.fences.Fences(workload.TenantID, workload.InstanceID); persisted.Generation >= effective.Intent.Generation {
		writeError(w, http.StatusConflict, "generation_consumed", "the committed generation is absent; submit a higher generation rather than replaying it")
		return
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
	opID, err := newOperationID(name, effective.Intent.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create operation identity")
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
	if err := s.docker.Create(r.Context(), name, workload); err != nil {
		if _, inspectErr := s.docker.Inspect(r.Context(), name); errors.Is(inspectErr, ErrNotFound) {
			if !s.rollbackSecureProvision(r.Context(), name, stateDocker, workload, stateCreated) {
				writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker create failed and topology rollback is ambiguous; operation remains prepared")
				return
			}
			s.recordCompensation(opID, prepared, "docker_create")
			writeDockerError(w, err)
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
	committed := prepared
	committed.Type = evidence.JournalCommit
	committed.Outcome = evidence.Committed
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
		ImageConfigDigest: effective.Capsule.Image.ConfigDigest, Present: true,
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
	s.writeSecureResponse(w, http.StatusCreated, name, observed.Status, effective)
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

func (s *Server) writeSecureResponse(w http.ResponseWriter, status int, runtimeRef, runtimeStatus string, effective admission.EffectiveAdmission) {
	response := secureProvisionResponse{
		RuntimeRef: runtimeRef, Status: runtimeStatus, CapsuleDigest: effective.CapsuleDigest,
		PolicyDigest: effective.PolicyDigest, Generation: effective.Intent.Generation,
		EvidenceKeyID: evidence.KeyID(s.secure.evidence.PublicKey()),
	}
	if effective.Intent.Capabilities.Inference || effective.Intent.Capabilities.Service {
		response.GrantID = gateway.GrantID(effective.Intent.TenantID, effective.Intent.InstanceID, effective.Intent.Generation)
	}
	if effective.Intent.Capabilities.Service {
		response.ServicePath = "/v1/services/" + response.GrantID + "/"
	}
	writeJSON(w, status, response)
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

func (s *Server) secureTransition(w http.ResponseWriter, r *http.Request, action string) {
	name, ok := runtimeRef(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_runtime_ref", "invalid executor runtime_ref")
		return
	}
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if len(s.secure.journal.Pending()) != 0 {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	observed, err := s.managed(r.Context(), name)
	if err != nil {
		writeDockerError(w, err)
		return
	}
	record, ok := s.authorizeSecureLifecycle(r.Context(), observed)
	if !ok {
		writeError(w, http.StatusForbidden, "signed_lifecycle_required", "workload is not bound to the authenticated signed admission")
		return
	}
	if ((action == "start" && observed.Status == "running") || (action == "stop" && observed.Status != "running")) &&
		s.runtimeLifecycleMatches(r.Context(), observed.Workload, action == "start") {
		writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": observed.Status})
		return
	}
	opID, err := newOperationID(action+"-"+name, record.Generation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "create operation identity")
		return
	}
	if _, err := s.secure.journal.Prepare(opID, action+":"+name, record.Generation); err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unavailable", err.Error())
		return
	}
	prepared := evidence.Event{
		Type: evidence.JournalPrepare, TenantID: record.TenantID, RuntimeRef: name,
		CapsuleDigest: record.CapsuleDigest, PolicyDigest: record.PolicyDigest,
		Generation: record.Generation, GrantID: "workload", Outcome: evidence.Allowed,
		ErrorCode: action,
	}
	if _, err := s.secure.evidence.Append(prepared); err != nil {
		_ = s.secure.journal.Compensate(opID)
		writeError(w, http.StatusServiceUnavailable, "evidence_unavailable", err.Error())
		return
	}
	err = s.applyRuntimeTransition(r.Context(), name, observed.Workload, action == "start")
	final, inspectErr := s.managed(r.Context(), name)
	expected := (action == "start" && final.Status == "running" || action == "stop" && final.Status != "running") &&
		s.runtimeLifecycleMatches(r.Context(), final.Workload, action == "start")
	unchanged := inspectErr == nil && final.Status == observed.Status &&
		s.runtimeLifecycleMatches(r.Context(), observed.Workload, observed.Status == "running")
	if err != nil && unchanged {
		s.recordCompensation(opID, prepared, "docker_"+action)
		writeDockerError(w, err)
		return
	}
	if inspectErr != nil {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "Docker lifecycle result is ambiguous; operation remains prepared")
		return
	}
	if !expected {
		if !s.restoreRuntimeLifecycle(r.Context(), name, observed.Workload, observed.Status == "running") {
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
	if action == "start" {
		committed.Type = evidence.LifecycleStart
	} else {
		committed.Type = evidence.LifecycleStop
	}
	if _, err := s.secure.evidence.Append(committed); err != nil {
		if !s.restoreRuntimeLifecycle(r.Context(), name, observed.Workload, observed.Status == "running") {
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
	writeJSON(w, http.StatusOK, map[string]string{"runtime_ref": name, "status": final.Status})
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
	if len(s.secure.journal.Pending()) != 0 {
		writeError(w, http.StatusServiceUnavailable, "reconciliation_required", "a prior host mutation requires reconciliation")
		return
	}
	observed, err := s.docker.Inspect(r.Context(), name)
	if errors.Is(err, ErrNotFound) {
		for _, record := range s.secure.fences.Records() {
			if RuntimeRef(record.TenantID, record.InstanceID) == name && !record.Present && s.authorizeRecord(r.Context(), record) {
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
	record, ok := s.authorizeSecureLifecycle(r.Context(), observed)
	if !ok {
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

func (s *Server) authorizeSecureLifecycle(ctx context.Context, observed ObservedWorkload) (admission.FenceRecord, bool) {
	record, ok := s.secure.fences.Record(observed.Workload.TenantID, observed.Workload.InstanceID)
	if !ok || !record.Present ||
		observed.Fingerprint != strings.TrimPrefix(record.WorkloadDigest, "sha256:") ||
		observed.ImageID != record.ImageConfigDigest ||
		RuntimeRef(record.TenantID, record.InstanceID) != RuntimeRef(observed.Workload.TenantID, observed.Workload.InstanceID) {
		return admission.FenceRecord{}, false
	}
	return record, s.authorizeRecord(ctx, record)
}

func (s *Server) authorizeRecord(ctx context.Context, record admission.FenceRecord) bool {
	if record.PolicyDigest != dsse.Digest(s.secure.policyEnvelope) {
		return false
	}
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
