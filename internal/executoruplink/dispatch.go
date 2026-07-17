package executoruplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
)

const activationAdmissionRequestSchema = "steward.executor-activation-admission.v1"

var errLocalResponseLimit = errors.New("local executor response exceeds its byte limit")

type command struct {
	CommandID          string          `json:"command_id"`
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	InstanceID         string          `json:"instance_id,omitempty"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	Payload            json.RawMessage `json:"payload"`
	ClaimGeneration    uint64          `json:"claim_generation"`
	InstanceGeneration uint64          `json:"instance_generation"`
	CommandSequence    uint64          `json:"command_sequence"`
	signed             bool
}

// legacyCommand pins the tenant-scoped v1 JSON contract. It intentionally does
// not include v2-only identity fields, so strict decoding cannot accidentally
// widen the unsigned compatibility protocol as the internal command evolves.
type legacyCommand struct {
	CommandID          string          `json:"command_id"`
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	Payload            json.RawMessage `json:"payload"`
	ClaimGeneration    uint64          `json:"claim_generation"`
	InstanceGeneration uint64          `json:"instance_generation"`
	CommandSequence    uint64          `json:"command_sequence"`
}

type report struct {
	CommandID       string         `json:"command_id"`
	Status          string         `json:"status"`
	ReportedStatus  string         `json:"reported_status"`
	ClaimGeneration uint64         `json:"claim_generation"`
	Result          map[string]any `json:"result"`
	// effectUncertain is local protocol evidence, not part of legacy wire JSON.
	// It distinguishes validation failures from an error after ServeHTTP began.
	effectUncertain bool
	// canaryTerminalErrorCode is set only after Gateway authenticated a
	// terminal failed or cancelled agent result. It preserves a real attempted
	// canary as failed instead of misclassifying it as a pre-effect rejection.
	canaryTerminalErrorCode string
	// admission is retained only for a protocol-4 successful signed admit. It
	// is deliberately outside legacy report JSON.
	admission *controlprotocol.ExecutorAdmissionProjectionV1
	// activationCanary is retained only for one protocol-4 successful closed
	// canary. It is deliberately outside legacy report JSON.
	activationCanary *controlprotocol.ExecutorActivationCanaryResultV1
}

type uncertainEffectError struct{ cause error }

func (err uncertainEffectError) Error() string { return err.cause.Error() }
func (err uncertainEffectError) Unwrap() error { return err.cause }

func effectMayHaveOccurred(err error) bool {
	var uncertain uncertainEffectError
	return errors.As(err, &uncertain)
}

func localCallError(method string, cause error) error {
	if method == http.MethodGet {
		return cause
	}
	return uncertainEffectError{cause: cause}
}

type workloadPayload struct {
	ProfileID string             `json:"profile_id"`
	Image     string             `json:"image"`
	Command   []string           `json:"command,omitempty"`
	Resources executor.Resources `json:"resources"`
	Egress    executor.Egress    `json:"egress"`
}

type admissionPayload struct {
	CapsuleDSSEBase64 string                   `json:"capsule_dsse_base64"`
	Intent            admission.InstanceIntent `json:"intent"`
	Activation        *admissionActivation     `json:"activation,omitempty"`
}

type admissionActivation struct {
	SchemaVersion string `json:"schema_version"`
	ActivationID  string `json:"activation_id"`
	BeginDigest   string `json:"begin_digest"`
}

// executorAdmissionResponse pins Executor's public response exactly. The
// protocol projection adds its own schema marker after this strict local
// response has been decoded.
type executorAdmissionResponse struct {
	RuntimeRef            string                                    `json:"runtime_ref"`
	Status                string                                    `json:"status"`
	CapsuleDigest         string                                    `json:"capsule_digest"`
	PolicyDigest          string                                    `json:"policy_digest"`
	Generation            uint64                                    `json:"generation"`
	EvidenceKeyID         string                                    `json:"evidence_key_id"`
	GrantID               string                                    `json:"grant_id,omitempty"`
	ServicePath           string                                    `json:"service_path,omitempty"`
	ServiceID             string                                    `json:"service_id,omitempty"`
	TaskAuthorities       []controlprotocol.ExecutorTaskAuthorityV1 `json:"task_authorities,omitempty"`
	EgressProxy           string                                    `json:"egress_proxy,omitempty"`
	EgressRouteIDs        []string                                  `json:"egress_route_ids,omitempty"`
	ConnectorURL          string                                    `json:"connector_url,omitempty"`
	ConnectorIDs          []string                                  `json:"connector_ids,omitempty"`
	RoutePolicyDigest     string                                    `json:"route_policy_digest,omitempty"`
	ActivationID          string                                    `json:"activation_id,omitempty"`
	ActivationBeginDigest string                                    `json:"activation_begin_digest,omitempty"`
}

type purgePayload struct {
	LineageID string `json:"lineage_id"`
}

type dispatcher struct {
	handler           http.Handler
	token             string
	tenantID          string
	nodeID            string
	nodeScoped        bool
	projectAdmission  bool
	activationGateway activationCanaryGateway
	now               func() time.Time
	wait              func(context.Context, time.Duration) error
	state             *StateStore
}

func (d *dispatcher) execute(ctx context.Context, cmd command) report {
	rep := report{
		CommandID: cmd.CommandID, Status: "failed", ReportedStatus: "failed",
		ClaimGeneration: cmd.ClaimGeneration, Result: map[string]any{},
	}
	if cmd.CommandID == "" || cmd.ClaimGeneration <= 0 || cmd.InstanceGeneration <= 0 || cmd.CommandSequence <= 0 {
		rep.Result["error"] = "command is missing required fencing fields"
		return rep
	}
	if cmd.NodeID != d.nodeID || (!d.nodeScoped && cmd.TenantID != d.tenantID) || (d.nodeScoped && !cmd.signed) {
		rep.Result["error"] = "command identity does not match this enrolled executor"
		return rep
	}
	identity, err := parseRuntimeRef(cmd.RuntimeRef)
	if err != nil || identity.NodeID != d.nodeID ||
		(cmd.signed && (identity.Version != 2 || identity.TenantID != cmd.TenantID || identity.InstanceID != cmd.InstanceID)) ||
		(!cmd.signed && identity.Version != 1) {
		rep.Result["error"] = "command runtime_ref is invalid or belongs to another node"
		return rep
	}
	instanceID := identity.InstanceID
	current, hasCurrent := d.state.position(cmd.TenantID, instanceID)
	if cmd.Kind == "activation-canary" {
		if !hasCurrent || current.LegacyClaimFence ||
			cmd.InstanceGeneration != current.Generation ||
			cmd.ClaimGeneration != current.ClaimGeneration {
			rep.Result["error"] = "activation canary does not match a durable claim-aware lifecycle generation"
			return rep
		}
	} else if cmd.Kind == "read" {
		if !hasCurrent || cmd.InstanceGeneration != current.Generation ||
			(!current.LegacyClaimFence && cmd.ClaimGeneration != current.ClaimGeneration) {
			rep.Result["error"] = "read-only command does not match the durable lifecycle generation"
			return rep
		}
	}
	if hasCurrent {
		if commandIsStale(cmd, current) {
			if cmd.Kind == "activation-canary" {
				rep.Result["error"] = "activation canary command is stale relative to the durable lifecycle fence"
				return rep
			}
			// A stale or replayed command is a successful no-op. Returning the last
			// durable outcome lets the control plane settle a redelivery without ever
			// applying an older mutation to a newer workload lineage.
			rep.Status = "done"
			rep.ReportedStatus = current.ReportedStatus
			rep.Result["replayed"] = true
			if current.Absent {
				rep.Result["absent"] = true
			}
			return rep
		}
	}

	runtimeRef := executor.RuntimeRef(cmd.TenantID, instanceID)
	var reported string
	var projection *controlprotocol.ExecutorAdmissionProjectionV1
	var canary *controlprotocol.ExecutorActivationCanaryResultV1
	if d.projectAdmission && cmd.Kind == "admit" {
		reported, projection, err = d.applyAdmissionV4(
			ctx,
			cmd,
			cmd.TenantID,
			instanceID,
			runtimeRef,
		)
	} else if d.projectAdmission && cmd.Kind == "activation-canary" {
		reported, canary, err = d.applyActivationCanary(
			ctx,
			cmd,
			cmd.TenantID,
			instanceID,
			runtimeRef,
		)
	} else {
		reported, err = d.apply(ctx, cmd, cmd.TenantID, instanceID, runtimeRef)
	}
	if err != nil {
		rep.effectUncertain = effectMayHaveOccurred(err)
		if cmd.Kind == "activation-canary" {
			var terminal activationCanaryTerminalError
			if errors.As(err, &terminal) {
				switch terminal.status {
				case "agent_reported_failed":
					rep.canaryTerminalErrorCode = "activation_canary_failed"
				case "agent_reported_cancelled":
					rep.canaryTerminalErrorCode = "activation_canary_cancelled"
					rep.ReportedStatus = "cancelled"
				}
			}
		}
		rep.Result["error"] = err.Error()
		return rep
	}
	absent := cmd.Kind == "destroy" || cmd.Kind == "purge"
	// A read-only key must not be able to advance the lifecycle high-water
	// position and fence out a later admit/stop/destroy. Reads are authorized
	// against the exact durable generation above, but intentionally do not
	// mutate the command fence.
	if cmd.Kind != "read" && cmd.Kind != "activation-canary" {
		if err := d.state.advance(cmd.TenantID, instanceID, position{
			ClaimGeneration: cmd.ClaimGeneration,
			Generation:      cmd.InstanceGeneration, Sequence: cmd.CommandSequence,
			ReportedStatus: reported, Absent: absent,
		}); err != nil {
			rep.effectUncertain = true
			rep.Result["error"] = "persist command fence: " + err.Error()
			return rep
		}
	}
	rep.Status = "done"
	rep.ReportedStatus = reported
	rep.Result["runtime_ref"] = runtimeRef
	rep.admission = cloneAdmissionProjection(projection)
	rep.activationCanary = cloneActivationCanaryResult(canary)
	if absent {
		rep.Result["absent"] = true
	}
	return rep
}

func commandIsStale(cmd command, current position) bool {
	if current.LegacyClaimFence {
		return cmd.InstanceGeneration < current.Generation ||
			(cmd.InstanceGeneration == current.Generation && cmd.CommandSequence <= current.Sequence)
	}
	return cmd.ClaimGeneration < current.ClaimGeneration || cmd.InstanceGeneration < current.Generation ||
		(cmd.ClaimGeneration == current.ClaimGeneration && cmd.InstanceGeneration == current.Generation && cmd.CommandSequence <= current.Sequence)
}

func (d *dispatcher) apply(ctx context.Context, cmd command, tenantID, instanceID, runtimeRef string) (string, error) {
	switch cmd.Kind {
	case "admit":
		payload, err := d.decodeAdmissionPayload(cmd, tenantID, instanceID)
		if err != nil {
			return "", err
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		return d.call(ctx, http.MethodPost, "/v1/admissions", payload)
	case "provision":
		if cmd.signed {
			return "", errors.New("signed command protocol requires admit instead of legacy provision")
		}
		var payload workloadPayload
		decoder := json.NewDecoder(bytes.NewReader(cmd.Payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			return "", fmt.Errorf("invalid provision payload: %w", err)
		}
		if err := requireEOF(decoder); err != nil {
			return "", fmt.Errorf("invalid provision payload: %w", err)
		}
		workload := executor.Workload{
			InstanceID: instanceID, TenantID: tenantID, ProfileID: payload.ProfileID,
			Image: payload.Image, Command: payload.Command, Resources: payload.Resources,
			Egress: payload.Egress,
		}
		return d.call(ctx, http.MethodPost, "/v1/workloads", workload)
	case "start":
		if err := validateLifecyclePayload(cmd); err != nil {
			return "", err
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		return d.call(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil)
	case "stop":
		if err := validateLifecyclePayload(cmd); err != nil {
			return "", err
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		return d.call(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", nil)
	case "destroy":
		if err := validateLifecyclePayload(cmd); err != nil {
			return "", err
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		if _, err := d.call(ctx, http.MethodDelete, "/v1/workloads/"+runtimeRef, nil); err != nil {
			return "", err
		}
		return "stopped", nil
	case "read":
		if err := validateLifecyclePayload(cmd); err != nil {
			return "", err
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		return d.call(ctx, http.MethodGet, "/v1/workloads/"+runtimeRef, nil)
	case "purge":
		var payload purgePayload
		if err := dsse.DecodeStrictInto(cmd.Payload, maxWireBytes, &payload); err != nil ||
			!boundedCommandText(payload.LineageID, 256) {
			return "", errors.New("invalid state purge payload")
		}
		ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
		request := map[string]any{
			"tenant_id": tenantID, "node_id": d.nodeID, "lineage_id": payload.LineageID,
			"generation": cmd.InstanceGeneration,
		}
		if _, err := d.call(ctx, http.MethodPost, "/v1/state/purge", request); err != nil {
			return "", err
		}
		return "stopped", nil
	case "hibernate":
		return "", errors.New("executor runtime does not support hibernate")
	default:
		return "", fmt.Errorf("unsupported command kind %q", cmd.Kind)
	}
}

func (d *dispatcher) decodeAdmissionPayload(
	cmd command,
	tenantID, instanceID string,
) (admissionPayload, error) {
	var payload admissionPayload
	if err := dsse.DecodeStrictInto(cmd.Payload, maxWireBytes, &payload); err != nil {
		return admissionPayload{}, fmt.Errorf("invalid signed admission payload: %w", err)
	}
	if payload.Intent.TenantID != tenantID || payload.Intent.NodeID != d.nodeID ||
		payload.Intent.InstanceID != instanceID ||
		payload.Intent.Generation != uint64(cmd.InstanceGeneration) {
		return admissionPayload{}, errors.New("signed admission intent does not match enrolled command identity and generation")
	}
	if payload.Activation != nil &&
		(payload.Activation.SchemaVersion != activationAdmissionRequestSchema ||
			!boundedRouteIdentifier(payload.Activation.ActivationID) ||
			!controlprotocol.ValidSHA256Digest(payload.Activation.BeginDigest)) {
		return admissionPayload{}, errors.New("signed admission activation metadata is invalid")
	}
	return payload, nil
}

func (d *dispatcher) applyAdmissionV4(
	ctx context.Context,
	cmd command,
	tenantID, instanceID, runtimeRef string,
) (string, *controlprotocol.ExecutorAdmissionProjectionV1, error) {
	payload, err := d.decodeAdmissionPayload(cmd, tenantID, instanceID)
	if err != nil {
		return "", nil, err
	}
	ctx = executor.WithAdmissionPrincipal(ctx, tenantID, d.nodeID, cmd.InstanceGeneration)
	return d.callAdmissionV4(ctx, payload, runtimeRef)
}

func (d *dispatcher) callAdmissionV4(
	ctx context.Context,
	payload admissionPayload,
	expectedRuntimeRef string,
) (string, *controlprotocol.ExecutorAdmissionProjectionV1, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://executor.local/v1/admissions",
		bytes.NewReader(raw),
	)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	response := newLocalResponse(controlprotocol.MaxExecutorReportBytes)
	d.handler.ServeHTTP(response, req)
	if response.overflow {
		return "", nil, localCallError(http.MethodPost, errLocalResponseLimit)
	}
	if response.status >= 400 {
		return "", nil, localCallError(
			http.MethodPost,
			fmt.Errorf(
				"local executor returned HTTP %d: %s",
				response.status,
				strings.TrimSpace(response.body.String()),
			),
		)
	}
	if response.body.Len() == 0 ||
		response.body.Len() > controlprotocol.MaxExecutorReportBytes {
		return "", nil, localCallError(
			http.MethodPost,
			errors.New("local executor admission response is empty or exceeds the protocol-4 projection limit"),
		)
	}
	var local executorAdmissionResponse
	if err := dsse.DecodeStrictInto(
		response.body.Bytes(),
		controlprotocol.MaxExecutorReportBytes,
		&local,
	); err != nil {
		return "", nil, localCallError(
			http.MethodPost,
			fmt.Errorf("decode strict local executor admission response: %w", err),
		)
	}
	projection := executorAdmissionProjection(local)
	if err := projection.Validate(); err != nil {
		return "", nil, localCallError(
			http.MethodPost,
			fmt.Errorf("validate local executor admission projection: %w", err),
		)
	}
	if err := correlateAdmissionProjection(payload, expectedRuntimeRef, projection); err != nil {
		return "", nil, localCallError(http.MethodPost, err)
	}
	reportedStatus := "stopped"
	if projection.Status == "running" {
		reportedStatus = "running"
	}
	return reportedStatus, &projection, nil
}

func correlateAdmissionProjection(
	payload admissionPayload,
	expectedRuntimeRef string,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
) error {
	intent := payload.Intent
	if projection.RuntimeRef != expectedRuntimeRef ||
		projection.Generation != intent.Generation ||
		projection.CapsuleDigest != intent.CapsuleDigest {
		return errors.New("local executor admission response changed signed runtime identity, generation, or capsule digest")
	}
	needsGrant := intent.Capabilities.Inference ||
		intent.Capabilities.Service ||
		intent.Capabilities.Egress ||
		intent.Capabilities.Connector
	expectedGrantID := ""
	if needsGrant {
		expectedGrantID = gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation)
	}
	if projection.GrantID != expectedGrantID {
		return errors.New("local executor admission response changed the command-bound runtime grant")
	}
	if intent.Capabilities.Service != (projection.ServicePath != "") {
		return errors.New("local executor admission response changed the signed service capability")
	}
	if intent.Capabilities.Service && projection.ServiceID != intent.ServiceID {
		return errors.New("local executor admission response changed the signed service identity")
	}
	expectedEgress := admission.CanonicalRouteIDs(intent.EgressRouteIDs)
	if !slices.Equal(projection.EgressRouteIDs, expectedEgress) {
		return errors.New("local executor admission response changed the signed egress routes")
	}
	expectedConnectors := admission.CanonicalConnectorIDs(intent.ConnectorIDs)
	if !slices.Equal(projection.ConnectorIDs, expectedConnectors) {
		return errors.New("local executor admission response changed the signed connector routes")
	}
	needsRoutePolicy := intent.Capabilities.Inference ||
		len(projection.TaskAuthorities) > 0 ||
		len(expectedEgress) > 0 ||
		len(expectedConnectors) > 0
	if needsRoutePolicy != (projection.RoutePolicyDigest != "") {
		return errors.New("local executor admission response changed the effective route-policy binding")
	}
	if payload.Activation == nil {
		if projection.ActivationID != "" || projection.ActivationBeginDigest != "" {
			return errors.New("local executor admission response introduced unsigned activation metadata")
		}
	} else if projection.ActivationID != payload.Activation.ActivationID ||
		projection.ActivationBeginDigest != payload.Activation.BeginDigest {
		return errors.New("local executor admission response changed signed activation metadata")
	}
	return nil
}

func boundedRouteIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validateLifecyclePayload(cmd command) error {
	if !cmd.signed {
		return nil
	}
	var payload struct{}
	if err := dsse.DecodeStrictInto(cmd.Payload, maxWireBytes, &payload); err != nil {
		return fmt.Errorf("invalid %s payload: %w", cmd.Kind, err)
	}
	return nil
}

func boundedCommandText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func (d *dispatcher) call(ctx context.Context, method, target string, body any) (string, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://executor.local"+target, reader)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res := newLocalResponse(1 << 20)
	d.handler.ServeHTTP(res, req)
	if res.overflow {
		return "", localCallError(method, errLocalResponseLimit)
	}
	if res.status >= 400 {
		return "", localCallError(method, fmt.Errorf("local executor returned HTTP %d: %s", res.status, strings.TrimSpace(res.body.String())))
	}
	if res.status == http.StatusNoContent {
		return "stopped", nil
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(&res.body, 1<<20)).Decode(&payload); err != nil {
		return "", localCallError(method, fmt.Errorf("decode local executor response: %w", err))
	}
	switch payload.Status {
	case "running":
		return "running", nil
	case "created", "exited", "stopped":
		return "stopped", nil
	case "restarting":
		return "provisioning", nil
	case "removing":
		return "stopping", nil
	case "paused":
		return "hibernated", nil
	case "dead":
		return "failed", nil
	default:
		return "", localCallError(method, fmt.Errorf("local executor returned unsupported status %q", payload.Status))
	}
}

type localResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	limit    int
	overflow bool
}

func newLocalResponse(limit int) *localResponse {
	return &localResponse{header: make(http.Header), status: 200, limit: limit}
}

func (r *localResponse) Header() http.Header    { return r.header }
func (r *localResponse) WriteHeader(status int) { r.status = status }
func (r *localResponse) Write(p []byte) (int, error) {
	if r.overflow || r.limit <= r.body.Len() {
		r.overflow = true
		return 0, errLocalResponseLimit
	}
	remaining := r.limit - r.body.Len()
	if len(p) > remaining {
		written, _ := r.body.Write(p[:remaining])
		r.overflow = true
		return written, errLocalResponseLimit
	}
	return r.body.Write(p)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

type runtimeIdentity struct {
	Version    int
	TenantID   string
	NodeID     string
	InstanceID string
}

// RuntimeRefV2 creates the tenant-aware signed-command reference. Lengths are
// byte counts, not rune counts, so parsers in any language identify exactly the
// same boundaries even when tenant or node IDs contain non-ASCII UTF-8.
func RuntimeRefV2(tenantID, nodeID, instanceID string) (string, error) {
	if !utf8.ValidString(tenantID) || !utf8.ValidString(nodeID) || !utf8.ValidString(instanceID) ||
		!boundedCommandText(tenantID, 128) || !boundedCommandText(nodeID, 128) || !boundedCommandText(instanceID, 256) {
		return "", errors.New("runtime reference identity is empty, invalid, or exceeds its limit")
	}
	return "uplink:v2:" + strconv.Itoa(len(tenantID)) + ":" + tenantID + ":" +
		strconv.Itoa(len(nodeID)) + ":" + nodeID + ":" + instanceID, nil
}

func parseRuntimeRef(ref string) (runtimeIdentity, error) {
	if strings.HasPrefix(ref, "uplink:v2:") {
		rest := strings.TrimPrefix(ref, "uplink:v2:")
		tenantID, rest, err := takeByteLength(rest)
		if err != nil {
			return runtimeIdentity{}, fmt.Errorf("invalid tenant segment: %w", err)
		}
		nodeID, instanceID, err := takeByteLength(rest)
		if err != nil {
			return runtimeIdentity{}, fmt.Errorf("invalid node segment: %w", err)
		}
		if !boundedCommandText(tenantID, 128) || !boundedCommandText(nodeID, 128) || !boundedCommandText(instanceID, 256) ||
			!utf8.ValidString(tenantID) || !utf8.ValidString(nodeID) || !utf8.ValidString(instanceID) {
			return runtimeIdentity{}, errors.New("invalid runtime reference identity")
		}
		return runtimeIdentity{Version: 2, TenantID: tenantID, NodeID: nodeID, InstanceID: instanceID}, nil
	}
	const prefix = "uplink:"
	if !strings.HasPrefix(ref, prefix) {
		return runtimeIdentity{}, errors.New("missing uplink prefix")
	}
	rest := strings.TrimPrefix(ref, prefix)
	separator := strings.IndexByte(rest, ':')
	if separator <= 0 {
		return runtimeIdentity{}, errors.New("missing node length")
	}
	length, err := strconv.Atoi(rest[:separator])
	if err != nil || length <= 0 {
		return runtimeIdentity{}, errors.New("invalid node length")
	}
	rest = rest[separator+1:]
	byteBoundary := 0
	for count := 0; count < length; count++ {
		if byteBoundary >= len(rest) {
			return runtimeIdentity{}, errors.New("node length overruns runtime_ref")
		}
		_, size := utf8.DecodeRuneInString(rest[byteBoundary:])
		if size == 0 || size == 1 && rest[byteBoundary] >= utf8.RuneSelf {
			return runtimeIdentity{}, errors.New("invalid utf-8 node id")
		}
		byteBoundary += size
	}
	if byteBoundary >= len(rest) || rest[byteBoundary] != ':' {
		return runtimeIdentity{}, errors.New("missing instance separator")
	}
	nodeID, instanceID := rest[:byteBoundary], rest[byteBoundary+1:]
	if nodeID == "" || instanceID == "" {
		return runtimeIdentity{}, errors.New("empty node or instance id")
	}
	return runtimeIdentity{Version: 1, NodeID: nodeID, InstanceID: instanceID}, nil
}

func takeByteLength(value string) (string, string, error) {
	separator := strings.IndexByte(value, ':')
	if separator <= 0 {
		return "", "", errors.New("missing byte length")
	}
	encodedLength := value[:separator]
	length, err := strconv.Atoi(encodedLength)
	if err != nil || length <= 0 || length > 1024 {
		return "", "", errors.New("invalid byte length")
	}
	if strconv.Itoa(length) != encodedLength {
		return "", "", errors.New("non-canonical byte length")
	}
	value = value[separator+1:]
	if len(value) <= length || value[length] != ':' {
		return "", "", errors.New("byte length overruns segment or lacks separator")
	}
	return value[:length], value[length+1:], nil
}
