package executoruplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
)

type command struct {
	CommandID          string          `json:"command_id"`
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	Payload            json.RawMessage `json:"payload"`
	ClaimGeneration    int64           `json:"claim_generation"`
	InstanceGeneration int64           `json:"instance_generation"`
	CommandSequence    int64           `json:"command_sequence"`
}

type report struct {
	CommandID       string         `json:"command_id"`
	Status          string         `json:"status"`
	ReportedStatus  string         `json:"reported_status"`
	ClaimGeneration int64          `json:"claim_generation"`
	Result          map[string]any `json:"result"`
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
}

type dispatcher struct {
	handler  http.Handler
	token    string
	tenantID string
	nodeID   string
	state    *StateStore
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
	if cmd.TenantID != d.tenantID || cmd.NodeID != d.nodeID {
		rep.Result["error"] = "command identity does not match this enrolled executor"
		return rep
	}
	nodeID, instanceID, err := parseRuntimeRef(cmd.RuntimeRef)
	if err != nil || nodeID != d.nodeID {
		rep.Result["error"] = "command runtime_ref is invalid or belongs to another node"
		return rep
	}
	if current, ok := d.state.position(instanceID); ok {
		if cmd.InstanceGeneration < current.Generation ||
			(cmd.InstanceGeneration == current.Generation && cmd.CommandSequence <= current.Sequence) {
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

	runtimeRef := executor.RuntimeRef(d.tenantID, instanceID)
	reported, err := d.apply(ctx, cmd, instanceID, runtimeRef)
	if err != nil {
		rep.Result["error"] = err.Error()
		return rep
	}
	absent := cmd.Kind == "destroy"
	if err := d.state.advance(instanceID, position{
		Generation: cmd.InstanceGeneration, Sequence: cmd.CommandSequence,
		ReportedStatus: reported, Absent: absent,
	}); err != nil {
		rep.Result["error"] = "persist command fence: " + err.Error()
		return rep
	}
	rep.Status = "done"
	rep.ReportedStatus = reported
	rep.Result["runtime_ref"] = runtimeRef
	if absent {
		rep.Result["absent"] = true
	}
	return rep
}

func (d *dispatcher) apply(ctx context.Context, cmd command, instanceID, runtimeRef string) (string, error) {
	switch cmd.Kind {
	case "admit":
		var payload admissionPayload
		if err := dsse.DecodeStrictInto(cmd.Payload, maxWireBytes, &payload); err != nil {
			return "", fmt.Errorf("invalid signed admission payload: %w", err)
		}
		if payload.Intent.TenantID != d.tenantID || payload.Intent.NodeID != d.nodeID ||
			payload.Intent.InstanceID != instanceID || payload.Intent.Generation != uint64(cmd.InstanceGeneration) {
			return "", errors.New("signed admission intent does not match enrolled command identity and generation")
		}
		ctx = executor.WithAdmissionPrincipal(ctx, d.tenantID, d.nodeID, uint64(cmd.InstanceGeneration))
		return d.call(ctx, http.MethodPost, "/v1/admissions", payload)
	case "provision":
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
			InstanceID: instanceID, TenantID: d.tenantID, ProfileID: payload.ProfileID,
			Image: payload.Image, Command: payload.Command, Resources: payload.Resources,
			Egress: payload.Egress,
		}
		return d.call(ctx, http.MethodPost, "/v1/workloads", workload)
	case "start":
		ctx = executor.WithAdmissionPrincipal(ctx, d.tenantID, d.nodeID, uint64(cmd.InstanceGeneration))
		return d.call(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil)
	case "stop":
		ctx = executor.WithAdmissionPrincipal(ctx, d.tenantID, d.nodeID, uint64(cmd.InstanceGeneration))
		return d.call(ctx, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", nil)
	case "destroy":
		ctx = executor.WithAdmissionPrincipal(ctx, d.tenantID, d.nodeID, uint64(cmd.InstanceGeneration))
		if _, err := d.call(ctx, http.MethodDelete, "/v1/workloads/"+runtimeRef, nil); err != nil {
			return "", err
		}
		return "stopped", nil
	case "hibernate":
		return "", errors.New("executor runtime does not support hibernate")
	default:
		return "", fmt.Errorf("unsupported command kind %q", cmd.Kind)
	}
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
	res := newLocalResponse()
	d.handler.ServeHTTP(res, req)
	if res.status >= 400 {
		return "", fmt.Errorf("local executor returned HTTP %d: %s", res.status, strings.TrimSpace(res.body.String()))
	}
	if res.status == http.StatusNoContent {
		return "stopped", nil
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(&res.body, 1<<20)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode local executor response: %w", err)
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
		return "", fmt.Errorf("local executor returned unsupported status %q", payload.Status)
	}
}

type localResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newLocalResponse() *localResponse               { return &localResponse{header: make(http.Header), status: 200} }
func (r *localResponse) Header() http.Header         { return r.header }
func (r *localResponse) WriteHeader(status int)      { r.status = status }
func (r *localResponse) Write(p []byte) (int, error) { return r.body.Write(p) }

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

func parseRuntimeRef(ref string) (nodeID, instanceID string, err error) {
	const prefix = "uplink:"
	if !strings.HasPrefix(ref, prefix) {
		return "", "", errors.New("missing uplink prefix")
	}
	rest := strings.TrimPrefix(ref, prefix)
	separator := strings.IndexByte(rest, ':')
	if separator <= 0 {
		return "", "", errors.New("missing node length")
	}
	length, err := strconv.Atoi(rest[:separator])
	if err != nil || length <= 0 {
		return "", "", errors.New("invalid node length")
	}
	rest = rest[separator+1:]
	byteBoundary := 0
	for count := 0; count < length; count++ {
		if byteBoundary >= len(rest) {
			return "", "", errors.New("node length overruns runtime_ref")
		}
		_, size := utf8.DecodeRuneInString(rest[byteBoundary:])
		if size == 0 || size == 1 && rest[byteBoundary] >= utf8.RuneSelf {
			return "", "", errors.New("invalid utf-8 node id")
		}
		byteBoundary += size
	}
	if byteBoundary >= len(rest) || rest[byteBoundary] != ':' {
		return "", "", errors.New("missing instance separator")
	}
	nodeID, instanceID = rest[:byteBoundary], rest[byteBoundary+1:]
	if nodeID == "" || instanceID == "" {
		return "", "", errors.New("empty node or instance id")
	}
	return nodeID, instanceID, nil
}
