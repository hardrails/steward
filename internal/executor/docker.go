package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Docker is the minimum Docker Engine API surface the executor needs. Keeping this
// interface narrow makes it possible to test the safety policy without a daemon.
type Docker interface {
	RuntimeAvailable(context.Context, string) (bool, error)
	WorkloadCounts(context.Context, string) (total int, tenant int, err error)
	Inspect(context.Context, string) (ObservedWorkload, error)
	Create(context.Context, string, Workload) error
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Remove(context.Context, string) error
	Logs(context.Context, string) (string, error)
}

// ObservedWorkload is the executor-owned subset of Docker inspect state. Keeping
// the projection narrow lets the lifecycle layer prove that a deterministic name
// already belongs to the same immutable workload before treating provision as an
// idempotent replay.
type ObservedWorkload struct {
	Workload    Workload
	Fingerprint string
	Managed     bool
	Hardened    bool
	Status      string
}

// DockerHTTP is a standard-library Docker Engine client over the local Unix socket.
// It deliberately does not expose a general request method to the HTTP API layer.
type DockerHTTP struct{ client *http.Client }

const managedWorkloadLabel = "io.hardrails.executor.managed"
const workloadFingerprintLabel = "io.hardrails.workload-sha256"
const workspaceTmpfs = "rw,nosuid,nodev,size=67108864"
const tempTmpfs = "rw,noexec,nosuid,nodev,size=67108864"
const workloadMemoryLabel = "io.hardrails.memory-bytes"
const workloadCPULabel = "io.hardrails.cpu-millis"
const workloadPIDsLabel = "io.hardrails.pids"

func NewDockerHTTP(socket string) *DockerHTTP {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	return &DockerHTTP{client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
}

// RuntimeAvailable checks Docker's own runtime registry at startup. A missing
// runsc runtime is a deployment error, not a workload-level error that should be
// discovered after an upstream control plane has already accepted a tenant request.
func (d *DockerHTTP) RuntimeAvailable(ctx context.Context, runtime string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/info", nil)
	if err != nil {
		return false, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, dockerError(resp)
	}
	var payload struct {
		Runtimes map[string]json.RawMessage `json:"Runtimes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return false, err
	}
	_, ok := payload.Runtimes[runtime]
	return ok, nil
}

// WorkloadCounts discovers existing executor-managed containers from Docker, rather
// than trusting in-memory state that would vanish on an executor restart. The Docker
// socket remains the authoritative host inventory; containers created outside this
// narrow executor contract intentionally do not consume its admission capacity.
func (d *DockerHTTP) WorkloadCounts(ctx context.Context, tenantID string) (int, int, error) {
	filters, err := json.Marshal(map[string][]string{
		"label": {managedWorkloadLabel + "=true"},
	})
	if err != nil {
		return 0, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.41/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil)
	if err != nil {
		return 0, 0, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, dockerError(resp)
	}
	var containers []struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&containers); err != nil {
		return 0, 0, err
	}
	total := len(containers)
	tenant := 0
	for _, container := range containers {
		if container.Labels["io.hardrails.tenant"] == tenantID {
			tenant++
		}
	}
	return total, tenant, nil
}

func (d *DockerHTTP) Create(ctx context.Context, name string, w Workload) error {
	body := map[string]any{
		"Image":          w.Image,
		"Cmd":            w.Command,
		"Env":            []string{"HOME=/workspace", "TMPDIR=/tmp"},
		"User":           "65532:65532",
		"WorkingDir":     "/workspace",
		"ReadonlyRootfs": true,
		"HostConfig": map[string]any{
			"Runtime":        "runsc",
			"NetworkMode":    "none",
			"ReadonlyRootfs": true,
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"PidsLimit":      w.Resources.PIDs,
			"Memory":         w.Resources.MemoryBytes,
			"NanoCPUs":       w.Resources.CPUMillis * 1_000_000,
			"Tmpfs": map[string]string{
				"/tmp": tempTmpfs, "/workspace": workspaceTmpfs,
			},
		},
		"Labels": map[string]string{
			managedWorkloadLabel:     "true",
			workloadFingerprintLabel: workloadFingerprint(w),
			"io.hardrails.tenant":    w.TenantID,
			"io.hardrails.instance":  w.InstanceID,
			"io.hardrails.profile":   w.ProfileID,
			workloadMemoryLabel:      strconv.FormatInt(w.Resources.MemoryBytes, 10),
			workloadCPULabel:         strconv.FormatInt(w.Resources.CPUMillis, 10),
			workloadPIDsLabel:        strconv.FormatInt(w.Resources.PIDs, 10),
		},
	}
	return d.call(ctx, http.MethodPost, "/v1.41/containers/create?name="+url.QueryEscape(name), body, http.StatusCreated)
}

func (d *DockerHTTP) Inspect(ctx context.Context, name string) (ObservedWorkload, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/containers/"+pathEscape(name)+"/json", nil)
	if err != nil {
		return ObservedWorkload{}, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return ObservedWorkload{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ObservedWorkload{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return ObservedWorkload{}, dockerError(resp)
	}
	var payload struct {
		Config struct {
			Image      string            `json:"Image"`
			Cmd        []string          `json:"Cmd"`
			Env        []string          `json:"Env"`
			User       string            `json:"User"`
			WorkingDir string            `json:"WorkingDir"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			Memory      int64             `json:"Memory"`
			NanoCPUs    int64             `json:"NanoCpus"`
			Pids        int64             `json:"PidsLimit"`
			Runtime     string            `json:"Runtime"`
			NetworkMode string            `json:"NetworkMode"`
			Readonly    bool              `json:"ReadonlyRootfs"`
			CapDrop     []string          `json:"CapDrop"`
			SecurityOpt []string          `json:"SecurityOpt"`
			Tmpfs       map[string]string `json:"Tmpfs"`
		} `json:"HostConfig"`
		State struct {
			Status string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedWorkload{}, err
	}
	labels := payload.Config.Labels
	return ObservedWorkload{
		Workload: Workload{
			TenantID:   labels["io.hardrails.tenant"],
			InstanceID: labels["io.hardrails.instance"],
			ProfileID:  labels["io.hardrails.profile"],
			Image:      payload.Config.Image,
			Command:    payload.Config.Cmd,
			Resources: Resources{
				MemoryBytes: payload.HostConfig.Memory,
				CPUMillis:   payload.HostConfig.NanoCPUs / 1_000_000,
				PIDs:        payload.HostConfig.Pids,
			},
			Egress: Egress{},
		},
		Fingerprint: labels[workloadFingerprintLabel],
		Managed:     labels[managedWorkloadLabel] == "true",
		Hardened: payload.Config.User == "65532:65532" &&
			validFingerprint(labels[workloadFingerprintLabel]) &&
			labels["io.hardrails.tenant"] != "" && labels["io.hardrails.instance"] != "" &&
			labels["io.hardrails.profile"] != "" &&
			labels[workloadMemoryLabel] == strconv.FormatInt(payload.HostConfig.Memory, 10) &&
			labels[workloadCPULabel] == strconv.FormatInt(payload.HostConfig.NanoCPUs/1_000_000, 10) &&
			labels[workloadPIDsLabel] == strconv.FormatInt(payload.HostConfig.Pids, 10) &&
			payload.Config.WorkingDir == "/workspace" &&
			contains(payload.Config.Env, "HOME=/workspace") &&
			contains(payload.Config.Env, "TMPDIR=/tmp") &&
			payload.HostConfig.Runtime == "runsc" && payload.HostConfig.NetworkMode == "none" &&
			payload.HostConfig.Readonly && contains(payload.HostConfig.CapDrop, "ALL") &&
			contains(payload.HostConfig.SecurityOpt, "no-new-privileges:true") &&
			payload.HostConfig.Tmpfs["/tmp"] == tempTmpfs &&
			payload.HostConfig.Tmpfs["/workspace"] == workspaceTmpfs,
		Status: payload.State.Status,
	}, nil
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func workloadFingerprint(w Workload) string {
	raw, _ := json.Marshal(w)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (d *DockerHTTP) Start(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodPost, "/v1.41/containers/"+pathEscape(name)+"/start", nil, http.StatusNoContent)
}
func (d *DockerHTTP) Stop(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodPost, "/v1.41/containers/"+pathEscape(name)+"/stop?t=10", nil, http.StatusNoContent)
}
func (d *DockerHTTP) Remove(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodDelete, "/v1.41/containers/"+pathEscape(name)+"?force=true", nil, http.StatusNoContent)
}

const maxLogBytes = 1 << 20

// Logs returns a bounded combined stdout/stderr tail. Docker uses an 8-byte
// frame header for non-TTY containers, which is removed before returning text.
func (d *DockerHTTP) Logs(ctx context.Context, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.41/containers/"+pathEscape(name)+"/logs?stdout=true&stderr=true&tail=1000", nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", dockerError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLogBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxLogBytes {
		return "", fmt.Errorf("Docker log response exceeds %d byte limit", maxLogBytes)
	}
	return string(unframeDockerLogs(raw)), nil
}

func unframeDockerLogs(raw []byte) []byte {
	var out bytes.Buffer
	for len(raw) >= 8 && (raw[0] == 0 || raw[0] == 1 || raw[0] == 2) && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		size := int(binary.BigEndian.Uint32(raw[4:8]))
		if size > len(raw)-8 {
			return raw
		}
		out.Write(raw[8 : 8+size])
		raw = raw[8+size:]
	}
	if out.Len() == 0 {
		return raw
	}
	return out.Bytes()
}

func (d *DockerHTTP) call(ctx context.Context, method, target string, body any, expected int) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+target, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != expected {
		return dockerError(resp)
	}
	return nil
}

func dockerError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("docker API returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
}
func pathEscape(value string) string { return url.PathEscape(value) }
