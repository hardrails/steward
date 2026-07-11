// Package executor is the narrow, host-local Docker execution boundary for
// tenant-scoped agent workloads. It deliberately lives outside Steward: the
// Steward daemon remains a generic lifecycle tracker and outbound control client.
package executor

import (
	"errors"
	"math"
	"regexp"
	"strings"
)

// PolicyError means a requested workload violates the non-negotiable V1 host policy.
// It maps to HTTP 400: callers must change their requested workload rather than retry.
type PolicyError struct{ Message string }

func (e *PolicyError) Error() string { return e.Message }

var imageDigest = regexp.MustCompile(`^.+@sha256:[a-f0-9]{64}$`)

// Workload is the complete, intentionally small request accepted by the privileged
// executor. Image references must be immutable digests; tags are never accepted.
// No caller can ask for privileged mode, a host mount, or a Docker socket through this
// contract, because those escape hatches are absent from its shape.
type Workload struct {
	InstanceID string    `json:"instance_id"`
	TenantID   string    `json:"tenant_id"`
	ProfileID  string    `json:"profile_id"`
	Image      string    `json:"image"`
	Command    []string  `json:"command,omitempty"`
	Resources  Resources `json:"resources"`
	Egress     Egress    `json:"egress"`
}

// Resources are mandatory cgroup limits. Docker has no resource limits by default,
// so zero values are rejected instead of silently creating an unbounded workload.
type Resources struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
}

// HostPolicy is exclusively host-operator configuration. It bounds values an
// untrusted tenant may request and limits how many executor-managed workloads
// may exist globally and for one tenant. It is deliberately separate from a
// workload request: a tenant cannot raise its own ceiling.
type HostPolicy struct {
	MaxMemoryBytes        int64
	MaxCPUMillis          int64
	MaxPIDs               int64
	MaxWorkloads          int
	MaxWorkloadsPerTenant int
}

// DefaultHostPolicy is conservative enough for a shared host. Operators with
// a capacity plan may raise these startup-only limits; requests can never do so.
func DefaultHostPolicy() HostPolicy {
	return HostPolicy{
		MaxMemoryBytes:        512 << 20,
		MaxCPUMillis:          1000,
		MaxPIDs:               128,
		MaxWorkloads:          32,
		MaxWorkloadsPerTenant: 4,
	}
}

func (p HostPolicy) Validate() error {
	if p.MaxMemoryBytes <= 0 || p.MaxCPUMillis <= 0 || p.MaxPIDs <= 0 ||
		p.MaxWorkloads <= 0 || p.MaxWorkloadsPerTenant <= 0 {
		return errors.New("all host policy limits must be positive")
	}
	if p.MaxCPUMillis > math.MaxInt64/1_000_000 {
		return errors.New("max CPU millicores is too large for Docker NanoCPUs")
	}
	if p.MaxWorkloadsPerTenant > p.MaxWorkloads {
		return errors.New("max workloads per tenant must not exceed max workloads")
	}
	return nil
}

func (p HostPolicy) ValidateWorkload(w Workload) error {
	if w.Resources.MemoryBytes > p.MaxMemoryBytes {
		return &PolicyError{"memory_bytes exceeds the host workload ceiling"}
	}
	if w.Resources.CPUMillis > p.MaxCPUMillis {
		return &PolicyError{"cpu_millis exceeds the host workload ceiling"}
	}
	if w.Resources.PIDs > p.MaxPIDs {
		return &PolicyError{"pids exceeds the host workload ceiling"}
	}
	return nil
}

// Egress remains deny-by-default. The executor currently only admits no networking;
// hostname allowlists will be implemented through a tenant-aware egress proxy rather
// than by giving an untrusted workload raw network access.
type Egress struct {
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

// Validate checks the deterministic, host-safe V1 policy before a Docker API request
// is made. Validation at this boundary is intentional: upstream policy bugs must not
// turn into host-level privilege or resource escapes.
func (w Workload) Validate() error {
	if !boundedText(w.InstanceID, 256) {
		return &PolicyError{"instance_id must be non-empty, at most 256 bytes, and contain no NUL"}
	}
	if !boundedText(w.TenantID, 128) {
		return &PolicyError{"tenant_id must be non-empty, at most 128 bytes, and contain no NUL"}
	}
	if !boundedText(w.ProfileID, 128) {
		return &PolicyError{"profile_id must be non-empty, at most 128 bytes, and contain no NUL"}
	}
	if len(w.Image) > 1024 || !imageDigest.MatchString(w.Image) {
		return &PolicyError{"image must be an immutable @sha256 digest reference"}
	}
	if len(w.Command) > 64 {
		return &PolicyError{"command may contain at most 64 arguments"}
	}
	if len(w.Command) == 0 {
		return &PolicyError{"command must contain at least one explicit argument"}
	}
	for _, argument := range w.Command {
		if len(argument) > 4096 || strings.ContainsRune(argument, '\x00') {
			return &PolicyError{"command arguments must be at most 4096 bytes and contain no NUL"}
		}
	}
	if w.Resources.MemoryBytes <= 0 || w.Resources.CPUMillis <= 0 || w.Resources.PIDs <= 0 {
		return &PolicyError{"memory_bytes, cpu_millis, and pids must all be positive"}
	}
	if len(w.Egress.AllowedHosts) != 0 {
		return &PolicyError{"egress allowlists require the tenant egress proxy and are not enabled"}
	}
	return nil
}

func boundedText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

var ErrNotFound = errors.New("unknown workload")
var ErrWorkloadDrift = errors.New("executor workload has drifted from its admitted definition")
