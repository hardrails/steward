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
var imageConfigDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var relayImageDigest = regexp.MustCompile(`^(?:.+@)?sha256:[a-f0-9]{64}$`)

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
	// State is trusted Executor-derived topology. It is intentionally excluded
	// from the public JSON request contract so legacy callers cannot select a
	// volume or host path.
	State *StateMount `json:"-"`
	// Runtime is the trusted, derived positive-capability topology. Like State,
	// it cannot be supplied through the public workload JSON contract.
	Runtime *RuntimeGrant `json:"-"`
	// ImageConfigDigest is the config identity verified during signed image
	// admission. Legacy requests leave it empty and retain their historical
	// repository@manifest create behavior.
	ImageConfigDigest string `json:"-"`
	// ImageRuntimeDigest is the exact Docker-store identity selected by signed
	// admission. It equals ImageConfigDigest on the classic graphdriver store and
	// the signed manifest digest on Docker's containerd image store.
	ImageRuntimeDigest string `json:"-"`
}

// ImageRequirement is the signed identity that a local Docker image must match
// before Executor mutates host state. Classic Docker executes by config digest;
// the containerd image store executes by manifest digest. Neither path depends
// on a mutable tag or a repository alias surviving an offline import.
type ImageRequirement struct {
	ManifestDigest string
	ConfigDigest   string
	OS             string
	Architecture   string
	Variant        string
}

// ValidateImage proves that Docker resolved the signed repository manifest to
// the exact admitted config and platform. Image-declared volumes are rejected:
// Docker would otherwise materialize anonymous writable storage outside the
// executor-managed lineage contract.
func ValidateImage(observed ObservedImage, expected ImageRequirement) error {
	if (expected.ManifestDigest != "" && !imageConfigDigest.MatchString(expected.ManifestDigest)) ||
		!imageConfigDigest.MatchString(expected.ConfigDigest) || expected.OS != "linux" ||
		!boundedText(expected.Architecture, 32) || len(expected.Variant) > 32 || strings.ContainsRune(expected.Variant, '\x00') {
		return &PolicyError{"signed image requirement is unsupported"}
	}
	if !observed.ConfigPresent || !imageConfigDigest.MatchString(observed.ID) ||
		!imageConfigDigest.MatchString(observed.ConfigDigest) ||
		!boundedText(observed.OS, 32) || !boundedText(observed.Architecture, 32) ||
		len(observed.Variant) > 32 || strings.ContainsRune(observed.Variant, '\x00') {
		return &PolicyError{"local image metadata is unsupported"}
	}
	if len(observed.DeclaredVolumes) != 0 {
		return &PolicyError{"image config must not declare writable volumes"}
	}
	if observed.ConfigDigest != expected.ConfigDigest {
		return &PolicyError{"local image config digest does not match signed admission"}
	}
	switch observed.Identity {
	case imageIdentityConfig:
		if observed.ID != expected.ConfigDigest || observed.ManifestDigest != "" {
			return &PolicyError{"local classic image identity does not match signed admission"}
		}
	case imageIdentityManifest:
		if expected.ManifestDigest == "" || observed.ID != expected.ManifestDigest || observed.ManifestDigest != expected.ManifestDigest {
			return &PolicyError{"local image manifest digest does not match signed admission"}
		}
	default:
		return &PolicyError{"local image identity mode is unsupported"}
	}
	if observed.OS != expected.OS || observed.Architecture != expected.Architecture || observed.Variant != expected.Variant {
		return &PolicyError{"local image platform does not match signed admission"}
	}
	return nil
}

type StateMount struct {
	VolumeName string `json:"volume_name"`
	Path       string `json:"path"`
}

type RuntimeGrant struct {
	NetworkName    string   `json:"network_name"`
	Subnet         string   `json:"subnet"`
	Gateway        string   `json:"gateway"`
	GrantID        string   `json:"grant_id"`
	Generation     uint64   `json:"generation"`
	Inference      bool     `json:"inference"`
	RouteID        string   `json:"route_id,omitempty"`
	RelayIP        string   `json:"relay_ip"`
	AgentIP        string   `json:"agent_ip"`
	ModelAlias     string   `json:"model_alias,omitempty"`
	ServicePort    int      `json:"service_port,omitempty"`
	EgressRouteIDs []string `json:"egress_route_ids,omitempty"`
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
	MaxTotalMemoryBytes   int64
	MaxTotalCPUMillis     int64
	MaxTotalPIDs          int64
	MaxTenantMemoryBytes  int64
	MaxTenantCPUMillis    int64
	MaxTenantPIDs         int64
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
		MaxTotalMemoryBytes:   8 << 30,
		MaxTotalCPUMillis:     8000,
		MaxTotalPIDs:          2048,
		MaxTenantMemoryBytes:  2 << 30,
		MaxTenantCPUMillis:    2000,
		MaxTenantPIDs:         512,
	}
}

func (p HostPolicy) Validate() error {
	if p.MaxMemoryBytes <= 0 || p.MaxCPUMillis <= 0 || p.MaxPIDs <= 0 ||
		p.MaxWorkloads <= 0 || p.MaxWorkloadsPerTenant <= 0 ||
		p.MaxTotalMemoryBytes <= 0 || p.MaxTotalCPUMillis <= 0 || p.MaxTotalPIDs <= 0 ||
		p.MaxTenantMemoryBytes <= 0 || p.MaxTenantCPUMillis <= 0 || p.MaxTenantPIDs <= 0 {
		return errors.New("all host policy limits must be positive")
	}
	if p.MaxCPUMillis > math.MaxInt64/1_000_000 || p.MaxTotalCPUMillis > math.MaxInt64/1_000_000 ||
		p.MaxTenantCPUMillis > math.MaxInt64/1_000_000 {
		return errors.New("max CPU millicores is too large for Docker NanoCPUs")
	}
	if p.MaxWorkloadsPerTenant > p.MaxWorkloads {
		return errors.New("max workloads per tenant must not exceed max workloads")
	}
	if p.MaxTenantMemoryBytes > p.MaxTotalMemoryBytes || p.MaxTenantCPUMillis > p.MaxTotalCPUMillis ||
		p.MaxTenantPIDs > p.MaxTotalPIDs {
		return errors.New("tenant aggregate limits must not exceed host aggregate limits")
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
	if w.ImageConfigDigest != "" && !imageConfigDigest.MatchString(w.ImageConfigDigest) {
		return &PolicyError{"internal image config digest is invalid"}
	}
	if w.ImageRuntimeDigest != "" && !imageConfigDigest.MatchString(w.ImageRuntimeDigest) {
		return &PolicyError{"internal image runtime digest is invalid"}
	}
	if w.ImageRuntimeDigest != "" && w.ImageConfigDigest == "" {
		return &PolicyError{"internal image runtime digest requires a config digest"}
	}
	if w.ImageRuntimeDigest != "" && !signedRuntimeDigestMatches(w.Image, w.ImageConfigDigest, w.ImageRuntimeDigest) {
		return &PolicyError{"internal image runtime digest must match the signed config or manifest digest"}
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
	if w.State != nil {
		if !strings.HasPrefix(w.State.VolumeName, "steward-state-") || len(w.State.VolumeName) != len("steward-state-")+64 ||
			w.State.Path != profileLayoutFor(w.ProfileID).StatePath {
			return &PolicyError{"internal state mount is invalid"}
		}
	}
	if w.Runtime != nil {
		if !strings.HasPrefix(w.Runtime.NetworkName, "steward-net-") || len(w.Runtime.NetworkName) != len("steward-net-")+64 ||
			!strings.HasPrefix(w.Runtime.GrantID, "grant-") || len(w.Runtime.GrantID) != len("grant-")+64 ||
			w.Runtime.Generation == 0 ||
			w.Runtime.ServicePort < 0 || w.Runtime.ServicePort > 65535 ||
			(w.Runtime.Inference && !boundedText(w.Runtime.ModelAlias, 256)) ||
			(w.Runtime.Inference && !boundedText(w.Runtime.RouteID, 128)) ||
			(!w.Runtime.Inference && (w.Runtime.ModelAlias != "" || w.Runtime.RouteID != "")) ||
			(!w.Runtime.Inference && w.Runtime.ServicePort == 0 && len(w.Runtime.EgressRouteIDs) == 0) ||
			len(w.Runtime.EgressRouteIDs) > 32 {
			return &PolicyError{"internal runtime capability topology is invalid"}
		}
		for index, route := range w.Runtime.EgressRouteIDs {
			if !egressRouteID.MatchString(route) || index > 0 && w.Runtime.EgressRouteIDs[index-1] >= route {
				return &PolicyError{"internal egress routes are invalid"}
			}
		}
		identity := NetworkSpecFor(w.TenantID, w.InstanceID, w.Runtime.Generation)
		allocationReady := runtimeAllocationMatches(identity, w.Runtime.Subnet, w.Runtime.Gateway, w.Runtime.RelayIP, w.Runtime.AgentIP)
		allocationPending := w.Runtime.Subnet == "" && w.Runtime.Gateway == "" && w.Runtime.RelayIP == "" && w.Runtime.AgentIP == ""
		if w.Runtime.NetworkName != identity.Name || !allocationReady && !allocationPending {
			return &PolicyError{"internal runtime addresses are invalid"}
		}
	}
	return nil
}

func signedRuntimeDigestMatches(imageReference, configDigest, runtimeDigest string) bool {
	separator := strings.LastIndexByte(imageReference, '@')
	return runtimeDigest == configDigest || separator >= 0 && runtimeDigest == imageReference[separator+1:]
}

type profileLayout struct {
	StatePath string
	Home      string
	WorkDir   string
}

func profileLayoutFor(profileID string) profileLayout {
	switch profileID {
	case "hermes-v1@v1":
		return profileLayout{StatePath: "/opt/data", Home: "/opt/data/home", WorkDir: "/opt/data"}
	case "openclaw-v1@v1":
		return profileLayout{StatePath: "/home/node/.openclaw", Home: "/home/node", WorkDir: "/home/node/.openclaw/workspace"}
	default:
		return profileLayout{StatePath: "/state", Home: "/state", WorkDir: "/state"}
	}
}

func boundedText(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

var ErrNotFound = errors.New("unknown workload")
var ErrWorkloadDrift = errors.New("executor workload has drifted from its admitted definition")

var egressRouteID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
