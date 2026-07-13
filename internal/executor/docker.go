package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
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

// CapacityDocker reports durable resource reservations reconstructed from all
// executor-managed containers, including stopped containers and the fixed relay
// overhead for every capability-bearing workload. Docker remains the inventory
// authority across Executor restarts; in-memory counters are not trusted.
type CapacityDocker interface {
	CapacityUsage(context.Context, string) (CapacityUsage, error)
}

type CapacityReservation struct {
	Workloads   int
	MemoryBytes int64
	CPUMillis   int64
	PIDs        int64
}

type CapacityUsage struct {
	Host   CapacityReservation
	Tenant CapacityReservation
}

// StateDocker is the additional narrow Docker surface used only after signed
// admission has granted persistent state. Legacy workload requests cannot
// reach these methods because StateMount is not part of their JSON contract.
type StateDocker interface {
	InspectStateVolume(context.Context, string) (ObservedStateVolume, error)
	CreateStateVolume(context.Context, StateVolumeSpec) error
	RemoveStateVolume(context.Context, string) error
}

// ImageDocker is the optional, narrow image-inspection surface required by
// signed admission. Keeping it separate preserves compatibility with legacy
// Docker test doubles while making pre-mutation image verification mandatory
// for the secure path.
type ImageDocker interface {
	InspectSignedImage(context.Context, string, string) (ObservedImage, error)
}

// ObservedImage is the security-relevant projection of Docker image inspect.
// DeclaredVolumes is sorted so policy decisions and tests are deterministic.
type ObservedImage struct {
	ID              string
	ConfigDigest    string
	ManifestDigest  string
	Identity        imageIdentity
	OS              string
	Architecture    string
	Variant         string
	DeclaredVolumes []string
	ConfigPresent   bool
}

type imageIdentity string

const (
	imageIdentityConfig   imageIdentity = "config"
	imageIdentityManifest imageIdentity = "manifest"
)

type StateVolumeSpec struct {
	Name      string
	TenantID  string
	LineageID string
}

type ObservedStateVolume struct {
	StateVolumeSpec
	Managed bool
}

type dockerMount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type dockerEndpoint struct {
	IPAddress  string `json:"IPAddress"`
	IPAMConfig *struct {
		IPv4Address string `json:"IPv4Address"`
	} `json:"IPAMConfig"`
}

// ObservedWorkload is the executor-owned subset of Docker inspect state. Keeping
// the projection narrow lets the lifecycle layer prove that a deterministic name
// already belongs to the same immutable workload before treating provision as an
// idempotent replay.
type ObservedWorkload struct {
	Workload Workload
	// ImageID is the signed config identity used by admission fences. RuntimeImageID
	// is Docker's actual store-specific selection (config on classic stores,
	// manifest on the containerd store).
	ImageID        string
	RuntimeImageID string
	Fingerprint    string
	Managed        bool
	Hardened       bool
	Status         string
}

// DockerHTTP is a standard-library Docker Engine client over the local Unix socket.
// It deliberately does not expose a general request method to the HTTP API layer.
type DockerHTTP struct{ client *http.Client }

const managedWorkloadLabel = "io.hardrails.executor.managed"
const workloadFingerprintLabel = "io.hardrails.workload-sha256"
const workspaceTmpfs = "rw,nosuid,nodev,size=67108864"
const tempTmpfs = "rw,noexec,nosuid,nodev,size=67108864"
const privateShmBytes int64 = 64 << 20
const workloadMemoryLabel = "io.hardrails.memory-bytes"
const workloadCPULabel = "io.hardrails.cpu-millis"
const workloadPIDsLabel = "io.hardrails.pids"
const workloadImageReferenceLabel = "io.hardrails.image.reference"
const workloadImageConfigLabel = "io.hardrails.image.config"
const workloadImageRuntimeLabel = "io.hardrails.image.runtime"
const managedStateLabel = "io.hardrails.state.managed"
const stateLineageLabel = "io.hardrails.state.lineage"
const stateVolumeLabel = "io.hardrails.state.volume"
const statePathLabel = "io.hardrails.state.path"
const runtimeNetworkLabel = "io.hardrails.runtime.network"
const runtimeGrantLabel = "io.hardrails.runtime.grant"
const runtimeNodeIDLabel = "io.hardrails.runtime.node-id"
const runtimeInferenceLabel = "io.hardrails.runtime.inference"
const runtimeModelLabel = "io.hardrails.runtime.model"
const runtimeRouteLabel = "io.hardrails.runtime.route"
const runtimeServicePortLabel = "io.hardrails.runtime.service-port"
const runtimeServiceIDLabel = "io.hardrails.runtime.service-id"
const runtimeTaskAuthoritiesLabel = "io.hardrails.runtime.task-authorities"
const runtimeGenerationLabel = "io.hardrails.runtime.generation"
const runtimeSubnetLabel = "io.hardrails.runtime.subnet"
const runtimeGatewayLabel = "io.hardrails.runtime.gateway"
const runtimeRelayIPLabel = "io.hardrails.runtime.relay-ip"
const runtimeAgentIPLabel = "io.hardrails.runtime.agent-ip"
const runtimeEgressRoutesLabel = "io.hardrails.runtime.egress-routes"
const runtimeConnectorsLabel = "io.hardrails.runtime.connectors"
const runtimeCapsuleDigestLabel = "io.hardrails.runtime.capsule-digest"
const runtimePolicyDigestLabel = "io.hardrails.runtime.policy-digest"

type dockerTaskAuthorityLabel struct {
	Authorities []gateway.TaskAuthority `json:"authorities"`
}

type dockerRestartPolicy struct {
	Name              string `json:"Name"`
	MaximumRetryCount int    `json:"MaximumRetryCount"`
}

// dockerClosedHostPolicy is the Docker-owned portion of the isolation envelope
// shared by untrusted agents and trusted per-instance relays. Docker API v1.41
// spells a private PID and UTS namespace as an empty mode; unlike omission from
// our create map, those empty values are sent deliberately. IPC and cgroup
// namespaces have explicit private modes and must never inherit daemon defaults.
type dockerClosedHostPolicy struct {
	ContainerIDFile   string              `json:"ContainerIDFile"`
	RestartPolicy     dockerRestartPolicy `json:"RestartPolicy"`
	AutoRemove        bool                `json:"AutoRemove"`
	VolumeDriver      string              `json:"VolumeDriver"`
	VolumesFrom       []string            `json:"VolumesFrom"`
	CgroupnsMode      string              `json:"CgroupnsMode"`
	DNSOptions        []string            `json:"DnsOptions"`
	DNSSearch         []string            `json:"DnsSearch"`
	GroupAdd          []string            `json:"GroupAdd"`
	IpcMode           string              `json:"IpcMode"`
	Cgroup            string              `json:"Cgroup"`
	Links             []string            `json:"Links"`
	OomScoreAdj       int                 `json:"OomScoreAdj"`
	PidMode           string              `json:"PidMode"`
	UTSMode           string              `json:"UTSMode"`
	UsernsMode        string              `json:"UsernsMode"`
	ShmSize           int64               `json:"ShmSize"`
	Sysctls           map[string]string   `json:"Sysctls"`
	StorageOpt        map[string]string   `json:"StorageOpt"`
	CgroupParent      string              `json:"CgroupParent"`
	DeviceCgroupRules []string            `json:"DeviceCgroupRules"`
	OomKillDisable    bool                `json:"OomKillDisable"`
}

func enforceClosedDockerHostPolicy(host map[string]any) map[string]any {
	host["PidMode"] = ""
	host["IpcMode"] = "private"
	host["UTSMode"] = ""
	host["CgroupnsMode"] = "private"
	host["UsernsMode"] = ""
	host["Cgroup"] = ""
	host["RestartPolicy"] = map[string]any{"Name": "no", "MaximumRetryCount": 0}
	host["AutoRemove"] = false
	host["OomKillDisable"] = false
	host["OomScoreAdj"] = 0
	host["ContainerIDFile"] = ""
	host["CgroupParent"] = ""
	host["VolumeDriver"] = ""
	host["VolumesFrom"] = []string{}
	host["Links"] = []string{}
	host["GroupAdd"] = []string{}
	host["DeviceCgroupRules"] = []string{}
	host["DnsOptions"] = []string{}
	host["DnsSearch"] = []string{}
	host["StorageOpt"] = map[string]string{}
	host["Sysctls"] = map[string]string{}
	host["ShmSize"] = privateShmBytes
	return host
}

func (p dockerClosedHostPolicy) namespacesHardened() bool {
	return p.PidMode == "" && p.IpcMode == "private" && p.UTSMode == "" && p.CgroupnsMode == "private" &&
		p.UsernsMode == "" && p.Cgroup == ""
}

func (p dockerClosedHostPolicy) lifecycleHardened() bool {
	return p.RestartPolicy.Name == "no" && p.RestartPolicy.MaximumRetryCount == 0 &&
		!p.AutoRemove && !p.OomKillDisable && p.OomScoreAdj == 0
}

func (p dockerClosedHostPolicy) hostAttachmentsHardened() bool {
	return p.ContainerIDFile == "" && p.CgroupParent == "" && p.VolumeDriver == "" &&
		len(p.VolumesFrom) == 0 && len(p.Links) == 0 && len(p.GroupAdd) == 0 && len(p.DeviceCgroupRules) == 0 &&
		len(p.DNSOptions) == 0 && len(p.DNSSearch) == 0 && len(p.StorageOpt) == 0 && len(p.Sysctls) == 0 &&
		p.ShmSize == privateShmBytes
}

const dockerLogDriver = "local"
const dockerLogMaxSize = "10m"
const dockerLogMaxFiles = "3"
const dockerLogCompress = "true"

func NewDockerHTTP(socket string) *DockerHTTP {
	return NewDockerHTTPWithTimeout(socket, 10*time.Second)
}

// NewDockerHTTPWithTimeout permits bounded long-running administrative calls,
// such as an offline image import, without weakening Executor's short runtime
// operation deadline. Callers still control cancellation through context.
func NewDockerHTTPWithTimeout(socket string, timeout time.Duration) *DockerHTTP {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	return &DockerHTTP{client: &http.Client{Transport: transport, Timeout: timeout}}
}

// LoadImage streams one already-verified Docker/OCI archive into the local
// daemon. Authorization and archive verification belong to stewardctl; this
// narrow method only performs Docker's native content import and checks its
// bounded result stream for daemon-reported errors.
func (d *DockerHTTP) LoadImage(ctx context.Context, archive io.Reader) error {
	if archive == nil {
		return &PolicyError{"image archive reader is required"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/v1.41/images/load?quiet=1", archive)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dockerError(resp)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return fmt.Errorf("read Docker image import response: %w", err)
	}
	if len(responseBody) > 1<<20 {
		return errors.New("Docker image import response exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	for {
		var message struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&message); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("decode Docker image import response: %w", err)
		}
		if message.ErrorDetail.Message != "" {
			return errors.New(message.ErrorDetail.Message)
		}
		if message.Error != "" {
			return errors.New(message.Error)
		}
	}
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
	containers, err := d.managedWorkloadSummaries(ctx)
	if err != nil {
		return 0, 0, err
	}
	tenant := 0
	for _, container := range containers {
		if container.Labels["io.hardrails.tenant"] == tenantID {
			tenant++
		}
	}
	return len(containers), tenant, nil
}

type managedWorkloadSummary struct {
	Labels map[string]string `json:"Labels"`
}

func (d *DockerHTTP) managedWorkloadSummaries(ctx context.Context) ([]managedWorkloadSummary, error) {
	filters, err := json.Marshal(map[string][]string{
		"label": {managedWorkloadLabel + "=true"},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.41/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, dockerError(resp)
	}
	var containers []managedWorkloadSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&containers); err != nil {
		return nil, err
	}
	return containers, nil
}

func (d *DockerHTTP) CapacityUsage(ctx context.Context, tenantID string) (CapacityUsage, error) {
	containers, err := d.managedWorkloadSummaries(ctx)
	if err != nil {
		return CapacityUsage{}, err
	}
	var usage CapacityUsage
	for _, container := range containers {
		reservation, tenant, err := reservationFromLabels(container.Labels)
		if err != nil {
			return CapacityUsage{}, err
		}
		if err := addReservation(&usage.Host, reservation); err != nil {
			return CapacityUsage{}, err
		}
		if tenant == tenantID {
			if err := addReservation(&usage.Tenant, reservation); err != nil {
				return CapacityUsage{}, err
			}
		}
	}
	return usage, nil
}

func reservationFromLabels(labels map[string]string) (CapacityReservation, string, error) {
	tenant := labels["io.hardrails.tenant"]
	if !boundedText(tenant, 128) {
		return CapacityReservation{}, "", errors.New("managed workload has an invalid tenant capacity label")
	}
	memory, memoryErr := strconv.ParseInt(labels[workloadMemoryLabel], 10, 64)
	cpu, cpuErr := strconv.ParseInt(labels[workloadCPULabel], 10, 64)
	pids, pidsErr := strconv.ParseInt(labels[workloadPIDsLabel], 10, 64)
	if memoryErr != nil || cpuErr != nil || pidsErr != nil || memory <= 0 || cpu <= 0 || pids <= 0 {
		return CapacityReservation{}, "", errors.New("managed workload has invalid resource capacity labels")
	}
	reservation := CapacityReservation{Workloads: 1, MemoryBytes: memory, CPUMillis: cpu, PIDs: pids}
	runtimeLabels := []string{runtimeGrantLabel, runtimeNodeIDLabel, runtimeInferenceLabel, runtimeModelLabel, runtimeRouteLabel,
		runtimeServicePortLabel, runtimeServiceIDLabel, runtimeTaskAuthoritiesLabel, runtimeGenerationLabel, runtimeSubnetLabel, runtimeGatewayLabel,
		runtimeRelayIPLabel, runtimeAgentIPLabel, runtimeEgressRoutesLabel, runtimeConnectorsLabel,
		runtimeCapsuleDigestLabel, runtimePolicyDigestLabel}
	hasRuntimeMetadata := labels[runtimeNetworkLabel] != ""
	for _, key := range runtimeLabels {
		hasRuntimeMetadata = hasRuntimeMetadata || labels[key] != ""
	}
	if hasRuntimeMetadata {
		if len(labels[runtimeNetworkLabel]) != len("steward-net-")+64 || !strings.HasPrefix(labels[runtimeNetworkLabel], "steward-net-") {
			return CapacityReservation{}, "", errors.New("managed workload has invalid runtime capacity labels")
		}
		var err error
		reservation.MemoryBytes, err = checkedCapacityAdd(reservation.MemoryBytes, defaultRelayMemory)
		if err != nil {
			return CapacityReservation{}, "", err
		}
		reservation.CPUMillis, err = checkedCapacityAdd(reservation.CPUMillis, defaultRelayCPU)
		if err != nil {
			return CapacityReservation{}, "", err
		}
		reservation.PIDs, err = checkedCapacityAdd(reservation.PIDs, defaultRelayPIDs)
		if err != nil {
			return CapacityReservation{}, "", err
		}
	}
	return reservation, tenant, nil
}

func addReservation(total *CapacityReservation, add CapacityReservation) error {
	if total.Workloads > math.MaxInt-add.Workloads {
		return errors.New("managed workload count overflows capacity accounting")
	}
	total.Workloads += add.Workloads
	var err error
	if total.MemoryBytes, err = checkedCapacityAdd(total.MemoryBytes, add.MemoryBytes); err != nil {
		return err
	}
	if total.CPUMillis, err = checkedCapacityAdd(total.CPUMillis, add.CPUMillis); err != nil {
		return err
	}
	if total.PIDs, err = checkedCapacityAdd(total.PIDs, add.PIDs); err != nil {
		return err
	}
	return nil
}

func checkedCapacityAdd(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, errors.New("managed workload resources overflow capacity accounting")
	}
	return left + right, nil
}

// InspectImage resolves one exact config digest through Docker. It remains the
// narrow compatibility surface used by image-import callers that have not yet
// supplied a signed manifest identity.
func (d *DockerHTTP) InspectImage(ctx context.Context, configDigest string) (ObservedImage, error) {
	if !imageConfigDigest.MatchString(configDigest) {
		return ObservedImage{}, &PolicyError{"image inspection requires an exact sha256 config digest"}
	}
	return d.inspectImageReference(ctx, "v1.41", configDigest, imageIdentityConfig)
}

// InspectSignedImage resolves a signed manifest/config pair without assuming a
// particular Docker image store. Classic Docker addresses the executable image
// by its config digest. Docker's containerd image store addresses it by manifest
// digest and reports the config digest in Descriptor.annotations["config.digest"].
// Only a not-found config lookup permits the manifest-store fallback; daemon and
// decoding failures are never hidden by a second lookup.
func (d *DockerHTTP) InspectSignedImage(ctx context.Context, imageReference, configDigest string) (ObservedImage, error) {
	if !imageDigest.MatchString(imageReference) || !imageConfigDigest.MatchString(configDigest) {
		return ObservedImage{}, &PolicyError{"image inspection requires exact signed manifest and config digests"}
	}
	observed, err := d.inspectImageReference(ctx, "v1.41", configDigest, imageIdentityConfig)
	if err == nil || !errors.Is(err, ErrNotFound) {
		return observed, err
	}
	manifestDigest := imageReference[strings.LastIndexByte(imageReference, '@')+1:]
	// API 1.48 is the first Docker 28 API and the first image-inspect response
	// that exposes Descriptor. Classic stores return from the config lookup above,
	// so only a containerd-store fallback requires this newer projection.
	observed, err = d.inspectImageReference(ctx, "v1.48", manifestDigest, imageIdentityManifest)
	if err != nil {
		return ObservedImage{}, err
	}
	// Descriptor.annotations is optional. Once Docker reports both Id and the
	// target Descriptor as the exact signed manifest, that content identity
	// already binds its config, so infer the config digest from the signed
	// requirement when the convenience annotation is absent. Never replace a
	// present value: a conflict must remain visible to ValidateImage and fail
	// closed.
	if observed.ConfigDigest == "" && observed.ID == manifestDigest && observed.ManifestDigest == manifestDigest {
		observed.ConfigDigest = configDigest
	}
	return observed, nil
}

func (d *DockerHTTP) inspectImageReference(ctx context.Context, apiVersion, reference string, identity imageIdentity) (ObservedImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/"+apiVersion+"/images/"+pathEscape(reference)+"/json", nil)
	if err != nil {
		return ObservedImage{}, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return ObservedImage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ObservedImage{}, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return ObservedImage{}, dockerError(resp)
	}
	var payload struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Variant      string `json:"Variant"`
		Config       *struct {
			Volumes map[string]json.RawMessage `json:"Volumes"`
		} `json:"Config"`
		Descriptor *struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"Descriptor"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedImage{}, err
	}
	observed := ObservedImage{
		ID: payload.ID, Identity: identity, OS: payload.OS, Architecture: payload.Architecture,
		Variant: payload.Variant, ConfigPresent: payload.Config != nil,
	}
	if payload.Descriptor == nil {
		observed.ConfigDigest = payload.ID
	} else {
		observed.Identity = imageIdentityManifest
		observed.ManifestDigest = payload.Descriptor.Digest
		observed.ConfigDigest = payload.Descriptor.Annotations["config.digest"]
	}
	if payload.Config != nil {
		observed.DeclaredVolumes = make([]string, 0, len(payload.Config.Volumes))
		for volume := range payload.Config.Volumes {
			observed.DeclaredVolumes = append(observed.DeclaredVolumes, volume)
		}
		slices.Sort(observed.DeclaredVolumes)
	}
	return observed, nil
}

func (d *DockerHTTP) Create(ctx context.Context, name string, w Workload) error {
	home := "/workspace"
	workingDirectory := "/workspace"
	tmpfs := map[string]string{"/tmp": tempTmpfs, "/workspace": workspaceTmpfs}
	mounts := []map[string]any(nil)
	labels := map[string]string{
		managedWorkloadLabel:     "true",
		workloadFingerprintLabel: workloadFingerprint(w),
		"io.hardrails.tenant":    w.TenantID,
		"io.hardrails.instance":  w.InstanceID,
		"io.hardrails.profile":   w.ProfileID,
		workloadMemoryLabel:      strconv.FormatInt(w.Resources.MemoryBytes, 10),
		workloadCPULabel:         strconv.FormatInt(w.Resources.CPUMillis, 10),
		workloadPIDsLabel:        strconv.FormatInt(w.Resources.PIDs, 10),
	}
	image := w.Image
	if w.ImageConfigDigest != "" {
		image = w.ImageRuntimeDigest
		if image == "" {
			// Workloads admitted before the runtime identity field existed used the
			// config digest directly. Preserve that exact classic-store behavior.
			image = w.ImageConfigDigest
		}
		labels[workloadImageReferenceLabel] = w.Image
		labels[workloadImageConfigLabel] = w.ImageConfigDigest
		labels[workloadImageRuntimeLabel] = image
	}
	if w.State != nil {
		layout := profileLayoutFor(w.ProfileID)
		home = layout.Home
		workingDirectory = layout.WorkDir
		tmpfs = map[string]string{"/tmp": tempTmpfs}
		mounts = []map[string]any{{
			"Type": "volume", "Source": w.State.VolumeName, "Target": w.State.Path, "ReadOnly": false,
		}}
		labels[stateVolumeLabel] = w.State.VolumeName
		labels[statePathLabel] = w.State.Path
	}
	networkMode := "none"
	var networkingConfig map[string]any
	if w.Runtime != nil {
		networkMode = w.Runtime.NetworkName
		networkingConfig = map[string]any{"EndpointsConfig": map[string]any{
			w.Runtime.NetworkName: map[string]any{"Aliases": []string{"agent"}, "IPAMConfig": map[string]string{"IPv4Address": w.Runtime.AgentIP}},
		}}
		labels[runtimeNetworkLabel] = w.Runtime.NetworkName
		labels[runtimeGrantLabel] = w.Runtime.GrantID
		labels[runtimeNodeIDLabel] = w.Runtime.NodeID
		labels[runtimeGenerationLabel] = strconv.FormatUint(w.Runtime.Generation, 10)
		labels[runtimeInferenceLabel] = strconv.FormatBool(w.Runtime.Inference)
		labels[runtimeModelLabel] = w.Runtime.ModelAlias
		labels[runtimeRouteLabel] = w.Runtime.RouteID
		labels[runtimeServicePortLabel] = strconv.Itoa(w.Runtime.ServicePort)
		labels[runtimeServiceIDLabel] = w.Runtime.ServiceID
		if len(w.Runtime.TaskAuthorities) > 0 {
			raw, _ := json.Marshal(dockerTaskAuthorityLabel{Authorities: w.Runtime.TaskAuthorities})
			labels[runtimeTaskAuthoritiesLabel] = string(raw)
		}
		labels[runtimeSubnetLabel] = w.Runtime.Subnet
		labels[runtimeGatewayLabel] = w.Runtime.Gateway
		labels[runtimeRelayIPLabel] = w.Runtime.RelayIP
		labels[runtimeAgentIPLabel] = w.Runtime.AgentIP
		labels[runtimeEgressRoutesLabel] = strings.Join(w.Runtime.EgressRouteIDs, ",")
		labels[runtimeConnectorsLabel] = strings.Join(w.Runtime.ConnectorIDs, ",")
		labels[runtimeCapsuleDigestLabel] = w.Runtime.CapsuleDigest
		labels[runtimePolicyDigestLabel] = w.Runtime.PolicyDigest
	}
	environment := []string{"HOME=" + home, "TMPDIR=/tmp"}
	if w.Runtime != nil && w.Runtime.Inference {
		environment = append(environment,
			"OPENAI_BASE_URL=http://steward-relay:8080/v1", "OPENAI_API_BASE=http://steward-relay:8080/v1",
			"OPENAI_API_KEY=steward-local", "OPENAI_MODEL="+w.Runtime.ModelAlias)
	}
	if w.Runtime != nil && len(w.Runtime.EgressRouteIDs) > 0 {
		const proxy = "http://steward-relay:8082"
		const noProxy = "steward-relay,agent,localhost,127.0.0.1"
		environment = append(environment, "STEWARD_EGRESS_PROXY="+proxy,
			"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "NO_PROXY="+noProxy,
			"http_proxy="+proxy, "https_proxy="+proxy, "no_proxy="+noProxy)
	}
	if w.Runtime != nil && len(w.Runtime.ConnectorIDs) > 0 {
		environment = append(environment, "STEWARD_CONNECTOR_URL=http://steward-relay:8081")
	}
	dns := []string(nil)
	if w.Runtime != nil {
		dns = []string{"127.0.0.1"}
	}
	body := map[string]any{
		"Image":          image,
		"Cmd":            w.Command,
		"Env":            environment,
		"User":           "65532:65532",
		"WorkingDir":     workingDirectory,
		"ReadonlyRootfs": true,
		"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
			"Runtime":        "runsc",
			"NetworkMode":    networkMode,
			"ReadonlyRootfs": true,
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"PidsLimit":      w.Resources.PIDs,
			"Memory":         w.Resources.MemoryBytes,
			"MemorySwap":     w.Resources.MemoryBytes,
			"NanoCPUs":       w.Resources.CPUMillis * 1_000_000,
			"Tmpfs":          tmpfs,
			"Mounts":         mounts,
			"ExtraHosts":     runtimeExtraHosts(w.Runtime),
			"Dns":            dns,
			"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
				"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress,
			}},
		}),
		"Labels":           labels,
		"NetworkingConfig": networkingConfig,
	}
	return d.call(ctx, http.MethodPost, "/v1.41/containers/create?name="+url.QueryEscape(name), body, http.StatusCreated)
}

func runtimeExtraHosts(runtime *RuntimeGrant) []string {
	if runtime == nil {
		return nil
	}
	return []string{"steward-relay:" + runtime.RelayIP}
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
		Image  string `json:"Image"`
		Config struct {
			Image      string            `json:"Image"`
			Cmd        []string          `json:"Cmd"`
			Env        []string          `json:"Env"`
			User       string            `json:"User"`
			WorkingDir string            `json:"WorkingDir"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			dockerClosedHostPolicy
			Memory          int64                      `json:"Memory"`
			MemorySwap      int64                      `json:"MemorySwap"`
			NanoCPUs        int64                      `json:"NanoCpus"`
			Pids            int64                      `json:"PidsLimit"`
			Runtime         string                     `json:"Runtime"`
			NetworkMode     string                     `json:"NetworkMode"`
			Readonly        bool                       `json:"ReadonlyRootfs"`
			CapDrop         []string                   `json:"CapDrop"`
			SecurityOpt     []string                   `json:"SecurityOpt"`
			Tmpfs           map[string]string          `json:"Tmpfs"`
			ExtraHosts      []string                   `json:"ExtraHosts"`
			DNS             []string                   `json:"Dns"`
			Privileged      bool                       `json:"Privileged"`
			CapAdd          []string                   `json:"CapAdd"`
			Binds           []string                   `json:"Binds"`
			Devices         []json.RawMessage          `json:"Devices"`
			DeviceRequests  []json.RawMessage          `json:"DeviceRequests"`
			PortBindings    map[string]json.RawMessage `json:"PortBindings"`
			PublishAllPorts bool                       `json:"PublishAllPorts"`
			LogConfig       struct {
				Type   string            `json:"Type"`
				Config map[string]string `json:"Config"`
			} `json:"LogConfig"`
		} `json:"HostConfig"`
		State struct {
			Status string `json:"Status"`
		} `json:"State"`
		Mounts          []dockerMount `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]dockerEndpoint `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedWorkload{}, err
	}
	labels := payload.Config.Labels
	imageReference := payload.Config.Image
	configuredImageID := ""
	configuredRuntimeID := ""
	observedImageID := payload.Image
	imageHardened := true
	if labels[workloadImageReferenceLabel] != "" || labels[workloadImageConfigLabel] != "" || labels[workloadImageRuntimeLabel] != "" {
		imageReference = labels[workloadImageReferenceLabel]
		configuredImageID = labels[workloadImageConfigLabel]
		configuredRuntimeID = labels[workloadImageRuntimeLabel]
		if configuredRuntimeID == "" {
			// Classic-store containers created by older Executor builds did not
			// need a distinct runtime identity.
			configuredRuntimeID = configuredImageID
		}
		observedImageID = configuredImageID
		imageHardened = imageDigest.MatchString(imageReference) && imageConfigDigest.MatchString(configuredImageID) &&
			imageConfigDigest.MatchString(configuredRuntimeID) &&
			signedRuntimeDigestMatches(imageReference, configuredImageID, configuredRuntimeID) &&
			payload.Config.Image == configuredRuntimeID && payload.Image == configuredRuntimeID
	}
	var state *StateMount
	stateHardened := labels[stateVolumeLabel] == "" && labels[statePathLabel] == "" &&
		payload.Config.WorkingDir == "/workspace" && contains(payload.Config.Env, "HOME=/workspace") &&
		exactStringMap(payload.HostConfig.Tmpfs, map[string]string{"/tmp": tempTmpfs, "/workspace": workspaceTmpfs}) && len(payload.Mounts) == 0
	if labels[stateVolumeLabel] != "" || labels[statePathLabel] != "" {
		state = &StateMount{VolumeName: labels[stateVolumeLabel], Path: labels[statePathLabel]}
		layout := profileLayoutFor(labels["io.hardrails.profile"])
		stateHardened = state.Path == layout.StatePath && strings.HasPrefix(state.VolumeName, "steward-state-") &&
			payload.Config.WorkingDir == layout.WorkDir && contains(payload.Config.Env, "HOME="+layout.Home) &&
			exactStringMap(payload.HostConfig.Tmpfs, map[string]string{"/tmp": tempTmpfs}) && hasExactStateMount(payload.Mounts, *state)
	}
	var runtimeGrant *RuntimeGrant
	runtimeHardened := payload.HostConfig.NetworkMode == "none" && labels[runtimeNetworkLabel] == "" && labels[runtimeGrantLabel] == "" &&
		labels[runtimeNodeIDLabel] == "" && labels[runtimeConnectorsLabel] == "" && labels[runtimeServiceIDLabel] == "" && labels[runtimeTaskAuthoritiesLabel] == "" &&
		labels[runtimeCapsuleDigestLabel] == "" && labels[runtimePolicyDigestLabel] == "" &&
		hasExactNetwork(payload.NetworkSettings.Networks, "none", "", false) && len(payload.HostConfig.ExtraHosts) == 0 && len(payload.HostConfig.DNS) == 0
	if labels[runtimeNetworkLabel] != "" || labels[runtimeGrantLabel] != "" {
		servicePort, serviceErr := strconv.Atoi(labels[runtimeServicePortLabel])
		inference, inferenceErr := strconv.ParseBool(labels[runtimeInferenceLabel])
		generation, generationErr := strconv.ParseUint(labels[runtimeGenerationLabel], 10, 64)
		taskAuthorities, taskAuthorityErr := decodeTaskAuthorityLabel(labels[runtimeTaskAuthoritiesLabel])
		runtimeGrant = &RuntimeGrant{
			NetworkName: labels[runtimeNetworkLabel], GrantID: labels[runtimeGrantLabel],
			NodeID:     labels[runtimeNodeIDLabel],
			Generation: generation, Inference: inference, RouteID: labels[runtimeRouteLabel], ModelAlias: labels[runtimeModelLabel], ServicePort: servicePort,
			ServiceID: labels[runtimeServiceIDLabel], TaskAuthorities: taskAuthorities,
			Subnet: labels[runtimeSubnetLabel], Gateway: labels[runtimeGatewayLabel],
			RelayIP: labels[runtimeRelayIPLabel], AgentIP: labels[runtimeAgentIPLabel],
			EgressRouteIDs: splitRouteIDs(labels[runtimeEgressRoutesLabel]),
			ConnectorIDs:   splitRouteIDs(labels[runtimeConnectorsLabel]),
			CapsuleDigest:  labels[runtimeCapsuleDigestLabel], PolicyDigest: labels[runtimePolicyDigestLabel],
		}
		runtimeHardened = serviceErr == nil && inferenceErr == nil && generationErr == nil && taskAuthorityErr == nil && generation > 0 &&
			(len(taskAuthorities) == 0 && runtimeGrant.NodeID == "" && runtimeGrant.ServiceID == "" ||
				len(taskAuthorities) > 0 && boundedText(runtimeGrant.NodeID, 128) && egressRouteID.MatchString(runtimeGrant.ServiceID) && servicePort > 0) &&
			validEgressRouteIDs(runtimeGrant.EgressRouteIDs) && validConnectorIDs(runtimeGrant.ConnectorIDs) &&
			validRuntimeAdmissionBindings(runtimeGrant) &&
			runtimeAllocationMatches(NetworkSpecFor(labels["io.hardrails.tenant"], labels["io.hardrails.instance"], generation),
				runtimeGrant.Subnet, runtimeGrant.Gateway, runtimeGrant.RelayIP, runtimeGrant.AgentIP) &&
			payload.HostConfig.NetworkMode == runtimeGrant.NetworkName &&
			strings.HasPrefix(runtimeGrant.NetworkName, "steward-net-") && strings.HasPrefix(runtimeGrant.GrantID, "grant-") &&
			exactStrings(payload.HostConfig.ExtraHosts, []string{"steward-relay:" + runtimeGrant.RelayIP}) &&
			len(payload.HostConfig.DNS) == 1 && payload.HostConfig.DNS[0] == "127.0.0.1" &&
			hasExactNetwork(payload.NetworkSettings.Networks, runtimeGrant.NetworkName, runtimeGrant.AgentIP, payload.State.Status == "running")
		if runtimeGrant.Inference {
			runtimeHardened = runtimeHardened && contains(payload.Config.Env, "OPENAI_BASE_URL=http://steward-relay:8080/v1") &&
				contains(payload.Config.Env, "OPENAI_API_BASE=http://steward-relay:8080/v1") &&
				contains(payload.Config.Env, "OPENAI_API_KEY=steward-local") && contains(payload.Config.Env, "OPENAI_MODEL="+runtimeGrant.ModelAlias)
		}
		if len(runtimeGrant.EgressRouteIDs) > 0 {
			const proxy = "http://steward-relay:8082"
			const noProxy = "steward-relay,agent,localhost,127.0.0.1"
			runtimeHardened = runtimeHardened &&
				contains(payload.Config.Env, "STEWARD_EGRESS_PROXY="+proxy) &&
				contains(payload.Config.Env, "HTTP_PROXY="+proxy) && contains(payload.Config.Env, "HTTPS_PROXY="+proxy) &&
				contains(payload.Config.Env, "NO_PROXY="+noProxy) && contains(payload.Config.Env, "http_proxy="+proxy) &&
				contains(payload.Config.Env, "https_proxy="+proxy) && contains(payload.Config.Env, "no_proxy="+noProxy)
		}
		if len(runtimeGrant.ConnectorIDs) > 0 {
			runtimeHardened = runtimeHardened && contains(payload.Config.Env, "STEWARD_CONNECTOR_URL=http://steward-relay:8081")
		}
	}
	return ObservedWorkload{
		ImageID: observedImageID, RuntimeImageID: payload.Image,
		Workload: Workload{
			TenantID:           labels["io.hardrails.tenant"],
			InstanceID:         labels["io.hardrails.instance"],
			ProfileID:          labels["io.hardrails.profile"],
			Image:              imageReference,
			ImageConfigDigest:  configuredImageID,
			ImageRuntimeDigest: configuredRuntimeID,
			Command:            payload.Config.Cmd,
			Resources: Resources{
				MemoryBytes: payload.HostConfig.Memory,
				CPUMillis:   payload.HostConfig.NanoCPUs / 1_000_000,
				PIDs:        payload.HostConfig.Pids,
			},
			Egress:  Egress{},
			State:   state,
			Runtime: runtimeGrant,
		},
		Fingerprint: labels[workloadFingerprintLabel],
		Managed:     labels[managedWorkloadLabel] == "true",
		Hardened: imageHardened && payload.Config.User == "65532:65532" &&
			validFingerprint(labels[workloadFingerprintLabel]) &&
			labels["io.hardrails.tenant"] != "" && labels["io.hardrails.instance"] != "" &&
			labels["io.hardrails.profile"] != "" &&
			labels[workloadMemoryLabel] == strconv.FormatInt(payload.HostConfig.Memory, 10) &&
			labels[workloadCPULabel] == strconv.FormatInt(payload.HostConfig.NanoCPUs/1_000_000, 10) &&
			labels[workloadPIDsLabel] == strconv.FormatInt(payload.HostConfig.Pids, 10) &&
			stateHardened &&
			contains(payload.Config.Env, "TMPDIR=/tmp") &&
			payload.HostConfig.Runtime == "runsc" && runtimeHardened &&
			payload.HostConfig.namespacesHardened() && payload.HostConfig.lifecycleHardened() &&
			payload.HostConfig.hostAttachmentsHardened() &&
			payload.HostConfig.Readonly && exactStrings(payload.HostConfig.CapDrop, []string{"ALL"}) &&
			exactStrings(payload.HostConfig.SecurityOpt, []string{"no-new-privileges:true"}) &&
			payload.HostConfig.MemorySwap == payload.HostConfig.Memory &&
			!payload.HostConfig.Privileged && len(payload.HostConfig.CapAdd) == 0 && len(payload.HostConfig.Binds) == 0 &&
			len(payload.HostConfig.Devices) == 0 && len(payload.HostConfig.DeviceRequests) == 0 &&
			len(payload.HostConfig.PortBindings) == 0 && !payload.HostConfig.PublishAllPorts &&
			exactLogConfig(payload.HostConfig.LogConfig.Type, payload.HostConfig.LogConfig.Config),
		Status: payload.State.Status,
	}, nil
}

func splitRouteIDs(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func decodeTaskAuthorityLabel(value string) ([]gateway.TaskAuthority, error) {
	if value == "" {
		return nil, nil
	}
	var label dockerTaskAuthorityLabel
	if err := dsse.DecodeStrictInto([]byte(value), 16<<10, &label); err != nil {
		return nil, err
	}
	if !gateway.TaskAuthoritiesValid(label.Authorities) {
		return nil, errors.New("invalid task authority label")
	}
	return label.Authorities, nil
}

func validEgressRouteIDs(routes []string) bool {
	if len(routes) > 32 {
		return false
	}
	for index, route := range routes {
		if !egressRouteID.MatchString(route) || index > 0 && routes[index-1] >= route {
			return false
		}
	}
	return true
}

func validConnectorIDs(connectors []string) bool {
	if len(connectors) > 32 {
		return false
	}
	for index, connector := range connectors {
		if !egressRouteID.MatchString(connector) || index > 0 && connectors[index-1] >= connector {
			return false
		}
	}
	return true
}

func validRuntimeAdmissionBindings(runtime *RuntimeGrant) bool {
	if runtime == nil {
		return true
	}
	absent := runtime.CapsuleDigest == "" && runtime.PolicyDigest == ""
	valid := imageConfigDigest.MatchString(runtime.CapsuleDigest) && imageConfigDigest.MatchString(runtime.PolicyDigest)
	return valid || absent && len(runtime.ConnectorIDs) == 0 && len(runtime.TaskAuthorities) == 0
}

func validFingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func workloadFingerprint(w Workload) string {
	raw, _ := json.Marshal(struct {
		InstanceID        string        `json:"instance_id"`
		TenantID          string        `json:"tenant_id"`
		ProfileID         string        `json:"profile_id"`
		Image             string        `json:"image"`
		Command           []string      `json:"command,omitempty"`
		Resources         Resources     `json:"resources"`
		Egress            Egress        `json:"egress"`
		State             *StateMount   `json:"state,omitempty"`
		Runtime           *RuntimeGrant `json:"runtime,omitempty"`
		ImageConfigDigest string        `json:"image_config_digest,omitempty"`
	}{w.InstanceID, w.TenantID, w.ProfileID, w.Image, w.Command, w.Resources, w.Egress, w.State, w.Runtime, w.ImageConfigDigest})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func hasExactStateMount(mounts []dockerMount, want StateMount) bool {
	return len(mounts) == 1 && mounts[0].Type == "volume" && mounts[0].Name == want.VolumeName &&
		mounts[0].Destination == want.Path && mounts[0].RW
}

func hasExactNetwork(networks map[string]dockerEndpoint, name, ip string, requireIP bool) bool {
	if len(networks) != 1 {
		return false
	}
	endpoint, ok := networks[name]
	configuredIP := ""
	if endpoint.IPAMConfig != nil {
		configuredIP = endpoint.IPAMConfig.IPv4Address
	}
	return ok && configuredIP == ip && (!requireIP || endpoint.IPAddress == ip)
}

func exactStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func exactStringMap(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func exactLogConfig(driver string, config map[string]string) bool {
	return driver == dockerLogDriver && exactStringMap(config, map[string]string{
		"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress,
	})
}

func StateVolumeName(tenantID, lineageID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + lineageID))
	return "steward-state-" + hex.EncodeToString(sum[:])
}

func (d *DockerHTTP) InspectStateVolume(ctx context.Context, name string) (ObservedStateVolume, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/volumes/"+pathEscape(name), nil)
	if err != nil {
		return ObservedStateVolume{}, err
	}
	response, err := d.client.Do(req)
	if err != nil {
		return ObservedStateVolume{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ObservedStateVolume{}, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return ObservedStateVolume{}, dockerError(response)
	}
	var payload struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedStateVolume{}, err
	}
	return ObservedStateVolume{StateVolumeSpec: StateVolumeSpec{
		Name: payload.Name, TenantID: payload.Labels["io.hardrails.tenant"], LineageID: payload.Labels[stateLineageLabel],
	}, Managed: payload.Labels[managedStateLabel] == "true"}, nil
}

func (d *DockerHTTP) CreateStateVolume(ctx context.Context, spec StateVolumeSpec) error {
	body := map[string]any{"Name": spec.Name, "Labels": map[string]string{
		managedStateLabel: "true", "io.hardrails.tenant": spec.TenantID, stateLineageLabel: spec.LineageID,
	}}
	return d.call(ctx, http.MethodPost, "/v1.41/volumes/create", body, http.StatusCreated)
}

func (d *DockerHTTP) RemoveStateVolume(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodDelete, "/v1.41/volumes/"+pathEscape(name), nil, http.StatusNoContent)
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
	return d.call(ctx, http.MethodDelete, "/v1.41/containers/"+pathEscape(name)+"?force=true&v=true", nil, http.StatusNoContent)
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
