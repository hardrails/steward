package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type TopologyDocker interface {
	InspectNetwork(context.Context, string) (ObservedNetwork, error)
	CreateNetwork(context.Context, NetworkSpec) error
	RemoveNetwork(context.Context, string) error
	CreateRelay(context.Context, RelaySpec) error
	InspectRelay(context.Context, string) (ObservedRelay, error)
}

type NetworkSpec struct {
	Name       string
	TenantID   string
	InstanceID string
	Generation uint64
	Subnet     string
	Gateway    string
	RelayIP    string
	AgentIP    string
}

type ObservedNetwork struct {
	NetworkSpec
	Managed  bool
	Internal bool
}

type RelaySpec struct {
	Name        string
	Image       string
	NetworkName string
	GrantID     string
	GrantDir    string
	TenantID    string
	InstanceID  string
	Generation  uint64
	RelayGID    int
	Inference   bool
	ServicePort int
	RelayIP     string
	AgentIP     string
	MemoryBytes int64
	CPUMillis   int64
	PIDs        int64
}

type ObservedRelay struct {
	Spec        RelaySpec
	ImageID     string
	Fingerprint string
	Managed     bool
	Hardened    bool
	Status      string
	IPAddress   string
	Drift       string
}

const managedNetworkLabel = "io.hardrails.network.managed"
const networkGenerationLabel = "io.hardrails.network.generation"
const managedRelayLabel = "io.hardrails.relay.managed"
const relayFingerprintLabel = "io.hardrails.relay-sha256"

func NetworkName(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "steward-net-" + hex.EncodeToString(sum[:])
}

func NetworkSpecFor(tenantID, instanceID string, generation uint64) NetworkSpec {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	base := int(sum[2] & 0xf8)
	prefix := "10." + strconv.Itoa(int(sum[0])) + "." + strconv.Itoa(int(sum[1])) + "."
	return NetworkSpec{
		Name: NetworkName(tenantID, instanceID, generation), TenantID: tenantID, InstanceID: instanceID, Generation: generation,
		Subnet: prefix + strconv.Itoa(base) + "/29", Gateway: prefix + strconv.Itoa(base+1),
		RelayIP: prefix + strconv.Itoa(base+2), AgentIP: prefix + strconv.Itoa(base+3),
	}
}

func RelayName(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte("relay\x00" + tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "steward-relay-" + hex.EncodeToString(sum[:])
}

func (d *DockerHTTP) CreateNetwork(ctx context.Context, spec NetworkSpec) error {
	if spec != NetworkSpecFor(spec.TenantID, spec.InstanceID, spec.Generation) ||
		!boundedText(spec.TenantID, 128) || !boundedText(spec.InstanceID, 256) || spec.Generation == 0 {
		return &PolicyError{"internal network specification is invalid"}
	}
	body := map[string]any{
		"Name": spec.Name, "CheckDuplicate": true, "Internal": true, "Attachable": false,
		"IPAM": map[string]any{"Driver": "default", "Config": []map[string]string{{"Subnet": spec.Subnet, "Gateway": spec.Gateway}}},
		"Labels": map[string]string{
			managedNetworkLabel: "true", "io.hardrails.tenant": spec.TenantID,
			"io.hardrails.instance": spec.InstanceID, networkGenerationLabel: strconv.FormatUint(spec.Generation, 10),
		},
	}
	return d.call(ctx, http.MethodPost, "/v1.41/networks/create", body, http.StatusCreated)
}

func (d *DockerHTTP) InspectNetwork(ctx context.Context, name string) (ObservedNetwork, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/networks/"+pathEscape(name), nil)
	if err != nil {
		return ObservedNetwork{}, err
	}
	response, err := d.client.Do(req)
	if err != nil {
		return ObservedNetwork{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ObservedNetwork{}, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return ObservedNetwork{}, dockerError(response)
	}
	var payload struct {
		Name       string            `json:"Name"`
		Internal   bool              `json:"Internal"`
		Attachable bool              `json:"Attachable"`
		Labels     map[string]string `json:"Labels"`
		IPAM       struct {
			Config []struct{ Subnet, Gateway string }
		} `json:"IPAM"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedNetwork{}, err
	}
	generation, err := strconv.ParseUint(payload.Labels[networkGenerationLabel], 10, 64)
	if err != nil {
		return ObservedNetwork{}, errors.New("managed network has invalid generation label")
	}
	observed := NetworkSpec{
		Name: payload.Name, TenantID: payload.Labels["io.hardrails.tenant"],
		InstanceID: payload.Labels["io.hardrails.instance"], Generation: generation,
	}
	want := NetworkSpecFor(observed.TenantID, observed.InstanceID, observed.Generation)
	if len(payload.IPAM.Config) == 1 {
		observed.Subnet, observed.Gateway = payload.IPAM.Config[0].Subnet, payload.IPAM.Config[0].Gateway
	}
	observed.RelayIP, observed.AgentIP = want.RelayIP, want.AgentIP
	return ObservedNetwork{NetworkSpec: observed, Managed: payload.Labels[managedNetworkLabel] == "true" && !payload.Attachable, Internal: payload.Internal}, nil
}

func (d *DockerHTTP) RemoveNetwork(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodDelete, "/v1.41/networks/"+pathEscape(name), nil, http.StatusNoContent)
}

func (d *DockerHTTP) CreateRelay(ctx context.Context, spec RelaySpec) error {
	if err := validateRelaySpec(spec); err != nil {
		return err
	}
	command := make([]string, 0, 2)
	mounts := []map[string]any(nil)
	if spec.Inference {
		command = append(command, "-inference-socket=/run/steward-grant/i.sock")
		mounts = []map[string]any{{"Type": "bind", "Source": spec.GrantDir, "Target": "/run/steward-grant", "ReadOnly": false}}
	}
	if spec.ServicePort > 0 {
		command = append(command, "-service-target=http://agent:"+strconv.Itoa(spec.ServicePort))
	}
	body := map[string]any{
		"Image": spec.Image, "Cmd": command, "User": "65532:" + strconv.Itoa(spec.RelayGID),
		"WorkingDir": "/", "ReadonlyRootfs": true,
		"Labels": map[string]string{
			managedRelayLabel: "true", relayFingerprintLabel: relayFingerprint(spec),
			"io.hardrails.tenant": spec.TenantID, "io.hardrails.instance": spec.InstanceID,
			networkGenerationLabel: strconv.FormatUint(spec.Generation, 10),
			runtimeNetworkLabel:    spec.NetworkName, runtimeGrantLabel: spec.GrantID,
		},
		"HostConfig": map[string]any{
			"Runtime": "runc", "NetworkMode": spec.NetworkName, "ReadonlyRootfs": true,
			"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
			"PidsLimit": spec.PIDs, "Memory": spec.MemoryBytes, "NanoCPUs": spec.CPUMillis * 1_000_000,
			"Tmpfs": map[string]string{"/tmp": tempTmpfs}, "Mounts": mounts,
			"ExtraHosts": []string{"agent:" + spec.AgentIP},
		},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{
			spec.NetworkName: map[string]any{"Aliases": []string{"steward-relay"}, "IPAMConfig": map[string]string{"IPv4Address": spec.RelayIP}},
		}},
	}
	return d.call(ctx, http.MethodPost, "/v1.41/containers/create?name="+url.QueryEscape(spec.Name), body, http.StatusCreated)
}

func (d *DockerHTTP) InspectRelay(ctx context.Context, name string) (ObservedRelay, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/containers/"+pathEscape(name)+"/json", nil)
	if err != nil {
		return ObservedRelay{}, err
	}
	response, err := d.client.Do(req)
	if err != nil {
		return ObservedRelay{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ObservedRelay{}, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return ObservedRelay{}, dockerError(response)
	}
	var payload struct {
		Image  string `json:"Image"`
		Config struct {
			Image      string            `json:"Image"`
			User       string            `json:"User"`
			WorkingDir string            `json:"WorkingDir"`
			Cmd        []string          `json:"Cmd"`
			Labels     map[string]string `json:"Labels"`
		}
		HostConfig struct {
			Memory         int64             `json:"Memory"`
			NanoCPUs       int64             `json:"NanoCpus"`
			PidsLimit      int64             `json:"PidsLimit"`
			Runtime        string            `json:"Runtime"`
			NetworkMode    string            `json:"NetworkMode"`
			ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
			CapDrop        []string          `json:"CapDrop"`
			SecurityOpt    []string          `json:"SecurityOpt"`
			Tmpfs          map[string]string `json:"Tmpfs"`
			PortBindings   map[string]any    `json:"PortBindings"`
			ExtraHosts     []string          `json:"ExtraHosts"`
		}
		Mounts          []dockerMount
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		}
		State struct{ Status string }
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedRelay{}, err
	}
	labels := payload.Config.Labels
	generation, _ := strconv.ParseUint(labels[networkGenerationLabel], 10, 64)
	ipAddress := payload.NetworkSettings.Networks[labels[runtimeNetworkLabel]].IPAddress
	spec := RelaySpec{
		Name: name, Image: payload.Config.Image, NetworkName: labels[runtimeNetworkLabel], GrantID: labels[runtimeGrantLabel],
		TenantID: labels["io.hardrails.tenant"], InstanceID: labels["io.hardrails.instance"], Generation: generation,
		RelayGID: relayGID(payload.Config.User), Inference: hasArgument(payload.Config.Cmd, "-inference-socket=/run/steward-grant/i.sock"),
		ServicePort: serviceTargetPort(payload.Config.Cmd), MemoryBytes: payload.HostConfig.Memory,
		CPUMillis: payload.HostConfig.NanoCPUs / 1_000_000, PIDs: payload.HostConfig.PidsLimit,
	}
	addresses := NetworkSpecFor(spec.TenantID, spec.InstanceID, spec.Generation)
	spec.RelayIP, spec.AgentIP = addresses.RelayIP, addresses.AgentIP
	if spec.Inference {
		for _, mount := range payload.Mounts {
			if mount.Type == "bind" && mount.Destination == "/run/steward-grant" && mount.RW {
				spec.GrantDir = mount.Source
			}
		}
	}
	fingerprint := labels[relayFingerprintLabel]
	var drift []string
	checkRelay := func(ok bool, field string) {
		if !ok {
			drift = append(drift, field)
		}
	}
	checkRelay(labels[managedRelayLabel] == "true", "managed_label")
	checkRelay(validFingerprint(fingerprint), "fingerprint_shape")
	checkRelay(payload.Config.User == "65532:"+strconv.Itoa(spec.RelayGID), "user")
	checkRelay(payload.Config.WorkingDir == "/", "working_dir")
	checkRelay(payload.HostConfig.Runtime == "runc", "runtime")
	checkRelay(payload.HostConfig.NetworkMode == spec.NetworkName, "network")
	checkRelay(payload.HostConfig.ReadonlyRootfs, "read_only_root")
	checkRelay(contains(payload.HostConfig.CapDrop, "ALL"), "cap_drop")
	checkRelay(contains(payload.HostConfig.SecurityOpt, "no-new-privileges:true"), "no_new_privileges")
	checkRelay(payload.HostConfig.Tmpfs["/tmp"] == tempTmpfs, "tmpfs")
	checkRelay(len(payload.HostConfig.PortBindings) == 0, "published_ports")
	checkRelay(contains(payload.HostConfig.ExtraHosts, "agent:"+spec.AgentIP), "agent_host")
	checkRelay(payload.State.Status != "running" || ipAddress == spec.RelayIP, "relay_ip")
	checkRelay(relayFingerprint(spec) == fingerprint, "fingerprint")
	hardened := len(drift) == 0
	return ObservedRelay{Spec: spec, ImageID: payload.Image, Fingerprint: fingerprint,
		Managed: labels[managedRelayLabel] == "true", Hardened: hardened, Status: payload.State.Status, IPAddress: ipAddress,
		Drift: strings.Join(drift, ",")}, nil
}

func validateRelaySpec(spec RelaySpec) error {
	if spec.Name != RelayName(spec.TenantID, spec.InstanceID, spec.Generation) ||
		spec.NetworkName != NetworkName(spec.TenantID, spec.InstanceID, spec.Generation) ||
		!relayImageDigest.MatchString(spec.Image) || !strings.HasPrefix(spec.GrantID, "grant-") || len(spec.GrantID) != len("grant-")+64 ||
		!boundedText(spec.TenantID, 128) || !boundedText(spec.InstanceID, 256) || spec.Generation == 0 ||
		spec.RelayGID <= 0 || spec.MemoryBytes <= 0 || spec.CPUMillis <= 0 || spec.PIDs <= 0 ||
		spec.ServicePort < 0 || spec.ServicePort > 65535 || !spec.Inference && spec.ServicePort == 0 {
		return &PolicyError{"internal relay specification is invalid"}
	}
	addresses := NetworkSpecFor(spec.TenantID, spec.InstanceID, spec.Generation)
	if spec.RelayIP != addresses.RelayIP || spec.AgentIP != addresses.AgentIP {
		return &PolicyError{"internal relay addresses are invalid"}
	}
	if spec.Inference && !validGrantDirectory(spec.GrantDir) {
		return &PolicyError{"internal inference grant directory is invalid"}
	}
	if !spec.Inference && spec.GrantDir != "" {
		return &PolicyError{"service-only relay cannot receive an inference grant directory"}
	}
	return nil
}

func relayFingerprint(spec RelaySpec) string {
	raw, _ := json.Marshal(spec)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func relayGID(user string) int {
	parts := strings.Split(user, ":")
	if len(parts) != 2 || parts[0] != "65532" {
		return 0
	}
	value, _ := strconv.Atoi(parts[1])
	return value
}

func hasArgument(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func serviceTargetPort(arguments []string) int {
	for _, argument := range arguments {
		const prefix = "-service-target=http://agent:"
		if strings.HasPrefix(argument, prefix) {
			value, _ := strconv.Atoi(strings.TrimPrefix(argument, prefix))
			return value
		}
	}
	return 0
}

func validGrantDirectory(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}
