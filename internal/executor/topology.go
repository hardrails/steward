package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
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
	Name             string
	Image            string
	NetworkName      string
	GrantID          string
	GrantDir         string
	TenantID         string
	InstanceID       string
	Generation       uint64
	RelayGID         int
	Inference        bool
	Connector        bool
	Egress           bool
	ControllerEvents bool
	ServicePort      int
	RelayIP          string
	AgentIP          string
	MemoryBytes      int64
	CPUMillis        int64
	PIDs             int64
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
const isolatedGatewayOption = "com.docker.network.bridge.gateway_mode_ipv4"
const isolatedGatewayMode = "isolated"

func NetworkName(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "steward-net-" + hex.EncodeToString(sum[:])
}

func NetworkSpecFor(tenantID, instanceID string, generation uint64) NetworkSpec {
	return NetworkSpec{
		Name: NetworkName(tenantID, instanceID, generation), TenantID: tenantID, InstanceID: instanceID, Generation: generation,
	}
}

// networkSpecFromIPAM binds a Docker-selected private subnet to Steward's two
// fixed endpoints. Docker, not tenant-controlled identity text, selects the
// subnet from the operator-configured daemon address pools and excludes existing
// Docker networks. The fresh non-attachable network contains only these two
// containers, so the first two usable addresses are unambiguous. Docker omits
// IPAM.Config.Gateway for gateway_mode_ipv4=isolated because the host bridge has
// no address. If an Engine reports a gateway, Steward validates and skips it.
func networkSpecFromIPAM(identity NetworkSpec, subnet, gateway string) (NetworkSpec, error) {
	want := NetworkSpecFor(identity.TenantID, identity.InstanceID, identity.Generation)
	if identity.Name != want.Name || identity.TenantID != want.TenantID || identity.InstanceID != want.InstanceID ||
		identity.Generation != want.Generation {
		return NetworkSpec{}, errors.New("network identity is invalid")
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 29 {
		return NetworkSpec{}, errors.New("Docker allocated an unsupported network subnet")
	}
	prefix = prefix.Masked()
	var gatewayAddress netip.Addr
	if gateway != "" {
		gatewayAddress, err = netip.ParseAddr(gateway)
		if err != nil || !gatewayAddress.Is4() || !gatewayAddress.IsPrivate() || !prefix.Contains(gatewayAddress) ||
			gatewayAddress == prefix.Addr() || !prefix.Contains(gatewayAddress.Next()) {
			return NetworkSpec{}, errors.New("Docker allocated an unsupported network gateway")
		}
	}
	endpoints := make([]netip.Addr, 0, 2)
	for candidate := prefix.Addr().Next(); prefix.Contains(candidate) && len(endpoints) < 2; candidate = candidate.Next() {
		// The final address in an IPv4 prefix is the broadcast address.
		if !prefix.Contains(candidate.Next()) {
			break
		}
		if !gatewayAddress.IsValid() || candidate != gatewayAddress {
			endpoints = append(endpoints, candidate)
		}
	}
	if len(endpoints) != 2 || !endpoints[0].IsPrivate() || !endpoints[1].IsPrivate() {
		return NetworkSpec{}, errors.New("Docker network has fewer than two private workload addresses")
	}
	want.Subnet = prefix.String()
	if gatewayAddress.IsValid() {
		want.Gateway = gatewayAddress.String()
	}
	want.RelayIP, want.AgentIP = endpoints[0].String(), endpoints[1].String()
	return want, nil
}

func validRuntimeAddresses(relay, agent string) bool {
	relayAddress, relayErr := netip.ParseAddr(relay)
	agentAddress, agentErr := netip.ParseAddr(agent)
	return relayErr == nil && agentErr == nil && relayAddress.Is4() && agentAddress.Is4() &&
		relayAddress.IsPrivate() && agentAddress.IsPrivate() && relayAddress != agentAddress
}

func runtimeAllocationMatches(identity NetworkSpec, subnet, gateway, relay, agent string) bool {
	allocated, err := networkSpecFromIPAM(identity, subnet, gateway)
	return err == nil && allocated.Subnet == subnet && allocated.Gateway == gateway &&
		allocated.RelayIP == relay && allocated.AgentIP == agent
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
		"Name": spec.Name, "Driver": "bridge", "CheckDuplicate": true, "Internal": true, "Attachable": false,
		"Options": map[string]string{isolatedGatewayOption: isolatedGatewayMode},
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
		Driver     string            `json:"Driver"`
		Internal   bool              `json:"Internal"`
		Attachable bool              `json:"Attachable"`
		Options    map[string]string `json:"Options"`
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
	if len(payload.IPAM.Config) != 1 {
		return ObservedNetwork{}, errors.New("managed network must have exactly one Docker IPAM allocation")
	}
	observed, err = networkSpecFromIPAM(observed, payload.IPAM.Config[0].Subnet, payload.IPAM.Config[0].Gateway)
	if err != nil {
		return ObservedNetwork{}, err
	}
	return ObservedNetwork{
		NetworkSpec: observed,
		Managed:     payload.Labels[managedNetworkLabel] == "true" && !payload.Attachable,
		Internal:    payload.Internal && payload.Driver == "bridge" && payload.Options[isolatedGatewayOption] == isolatedGatewayMode,
	}, nil
}

func (d *DockerHTTP) RemoveNetwork(ctx context.Context, name string) error {
	return d.call(ctx, http.MethodDelete, "/v1.41/networks/"+pathEscape(name), nil, http.StatusNoContent)
}

func (d *DockerHTTP) CreateRelay(ctx context.Context, spec RelaySpec) error {
	if err := validateRelaySpec(spec); err != nil {
		return err
	}
	command := relayCommand(spec)
	mounts := []map[string]any(nil)
	if spec.Inference || spec.Connector || spec.Egress || spec.ControllerEvents || spec.ServicePort > 0 {
		mounts = []map[string]any{{"Type": "bind", "Source": spec.GrantDir, "Target": "/run/steward-grant", "ReadOnly": false}}
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
		"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
			"Runtime": "runc", "NetworkMode": spec.NetworkName, "ReadonlyRootfs": true,
			"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
			"PidsLimit": spec.PIDs, "Memory": spec.MemoryBytes, "MemorySwap": spec.MemoryBytes, "NanoCPUs": spec.CPUMillis * 1_000_000,
			"Tmpfs": map[string]string{"/tmp": tempTmpfs}, "Mounts": mounts,
			"ExtraHosts": []string{"agent:" + spec.AgentIP}, "Dns": []string{"127.0.0.1"},
			"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
				"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress,
			}},
		}),
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
			dockerClosedHostPolicy
			Memory          int64             `json:"Memory"`
			MemorySwap      int64             `json:"MemorySwap"`
			NanoCPUs        int64             `json:"NanoCpus"`
			PidsLimit       int64             `json:"PidsLimit"`
			Runtime         string            `json:"Runtime"`
			NetworkMode     string            `json:"NetworkMode"`
			ReadonlyRootfs  bool              `json:"ReadonlyRootfs"`
			CapDrop         []string          `json:"CapDrop"`
			SecurityOpt     []string          `json:"SecurityOpt"`
			Tmpfs           map[string]string `json:"Tmpfs"`
			PortBindings    map[string]any    `json:"PortBindings"`
			ExtraHosts      []string          `json:"ExtraHosts"`
			DNS             []string          `json:"Dns"`
			Privileged      bool              `json:"Privileged"`
			CapAdd          []string          `json:"CapAdd"`
			Binds           []string          `json:"Binds"`
			Devices         []json.RawMessage `json:"Devices"`
			DeviceRequests  []json.RawMessage `json:"DeviceRequests"`
			PublishAllPorts bool              `json:"PublishAllPorts"`
			LogConfig       struct {
				Type   string            `json:"Type"`
				Config map[string]string `json:"Config"`
			} `json:"LogConfig"`
		}
		Mounts          []dockerMount
		NetworkSettings struct {
			Networks map[string]dockerEndpoint `json:"Networks"`
		}
		State struct{ Status string }
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return ObservedRelay{}, err
	}
	labels := payload.Config.Labels
	generation, _ := strconv.ParseUint(labels[networkGenerationLabel], 10, 64)
	endpoint := payload.NetworkSettings.Networks[labels[runtimeNetworkLabel]]
	ipAddress := endpoint.IPAddress
	configuredIP := ""
	if endpoint.IPAMConfig != nil {
		configuredIP = endpoint.IPAMConfig.IPv4Address
	}
	spec := RelaySpec{
		Name: name, Image: payload.Config.Image, NetworkName: labels[runtimeNetworkLabel], GrantID: labels[runtimeGrantLabel],
		TenantID: labels["io.hardrails.tenant"], InstanceID: labels["io.hardrails.instance"], Generation: generation,
		RelayGID: relayGID(payload.Config.User), Inference: hasArgument(payload.Config.Cmd, "-inference-socket=/run/steward-grant/i.sock"),
		Connector:        hasArgument(payload.Config.Cmd, "-connector-socket=/run/steward-grant/c.sock"),
		Egress:           hasArgument(payload.Config.Cmd, "-egress-socket=/run/steward-grant/e.sock"),
		ControllerEvents: hasArgument(payload.Config.Cmd, "-event-socket=/run/steward-grant/v.sock"),
		ServicePort:      serviceTargetPort(payload.Config.Cmd), MemoryBytes: payload.HostConfig.Memory,
		CPUMillis: payload.HostConfig.NanoCPUs / 1_000_000, PIDs: payload.HostConfig.PidsLimit,
	}
	// Docker leaves IPAddress empty until a created container starts. The
	// immutable IPAMConfig retains the static address supplied at create time,
	// so it is the authoritative relay identity in every lifecycle state.
	spec.RelayIP = configuredIP
	if len(payload.HostConfig.ExtraHosts) == 1 && strings.HasPrefix(payload.HostConfig.ExtraHosts[0], "agent:") {
		spec.AgentIP = strings.TrimPrefix(payload.HostConfig.ExtraHosts[0], "agent:")
	}
	if (spec.Inference || spec.Connector || spec.Egress || spec.ControllerEvents || spec.ServicePort > 0) && len(payload.Mounts) == 1 {
		mount := payload.Mounts[0]
		if mount.Type == "bind" && mount.Destination == "/run/steward-grant" && mount.RW {
			spec.GrantDir = mount.Source
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
	checkRelay(exactStrings(payload.Config.Cmd, relayCommand(spec)), "command")
	checkRelay(payload.HostConfig.Runtime == "runc", "runtime")
	checkRelay(payload.HostConfig.NetworkMode == spec.NetworkName, "network")
	checkRelay(payload.HostConfig.namespacesHardened(), "namespace_policy")
	checkRelay(payload.HostConfig.lifecycleHardened(), "lifecycle_policy")
	checkRelay(payload.HostConfig.hostAttachmentsHardened(), "host_attachment_policy")
	checkRelay(payload.HostConfig.ReadonlyRootfs, "read_only_root")
	checkRelay(exactStrings(payload.HostConfig.CapDrop, []string{"ALL"}), "cap_drop")
	checkRelay(exactStrings(payload.HostConfig.SecurityOpt, []string{"no-new-privileges:true"}), "no_new_privileges")
	checkRelay(exactStringMap(payload.HostConfig.Tmpfs, map[string]string{"/tmp": tempTmpfs}), "tmpfs")
	checkRelay(payload.HostConfig.MemorySwap == payload.HostConfig.Memory, "memory_swap")
	checkRelay(len(payload.HostConfig.PortBindings) == 0, "published_ports")
	checkRelay(!payload.HostConfig.PublishAllPorts, "publish_all_ports")
	checkRelay(!payload.HostConfig.Privileged, "privileged")
	checkRelay(len(payload.HostConfig.CapAdd) == 0, "cap_add")
	checkRelay(len(payload.HostConfig.Binds) == 0, "binds")
	checkRelay(len(payload.HostConfig.Devices) == 0 && len(payload.HostConfig.DeviceRequests) == 0, "devices")
	checkRelay(exactStrings(payload.HostConfig.ExtraHosts, []string{"agent:" + spec.AgentIP}), "agent_host")
	checkRelay(exactStrings(payload.HostConfig.DNS, []string{"127.0.0.1"}), "dns")
	checkRelay(exactLogConfig(payload.HostConfig.LogConfig.Type, payload.HostConfig.LogConfig.Config), "log_config")
	checkRelay(hasExactRelayMounts(payload.Mounts, spec), "mounts")
	checkRelay(hasExactNetwork(payload.NetworkSettings.Networks, spec.NetworkName, spec.RelayIP, payload.State.Status == "running"), "networks")
	checkRelay(relayFingerprint(spec) == fingerprint, "fingerprint")
	hardened := len(drift) == 0
	return ObservedRelay{Spec: spec, ImageID: payload.Image, Fingerprint: fingerprint,
		Managed: labels[managedRelayLabel] == "true", Hardened: hardened, Status: payload.State.Status, IPAddress: ipAddress,
		Drift: strings.Join(drift, ",")}, nil
}

func hasExactRelayMounts(mounts []dockerMount, spec RelaySpec) bool {
	if !spec.Inference && !spec.Connector && !spec.Egress && !spec.ControllerEvents && spec.ServicePort == 0 {
		return len(mounts) == 0
	}
	return len(mounts) == 1 && mounts[0].Type == "bind" && mounts[0].Source == spec.GrantDir &&
		mounts[0].Destination == "/run/steward-grant" && mounts[0].RW
}

func validateRelaySpec(spec RelaySpec) error {
	if spec.Name != RelayName(spec.TenantID, spec.InstanceID, spec.Generation) ||
		spec.NetworkName != NetworkName(spec.TenantID, spec.InstanceID, spec.Generation) ||
		!relayImageDigest.MatchString(spec.Image) || !strings.HasPrefix(spec.GrantID, "grant-") || len(spec.GrantID) != len("grant-")+64 ||
		!boundedText(spec.TenantID, 128) || !boundedText(spec.InstanceID, 256) || spec.Generation == 0 ||
		spec.RelayGID <= 0 || spec.MemoryBytes <= 0 || spec.CPUMillis <= 0 || spec.PIDs <= 0 ||
		spec.ServicePort < 0 || spec.ServicePort > 65535 || !spec.Inference && !spec.Connector && !spec.Egress && !spec.ControllerEvents && spec.ServicePort == 0 {
		return &PolicyError{"internal relay specification is invalid"}
	}
	if !validRuntimeAddresses(spec.RelayIP, spec.AgentIP) {
		return &PolicyError{"internal relay addresses are invalid"}
	}
	if (spec.Inference || spec.Connector || spec.Egress || spec.ControllerEvents || spec.ServicePort > 0) && !validGrantDirectory(spec.GrantDir) {
		return &PolicyError{"internal capability grant directory is invalid"}
	}
	if !spec.Inference && !spec.Connector && !spec.Egress && !spec.ControllerEvents && spec.ServicePort == 0 && spec.GrantDir != "" {
		return &PolicyError{"relay without capabilities cannot receive a capability grant directory"}
	}
	return nil
}

func relayCommand(spec RelaySpec) []string {
	command := make([]string, 0, 5)
	if spec.Inference {
		command = append(command, "-inference-socket=/run/steward-grant/i.sock")
	}
	if spec.Connector {
		command = append(command, "-connector-socket=/run/steward-grant/c.sock")
	}
	if spec.Egress {
		command = append(command, "-egress-socket=/run/steward-grant/e.sock")
	}
	if spec.ControllerEvents {
		command = append(command, "-event-socket=/run/steward-grant/v.sock")
	}
	if spec.ServicePort > 0 {
		command = append(command, "-service-socket=/run/steward-grant/s.sock", "-service-target=http://agent:"+strconv.Itoa(spec.ServicePort))
	}
	return command
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
