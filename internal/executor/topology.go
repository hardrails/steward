package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	Managed            bool
	Internal           bool
	ExplicitIPAM       bool
	ReservationPresent bool
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
const networkAllocationLabel = "io.hardrails.network.allocation"
const networkSubnetLabel = "io.hardrails.network.subnet"
const networkReservationForLabel = "io.hardrails.network.reservation-for"
const managedRelayLabel = "io.hardrails.relay.managed"
const relayFingerprintLabel = "io.hardrails.relay-sha256"
const defaultIPAMDriver = "default"
const networkReservationAllocation = "docker-default-reservation-v1"
const networkExplicitAllocation = "docker-default-explicit-v1"
const maxNetworkAllocationAttempts = 3
const networkCleanupTimeout = 5 * time.Second
const isolatedGatewayOption = "com.docker.network.bridge.gateway_mode_ipv4"
const isolatedGatewayMode = "isolated"
const bridgeIPv4Option = "com.docker.network.enable_ipv4"
const bridgeIPv6Option = "com.docker.network.enable_ipv6"
const dockerPoolOverlapMessage = "invalid pool request: Pool overlaps with other one on this address space"

func NetworkName(tenantID, instanceID string, generation uint64) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + instanceID + "\x00" + strconv.FormatUint(generation, 10)))
	return "steward-net-" + hex.EncodeToString(sum[:])
}

func NetworkSpecFor(tenantID, instanceID string, generation uint64) NetworkSpec {
	return NetworkSpec{
		Name: NetworkName(tenantID, instanceID, generation), TenantID: tenantID, InstanceID: instanceID, Generation: generation,
	}
}

func networkReservationName(spec NetworkSpec) string {
	return "steward-ipam-" + strings.TrimPrefix(spec.Name, "steward-net-")
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
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 29 ||
		!privateIPv4Prefix(prefix) {
		return NetworkSpec{}, errors.New("Docker allocated an unsupported network subnet")
	}
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

func privateIPv4Prefix(prefix netip.Prefix) bool {
	for _, private := range [...]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= private.Bits() && private.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
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
	var lastErr error
	for attempt := 0; attempt < maxNetworkAllocationAttempts; attempt++ {
		observed, err := d.InspectNetwork(ctx, spec.Name)
		switch {
		case err == nil && explicitNetworkShapeEqual(observed, spec):
			if observed.ReservationPresent {
				if err := d.removeNetworkReservation(ctx, spec.Name); err != nil {
					return fmt.Errorf("clean stale Docker subnet reservation: %w", err)
				}
			}
			return nil
		case err == nil:
			return errors.New("managed runtime network already exists with drift")
		case !errors.Is(err, ErrNotFound):
			return fmt.Errorf("inspect managed runtime network before allocation: %w", err)
		}
		retry, err := d.createNetworkAttempt(ctx, spec)
		if !retry {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("allocate Docker runtime subnet after %d attempts: %w", maxNetworkAllocationAttempts, lastErr)
}

func (d *DockerHTTP) createNetworkAttempt(ctx context.Context, spec NetworkSpec) (bool, error) {
	reservation, allocated, err := d.acquireNetworkReservation(ctx, spec)
	if err != nil {
		return false, err
	}
	released := false
	defer func() {
		if !released {
			d.cleanupNetworkReservationID(reservation.ID)
		}
	}()
	if err := d.releaseNetworkReservation(ctx, spec, reservation.ID); err != nil {
		return false, err
	}
	released = true
	createErr := d.call(
		ctx, http.MethodPost, "/v1.41/networks/create",
		networkCreateBody(spec, spec.Name, networkExplicitAllocation, allocated.Subnet), http.StatusCreated,
	)
	observed, inspectErr := d.InspectNetwork(ctx, spec.Name)
	switch {
	case inspectErr == nil && explicitNetworkEqual(observed, spec):
		return false, nil
	case inspectErr == nil:
		return false, errors.New("created runtime network does not match its explicit Docker IPAM allocation")
	case !errors.Is(inspectErr, ErrNotFound):
		if createErr != nil {
			return false, errors.Join(createErr, fmt.Errorf("inspect created runtime network: %w", inspectErr))
		}
		return false, fmt.Errorf("inspect created runtime network: %w", inspectErr)
	case createErr == nil:
		return false, errors.New("Docker reported runtime network creation but the network is absent")
	case dockerPoolOverlap(createErr):
		return true, createErr
	default:
		return false, createErr
	}
}

func dockerPoolOverlap(err error) bool {
	var apiErr *dockerAPIError
	return errors.As(err, &apiErr) && apiErr.status == http.StatusForbidden &&
		apiErr.message == dockerPoolOverlapMessage
}

func (d *DockerHTTP) acquireNetworkReservation(
	ctx context.Context, spec NetworkSpec,
) (dockerNetworkInspect, NetworkSpec, error) {
	name := networkReservationName(spec)
	reservation, err := d.inspectDockerNetwork(ctx, name)
	if errors.Is(err, ErrNotFound) {
		createErr := d.call(
			ctx, http.MethodPost, "/v1.41/networks/create",
			networkCreateBody(spec, name, networkReservationAllocation, ""), http.StatusCreated,
		)
		reservation, err = d.inspectDockerNetwork(ctx, name)
		if err != nil {
			if createErr != nil {
				return dockerNetworkInspect{}, NetworkSpec{}, errors.Join(
					createErr, fmt.Errorf("inspect Docker subnet reservation: %w", err),
				)
			}
			return dockerNetworkInspect{}, NetworkSpec{}, fmt.Errorf("inspect Docker subnet reservation: %w", err)
		}
	} else if err != nil {
		return dockerNetworkInspect{}, NetworkSpec{}, fmt.Errorf("inspect existing Docker subnet reservation: %w", err)
	}
	allocated, err := reservationAllocation(reservation, spec)
	if err != nil {
		return dockerNetworkInspect{}, NetworkSpec{}, err
	}
	return reservation, allocated, nil
}

func (d *DockerHTTP) releaseNetworkReservation(ctx context.Context, spec NetworkSpec, id string) error {
	removeErr := d.call(ctx, http.MethodDelete, "/v1.41/networks/"+pathEscape(id), nil, http.StatusNoContent)
	reservation, inspectErr := d.inspectDockerNetwork(ctx, networkReservationName(spec))
	if errors.Is(inspectErr, ErrNotFound) {
		return nil
	}
	if inspectErr != nil {
		if removeErr != nil {
			return errors.Join(removeErr, fmt.Errorf("prove Docker subnet reservation removal: %w", inspectErr))
		}
		return fmt.Errorf("prove Docker subnet reservation removal: %w", inspectErr)
	}
	if reservation.ID != id {
		return errors.New("Docker subnet reservation identity changed during removal")
	}
	if _, err := reservationAllocation(reservation, spec); err != nil {
		return err
	}
	if removeErr != nil {
		return fmt.Errorf("release Docker subnet reservation: %w", removeErr)
	}
	return errors.New("Docker subnet reservation remained after removal")
}

func (d *DockerHTTP) cleanupNetworkReservationID(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkCleanupTimeout)
	defer cancel()
	_ = d.call(ctx, http.MethodDelete, "/v1.41/networks/"+pathEscape(id), nil, http.StatusNoContent)
}

func networkCreateBody(spec NetworkSpec, name, allocation, subnet string) map[string]any {
	labels := networkLabels(spec, allocation, subnet)
	body := map[string]any{
		"Name": name, "Driver": "bridge", "CheckDuplicate": true, "Internal": true, "Attachable": false, "EnableIPv6": false,
		"Options": map[string]string{isolatedGatewayOption: isolatedGatewayMode},
		"Labels":  labels,
	}
	if allocation == networkExplicitAllocation {
		body["IPAM"] = map[string]any{
			"Driver": defaultIPAMDriver,
			"Config": []map[string]string{{"Subnet": subnet}},
		}
	}
	return body
}

func networkLabels(spec NetworkSpec, allocation, subnet string) map[string]string {
	labels := map[string]string{
		managedNetworkLabel: "true", "io.hardrails.tenant": spec.TenantID,
		"io.hardrails.instance": spec.InstanceID, networkGenerationLabel: strconv.FormatUint(spec.Generation, 10),
		networkAllocationLabel: allocation,
	}
	if allocation == networkReservationAllocation {
		labels[networkReservationForLabel] = spec.Name
	}
	if allocation == networkExplicitAllocation {
		labels[networkSubnetLabel] = subnet
	}
	return labels
}

func legacyNetworkLabels(spec NetworkSpec) map[string]string {
	return map[string]string{
		managedNetworkLabel: "true", "io.hardrails.tenant": spec.TenantID,
		"io.hardrails.instance": spec.InstanceID, networkGenerationLabel: strconv.FormatUint(spec.Generation, 10),
	}
}

type dockerNetworkInspect struct {
	ID         string            `json:"Id"`
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Scope      string            `json:"Scope"`
	Internal   bool              `json:"Internal"`
	Attachable bool              `json:"Attachable"`
	Ingress    bool              `json:"Ingress"`
	ConfigOnly bool              `json:"ConfigOnly"`
	EnableIPv6 bool              `json:"EnableIPv6"`
	Options    map[string]string `json:"Options"`
	Labels     map[string]string `json:"Labels"`
	Containers map[string]struct {
		Name        string `json:"Name"`
		IPv4Address string `json:"IPv4Address"`
	} `json:"Containers"`
	IPAM struct {
		Driver  string            `json:"Driver"`
		Options map[string]string `json:"Options"`
		Config  []struct {
			Subnet             string            `json:"Subnet"`
			IPRange            string            `json:"IPRange"`
			Gateway            string            `json:"Gateway"`
			AuxiliaryAddresses map[string]string `json:"AuxiliaryAddresses"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func (d *DockerHTTP) inspectDockerNetwork(ctx context.Context, name string) (dockerNetworkInspect, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/networks/"+pathEscape(name), nil)
	if err != nil {
		return dockerNetworkInspect{}, err
	}
	response, err := d.client.Do(req)
	if err != nil {
		return dockerNetworkInspect{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return dockerNetworkInspect{}, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return dockerNetworkInspect{}, dockerError(response)
	}
	var payload dockerNetworkInspect
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return dockerNetworkInspect{}, err
	}
	return payload, nil
}

func networkEnvelopeMatches(payload dockerNetworkInspect, name string, labels map[string]string) bool {
	return payload.ID != "" && payload.Name == name && payload.Driver == "bridge" && payload.Scope == "local" &&
		payload.Internal && !payload.Attachable && !payload.Ingress && !payload.ConfigOnly && !payload.EnableIPv6 &&
		hardenedNetworkOptions(payload.Options) &&
		exactStringMap(payload.Labels, labels) && payload.IPAM.Driver == defaultIPAMDriver &&
		len(payload.IPAM.Options) == 0 && len(payload.IPAM.Config) == 1 &&
		payload.IPAM.Config[0].IPRange == "" && len(payload.IPAM.Config[0].AuxiliaryAddresses) == 0
}

func hardenedNetworkOptions(options map[string]string) bool {
	if options[isolatedGatewayOption] != isolatedGatewayMode {
		return false
	}
	for key, value := range options {
		switch key {
		case isolatedGatewayOption:
			if value != isolatedGatewayMode {
				return false
			}
		case bridgeIPv4Option:
			if value != "true" {
				return false
			}
		case bridgeIPv6Option:
			if value != "false" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func reservationAllocation(payload dockerNetworkInspect, spec NetworkSpec) (NetworkSpec, error) {
	if !networkEnvelopeMatches(
		payload, networkReservationName(spec), networkLabels(spec, networkReservationAllocation, ""),
	) || len(payload.Containers) != 0 {
		return NetworkSpec{}, errors.New("Docker subnet reservation is drifted or in use")
	}
	allocated, err := networkSpecFromIPAM(spec, payload.IPAM.Config[0].Subnet, payload.IPAM.Config[0].Gateway)
	if err != nil {
		return NetworkSpec{}, err
	}
	return allocated, nil
}

func (d *DockerHTTP) InspectNetwork(ctx context.Context, name string) (ObservedNetwork, error) {
	payload, err := d.inspectDockerNetwork(ctx, name)
	if err != nil {
		return ObservedNetwork{}, err
	}
	observed, err := observedNetworkFromPayload(payload)
	if err != nil {
		return ObservedNetwork{}, err
	}
	reservation, reservationErr := d.inspectDockerNetwork(ctx, networkReservationName(observed.NetworkSpec))
	if errors.Is(reservationErr, ErrNotFound) {
		return observed, nil
	}
	if reservationErr != nil {
		return ObservedNetwork{}, fmt.Errorf("inspect Docker subnet reservation: %w", reservationErr)
	}
	if _, err := reservationAllocation(reservation, NetworkSpecFor(
		observed.TenantID, observed.InstanceID, observed.Generation,
	)); err != nil {
		return ObservedNetwork{}, err
	}
	observed.ReservationPresent = true
	return observed, nil
}

func observedNetworkFromPayload(payload dockerNetworkInspect) (ObservedNetwork, error) {
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
	internal := payload.Name == observed.Name && payload.Driver == "bridge" && payload.Scope == "local" &&
		payload.Internal && !payload.Attachable && !payload.Ingress && !payload.ConfigOnly && !payload.EnableIPv6 &&
		hardenedNetworkOptions(payload.Options)
	explicitIPAM := networkEnvelopeMatches(
		payload, observed.Name, networkLabels(observed, networkExplicitAllocation, observed.Subnet),
	)
	legacyIPAM := networkEnvelopeMatches(payload, observed.Name, legacyNetworkLabels(observed))
	return ObservedNetwork{
		NetworkSpec:  observed,
		Managed:      explicitIPAM || legacyIPAM,
		Internal:     internal,
		ExplicitIPAM: explicitIPAM,
	}, nil
}

func (d *DockerHTTP) RemoveNetwork(ctx context.Context, name string) error {
	final, finalErr := d.managedNetworkForRemoval(ctx, name)
	finalMissing := errors.Is(finalErr, ErrNotFound)
	if finalErr != nil && !finalMissing {
		return finalErr
	}
	reservation, reservationPresent, err := d.networkReservationForRemoval(ctx, name)
	if err != nil {
		return err
	}
	var removeErrors []error
	if reservationPresent {
		if err := d.removeVerifiedNetwork(ctx, reservation, "Docker subnet reservation"); err != nil {
			removeErrors = append(removeErrors, err)
		}
	}
	if !finalMissing {
		if err := d.removeVerifiedNetwork(ctx, final, "managed runtime network"); err != nil {
			removeErrors = append(removeErrors, err)
		}
	}
	if len(removeErrors) != 0 {
		return errors.Join(removeErrors...)
	}
	if finalMissing {
		return ErrNotFound
	}
	return nil
}

func (d *DockerHTTP) removeNetworkReservation(ctx context.Context, finalName string) error {
	reservation, present, err := d.networkReservationForRemoval(ctx, finalName)
	if err != nil || !present {
		return err
	}
	return d.removeVerifiedNetwork(ctx, reservation, "Docker subnet reservation")
}

func (d *DockerHTTP) managedNetworkForRemoval(ctx context.Context, name string) (dockerNetworkInspect, error) {
	payload, err := d.inspectDockerNetwork(ctx, name)
	if err != nil {
		return dockerNetworkInspect{}, err
	}
	observed, err := observedNetworkFromPayload(payload)
	if err != nil {
		return dockerNetworkInspect{}, err
	}
	want := NetworkSpecFor(observed.TenantID, observed.InstanceID, observed.Generation)
	if !networkEqual(observed, want) || observed.Name != name {
		return dockerNetworkInspect{}, errors.New("refusing to remove a drifted or foreign runtime network")
	}
	return payload, nil
}

func (d *DockerHTTP) networkReservationForRemoval(
	ctx context.Context, finalName string,
) (dockerNetworkInspect, bool, error) {
	if !strings.HasPrefix(finalName, "steward-net-") || len(finalName) != len("steward-net-")+sha256.Size*2 {
		return dockerNetworkInspect{}, false, nil
	}
	reservationName := "steward-ipam-" + strings.TrimPrefix(finalName, "steward-net-")
	reservation, err := d.inspectDockerNetwork(ctx, reservationName)
	if errors.Is(err, ErrNotFound) {
		return dockerNetworkInspect{}, false, nil
	}
	if err != nil {
		return dockerNetworkInspect{}, false, fmt.Errorf("inspect Docker subnet reservation during cleanup: %w", err)
	}
	generation, err := strconv.ParseUint(reservation.Labels[networkGenerationLabel], 10, 64)
	if err != nil {
		return dockerNetworkInspect{}, false, errors.New("Docker subnet reservation has invalid generation label")
	}
	spec := NetworkSpecFor(
		reservation.Labels["io.hardrails.tenant"], reservation.Labels["io.hardrails.instance"], generation,
	)
	if spec.Name != finalName {
		return dockerNetworkInspect{}, false, errors.New("Docker subnet reservation does not belong to the requested runtime network")
	}
	if _, err := reservationAllocation(reservation, spec); err != nil {
		return dockerNetworkInspect{}, false, err
	}
	return reservation, true, nil
}

func (d *DockerHTTP) removeVerifiedNetwork(
	ctx context.Context, payload dockerNetworkInspect, boundary string,
) error {
	removeErr := d.call(
		ctx, http.MethodDelete, "/v1.41/networks/"+pathEscape(payload.ID), nil, http.StatusNoContent,
	)
	after, inspectErr := d.inspectDockerNetwork(ctx, payload.Name)
	if errors.Is(inspectErr, ErrNotFound) {
		return nil
	}
	if inspectErr != nil {
		if removeErr != nil {
			return errors.Join(removeErr, fmt.Errorf("prove %s removal: %w", boundary, inspectErr))
		}
		return fmt.Errorf("prove %s removal: %w", boundary, inspectErr)
	}
	if after.ID != payload.ID {
		return fmt.Errorf("%s identity changed during removal", boundary)
	}
	if removeErr != nil {
		return fmt.Errorf("remove %s: %w", boundary, removeErr)
	}
	return fmt.Errorf("%s remained after removal", boundary)
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
