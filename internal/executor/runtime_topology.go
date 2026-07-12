package executor

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/hardrails/steward/internal/gateway"
)

const (
	defaultRelayMemory = int64(64 << 20)
	defaultRelayCPU    = int64(100)
	defaultRelayPIDs   = int64(32)
)

func (s *Server) desiredGatewayGrant(workload Workload, serviceURL string) gateway.Grant {
	grant := gateway.Grant{
		GrantID: workload.Runtime.GrantID, TenantID: workload.TenantID, InstanceID: workload.InstanceID,
		Generation: workload.Runtime.Generation, Service: workload.Runtime.ServicePort > 0, ServiceURL: serviceURL,
	}
	if workload.Runtime.Inference {
		grant.RouteID = workload.Runtime.RouteID
		grant.ModelAlias = workload.Runtime.ModelAlias
	}
	return grant
}

func (s *Server) desiredRelay(workload Workload) RelaySpec {
	grantDir := ""
	if workload.Runtime.Inference {
		grantDir = gateway.GrantDirectory(s.secure.grantRoot, workload.Runtime.GrantID)
	}
	return RelaySpec{
		Name:  RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation),
		Image: s.secure.relayImage, NetworkName: workload.Runtime.NetworkName, GrantID: workload.Runtime.GrantID,
		GrantDir: grantDir, TenantID: workload.TenantID, InstanceID: workload.InstanceID,
		Generation: workload.Runtime.Generation, RelayGID: s.secure.relayGID,
		Inference: workload.Runtime.Inference, ServicePort: workload.Runtime.ServicePort,
		RelayIP: workload.Runtime.RelayIP, AgentIP: workload.Runtime.AgentIP,
		MemoryBytes: defaultRelayMemory, CPUMillis: defaultRelayCPU, PIDs: defaultRelayPIDs,
	}
}

func (s *Server) prepareRuntimeTopology(ctx context.Context, workload Workload) error {
	if workload.Runtime == nil {
		return nil
	}
	wantNetwork := NetworkSpecFor(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	observed, err := s.secure.topology.InspectNetwork(ctx, wantNetwork.Name)
	if errors.Is(err, ErrNotFound) {
		if err := s.secure.topology.CreateNetwork(ctx, wantNetwork); err != nil {
			if after, inspectErr := s.secure.topology.InspectNetwork(ctx, wantNetwork.Name); inspectErr != nil || !networkEqual(after, wantNetwork) {
				return fmt.Errorf("create isolated runtime network: %w", err)
			}
		}
		observed, err = s.secure.topology.InspectNetwork(ctx, wantNetwork.Name)
	}
	if err != nil || !networkEqual(observed, wantNetwork) {
		return errors.New("isolated runtime network is missing or has drifted")
	}
	if err := s.secure.gateway.Register(ctx, s.desiredGatewayGrant(workload, "")); err != nil {
		return fmt.Errorf("reserve capability grant: %w", err)
	}
	return nil
}

func (s *Server) completeRuntimeTopology(ctx context.Context, workload Workload) error {
	if workload.Runtime == nil {
		return nil
	}
	want := s.desiredRelay(workload)
	observed, err := s.secure.topology.InspectRelay(ctx, want.Name)
	if errors.Is(err, ErrNotFound) {
		if err := s.secure.topology.CreateRelay(ctx, want); err != nil {
			if after, inspectErr := s.secure.topology.InspectRelay(ctx, want.Name); inspectErr != nil || !relayEqual(after, want) {
				return fmt.Errorf("create trusted relay: %w", err)
			}
		}
		observed, err = s.secure.topology.InspectRelay(ctx, want.Name)
	}
	if err != nil {
		return fmt.Errorf("inspect trusted relay: %w", err)
	}
	if !relayEqual(observed, want) {
		return fmt.Errorf("trusted relay drift: managed=%t hardened=%t spec=%t fingerprint=%t fields=%s observed_ip=%s expected_ip=%s", observed.Managed, observed.Hardened, observed.Spec == want, observed.Fingerprint == relayFingerprint(want), observed.Drift, observed.IPAddress, want.RelayIP)
	}
	return nil
}

func (s *Server) runtimeTopologyMatches(ctx context.Context, workload Workload, wantActive bool) bool {
	if workload.Runtime == nil {
		return true
	}
	network, err := s.secure.topology.InspectNetwork(ctx, workload.Runtime.NetworkName)
	wantNetwork := NetworkSpecFor(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	if err != nil || !networkEqual(network, wantNetwork) {
		return false
	}
	relay, err := s.secure.topology.InspectRelay(ctx, RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation))
	if err != nil || !relayEqual(relay, s.desiredRelay(workload)) {
		return false
	}
	observedGrant, err := s.secure.gateway.Inspect(ctx, workload.Runtime.GrantID)
	if err != nil {
		return false
	}
	serviceURL := observedGrant.ServiceURL
	if wantActive && workload.Runtime.ServicePort > 0 {
		serviceURL = relayServiceURL(relay)
	}
	wantGrant := s.desiredGatewayGrant(workload, serviceURL)
	wantGrant.Active = wantActive
	return observedGrant == wantGrant
}

func networkEqual(observed ObservedNetwork, want NetworkSpec) bool {
	return observed.Managed && observed.Internal && observed.NetworkSpec == want
}

func relayEqual(observed ObservedRelay, want RelaySpec) bool {
	return observed.Managed && observed.Hardened && observed.Spec == want && observed.Fingerprint == relayFingerprint(want)
}

func (s *Server) removeRuntimeTopology(ctx context.Context, workload Workload) bool {
	if workload.Runtime == nil {
		return true
	}
	relayName := RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	_ = s.docker.Remove(ctx, relayName)
	if _, err := s.secure.topology.InspectRelay(ctx, relayName); !errors.Is(err, ErrNotFound) {
		return false
	}
	if err := s.secure.gateway.Unregister(ctx, workload.Runtime.GrantID); err != nil {
		return false
	}
	_ = s.secure.topology.RemoveNetwork(ctx, workload.Runtime.NetworkName)
	if _, err := s.secure.topology.InspectNetwork(ctx, workload.Runtime.NetworkName); !errors.Is(err, ErrNotFound) {
		return false
	}
	return true
}

func (s *Server) runtimeLifecycleMatches(ctx context.Context, workload Workload, wantRunning bool) bool {
	if workload.Runtime == nil {
		return true
	}
	relay, err := s.secure.topology.InspectRelay(ctx, RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation))
	if err != nil || !relayEqual(relay, s.desiredRelay(workload)) || (relay.Status == "running") != wantRunning {
		return false
	}
	grant, err := s.secure.gateway.Inspect(ctx, workload.Runtime.GrantID)
	if err != nil || grant.Active != wantRunning {
		return false
	}
	if wantRunning && workload.Runtime.ServicePort > 0 {
		return grant.ServiceURL == relayServiceURL(relay)
	}
	return true
}

func (s *Server) applyRuntimeTransition(ctx context.Context, runtimeRef string, workload Workload, start bool) error {
	if workload.Runtime == nil {
		if start {
			return s.docker.Start(ctx, runtimeRef)
		}
		return s.docker.Stop(ctx, runtimeRef)
	}
	relay := RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	if start {
		if err := s.docker.Start(ctx, relay); err != nil {
			return fmt.Errorf("start trusted relay: %w", err)
		}
		serviceURL := ""
		if workload.Runtime.ServicePort > 0 {
			observed, err := s.secure.topology.InspectRelay(ctx, relay)
			if err != nil || relayServiceURL(observed) == "" {
				_ = s.docker.Stop(ctx, relay)
				return errors.New("trusted relay did not receive a private internal address")
			}
			serviceURL = relayServiceURL(observed)
		}
		if err := s.secure.gateway.Register(ctx, s.desiredGatewayGrant(workload, serviceURL)); err != nil {
			_ = s.docker.Stop(ctx, relay)
			return fmt.Errorf("bind gateway service grant: %w", err)
		}
		if err := s.secure.gateway.Activate(ctx, workload.Runtime.GrantID); err != nil {
			_ = s.docker.Stop(ctx, relay)
			return fmt.Errorf("activate gateway grant: %w", err)
		}
		if err := s.docker.Start(ctx, runtimeRef); err != nil {
			_ = s.secure.gateway.Deactivate(ctx, workload.Runtime.GrantID)
			_ = s.docker.Stop(ctx, relay)
			return err
		}
		return nil
	}
	if err := s.secure.gateway.Deactivate(ctx, workload.Runtime.GrantID); err != nil {
		return fmt.Errorf("deactivate gateway grant: %w", err)
	}
	if err := s.docker.Stop(ctx, runtimeRef); err != nil {
		_ = s.secure.gateway.Activate(ctx, workload.Runtime.GrantID)
		return err
	}
	if err := s.docker.Stop(ctx, relay); err != nil {
		_ = s.docker.Start(ctx, runtimeRef)
		_ = s.secure.gateway.Activate(ctx, workload.Runtime.GrantID)
		return fmt.Errorf("stop trusted relay: %w", err)
	}
	return nil
}

func relayServiceURL(relay ObservedRelay) string {
	address := net.ParseIP(relay.IPAddress)
	if address == nil || !address.IsPrivate() {
		return ""
	}
	return "http://" + net.JoinHostPort(relay.IPAddress, "8081")
}

func (s *Server) restoreRuntimeLifecycle(ctx context.Context, runtimeRef string, workload Workload, wantRunning bool) bool {
	_ = s.applyRuntimeTransition(ctx, runtimeRef, workload, wantRunning)
	observed, err := s.managed(ctx, runtimeRef)
	return err == nil && (observed.Status == "running") == wantRunning && s.runtimeLifecycleMatches(ctx, workload, wantRunning)
}
