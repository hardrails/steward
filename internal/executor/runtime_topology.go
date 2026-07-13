package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/gateway"
)

const (
	defaultRelayMemory = int64(64 << 20)
	defaultRelayCPU    = int64(100)
	defaultRelayPIDs   = int64(32)
)

type runtimeTopologyComponent string

const (
	runtimeTopologyConfiguration runtimeTopologyComponent = "configuration"
	runtimeTopologyNetwork       runtimeTopologyComponent = "network"
	runtimeTopologyRelay         runtimeTopologyComponent = "relay"
	runtimeTopologyGateway       runtimeTopologyComponent = "gateway"
)

// runtimeTopologyFailure preserves the difference between an observed mismatch
// and a backend that could not be inspected. Both fail closed, but callers map
// drift to a conflict and inspection failure to the unavailable backend instead
// of telling an operator that a timeout is durable state drift.
type runtimeTopologyFailure struct {
	component   runtimeTopologyComponent
	unavailable bool
	message     string
	cause       error
}

func (e *runtimeTopologyFailure) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.message, e.cause)
	}
	return e.message
}

func (e *runtimeTopologyFailure) Unwrap() error { return e.cause }

func topologyDrift(component runtimeTopologyComponent, message string) error {
	return &runtimeTopologyFailure{component: component, message: message}
}

func topologyUnavailable(component runtimeTopologyComponent, message string, cause error) error {
	return &runtimeTopologyFailure{component: component, unavailable: true, message: message, cause: cause}
}

// runtimeStartProofFailure identifies a failed topology proof before the first
// start mutation. The HTTP transaction can compensate its prepared journal
// immediately without invoking any rollback operation.
type runtimeStartProofFailure struct {
	err error
}

func (e *runtimeStartProofFailure) Error() string { return e.err.Error() }
func (e *runtimeStartProofFailure) Unwrap() error { return e.err }

func startPreconditionFailure(err error) error {
	return &runtimeStartProofFailure{err: err}
}

// runtimeFailedStart is returned after an exact stopped precondition when a
// later start stage fails. contained is true only when monotonic recovery has
// re-proved the complete prior stopped topology. Callers must never feed this
// failure into the normal stop rollback, which may start/reactivate objects to
// restore a prior running state.
type runtimeFailedStart struct {
	err                    error
	contained              bool
	topologyReconciliation bool
}

func (e *runtimeFailedStart) Error() string { return e.err.Error() }
func (e *runtimeFailedStart) Unwrap() error { return e.err }

func (s *Server) desiredGatewayGrant(workload Workload, serviceURL string) gateway.Grant {
	grant := gateway.Grant{
		GrantID: workload.Runtime.GrantID, TenantID: workload.TenantID, InstanceID: workload.InstanceID,
		Generation: workload.Runtime.Generation, Service: workload.Runtime.ServicePort > 0, ServiceURL: serviceURL,
	}
	if imageConfigDigest.MatchString(workload.Runtime.CapsuleDigest) && imageConfigDigest.MatchString(workload.Runtime.PolicyDigest) {
		grant.RuntimeRef = RuntimeRef(workload.TenantID, workload.InstanceID)
		grant.CapsuleDigest = workload.Runtime.CapsuleDigest
		grant.PolicyDigest = workload.Runtime.PolicyDigest
	}
	grant.EgressRouteIDs = append([]string(nil), workload.Runtime.EgressRouteIDs...)
	grant.ConnectorIDs = append([]string(nil), workload.Runtime.ConnectorIDs...)
	if workload.Runtime.Inference || len(workload.Runtime.EgressRouteIDs) > 0 {
		grant.RouteID = workload.Runtime.RouteID
		grant.ModelAlias = workload.Runtime.ModelAlias
	}
	return grant
}

func (s *Server) desiredRelay(workload Workload) RelaySpec {
	grantDir := ""
	if workload.Runtime.Inference || len(workload.Runtime.EgressRouteIDs) > 0 || len(workload.Runtime.ConnectorIDs) > 0 || workload.Runtime.ServicePort > 0 {
		grantDir = gateway.GrantDirectory(s.secure.grantRoot, workload.Runtime.GrantID)
	}
	return RelaySpec{
		Name:  RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation),
		Image: s.secure.relayImage, NetworkName: workload.Runtime.NetworkName, GrantID: workload.Runtime.GrantID,
		GrantDir: grantDir, TenantID: workload.TenantID, InstanceID: workload.InstanceID,
		Generation: workload.Runtime.Generation, RelayGID: s.secure.relayGID,
		Inference: workload.Runtime.Inference, Connector: len(workload.Runtime.ConnectorIDs) > 0,
		Egress: len(workload.Runtime.EgressRouteIDs) > 0, ServicePort: workload.Runtime.ServicePort,
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
	workload.Runtime.NetworkName = observed.Name
	workload.Runtime.Subnet, workload.Runtime.Gateway = observed.Subnet, observed.Gateway
	workload.Runtime.RelayIP, workload.Runtime.AgentIP = observed.RelayIP, observed.AgentIP
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
	if !s.runtimeNetworkMatches(ctx, workload) {
		return false
	}
	relay, err := s.secure.topology.InspectRelay(ctx, RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation))
	if err != nil || !relayEqual(relay, s.desiredRelay(workload)) {
		return false
	}
	inspection, err := s.secure.gateway.InspectWithPolicy(ctx, workload.Runtime.GrantID)
	if err != nil {
		return false
	}
	observedGrant := inspection.Grant
	serviceURL := observedGrant.ServiceURL
	if wantActive && workload.Runtime.ServicePort > 0 {
		serviceURL = gateway.ServiceSocketURL(s.secure.grantRoot, workload.Runtime.GrantID)
	}
	wantGrant := s.desiredGatewayGrant(workload, serviceURL)
	wantGrant.Active = wantActive
	return gateway.GrantsEqual(observedGrant, wantGrant)
}

// runtimeNetworkMatches proves that Docker's live network remains the exact
// isolated allocation bound into the signed runtime record. This check is
// separate from the relay and Gateway checks so a lifecycle start can verify
// the network before it widens authority.
func (s *Server) runtimeNetworkMatches(ctx context.Context, workload Workload) bool {
	return s.inspectRuntimeNetwork(ctx, workload) == nil
}

func (s *Server) inspectRuntimeNetwork(ctx context.Context, workload Workload) error {
	if workload.Runtime == nil {
		return nil
	}
	if s.secure == nil || s.secure.topology == nil {
		return topologyUnavailable(runtimeTopologyConfiguration, "runtime topology inspection is not configured", nil)
	}
	network, err := s.secure.topology.InspectNetwork(ctx, workload.Runtime.NetworkName)
	if errors.Is(err, ErrNotFound) {
		return topologyDrift(runtimeTopologyNetwork, "isolated runtime network is missing")
	}
	if err != nil {
		return topologyUnavailable(runtimeTopologyNetwork, "inspect isolated runtime network", err)
	}
	want := NetworkSpecFor(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	if !networkEqual(network, want) ||
		network.Subnet != workload.Runtime.Subnet || network.Gateway != workload.Runtime.Gateway ||
		network.RelayIP != workload.Runtime.RelayIP || network.AgentIP != workload.Runtime.AgentIP {
		return topologyDrift(runtimeTopologyNetwork, "isolated runtime network does not match the committed admission fence")
	}
	return nil
}

// proveRuntimeTopologyState is the complete precondition and postcondition for
// widening a signed runtime. It proves the live network, the exact hardened
// relay and its lifecycle, the complete Gateway grant and its lifecycle, and
// the route-policy binding retained by the admission fence.
func (s *Server) proveRuntimeTopologyState(
	ctx context.Context, workload Workload, wantActive bool, expectedRoutePolicyDigest string,
) error {
	if err := s.proveRuntimeAuthorityState(ctx, workload, wantActive, expectedRoutePolicyDigest); err != nil {
		return err
	}
	return s.inspectRuntimeNetwork(ctx, workload)
}

// proveRuntimeAuthorityState proves the agent-facing control objects without
// requiring the dormant Docker network itself to be healthy. Failed-start
// containment uses this narrower proof after every agent and relay is stopped;
// network drift still degrades readiness, but cannot make a completed
// authority-narrowing transaction look active.
func (s *Server) proveRuntimeAuthorityState(
	ctx context.Context, workload Workload, wantActive bool, expectedRoutePolicyDigest string,
) error {
	if workload.Runtime == nil {
		if expectedRoutePolicyDigest != "" {
			return topologyDrift(runtimeTopologyGateway, "workload without a Gateway route has an unexpected route-policy binding")
		}
		return nil
	}
	if s.secure == nil || s.secure.topology == nil || s.secure.gateway == nil {
		return topologyUnavailable(runtimeTopologyConfiguration, "complete runtime topology inspection is not configured", nil)
	}

	wantRelay := s.desiredRelay(workload)
	relay, err := s.secure.topology.InspectRelay(ctx, wantRelay.Name)
	if errors.Is(err, ErrNotFound) {
		return topologyDrift(runtimeTopologyRelay, "trusted relay is missing")
	}
	if err != nil {
		return topologyUnavailable(runtimeTopologyRelay, "inspect trusted relay", err)
	}
	if !relayEqual(relay, wantRelay) || !lifecycleMatches(relay.Status, wantActive) {
		return topologyDrift(runtimeTopologyRelay, "trusted relay does not match the committed admission fence and lifecycle")
	}

	inspection, err := s.secure.gateway.InspectWithPolicy(ctx, workload.Runtime.GrantID)
	if gatewayGrantNotFound(err) {
		return topologyDrift(runtimeTopologyGateway, "Gateway grant is missing")
	}
	if err != nil {
		return topologyUnavailable(runtimeTopologyGateway, "inspect Gateway grant", err)
	}
	serviceURL := ""
	if workload.Runtime.ServicePort > 0 && (wantActive || inspection.Grant.ServiceURL != "") {
		serviceURL = gateway.ServiceSocketURL(s.secure.grantRoot, workload.Runtime.GrantID)
	}
	wantGrant := s.desiredGatewayGrant(workload, serviceURL)
	wantGrant.Active = wantActive
	if !gateway.GrantsEqual(inspection.Grant, wantGrant) {
		return topologyDrift(runtimeTopologyGateway, "Gateway grant does not match the committed admission fence and lifecycle")
	}
	if inspection.RoutePolicyDigest != expectedRoutePolicyDigest {
		return topologyDrift(runtimeTopologyGateway, "Gateway route policy does not match the committed admission fence")
	}
	return nil
}

func networkEqual(observed ObservedNetwork, want NetworkSpec) bool {
	allocated, err := networkSpecFromIPAM(want, observed.Subnet, observed.Gateway)
	return err == nil && observed.Managed && observed.Internal && observed.NetworkSpec == allocated
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
	if err != nil || !relayEqual(relay, s.desiredRelay(workload)) || !lifecycleMatches(relay.Status, wantRunning) {
		return false
	}
	inspection, err := s.secure.gateway.InspectWithPolicy(ctx, workload.Runtime.GrantID)
	grant := inspection.Grant
	if err != nil || grant.Active != wantRunning {
		return false
	}
	if wantRunning && workload.Runtime.ServicePort > 0 {
		return grant.ServiceURL == gateway.ServiceSocketURL(s.secure.grantRoot, workload.Runtime.GrantID)
	}
	return true
}

func (s *Server) stopWorkloadAndConfirm(ctx context.Context, runtimeRef string, workload Workload) error {
	stopErr := boundedDockerStop(ctx, s.docker, runtimeRef)
	observed, inspectErr := s.managed(ctx, runtimeRef)
	if inspectErr != nil {
		if stopErr != nil {
			return fmt.Errorf("stop workload: %v; inspect stopped workload: %w", stopErr, inspectErr)
		}
		return fmt.Errorf("inspect stopped workload: %w", inspectErr)
	}
	wantFingerprint := workloadFingerprint(workload)
	identityMatches := workloadFingerprint(observed.Workload) == wantFingerprint &&
		observed.Fingerprint == wantFingerprint &&
		(workload.ImageConfigDigest == "" || observed.ImageID == workload.ImageConfigDigest)
	if !identityMatches {
		return errors.New("stopped workload identity changed during lifecycle transition")
	}
	if lifecycleMatches(observed.Status, false) {
		// Docker may apply the stop and then lose the response. The exact
		// reinspection is authoritative in that case.
		return nil
	}
	if stopErr != nil {
		return fmt.Errorf("stop workload: %v; Docker status remains %q", stopErr, observed.Status)
	}
	return fmt.Errorf("workload did not reach an exact stopped state; Docker status is %q", observed.Status)
}

func (s *Server) stopRelayAndConfirm(ctx context.Context, relayName string, want RelaySpec) error {
	stopErr := boundedDockerStop(ctx, s.docker, relayName)
	observed, inspectErr := s.secure.topology.InspectRelay(ctx, relayName)
	if inspectErr != nil {
		if stopErr != nil {
			return fmt.Errorf("stop trusted relay: %v; inspect stopped trusted relay: %w", stopErr, inspectErr)
		}
		return fmt.Errorf("inspect stopped trusted relay: %w", inspectErr)
	}
	if !relayEqual(observed, want) {
		return errors.New("trusted relay identity changed during lifecycle transition")
	}
	if lifecycleMatches(observed.Status, false) {
		return nil
	}
	if stopErr != nil {
		return fmt.Errorf("stop trusted relay: %v; Docker status remains %q", stopErr, observed.Status)
	}
	return fmt.Errorf("trusted relay did not reach an exact stopped state; Docker status is %q", observed.Status)
}

func (s *Server) gatewayRoutePolicyDigest(ctx context.Context, workload Workload) (string, error) {
	if workload.Runtime == nil || !workload.Runtime.Inference && len(workload.Runtime.EgressRouteIDs) == 0 && len(workload.Runtime.ConnectorIDs) == 0 {
		return "", nil
	}
	inspection, err := s.secure.gateway.InspectWithPolicy(ctx, workload.Runtime.GrantID)
	if err != nil {
		return "", err
	}
	if !imageConfigDigest.MatchString(inspection.RoutePolicyDigest) {
		return "", errors.New("gateway returned an invalid route policy digest")
	}
	return inspection.RoutePolicyDigest, nil
}

func (s *Server) gatewayRoutePolicyMatches(ctx context.Context, workload Workload, expected string) bool {
	return s.inspectGatewayRoutePolicy(ctx, workload, expected) == nil
}

func (s *Server) inspectGatewayRoutePolicy(ctx context.Context, workload Workload, expected string) error {
	policyBearing := workload.Runtime != nil && (workload.Runtime.Inference || len(workload.Runtime.EgressRouteIDs) != 0 || len(workload.Runtime.ConnectorIDs) != 0)
	if !policyBearing {
		if expected != "" {
			return topologyDrift(runtimeTopologyGateway, "workload without an inference, egress, or connector route has an unexpected route-policy binding")
		}
		return nil
	}
	if !imageConfigDigest.MatchString(expected) {
		return topologyDrift(runtimeTopologyGateway, "committed Gateway route-policy binding is invalid")
	}
	inspection, err := s.secure.gateway.InspectWithPolicy(ctx, workload.Runtime.GrantID)
	if gatewayGrantNotFound(err) {
		return topologyDrift(runtimeTopologyGateway, "Gateway grant is missing")
	}
	if err != nil {
		return topologyUnavailable(runtimeTopologyGateway, "inspect Gateway route policy", err)
	}
	if inspection.RoutePolicyDigest != expected {
		return topologyDrift(runtimeTopologyGateway, "Gateway route policy does not match the committed admission fence")
	}
	return nil
}

func (s *Server) applyRuntimeTransition(ctx context.Context, runtimeRef string, workload Workload, start bool, expectedRoutePolicyDigest string) error {
	if workload.Runtime == nil {
		if start {
			if err := s.docker.Start(ctx, runtimeRef); err != nil {
				return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest, err, false)
			}
			return nil
		}
		return s.stopWorkloadAndConfirm(ctx, runtimeRef, workload)
	}
	relay := RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
	if start {
		// This is the lowest authority-widening primitive. Request handlers perform
		// the same proof before journaling for precise fast failure, but recovery
		// and rollback callers must not be able to bypass it.
		if err := s.proveRuntimeTopologyState(ctx, workload, false, expectedRoutePolicyDigest); err != nil {
			return startPreconditionFailure(err)
		}
		if err := s.docker.Start(ctx, relay); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				fmt.Errorf("start trusted relay: %w", err), false)
		}
		serviceURL := ""
		if workload.Runtime.ServicePort > 0 {
			serviceURL = gateway.ServiceSocketURL(s.secure.grantRoot, workload.Runtime.GrantID)
		}
		if err := s.secure.gateway.Register(ctx, s.desiredGatewayGrant(workload, serviceURL)); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				fmt.Errorf("bind gateway service grant: %w", err), false)
		}
		if err := s.inspectGatewayRoutePolicy(ctx, workload, expectedRoutePolicyDigest); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				err, true)
		}
		if err := s.docker.Start(ctx, runtimeRef); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				fmt.Errorf("start agent: %w", err), false)
		}
		if err := s.secure.gateway.Activate(ctx, workload.Runtime.GrantID); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				fmt.Errorf("activate gateway grant: %w", err), false)
		}
		if err := s.proveRuntimeTopologyState(ctx, workload, true, expectedRoutePolicyDigest); err != nil {
			return s.failedRuntimeStart(ctx, runtimeRef, workload, expectedRoutePolicyDigest,
				fmt.Errorf("verify started runtime topology: %w", err), true)
		}
		return nil
	}
	if err := s.secure.gateway.Deactivate(ctx, workload.Runtime.GrantID); err != nil {
		return fmt.Errorf("deactivate gateway grant: %w", err)
	}
	if err := s.stopWorkloadAndConfirm(ctx, runtimeRef, workload); err != nil {
		_ = s.secure.gateway.Activate(ctx, workload.Runtime.GrantID)
		return err
	}
	if err := s.stopRelayAndConfirm(ctx, relay, s.desiredRelay(workload)); err != nil {
		_ = s.docker.Start(ctx, runtimeRef)
		_ = s.secure.gateway.Activate(ctx, workload.Runtime.GrantID)
		return err
	}
	return nil
}

// failedRuntimeStart restores only the exact stopped state proved before the
// start. It is deliberately monotonic: every operation narrows authority, all
// operations are attempted even after an earlier failure, and no failure path
// starts an agent/relay or activates a grant.
func (s *Server) failedRuntimeStart(
	ctx context.Context, runtimeRef string, workload Workload, expectedRoutePolicyDigest string,
	cause error, topologyReconciliation bool,
) *runtimeFailedStart {
	contained := true
	if workload.Runtime != nil {
		_ = s.secure.gateway.Deactivate(ctx, workload.Runtime.GrantID)
	}
	if err := s.stopWorkloadAndConfirm(ctx, runtimeRef, workload); err != nil {
		contained = false
	}
	if workload.Runtime != nil {
		relay := RelayName(workload.TenantID, workload.InstanceID, workload.Runtime.Generation)
		if err := s.stopRelayAndConfirm(ctx, relay, s.desiredRelay(workload)); err != nil {
			contained = false
		}
	}
	observed, err := s.managed(ctx, runtimeRef)
	if err != nil || !lifecycleMatches(observed.Status, false) {
		contained = false
	}
	if contained && s.proveRuntimeAuthorityState(ctx, observed.Workload, false, expectedRoutePolicyDigest) != nil {
		contained = false
	}
	return &runtimeFailedStart{err: cause, contained: contained, topologyReconciliation: topologyReconciliation}
}

func (s *Server) restoreRuntimeLifecycle(ctx context.Context, runtimeRef string, workload Workload, wantRunning bool, expectedRoutePolicyDigest string) bool {
	_ = s.applyRuntimeTransition(ctx, runtimeRef, workload, wantRunning, expectedRoutePolicyDigest)
	observed, err := s.managed(ctx, runtimeRef)
	if err != nil || !lifecycleMatches(observed.Status, wantRunning) {
		return false
	}
	if wantRunning {
		return s.proveRuntimeTopologyState(ctx, observed.Workload, true, expectedRoutePolicyDigest) == nil
	}
	return s.runtimeLifecycleMatches(ctx, observed.Workload, false)
}
