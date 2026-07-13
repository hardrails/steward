package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

var testGatewayRoutePolicyDigest = "sha256:" + strings.Repeat("e", 64)

type topologyFixture struct {
	agent             ObservedWorkload
	network           *ObservedNetwork
	relay             *ObservedRelay
	inspectNetworkErr error
	createNetworkErr  error
	inspectRelayErr   error
	createRelayErr    error
	removeNetworkNoop bool
	removeRelayNoop   bool
	startErrAt        int
	stopErrAt         int
	startAppliesOnErr bool
	stopAppliesOnErr  bool
	startCalls        int
	stopCalls         int
	onStart           func(string)
}

func (f *topologyFixture) RuntimeAvailable(context.Context, string) (bool, error)   { return true, nil }
func (f *topologyFixture) WorkloadCounts(context.Context, string) (int, int, error) { return 0, 0, nil }
func (f *topologyFixture) Inspect(_ context.Context, _ string) (ObservedWorkload, error) {
	return f.agent, nil
}
func (f *topologyFixture) Create(context.Context, string, Workload) error { return nil }
func (f *topologyFixture) Logs(context.Context, string) (string, error)   { return "", nil }
func (f *topologyFixture) Start(_ context.Context, name string) error {
	f.startCalls++
	failed := f.startErrAt == f.startCalls
	if failed && !f.startAppliesOnErr {
		return errors.New("start failure")
	}
	if strings.HasPrefix(name, "steward-relay-") {
		f.relay.Status, f.relay.IPAddress = "running", f.relay.Spec.RelayIP
	} else {
		f.agent.Status = "running"
	}
	if f.onStart != nil {
		f.onStart(name)
	}
	if failed {
		return errors.New("start response lost")
	}
	return nil
}
func (f *topologyFixture) Stop(_ context.Context, name string) error {
	f.stopCalls++
	failed := f.stopErrAt == f.stopCalls
	if failed && !f.stopAppliesOnErr {
		return errors.New("stop failure")
	}
	if strings.HasPrefix(name, "steward-relay-") {
		f.relay.Status, f.relay.IPAddress = "exited", ""
	} else {
		f.agent.Status = "exited"
	}
	if failed {
		return errors.New("stop response lost")
	}
	return nil
}
func (f *topologyFixture) Remove(_ context.Context, name string) error {
	if strings.HasPrefix(name, "steward-relay-") {
		if !f.removeRelayNoop {
			f.relay = nil
		}
	}
	return nil
}
func (f *topologyFixture) InspectNetwork(context.Context, string) (ObservedNetwork, error) {
	if f.inspectNetworkErr != nil {
		return ObservedNetwork{}, f.inspectNetworkErr
	}
	if f.network == nil {
		return ObservedNetwork{}, ErrNotFound
	}
	return *f.network, nil
}
func (f *topologyFixture) CreateNetwork(_ context.Context, spec NetworkSpec) error {
	if f.createNetworkErr != nil {
		return f.createNetworkErr
	}
	allocated := testNetworkSpec(spec.TenantID, spec.InstanceID, spec.Generation)
	f.network = &ObservedNetwork{NetworkSpec: allocated, Managed: true, Internal: true}
	return nil
}
func (f *topologyFixture) RemoveNetwork(context.Context, string) error {
	if !f.removeNetworkNoop {
		f.network = nil
	}
	return nil
}
func (f *topologyFixture) CreateRelay(_ context.Context, spec RelaySpec) error {
	if f.createRelayErr != nil {
		return f.createRelayErr
	}
	f.relay = &ObservedRelay{Spec: spec, Fingerprint: relayFingerprint(spec), Managed: true, Hardened: true, Status: "created"}
	return nil
}
func (f *topologyFixture) InspectRelay(context.Context, string) (ObservedRelay, error) {
	if f.inspectRelayErr != nil {
		return ObservedRelay{}, f.inspectRelayErr
	}
	if f.relay == nil {
		return ObservedRelay{}, ErrNotFound
	}
	return *f.relay, nil
}

type gatewayFixture struct {
	grants          map[string]gateway.Grant
	registerErr     error
	registerApplies bool
	inspectErr      error
	activateErr     error
	activateApplies bool
	deactivateErr   error
	unregisterErr   error
	policyDigest    string
}

func (f *gatewayFixture) Register(_ context.Context, grant gateway.Grant) error {
	if f.registerErr != nil && !f.registerApplies {
		return f.registerErr
	}
	if current, ok := f.grants[grant.GrantID]; ok && current.Active {
		return errors.New("active")
	}
	f.grants[grant.GrantID] = grant
	return f.registerErr
}
func (f *gatewayFixture) Inspect(_ context.Context, id string) (gateway.Grant, error) {
	if f.inspectErr != nil {
		return gateway.Grant{}, f.inspectErr
	}
	grant, ok := f.grants[id]
	if !ok {
		return gateway.Grant{}, errors.New("missing")
	}
	return grant, nil
}
func (f *gatewayFixture) InspectWithPolicy(ctx context.Context, id string) (gateway.GrantInspection, error) {
	grant, err := f.Inspect(ctx, id)
	if err != nil {
		return gateway.GrantInspection{}, err
	}
	digest := ""
	if grant.RouteID != "" || len(grant.EgressRouteIDs) != 0 || len(grant.ConnectorIDs) != 0 {
		digest = f.policyDigest
		if digest == "" {
			digest = testGatewayRoutePolicyDigest
		}
	}
	return gateway.GrantInspection{Grant: grant, RoutePolicyDigest: digest}, nil
}
func (f *gatewayFixture) EgressStats(_ context.Context, id string) (gateway.EgressStats, error) {
	if f.inspectErr != nil {
		return gateway.EgressStats{}, f.inspectErr
	}
	if _, ok := f.grants[id]; !ok {
		return gateway.EgressStats{}, errors.New("missing")
	}
	return gateway.EgressStats{Allowed: 1}, nil
}
func (f *gatewayFixture) Activate(_ context.Context, id string) error {
	if f.activateErr != nil {
		if f.activateApplies {
			grant := f.grants[id]
			grant.Active = true
			f.grants[id] = grant
		}
		return f.activateErr
	}
	grant := f.grants[id]
	grant.Active = true
	f.grants[id] = grant
	return nil
}
func (f *gatewayFixture) Deactivate(_ context.Context, id string) error {
	if f.deactivateErr != nil {
		return f.deactivateErr
	}
	grant := f.grants[id]
	grant.Active = false
	f.grants[id] = grant
	return nil
}
func (f *gatewayFixture) Unregister(_ context.Context, id string) error {
	if f.unregisterErr != nil {
		return f.unregisterErr
	}
	delete(f.grants, id)
	return nil
}

func TestDesiredRelayMountsGrantDirectoryForEgressOnly(t *testing.T) {
	addresses := testNetworkSpec("tenant-a", "egress-only", 1)
	grantID := gateway.GrantID("tenant-a", "egress-only", 1)
	server := &Server{secure: &secureAdmission{
		grantRoot:  "/run/steward-gateway/grants",
		relayImage: "sha256:" + strings.Repeat("a", 64),
		relayGID:   1234,
	}}
	workload := Workload{TenantID: "tenant-a", InstanceID: "egress-only", Runtime: &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: grantID, Generation: 1,
		Subnet: addresses.Subnet, Gateway: addresses.Gateway,
		EgressRouteIDs: []string{"public-web"}, RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
	}}
	want := server.desiredRelay(workload)
	if !want.Egress || want.Inference || want.GrantDir != gateway.GrantDirectory(server.secure.grantRoot, grantID) {
		t.Fatalf("egress-only relay=%#v", want)
	}
	if err := validateRelaySpec(want); err != nil {
		t.Fatalf("egress-only relay rejected: %v", err)
	}
}

func TestDesiredRelayMountsGrantDirectoryForServiceOnly(t *testing.T) {
	addresses := testNetworkSpec("tenant-a", "service-only", 1)
	grantID := gateway.GrantID("tenant-a", "service-only", 1)
	server := &Server{secure: &secureAdmission{
		grantRoot:  "/run/steward-gateway/grants",
		relayImage: "sha256:" + strings.Repeat("a", 64),
		relayGID:   1234,
	}}
	workload := Workload{TenantID: "tenant-a", InstanceID: "service-only", Runtime: &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: grantID, Generation: 1, ServicePort: 8080,
		Subnet: addresses.Subnet, Gateway: addresses.Gateway,
		RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
	}}
	want := server.desiredRelay(workload)
	if want.Egress || want.Inference || want.ServicePort != 8080 ||
		want.GrantDir != gateway.GrantDirectory(server.secure.grantRoot, grantID) {
		t.Fatalf("service-only relay=%#v", want)
	}
	if err := validateRelaySpec(want); err != nil {
		t.Fatalf("service-only relay rejected: %v", err)
	}
}

func TestDesiredGatewayGrantBindsConnectorAdmission(t *testing.T) {
	workload := Workload{TenantID: "tenant-a", InstanceID: "connector-only", Runtime: &RuntimeGrant{
		GrantID: "grant-" + strings.Repeat("a", 64), Generation: 3,
		ConnectorIDs:  []string{"git.read", "issues.create"},
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
	}}
	server := &Server{}
	grant := server.desiredGatewayGrant(workload, "")
	if grant.RuntimeRef != RuntimeRef(workload.TenantID, workload.InstanceID) ||
		grant.CapsuleDigest != workload.Runtime.CapsuleDigest || grant.PolicyDigest != workload.Runtime.PolicyDigest ||
		len(grant.ConnectorIDs) != 2 || grant.ConnectorIDs[0] != "git.read" || grant.ConnectorIDs[1] != "issues.create" {
		t.Fatalf("connector grant=%#v", grant)
	}
	workload.Runtime.ConnectorIDs[0] = "changed"
	if grant.ConnectorIDs[0] != "git.read" {
		t.Fatal("gateway grant aliases mutable runtime connector IDs")
	}
}

func TestRuntimeTopologyHappyPathAndLifecycle(t *testing.T) {
	addresses := testNetworkSpec("tenant-a", "agent-a", 2)
	workload := Workload{
		TenantID: "tenant-a", InstanceID: "agent-a", ProfileID: "generic-v1@v1",
		Runtime: &RuntimeGrant{
			NetworkName: addresses.Name, GrantID: gateway.GrantID("tenant-a", "agent-a", 2), Generation: 2,
			Inference: true, RouteID: "local-openai", ModelAlias: "model", ServicePort: 8080,
			Subnet: addresses.Subnet, Gateway: addresses.Gateway,
			RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
		},
	}
	docker := &topologyFixture{agent: ObservedWorkload{
		Workload: workload, Fingerprint: workloadFingerprint(workload), Managed: true, Hardened: true, Status: "created",
	}}
	grants := &gatewayFixture{grants: map[string]gateway.Grant{}}
	server := &Server{docker: docker, secure: &secureAdmission{
		topology: docker, gateway: grants, relayImage: "sha256:" + strings.Repeat("a", 64),
		grantRoot: "/run/steward-gateway/grants", relayGID: 1234,
	}}
	ctx := context.Background()
	if err := server.prepareRuntimeTopology(ctx, workload); err != nil {
		t.Fatal(err)
	}
	if err := server.completeRuntimeTopology(ctx, workload); err != nil {
		t.Fatal(err)
	}
	if !server.runtimeTopologyMatches(ctx, workload, false) {
		t.Fatal("stopped topology mismatch")
	}
	if err := server.applyRuntimeTransition(ctx, "executor-agent", workload, true, testGatewayRoutePolicyDigest); err != nil {
		t.Fatal(err)
	}
	if !server.runtimeLifecycleMatches(ctx, workload, true) || !server.runtimeTopologyMatches(ctx, workload, true) {
		t.Fatal("running topology mismatch")
	}
	if got := grants.grants[workload.Runtime.GrantID].ServiceURL; got != gateway.ServiceSocketURL(server.secure.grantRoot, workload.Runtime.GrantID) {
		t.Fatalf("service URL=%q", got)
	}
	if !server.restoreRuntimeLifecycle(ctx, "executor-agent", workload, false, testGatewayRoutePolicyDigest) {
		t.Fatal("restore stop failed")
	}
	if !server.removeRuntimeTopology(ctx, workload) || len(grants.grants) != 0 || docker.network != nil || docker.relay != nil {
		t.Fatal("topology cleanup failed")
	}
}

func TestRuntimeTopologyNoopWithoutGrant(t *testing.T) {
	server := &Server{}
	if err := server.prepareRuntimeTopology(context.Background(), Workload{}); err != nil {
		t.Fatal(err)
	}
	if err := server.completeRuntimeTopology(context.Background(), Workload{}); err != nil {
		t.Fatal(err)
	}
	if !server.runtimeTopologyMatches(context.Background(), Workload{}, false) || !server.runtimeLifecycleMatches(context.Background(), Workload{}, false) {
		t.Fatal("nil runtime mismatch")
	}
}

func TestRuntimeTopologyPreparationAndCompletionFailures(t *testing.T) {
	workload := runtimeTopologyWorkload()
	for _, test := range []struct {
		name   string
		docker *topologyFixture
		grants *gatewayFixture
		phase  string
	}{
		{name: "network inspect", docker: &topologyFixture{inspectNetworkErr: errors.New("inspect")}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "prepare"},
		{name: "network create", docker: &topologyFixture{createNetworkErr: errors.New("create")}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "prepare"},
		{name: "network drift", docker: &topologyFixture{network: &ObservedNetwork{}}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "prepare"},
		{name: "grant register", docker: &topologyFixture{}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}, registerErr: errors.New("register")}, phase: "prepare"},
		{name: "relay inspect", docker: &topologyFixture{inspectRelayErr: errors.New("inspect")}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "complete"},
		{name: "relay create", docker: &topologyFixture{createRelayErr: errors.New("create")}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "complete"},
		{name: "relay drift", docker: &topologyFixture{relay: &ObservedRelay{}}, grants: &gatewayFixture{grants: map[string]gateway.Grant{}}, phase: "complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := runtimeTopologyServer(test.docker, test.grants)
			var err error
			if test.phase == "prepare" {
				err = server.prepareRuntimeTopology(context.Background(), workload)
			} else {
				err = server.completeRuntimeTopology(context.Background(), workload)
			}
			if err == nil {
				t.Fatal("expected topology failure")
			}
		})
	}
}

func TestRuntimeTransitionAndCleanupFailures(t *testing.T) {
	workload := runtimeTopologyWorkload()
	makeReady := func() (*topologyFixture, *gatewayFixture, *Server) {
		docker := &topologyFixture{agent: ObservedWorkload{
			Workload: workload, Fingerprint: workloadFingerprint(workload), Managed: true, Hardened: true, Status: "created",
		}}
		grants := &gatewayFixture{grants: map[string]gateway.Grant{}}
		server := runtimeTopologyServer(docker, grants)
		if err := server.prepareRuntimeTopology(context.Background(), workload); err != nil {
			t.Fatal(err)
		}
		if err := server.completeRuntimeTopology(context.Background(), workload); err != nil {
			t.Fatal(err)
		}
		return docker, grants, server
	}
	for _, test := range []struct {
		name   string
		mutate func(*topologyFixture, *gatewayFixture)
		start  bool
	}{
		{name: "relay start", start: true, mutate: func(d *topologyFixture, _ *gatewayFixture) { d.startErrAt = 1 }},
		{name: "service bind", start: true, mutate: func(_ *topologyFixture, g *gatewayFixture) { g.registerErr = errors.New("bind") }},
		{name: "grant activate", start: true, mutate: func(_ *topologyFixture, g *gatewayFixture) { g.activateErr = errors.New("activate") }},
		{name: "agent start", start: true, mutate: func(d *topologyFixture, _ *gatewayFixture) { d.startErrAt = 2 }},
		{name: "activation rollback deactivation", start: true, mutate: func(_ *topologyFixture, g *gatewayFixture) {
			g.activateErr, g.deactivateErr = errors.New("activate"), errors.New("deactivate")
		}},
		{name: "activation rollback agent stop", start: true, mutate: func(d *topologyFixture, g *gatewayFixture) {
			g.activateErr, d.stopErrAt = errors.New("activate"), 1
		}},
		{name: "activation rollback relay stop", start: true, mutate: func(d *topologyFixture, g *gatewayFixture) {
			g.activateErr, d.stopErrAt = errors.New("activate"), 2
		}},
		{name: "grant deactivate", start: false, mutate: func(_ *topologyFixture, g *gatewayFixture) { g.deactivateErr = errors.New("deactivate") }},
		{name: "agent stop", start: false, mutate: func(d *topologyFixture, _ *gatewayFixture) { d.stopErrAt = 1 }},
		{name: "relay stop", start: false, mutate: func(d *topologyFixture, _ *gatewayFixture) { d.stopErrAt = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker, grants, server := makeReady()
			if !test.start {
				if err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest); err != nil {
					t.Fatal(err)
				}
				docker.startCalls, docker.stopCalls = 0, 0
			}
			test.mutate(docker, grants)
			if err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, test.start, testGatewayRoutePolicyDigest); err == nil {
				t.Fatal("expected transition failure")
			}
		})
	}
	t.Run("ambiguous activation containment never widens on deactivation failure", func(t *testing.T) {
		docker, grants, server := makeReady()
		grants.activateErr, grants.activateApplies, grants.deactivateErr = errors.New("response lost"), true, errors.New("gateway unavailable")
		err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
		var failed *runtimeFailedStart
		if !errors.As(err, &failed) || failed.contained {
			t.Fatal("ambiguous activation accepted")
		}
		grant := grants.grants[workload.Runtime.GrantID]
		if !grant.Active || !stoppedStatus(docker.agent.Status) || !stoppedStatus(docker.relay.Status) {
			t.Fatalf("failed start widened during containment: grant=%#v agent=%s relay=%s", grant, docker.agent.Status, docker.relay.Status)
		}
	})
	t.Run("cleanup failures", func(t *testing.T) {
		docker, grants, server := makeReady()
		docker.removeRelayNoop = true
		if server.removeRuntimeTopology(context.Background(), workload) {
			t.Fatal("retained relay accepted")
		}
		docker.removeRelayNoop, docker.relay = false, nil
		grants.unregisterErr = errors.New("delete")
		if server.removeRuntimeTopology(context.Background(), workload) {
			t.Fatal("grant delete failure accepted")
		}
	})
}

func TestAuthorityWideningPrimitiveRejectsTopologyDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*topologyFixture, *gatewayFixture, Workload)
		want   runtimeTopologyComponent
	}{
		{name: "network", want: runtimeTopologyNetwork, mutate: func(d *topologyFixture, _ *gatewayFixture, _ Workload) {
			d.network.Internal = false
		}},
		{name: "relay", want: runtimeTopologyRelay, mutate: func(d *topologyFixture, _ *gatewayFixture, _ Workload) {
			d.relay.Hardened = false
		}},
		{name: "Gateway grant", want: runtimeTopologyGateway, mutate: func(_ *topologyFixture, g *gatewayFixture, workload Workload) {
			grant := g.grants[workload.Runtime.GrantID]
			grant.TenantID = "other-tenant"
			g.grants[workload.Runtime.GrantID] = grant
		}},
		{name: "active Gateway grant", want: runtimeTopologyGateway, mutate: func(_ *topologyFixture, g *gatewayFixture, workload Workload) {
			grant := g.grants[workload.Runtime.GrantID]
			grant.Active = true
			g.grants[workload.Runtime.GrantID] = grant
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			workload, docker, grants, server := readyRuntimeTopology(t)
			test.mutate(docker, grants, workload)
			err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
			var failure *runtimeTopologyFailure
			var phase *runtimeStartProofFailure
			if !errors.As(err, &failure) || failure.unavailable || failure.component != test.want ||
				!errors.As(err, &phase) {
				t.Fatalf("transition error=%v failure=%#v", err, failure)
			}
			if docker.startCalls != 0 {
				t.Fatalf("drifted topology received %d start mutations", docker.startCalls)
			}
		})
	}
}

func TestFailedStartResponseLossIsMonotonicallyContained(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*topologyFixture, *gatewayFixture)
	}{
		{name: "relay start applied", mutate: func(d *topologyFixture, _ *gatewayFixture) {
			d.startErrAt, d.startAppliesOnErr = 1, true
		}},
		{name: "Gateway register applied", mutate: func(_ *topologyFixture, g *gatewayFixture) {
			g.registerErr, g.registerApplies = errors.New("register response lost"), true
		}},
		{name: "agent start applied", mutate: func(d *topologyFixture, _ *gatewayFixture) {
			d.startErrAt, d.startAppliesOnErr = 2, true
		}},
		{name: "Gateway activation applied", mutate: func(_ *topologyFixture, g *gatewayFixture) {
			g.activateErr, g.activateApplies = errors.New("activation response lost"), true
		}},
		{name: "containment stop applied", mutate: func(d *topologyFixture, _ *gatewayFixture) {
			d.startErrAt, d.startAppliesOnErr = 2, true
			d.stopErrAt, d.stopAppliesOnErr = 1, true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			workload, docker, grants, server := readyRuntimeTopology(t)
			test.mutate(docker, grants)
			err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
			var failed *runtimeFailedStart
			if !errors.As(err, &failed) || !failed.contained {
				t.Fatalf("failed start=%v state=%#v", err, failed)
			}
			grant := grants.grants[workload.Runtime.GrantID]
			if grant.Active || !stoppedStatus(docker.agent.Status) || !stoppedStatus(docker.relay.Status) {
				t.Fatalf("grant=%#v agent=%q relay=%q", grant, docker.agent.Status, docker.relay.Status)
			}
		})
	}
}

func TestFailedStartContainmentFailureNeverWidensAuthority(t *testing.T) {
	workload, docker, grants, server := readyRuntimeTopology(t)
	docker.startErrAt, docker.startAppliesOnErr = 2, true
	docker.stopErrAt = 1
	err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
	var failed *runtimeFailedStart
	if !errors.As(err, &failed) || failed.contained {
		t.Fatalf("failed start=%v state=%#v", err, failed)
	}
	grant := grants.grants[workload.Runtime.GrantID]
	if grant.Active || docker.agent.Status != "running" || !stoppedStatus(docker.relay.Status) {
		t.Fatalf("containment grant=%#v agent=%q relay=%q", grant, docker.agent.Status, docker.relay.Status)
	}
	if docker.startCalls != 2 {
		t.Fatalf("containment issued a widening start; calls=%d", docker.startCalls)
	}
}

func TestRestoreCannotBypassRuntimeTopologyProof(t *testing.T) {
	workload, docker, _, server := readyRuntimeTopology(t)
	docker.network.Internal = false
	if server.restoreRuntimeLifecycle(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest) {
		t.Fatal("restore widened authority on a drifted network")
	}
	if docker.startCalls != 0 {
		t.Fatalf("restore issued %d start mutations", docker.startCalls)
	}
}

func TestStartedTopologyPostconditionContainsNetworkDrift(t *testing.T) {
	workload, docker, grants, server := readyRuntimeTopology(t)
	docker.onStart = func(name string) {
		if !strings.HasPrefix(name, "steward-relay-") {
			docker.network.Internal = false
		}
	}
	err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
	var failure *runtimeTopologyFailure
	var failed *runtimeFailedStart
	if !errors.As(err, &failure) || failure.component != runtimeTopologyNetwork || failure.unavailable ||
		!errors.As(err, &failed) || !failed.contained || !failed.topologyReconciliation {
		t.Fatalf("postcondition error=%v failure=%#v", err, failure)
	}
	grant := grants.grants[workload.Runtime.GrantID]
	if grant.Active || !stoppedStatus(docker.agent.Status) || !stoppedStatus(docker.relay.Status) {
		t.Fatalf("postcondition rollback grant=%#v agent=%q relay=%q", grant, docker.agent.Status, docker.relay.Status)
	}
}

func TestTopologyProofPreservesInspectionUnavailable(t *testing.T) {
	workload, docker, _, server := readyRuntimeTopology(t)
	docker.inspectNetworkErr = errors.New("Docker socket timeout")
	err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true, testGatewayRoutePolicyDigest)
	var failure *runtimeTopologyFailure
	if !errors.As(err, &failure) || !failure.unavailable || failure.component != runtimeTopologyNetwork ||
		!strings.Contains(err.Error(), "Docker socket timeout") {
		t.Fatalf("inspection error=%v failure=%#v", err, failure)
	}
	if docker.startCalls != 0 {
		t.Fatalf("unavailable inspection received %d start mutations", docker.startCalls)
	}
}

func readyRuntimeTopology(t *testing.T) (Workload, *topologyFixture, *gatewayFixture, *Server) {
	t.Helper()
	workload := runtimeTopologyWorkload()
	docker := &topologyFixture{agent: ObservedWorkload{
		Workload: workload, Fingerprint: workloadFingerprint(workload), Managed: true, Hardened: true, Status: "created",
	}}
	grants := &gatewayFixture{grants: map[string]gateway.Grant{}}
	server := runtimeTopologyServer(docker, grants)
	if err := server.prepareRuntimeTopology(context.Background(), workload); err != nil {
		t.Fatal(err)
	}
	if err := server.completeRuntimeTopology(context.Background(), workload); err != nil {
		t.Fatal(err)
	}
	return workload, docker, grants, server
}

func runtimeTopologyWorkload() Workload {
	addresses := testNetworkSpec("tenant-a", "agent-a", 2)
	return Workload{TenantID: "tenant-a", InstanceID: "agent-a", ProfileID: "generic-v1@v1", Runtime: &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: gateway.GrantID("tenant-a", "agent-a", 2), Generation: 2,
		Inference: true, RouteID: "local-openai", ModelAlias: "model", ServicePort: 8080,
		Subnet: addresses.Subnet, Gateway: addresses.Gateway,
		RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
	}}
}

func runtimeTopologyServer(docker *topologyFixture, grants *gatewayFixture) *Server {
	return &Server{docker: docker, secure: &secureAdmission{
		topology: docker, gateway: grants, relayImage: "sha256:" + strings.Repeat("a", 64),
		grantRoot: "/run/steward-gateway/grants", relayGID: 1234,
	}}
}
