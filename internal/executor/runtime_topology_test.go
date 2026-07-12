package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

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
	startCalls        int
	stopCalls         int
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
	if f.startErrAt == f.startCalls {
		return errors.New("start failure")
	}
	if strings.HasPrefix(name, "steward-relay-") {
		f.relay.Status, f.relay.IPAddress = "running", f.relay.Spec.RelayIP
	} else {
		f.agent.Status = "running"
	}
	return nil
}
func (f *topologyFixture) Stop(_ context.Context, name string) error {
	f.stopCalls++
	if f.stopErrAt == f.stopCalls {
		return errors.New("stop failure")
	}
	if strings.HasPrefix(name, "steward-relay-") {
		f.relay.Status, f.relay.IPAddress = "exited", ""
	} else {
		f.agent.Status = "exited"
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
	f.network = &ObservedNetwork{NetworkSpec: spec, Managed: true, Internal: true}
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
	inspectErr      error
	activateErr     error
	activateApplies bool
	deactivateErr   error
	unregisterErr   error
}

func (f *gatewayFixture) Register(_ context.Context, grant gateway.Grant) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	if current, ok := f.grants[grant.GrantID]; ok && current.Active {
		return errors.New("active")
	}
	f.grants[grant.GrantID] = grant
	return nil
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

func TestRuntimeTopologyHappyPathAndLifecycle(t *testing.T) {
	addresses := NetworkSpecFor("tenant-a", "agent-a", 2)
	workload := Workload{
		TenantID: "tenant-a", InstanceID: "agent-a", ProfileID: "generic-v1@v1",
		Runtime: &RuntimeGrant{
			NetworkName: addresses.Name, GrantID: gateway.GrantID("tenant-a", "agent-a", 2), Generation: 2,
			Inference: true, RouteID: "local-openai", ModelAlias: "model", ServicePort: 8080,
			RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
		},
	}
	docker := &topologyFixture{agent: ObservedWorkload{Workload: workload, Managed: true, Hardened: true, Status: "created"}}
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
	if err := server.applyRuntimeTransition(ctx, "executor-agent", workload, true); err != nil {
		t.Fatal(err)
	}
	if !server.runtimeLifecycleMatches(ctx, workload, true) || !server.runtimeTopologyMatches(ctx, workload, true) {
		t.Fatal("running topology mismatch")
	}
	if got := relayServiceURL(*docker.relay); got != "http://"+addresses.RelayIP+":8081" {
		t.Fatalf("service URL=%q", got)
	}
	if !server.restoreRuntimeLifecycle(ctx, "executor-agent", workload, false) {
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
		docker := &topologyFixture{agent: ObservedWorkload{Workload: workload, Managed: true, Hardened: true, Status: "created"}}
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
		{name: "missing relay address", start: true, mutate: func(d *topologyFixture, _ *gatewayFixture) { d.relay.Spec.RelayIP = "" }},
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
				if err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true); err != nil {
					t.Fatal(err)
				}
				docker.startCalls, docker.stopCalls = 0, 0
			}
			test.mutate(docker, grants)
			if err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, test.start); err == nil {
				t.Fatal("expected transition failure")
			}
		})
	}
	t.Run("ambiguous activation never points at stopped backends", func(t *testing.T) {
		docker, grants, server := makeReady()
		grants.activateErr, grants.activateApplies, grants.deactivateErr = errors.New("response lost"), true, errors.New("gateway unavailable")
		if err := server.applyRuntimeTransition(context.Background(), "executor-agent", workload, true); err == nil {
			t.Fatal("ambiguous activation accepted")
		}
		grant := grants.grants[workload.Runtime.GrantID]
		if !grant.Active || docker.agent.Status != "running" || docker.relay.Status != "running" {
			t.Fatalf("active grant points at stopped backend: grant=%#v agent=%s relay=%s", grant, docker.agent.Status, docker.relay.Status)
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

func runtimeTopologyWorkload() Workload {
	addresses := NetworkSpecFor("tenant-a", "agent-a", 2)
	return Workload{TenantID: "tenant-a", InstanceID: "agent-a", ProfileID: "generic-v1@v1", Runtime: &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: gateway.GrantID("tenant-a", "agent-a", 2), Generation: 2,
		Inference: true, RouteID: "local-openai", ModelAlias: "model", ServicePort: 8080,
		RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
	}}
}

func runtimeTopologyServer(docker *topologyFixture, grants *gatewayFixture) *Server {
	return &Server{docker: docker, secure: &secureAdmission{
		topology: docker, gateway: grants, relayImage: "sha256:" + strings.Repeat("a", 64),
		grantRoot: "/run/steward-gateway/grants", relayGID: 1234,
	}}
}
