package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
)

type reconcileRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *reconcileRecorder) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *reconcileRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type reconcileDocker struct {
	mu               sync.Mutex
	agent            ObservedWorkload
	network          ObservedNetwork
	relay            ObservedRelay
	volume           *ObservedStateVolume
	recorder         *reconcileRecorder
	networkErr       error
	networkInspects  int
	onNetworkInspect func(int, *reconcileDocker)
}

func (d *reconcileDocker) RuntimeAvailable(context.Context, string) (bool, error) {
	return true, nil
}

func (d *reconcileDocker) WorkloadCounts(context.Context, string) (int, int, error) {
	return 1, 1, nil
}

func (d *reconcileDocker) Inspect(_ context.Context, name string) (ObservedWorkload, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name != RuntimeRef(d.agent.Workload.TenantID, d.agent.Workload.InstanceID) {
		return ObservedWorkload{}, ErrNotFound
	}
	return d.agent, nil
}

func (d *reconcileDocker) Create(context.Context, string, Workload) error {
	return errors.New("unexpected create")
}

func (d *reconcileDocker) Start(_ context.Context, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name != d.relay.Spec.Name {
		return errors.New("reconciler must not start the observed agent")
	}
	d.recorder.add("start_relay")
	d.relay.Status = "running"
	d.relay.IPAddress = d.relay.Spec.RelayIP
	return nil
}

func (d *reconcileDocker) Stop(_ context.Context, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch name {
	case d.relay.Spec.Name:
		d.recorder.add("stop_relay")
		d.relay.Status = "exited"
		d.relay.IPAddress = ""
	case RuntimeRef(d.agent.Workload.TenantID, d.agent.Workload.InstanceID):
		d.recorder.add("stop_agent")
		d.agent.Status = "exited"
	default:
		return errors.New("unexpected stop target")
	}
	return nil
}

func (d *reconcileDocker) Remove(context.Context, string) error {
	return errors.New("unexpected remove")
}

func (d *reconcileDocker) Logs(context.Context, string) (string, error) { return "", nil }

func (d *reconcileDocker) InspectNetwork(context.Context, string) (ObservedNetwork, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.networkInspects++
	if d.onNetworkInspect != nil {
		d.onNetworkInspect(d.networkInspects, d)
	}
	if d.networkErr != nil {
		return ObservedNetwork{}, d.networkErr
	}
	return d.network, nil
}

func (d *reconcileDocker) CreateNetwork(context.Context, NetworkSpec) error {
	return errors.New("unexpected network create")
}

func (d *reconcileDocker) RemoveNetwork(context.Context, string) error {
	return errors.New("unexpected network remove")
}

func (d *reconcileDocker) CreateRelay(context.Context, RelaySpec) error {
	return errors.New("unexpected relay create")
}

func (d *reconcileDocker) InspectRelay(context.Context, string) (ObservedRelay, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.relay, nil
}

func (d *reconcileDocker) InspectStateVolume(context.Context, string) (ObservedStateVolume, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.volume == nil {
		return ObservedStateVolume{}, ErrNotFound
	}
	return *d.volume, nil
}

func (d *reconcileDocker) CreateStateVolume(context.Context, StateVolumeSpec) error {
	return errors.New("unexpected state create")
}

func (d *reconcileDocker) RemoveStateVolume(context.Context, string) error {
	return errors.New("unexpected state remove")
}

func (d *reconcileDocker) setRelayStatus(status string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.relay.Status = status
	if status == "running" {
		d.relay.IPAddress = d.relay.Spec.RelayIP
	} else {
		d.relay.IPAddress = ""
	}
}

func (d *reconcileDocker) setHardened(hardened bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.agent.Hardened = hardened
}

func (d *reconcileDocker) removeStateVolume() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.volume = nil
}

func (d *reconcileDocker) driftNetwork() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.network.Internal = false
}

func (d *reconcileDocker) driftRelay() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.relay.Hardened = false
}

func (d *reconcileDocker) states() (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.agent.Status, d.relay.Status
}

type reconcileGateway struct {
	mu              sync.Mutex
	grants          map[string]gateway.Grant
	inspectErr      error
	activateErr     error
	activateApplies bool
	deactivateErr   error
	policyDigest    string
	recorder        *reconcileRecorder
}

func (g *reconcileGateway) Register(_ context.Context, grant gateway.Grant) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if current, ok := g.grants[grant.GrantID]; ok && current.Active {
		return errors.New("active grant cannot be replaced")
	}
	g.recorder.add("register_grant")
	grant.Active = false
	g.grants[grant.GrantID] = grant
	return nil
}

func (g *reconcileGateway) Inspect(_ context.Context, id string) (gateway.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inspectErr != nil {
		return gateway.Grant{}, g.inspectErr
	}
	grant, ok := g.grants[id]
	if !ok {
		return gateway.Grant{}, errors.New("gateway grant_not_found: gateway grant not found")
	}
	return grant, nil
}
func (g *reconcileGateway) InspectWithPolicy(ctx context.Context, id string) (gateway.GrantInspection, error) {
	grant, err := g.Inspect(ctx, id)
	if err != nil {
		return gateway.GrantInspection{}, err
	}
	g.mu.Lock()
	digest := g.policyDigest
	g.mu.Unlock()
	return gateway.GrantInspection{Grant: grant, RoutePolicyDigest: digest}, nil
}

func (g *reconcileGateway) Activate(_ context.Context, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recorder.add("activate_grant")
	if g.activateErr == nil || g.activateApplies {
		grant := g.grants[id]
		grant.Active = true
		g.grants[id] = grant
	}
	return g.activateErr
}

func (g *reconcileGateway) Deactivate(_ context.Context, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recorder.add("deactivate_grant")
	if g.deactivateErr != nil {
		return g.deactivateErr
	}
	grant := g.grants[id]
	grant.Active = false
	g.grants[id] = grant
	return nil
}

func (g *reconcileGateway) Unregister(_ context.Context, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, id)
	return nil
}

func (g *reconcileGateway) EgressStats(context.Context, string) (gateway.EgressStats, error) {
	return gateway.EgressStats{}, nil
}

func (g *reconcileGateway) remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.grants, id)
}

func (g *reconcileGateway) grant(id string) (gateway.Grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	grant, ok := g.grants[id]
	return grant, ok
}

func (g *reconcileGateway) setPolicyDigest(digest string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policyDigest = digest
}

type reconcileRig struct {
	server   *Server
	docker   *reconcileDocker
	gateway  *reconcileGateway
	recorder *reconcileRecorder
	config   SecureAdmissionConfig
	record   admission.FenceRecord
}

func newReconcileRig(t *testing.T, policyCurrent bool) *reconcileRig {
	return newReconcileRigWithRoutePolicy(t, policyCurrent, "sha256:"+strings.Repeat("e", 64))
}

func newReconcileRigWithRoutePolicy(t *testing.T, policyCurrent bool, routePolicyDigest string, namedConnector ...bool) *reconcileRig {
	t.Helper()
	connectorRuntime := len(namedConnector) != 0 && namedConnector[0]
	var intent admission.InstanceIntent
	var config SecureAdmissionConfig
	if connectorRuntime {
		_, intent, config = secureAdmissionFixtureFor(t, admission.Capabilities{Connector: true})
	} else {
		_, intent, config = secureAdmissionFixture(t)
	}
	recorder := &reconcileRecorder{}
	docker := &reconcileDocker{recorder: recorder}
	control := &reconcileGateway{
		grants: make(map[string]gateway.Grant), policyDigest: "sha256:" + strings.Repeat("e", 64), recorder: recorder,
	}
	config.Topology = docker
	config.Gateway = control
	config.RelayImage = "sha256:" + strings.Repeat("d", 64)
	config.GrantRoot = "/run/steward-gateway/grants"
	config.RelayGID = 65531
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}

	network := testNetworkSpec(intent.TenantID, intent.InstanceID, intent.Generation)
	runtime := &RuntimeGrant{
		NetworkName: network.Name, GrantID: gateway.GrantID(intent.TenantID, intent.InstanceID, intent.Generation),
		Generation: intent.Generation,
		Subnet:     network.Subnet, Gateway: network.Gateway,
		RelayIP: network.RelayIP, AgentIP: network.AgentIP,
	}
	if connectorRuntime {
		runtime.ConnectorIDs = admission.CanonicalConnectorIDs(intent.ConnectorIDs)
		runtime.CapsuleDigest = intent.CapsuleDigest
	} else {
		runtime.Inference, runtime.RouteID, runtime.ModelAlias = true, "local", "private-model"
	}
	policyDigest := dsse.Digest(config.PolicyEnvelope)
	if !policyCurrent {
		policyDigest = "sha256:" + strings.Repeat("c", 64)
	}
	if connectorRuntime {
		runtime.PolicyDigest = policyDigest
	}
	workload := Workload{
		InstanceID: intent.InstanceID, TenantID: intent.TenantID, ProfileID: "generic-v1@v1",
		Image:             "registry.local/agent@sha256:" + strings.Repeat("a", 64),
		ImageConfigDigest: "sha256:" + strings.Repeat("b", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		State:     &StateMount{VolumeName: StateVolumeName(intent.TenantID, intent.LineageID), Path: "/home/steward"}, Runtime: runtime,
	}
	docker.agent = ObservedWorkload{
		Workload: workload, ImageID: workload.ImageConfigDigest, Fingerprint: workloadFingerprint(workload),
		Managed: true, Hardened: true, Status: "running",
	}
	docker.network = ObservedNetwork{NetworkSpec: network, Managed: true, Internal: true}
	docker.volume = &ObservedStateVolume{StateVolumeSpec: StateVolumeSpec{
		Name: workload.State.VolumeName, TenantID: intent.TenantID, LineageID: intent.LineageID,
	}, Managed: true}
	relay := server.desiredRelay(workload)
	docker.relay = ObservedRelay{
		Spec: relay, Fingerprint: relayFingerprint(relay), Managed: true, Hardened: true,
		Status: "running", IPAddress: relay.RelayIP,
	}
	wantGrant := server.desiredGatewayGrant(workload, "")
	wantGrant.Active = true
	control.grants[wantGrant.GrantID] = wantGrant
	record := admission.FenceRecord{
		TenantID: intent.TenantID, InstanceID: intent.InstanceID, Generation: intent.Generation,
		CapsuleDigest: intent.CapsuleDigest, PolicyDigest: policyDigest, LineageID: intent.LineageID,
		WorkloadDigest: "sha256:" + workloadFingerprint(workload), ImageConfigDigest: workload.ImageConfigDigest,
		RoutePolicyDigest: routePolicyDigest, Present: true,
	}
	if err := config.Fences.Commit(record, 1); err != nil {
		t.Fatal(err)
	}
	return &reconcileRig{server: server, docker: docker, gateway: control, recorder: recorder, config: config, record: record}
}

func TestReconcileCleanRuntimeIsReceiptFreeNoop(t *testing.T) {
	rig := newReconcileRig(t, true)
	before := rig.config.Evidence.NextSequence()
	report, err := rig.server.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if !report.Ready || report.Checked != 1 || report.Changed != 0 || report.Revoked != 0 || len(report.Failures) != 0 {
		t.Fatalf("report = %#v", report)
	}
	if got := rig.config.Evidence.NextSequence(); got != before {
		t.Fatalf("evidence next sequence = %d, want unchanged %d", got, before)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("pending journal = %#v", pending)
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("mutations = %#v", events)
	}
}

func TestReconcileCleanConnectorRuntimeProvesSignedGatewayGrant(t *testing.T) {
	rig := newReconcileRigWithRoutePolicy(t, true, "sha256:"+strings.Repeat("e", 64), true)
	report, err := rig.server.Reconcile(context.Background())
	if err != nil || !report.Ready || report.Changed != 0 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	grant, ok := rig.gateway.grant(rig.recordGrantID())
	if !ok || grant.RuntimeRef != RuntimeRef(rig.record.TenantID, rig.record.InstanceID) ||
		grant.CapsuleDigest != rig.record.CapsuleDigest || grant.PolicyDigest != rig.record.PolicyDigest ||
		len(grant.ConnectorIDs) != 2 || !rig.docker.relay.Spec.Connector {
		t.Fatalf("grant=%#v relay=%#v", grant, rig.docker.relay)
	}
}

func TestReconcileContainsConnectorGrantBindingDrift(t *testing.T) {
	rig := newReconcileRigWithRoutePolicy(t, true, "sha256:"+strings.Repeat("e", 64), true)
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	grant.PolicyDigest = "sha256:" + strings.Repeat("f", 64)
	rig.gateway.mu.Lock()
	rig.gateway.grants[grant.GrantID] = grant
	rig.gateway.mu.Unlock()

	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 ||
		len(report.Failures) != 1 || report.Failures[0].Code != "gateway_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment mutations=%q", events)
	}
}

func TestSignedStartContainsLiveNetworkDriftAndDegradesReadiness(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.network.Internal = false
	before := rig.config.Evidence.NextSequence()

	response := degradedLifecycleRequest(rig, http.MethodPost,
		"/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start",
		rig.record.TenantID)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"reconciliation_required"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := rig.config.Evidence.NextSequence(); got != before {
		t.Fatalf("evidence next sequence = %d, want %d", got, before)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("pending journal = %#v", pending)
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment mutations=%q", events)
	}
	agent, relay := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if !stoppedStatus(agent) || !stoppedStatus(relay) || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
	rig.server.reconcileMu.RLock()
	attempted, report := rig.server.reconcileAttempted, cloneReconcileReport(rig.server.reconcileReport)
	rig.server.reconcileMu.RUnlock()
	if !attempted || report.Ready || len(report.Failures) != 1 || report.Failures[0].Code != "runtime_drift" {
		t.Fatalf("degraded report=%#v attempted=%t", report, attempted)
	}
}

func TestSignedStartRejectsStoppedNetworkDriftWithoutMutation(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.agent.Status = "exited"
	rig.docker.relay.Status = "exited"
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	grant.Active = false
	rig.gateway.grants[rig.recordGrantID()] = grant
	rig.docker.network.Internal = false
	before := rig.config.Evidence.NextSequence()

	response := degradedLifecycleRequest(rig, http.MethodPost,
		"/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start",
		rig.record.TenantID)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"runtime_drift"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := rig.config.Evidence.NextSequence(); got != before || len(rig.config.Journal.Pending()) != 0 {
		t.Fatalf("evidence sequence=%d want=%d pending=%#v", got, before, rig.config.Journal.Pending())
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("mutations=%#v", events)
	}
}

func TestSignedStartReportsStoppedNetworkInspectionUnavailable(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.agent.Status = "exited"
	rig.docker.relay.Status = "exited"
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	grant.Active = false
	rig.gateway.grants[rig.recordGrantID()] = grant
	rig.docker.networkErr = errors.New("Docker network inspect timeout")
	before := rig.config.Evidence.NextSequence()

	response := degradedLifecycleRequest(rig, http.MethodPost,
		"/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start",
		rig.record.TenantID)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), `"error":"docker_error"`) ||
		!strings.Contains(response.Body.String(), "Docker network inspect timeout") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := rig.config.Evidence.NextSequence(); got != before || len(rig.config.Journal.Pending()) != 0 {
		t.Fatalf("evidence sequence=%d want=%d pending=%#v", got, before, rig.config.Journal.Pending())
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("mutations=%#v", events)
	}
}

func TestSignedStartCompensatesLatePreconditionDriftWithoutHostRollback(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.agent.Status = "exited"
	rig.docker.relay.Status = "exited"
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	grant.Active = false
	rig.gateway.grants[rig.recordGrantID()] = grant
	rig.docker.onNetworkInspect = func(call int, docker *reconcileDocker) {
		if call == 2 {
			docker.network.Internal = false
		}
	}

	response := degradedLifecycleRequest(rig, http.MethodPost,
		"/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start",
		rig.record.TenantID)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"error":"runtime_drift"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("late precondition left journal pending=%#v", pending)
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("precondition failure invoked host rollback=%#v", events)
	}
	agent, relay := rig.docker.states()
	grant, _ = rig.gateway.grant(rig.recordGrantID())
	if !stoppedStatus(agent) || !stoppedStatus(relay) || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
}

func TestSignedStartReturns503WhenLiveDriftContainmentIsUnprovable(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.network.Internal = false
	rig.docker.relay.Managed = false
	before := rig.config.Evidence.NextSequence()

	response := degradedLifecycleRequest(rig, http.MethodPost,
		"/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start",
		rig.record.TenantID)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "could not be verified") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := rig.config.Evidence.NextSequence(); got != before || len(rig.config.Journal.Pending()) != 0 {
		t.Fatalf("evidence sequence=%d want=%d pending=%#v", got, before, rig.config.Journal.Pending())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent" {
		t.Fatalf("containment mutations=%q", events)
	}
	agent, relay := rig.docker.states()
	if !stoppedStatus(agent) || stoppedStatus(relay) {
		t.Fatalf("agent=%q relay=%q", agent, relay)
	}
}

func TestReconcileContainsRoutePolicyDigestMismatch(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.gateway.setPolicyDigest("sha256:" + strings.Repeat("f", 64))
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || len(report.Failures) != 1 || report.Failures[0].Code != "gateway_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment mutations=%q", events)
	}
	agent, _ := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if agent != "exited" || grant.Active {
		t.Fatalf("agent=%q grant=%#v", agent, grant)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("pending journal=%#v", pending)
	}
}

func TestReconcileContainsLegacyFenceWithoutRoutePolicyBinding(t *testing.T) {
	rig := newReconcileRigWithRoutePolicy(t, true, "")
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || len(report.Failures) != 1 || report.Failures[0].Code != "gateway_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("legacy containment mutations=%q", events)
	}
}

func TestReconcileContainsConnectorFenceWithoutRoutePolicyBinding(t *testing.T) {
	rig := newReconcileRigWithRoutePolicy(t, true, "", true)
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 ||
		len(report.Failures) != 1 || report.Failures[0].Code != "gateway_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestReconcileContainsEveryAmbiguousDockerLifecycleState(t *testing.T) {
	for _, status := range []string{"paused", "restarting", "removing", "dead", "unknown"} {
		t.Run("agent "+status, func(t *testing.T) {
			rig := newReconcileRig(t, true)
			rig.docker.agent.Status = status
			report, err := rig.server.Reconcile(context.Background())
			if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 ||
				len(report.Failures) != 1 || report.Failures[0].Code != "workload_state_ambiguous" {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			agent, relay := rig.docker.states()
			if !stoppedStatus(agent) || !stoppedStatus(relay) || len(rig.config.Journal.Pending()) != 0 {
				t.Fatalf("agent=%q relay=%q pending=%#v", agent, relay, rig.config.Journal.Pending())
			}
		})
	}

	for _, status := range []string{"paused", "restarting", "removing", "dead", "unknown"} {
		t.Run("relay "+status, func(t *testing.T) {
			rig := newReconcileRig(t, true)
			rig.docker.setRelayStatus(status)
			report, err := rig.server.Reconcile(context.Background())
			if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 ||
				len(report.Failures) != 1 || report.Failures[0].Code != "relay_state_ambiguous" {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			agent, relay := rig.docker.states()
			if !stoppedStatus(agent) || !stoppedStatus(relay) || len(rig.config.Journal.Pending()) != 0 {
				t.Fatalf("agent=%q relay=%q pending=%#v", agent, relay, rig.config.Journal.Pending())
			}
		})
	}
}

func TestReconcileStopConfirmationHandlesLostResponseAndNoop(t *testing.T) {
	t.Run("lost response is settled by exact reinspection", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.agent.Status = "paused"
		docker := &reconciliationFailureDocker{
			reconcileDocker: rig.docker, stopErr: errors.New("response lost"), stopAppliesOnErr: true,
		}
		rig.server.docker, rig.server.secure.topology = docker, docker
		report, err := rig.server.Reconcile(context.Background())
		if !errors.Is(err, ErrReconciliationIncomplete) || report.Changed != 1 ||
			len(report.Failures) != 1 || report.Failures[0].Code != "workload_state_ambiguous" ||
			len(rig.config.Journal.Pending()) != 0 {
			t.Fatalf("report=%#v err=%v pending=%#v", report, err, rig.config.Journal.Pending())
		}
		agent, _ := rig.docker.states()
		if !stoppedStatus(agent) {
			t.Fatalf("agent status=%q", agent)
		}
	})

	t.Run("lost relay response is settled by exact reinspection", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.setRelayStatus("paused")
		docker := &reconciliationFailureDocker{
			reconcileDocker: rig.docker, stopErr: errors.New("response lost"), stopAppliesOnErr: true,
			stopTarget: rig.docker.relay.Spec.Name,
		}
		rig.server.docker, rig.server.secure.topology = docker, docker
		report, err := rig.server.Reconcile(context.Background())
		if !errors.Is(err, ErrReconciliationIncomplete) || report.Changed != 1 ||
			len(report.Failures) != 1 || report.Failures[0].Code != "relay_state_ambiguous" ||
			len(rig.config.Journal.Pending()) != 0 {
			t.Fatalf("report=%#v err=%v pending=%#v", report, err, rig.config.Journal.Pending())
		}
		agent, relay := rig.docker.states()
		if !stoppedStatus(agent) || !stoppedStatus(relay) {
			t.Fatalf("agent=%q relay=%q", agent, relay)
		}
	})

	t.Run("no-op stop leaves reconciliation degraded", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.agent.Status = "paused"
		docker := &reconciliationFailureDocker{reconcileDocker: rig.docker, stopNoop: true}
		rig.server.docker, rig.server.secure.topology = docker, docker
		report, err := rig.server.Reconcile(context.Background())
		if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 0 ||
			len(report.Failures) != 1 || report.Failures[0].Code != "containment_ambiguous" ||
			len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("report=%#v err=%v pending=%#v", report, err, rig.config.Journal.Pending())
		}
	})

	t.Run("no-op relay stop leaves reconciliation degraded", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.setRelayStatus("paused")
		docker := &reconciliationFailureDocker{
			reconcileDocker: rig.docker, stopNoop: true, stopTarget: rig.docker.relay.Spec.Name,
		}
		rig.server.docker, rig.server.secure.topology = docker, docker
		report, err := rig.server.Reconcile(context.Background())
		if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 0 ||
			len(report.Failures) != 1 || report.Failures[0].Code != "containment_ambiguous" ||
			len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("report=%#v err=%v pending=%#v", report, err, rig.config.Journal.Pending())
		}
		agent, relay := rig.docker.states()
		if !stoppedStatus(agent) || classifyDockerLifecycle(relay) != dockerLifecycleAmbiguous {
			t.Fatalf("agent=%q relay=%q", agent, relay)
		}
	})
}

func TestReadinessTracksLastBoundedReconciliation(t *testing.T) {
	rig := newReconcileRig(t, true)
	status, body := reconcileReadiness(t, rig.server)
	if status != http.StatusServiceUnavailable || body["status"] != "reconciling" {
		t.Fatalf("before status=%d body=%#v", status, body)
	}
	if _, err := rig.server.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, body = reconcileReadiness(t, rig.server)
	if status != http.StatusOK || body["status"] != "ready" || body["last_attempt"] == nil {
		t.Fatalf("ready status=%d body=%#v", status, body)
	}
	rig.docker.setHardened(false)
	if _, err := rig.server.Reconcile(context.Background()); !errors.Is(err, ErrReconciliationIncomplete) {
		t.Fatal(err)
	}
	status, body = reconcileReadiness(t, rig.server)
	if status != http.StatusServiceUnavailable || body["status"] != "degraded" {
		t.Fatalf("degraded status=%d body=%#v", status, body)
	}
}

func reconcileReadiness(t *testing.T, server *Server) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/readiness", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return response.Code, body
}

func TestReconcileRestoresLostGrantAndStoppedRelay(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.setRelayStatus("exited")
	rig.gateway.remove(rig.recordGrantID())

	report, err := rig.server.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.Changed != 1 {
		t.Fatalf("report = %#v", report)
	}
	grant, ok := rig.gateway.grant(rig.recordGrantID())
	if !ok || !grant.Active {
		t.Fatalf("restored grant = %#v, %t", grant, ok)
	}
	if events := rig.recorder.snapshot(); strings.Join(events, ",") != "start_relay,register_grant,activate_grant" {
		t.Fatalf("mutation order = %#v", events)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("pending journal = %#v", pending)
	}
	next := rig.config.Evidence.NextSequence()
	second, err := rig.server.Reconcile(context.Background())
	if err != nil || second.Changed != 0 || rig.config.Evidence.NextSequence() != next {
		t.Fatalf("second report=%#v err=%v next=%d", second, err, rig.config.Evidence.NextSequence())
	}
}

func TestReconcilePolicyRotationRevokesInSafeOrder(t *testing.T) {
	rig := newReconcileRig(t, false)
	report, err := rig.server.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.Changed != 1 || report.Revoked != 1 {
		t.Fatalf("report = %#v", report)
	}
	if events := rig.recorder.snapshot(); strings.Join(events, ",") != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("revocation order = %#v", events)
	}
	agent, relay := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if agent != "exited" || relay != "exited" || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
	next := rig.config.Evidence.NextSequence()
	second, err := rig.server.Reconcile(context.Background())
	if err != nil || second.Changed != 0 || second.Revoked != 1 || rig.config.Evidence.NextSequence() != next {
		t.Fatalf("second report=%#v err=%v next=%d", second, err, rig.config.Evidence.NextSequence())
	}
}

func TestReconcileContainsExactManagedWorkloadWithHardeningDrift(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.setHardened(false)
	before := rig.config.Evidence.NextSequence()

	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || report.Revoked != 0 ||
		len(report.Failures) != 1 || report.Failures[0].Code != "workload_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment order=%q", events)
	}
	agent, relay := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if !stoppedStatus(agent) || !stoppedStatus(relay) || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
	if rig.config.Evidence.NextSequence() != before+2 || len(rig.config.Journal.Pending()) != 0 {
		t.Fatal("hardening-drift containment must be journaled, receipted, and settled")
	}

	next := rig.config.Evidence.NextSequence()
	second, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || second.Ready || second.Changed != 0 ||
		len(second.Failures) != 1 || second.Failures[0].Code != "workload_drift" ||
		rig.config.Evidence.NextSequence() != next || len(rig.config.Journal.Pending()) != 0 {
		t.Fatalf("second report=%#v err=%v next=%d pending=%#v", second, err, rig.config.Evidence.NextSequence(), rig.config.Journal.Pending())
	}
}

func TestReconcileNeverOperatesUnmanagedOrIdentityMismatchedWorkload(t *testing.T) {
	tests := []struct {
		name     string
		wantCode string
		mutate   func(*reconcileRig)
	}{
		{name: "unmanaged", wantCode: "workload_drift", mutate: func(rig *reconcileRig) {
			rig.docker.agent.Managed = false
			rig.docker.agent.Hardened = false
		}},
		{name: "identity mismatch", wantCode: "workload_identity_drift", mutate: func(rig *reconcileRig) {
			rig.docker.agent.Hardened = false
			rig.docker.agent.Fingerprint = strings.Repeat("f", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newReconcileRig(t, true)
			test.mutate(rig)
			before := rig.config.Evidence.NextSequence()

			report, err := rig.server.Reconcile(context.Background())
			if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 0 ||
				len(report.Failures) != 1 || report.Failures[0].Code != test.wantCode {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			if events := rig.recorder.snapshot(); len(events) != 0 {
				t.Fatalf("mutations=%#v", events)
			}
			agent, relay := rig.docker.states()
			grant, _ := rig.gateway.grant(rig.recordGrantID())
			if agent != "running" || relay != "running" || !grant.Active {
				t.Fatalf("untrusted object was mutated: agent=%q relay=%q grant=%#v", agent, relay, grant)
			}
			if rig.config.Evidence.NextSequence() != before || len(rig.config.Journal.Pending()) != 0 {
				t.Fatal("untrusted object validation must not journal or receipt a mutation")
			}
		})
	}
}

func TestReconcileContainsButNeverRecreatesMissingStateVolume(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.removeStateVolume()
	before := rig.config.Evidence.NextSequence()
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || len(report.Failures) != 1 || report.Failures[0].Code != "state_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := rig.recorder.snapshot(); strings.Join(events, ",") != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment mutations = %#v", events)
	}
	agent, relay := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if agent != "exited" || relay != "exited" || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
	if rig.config.Evidence.NextSequence() != before+2 || len(rig.config.Journal.Pending()) != 0 {
		t.Fatal("state containment must be journaled and receipted without recreating the volume")
	}
	next := rig.config.Evidence.NextSequence()
	second, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || second.Changed != 0 || rig.config.Evidence.NextSequence() != next {
		t.Fatalf("second report=%#v err=%v next=%d", second, err, rig.config.Evidence.NextSequence())
	}
}

func TestReconcileContainsButNeverRecreatesDriftedTopology(t *testing.T) {
	tests := []struct {
		name  string
		code  string
		drift func(*reconcileDocker)
	}{
		{name: "network", code: "network_drift", drift: (*reconcileDocker).driftNetwork},
		{name: "relay", code: "relay_drift", drift: (*reconcileDocker).driftRelay},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newReconcileRig(t, true)
			test.drift(rig.docker)
			before := rig.config.Evidence.NextSequence()
			report, err := rig.server.Reconcile(context.Background())
			if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || len(report.Failures) != 1 || report.Failures[0].Code != test.code {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			if events := rig.recorder.snapshot(); strings.Join(events, ",") != "deactivate_grant,stop_agent,stop_relay" {
				t.Fatalf("containment mutations = %#v", events)
			}
			agent, relay := rig.docker.states()
			grant, _ := rig.gateway.grant(rig.recordGrantID())
			if agent != "exited" || relay != "exited" || grant.Active {
				t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
			}
			if rig.config.Evidence.NextSequence() != before+2 || len(rig.config.Journal.Pending()) != 0 {
				t.Fatal("topology containment must be journaled and receipted without adopting drift")
			}
		})
	}
}

func TestReconcileContainsIsolationDriftEvenWhenPolicyIsRevoked(t *testing.T) {
	rig := newReconcileRig(t, false)
	rig.docker.driftNetwork()
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 1 || report.Revoked != 1 ||
		len(report.Failures) != 1 || report.Failures[0].Code != "network_drift" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := rig.recorder.snapshot(); strings.Join(events, ",") != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("revoked containment order = %#v", events)
	}
	agent, _ := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if agent != "exited" || grant.Active {
		t.Fatalf("agent=%q grant=%#v", agent, grant)
	}
}

func TestReconcileAmbiguousMutationLeavesJournalPending(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.setRelayStatus("exited")
	rig.gateway.remove(rig.recordGrantID())
	rig.gateway.activateErr = errors.New("lost activation response")
	rig.gateway.activateApplies = true

	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Changed != 0 || len(report.Failures) != 1 || report.Failures[0].Code != "repair_ambiguous" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 1 {
		t.Fatalf("pending journal = %#v", pending)
	}
	second, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || len(second.Failures) != 1 || second.Failures[0].Code != "journal_pending" {
		t.Fatalf("second report=%#v err=%v", second, err)
	}
}

func TestReconcileRevocationStopsLocalRuntimeWhenGatewayIsUnavailable(t *testing.T) {
	rig := newReconcileRig(t, false)
	rig.gateway.inspectErr = errors.New("gateway connection refused")
	rig.gateway.deactivateErr = errors.New("gateway connection refused")

	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || len(report.Failures) != 1 || report.Failures[0].Code != "revocation_ambiguous" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := rig.recorder.snapshot(); strings.Join(events, ",") != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("best-effort revocation order = %#v", events)
	}
	agent, relay := rig.docker.states()
	if agent != "exited" || relay != "exited" {
		t.Fatalf("agent=%q relay=%q", agent, relay)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 1 {
		t.Fatalf("pending journal = %#v", pending)
	}
}

func TestConcurrentReconcileCommitsOneRepair(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.setRelayStatus("exited")
	rig.gateway.remove(rig.recordGrantID())

	const callers = 16
	results := make(chan ReconcileReport, callers)
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			report, err := rig.server.Reconcile(context.Background())
			results <- report
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	changed := 0
	for err := range errorsSeen {
		if err != nil {
			t.Errorf("Reconcile: %v", err)
		}
	}
	for report := range results {
		changed += report.Changed
	}
	if changed != 1 {
		t.Fatalf("committed repairs = %d, want 1", changed)
	}
	if got := rig.config.Evidence.NextSequence(); got != 3 {
		t.Fatalf("evidence next sequence = %d, want 3", got)
	}
}

func TestRunReconcilerBoundsIntervalAndStopsWithContext(t *testing.T) {
	rig := newReconcileRig(t, true)
	if err := rig.server.RunReconciler(context.Background(), 0); err == nil {
		t.Fatal("zero interval accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- rig.server.RunReconciler(ctx, time.Second) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciler did not stop after cancellation")
	}
}

func (r *reconcileRig) recordGrantID() string {
	return gateway.GrantID(r.record.TenantID, r.record.InstanceID, r.record.Generation)
}
