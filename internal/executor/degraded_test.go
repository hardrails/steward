package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestDegradedStopContainsExactDriftedAgentAndRelayWithoutSettlingJournal(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	rig.docker.setHardened(false)
	rig.docker.mu.Lock()
	rig.docker.relay.Hardened = false
	rig.docker.mu.Unlock()

	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", rig.record.TenantID)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("containment events=%q", events)
	}
	agent, relay := rig.docker.states()
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if !stoppedStatus(agent) || !stoppedStatus(relay) || grant.Active {
		t.Fatalf("agent=%q relay=%q grant=%#v", agent, relay, grant)
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 1 || pending[0].ID != "ambiguous-prior-operation" {
		t.Fatalf("containment changed prior journal outcome: %#v", pending)
	}
}

func TestDegradedStopNeverOperatesAnInsufficientRelayIdentity(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	rig.docker.mu.Lock()
	rig.docker.relay.Spec.Image = "sha256:" + strings.Repeat("f", 64)
	rig.docker.mu.Unlock()

	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", rig.record.TenantID)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent" {
		t.Fatalf("containment crossed drifted relay identity: %q", events)
	}
	agent, relay := rig.docker.states()
	if !stoppedStatus(agent) || relay != "running" {
		t.Fatalf("agent=%q relay=%q", agent, relay)
	}
}

func TestDegradedStopNeverOperatesAnUnrelatedRuntimeImageIdentity(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	rig.docker.mu.Lock()
	rig.docker.agent.RuntimeImageID = "sha256:" + strings.Repeat("f", 64)
	rig.docker.mu.Unlock()

	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", rig.record.TenantID)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant" {
		t.Fatalf("runtime-image drift containment events=%q", events)
	}
	agent, _ := rig.docker.states()
	if stoppedStatus(agent) {
		t.Fatalf("unrelated runtime image was operated: status=%q", agent)
	}
}

func TestDegradedStopDeniesCrossTenantPrincipalBeforeMutation(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", "other-tenant")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("cross-tenant request mutated runtime: %#v", events)
	}
}

func TestDegradedStopContainsLocalObjectsWhenGatewayIsUnavailable(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	rig.gateway.inspectErr = errors.New("gateway unavailable")
	rig.gateway.deactivateErr = errors.New("gateway unavailable")

	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", rig.record.TenantID)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant,stop_agent,stop_relay" {
		t.Fatalf("best-effort containment events=%q", events)
	}
	agent, relay := rig.docker.states()
	if !stoppedStatus(agent) || !stoppedStatus(relay) {
		t.Fatalf("agent=%q relay=%q", agent, relay)
	}
}

func TestDegradedStopDeactivatesFenceDerivedGrantWhenAgentIsMissing(t *testing.T) {
	rig := newReconcileRig(t, true)
	if _, err := rig.config.Journal.Prepare("ambiguous-prior-operation", "prior:"+rig.record.InstanceID, rig.record.Generation); err != nil {
		t.Fatal(err)
	}
	rig.server.docker = &reconciliationFailureDocker{reconcileDocker: rig.docker, inspectErr: ErrNotFound}

	response := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/stop", rig.record.TenantID)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if events := strings.Join(rig.recorder.snapshot(), ","); events != "deactivate_grant" {
		t.Fatalf("missing-agent containment events=%q", events)
	}
	grant, _ := rig.gateway.grant(rig.recordGrantID())
	if grant.Active {
		t.Fatalf("deterministic grant remained active: %#v", grant)
	}
}

func TestDegradedStateBlocksExpansionAndRecoversAfterCompleteReconciliation(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.driftNetwork()
	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready {
		t.Fatalf("report=%#v err=%v", report, err)
	}

	start := degradedLifecycleRequest(rig, http.MethodPost, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID)+"/start", rig.record.TenantID)
	if start.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded start status=%d body=%s", start.Code, start.Body.String())
	}
	destroy := degradedLifecycleRequest(rig, http.MethodDelete, "/v1/workloads/"+RuntimeRef(rig.record.TenantID, rig.record.InstanceID), rig.record.TenantID)
	if destroy.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded destroy status=%d body=%s", destroy.Code, destroy.Body.String())
	}

	rig.docker.mu.Lock()
	rig.docker.network.Internal = true
	rig.docker.mu.Unlock()
	recovered, err := rig.server.Reconcile(context.Background())
	if err != nil || !recovered.Ready {
		t.Fatalf("recovered report=%#v err=%v", recovered, err)
	}
	status, body := reconcileReadiness(t, rig.server)
	if status != http.StatusOK || body["status"] != "ready" {
		t.Fatalf("readiness status=%d body=%#v", status, body)
	}
}

func TestReconcileDoesNotWidenOneRuntimeWhenAnotherRuntimeIsAmbiguous(t *testing.T) {
	rig := newReconcileRig(t, true)
	rig.docker.setRelayStatus("exited")
	rig.gateway.remove(rig.recordGrantID())
	missing := admission.FenceRecord{
		TenantID: "zz-missing-tenant", InstanceID: "missing-instance", Generation: 1,
		CapsuleDigest: rig.record.CapsuleDigest, PolicyDigest: rig.record.PolicyDigest,
		LineageID: "missing-lineage", WorkloadDigest: rig.record.WorkloadDigest,
		ImageConfigDigest: rig.record.ImageConfigDigest, RoutePolicyDigest: rig.record.RoutePolicyDigest,
		Present: true,
	}
	if err := rig.config.Fences.Commit(missing, 1); err != nil {
		t.Fatal(err)
	}

	report, err := rig.server.Reconcile(context.Background())
	if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || report.Checked != 2 ||
		len(report.Failures) != 1 || report.Failures[0].Code != "workload_missing" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if events := rig.recorder.snapshot(); len(events) != 0 {
		t.Fatalf("degraded scan widened another runtime: %#v", events)
	}
	if _, ok := rig.gateway.grant(rig.recordGrantID()); ok {
		t.Fatal("degraded scan restored a missing grant")
	}
	if pending := rig.config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("degraded no-op scan journaled work: %#v", pending)
	}
}

func degradedLifecycleRequest(rig *reconcileRig, method, path, tenantID string) *httptest.ResponseRecorder {
	ctx := WithAdmissionPrincipal(context.Background(), tenantID, rig.config.NodeID, rig.record.Generation)
	request := httptest.NewRequest(method, path, nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	rig.server.Handler().ServeHTTP(response, request)
	return response
}
