package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
)

type countFailureDocker struct {
	*secureDocker
}

func (d *countFailureDocker) WorkloadCounts(context.Context, string) (int, int, error) {
	return 0, 0, errors.New("inventory unavailable")
}

type stateFailureDocker struct {
	*secureDocker
	mode         string
	inspectCalls int
	want         StateVolumeSpec
}

func (d *stateFailureDocker) InspectStateVolume(context.Context, string) (ObservedStateVolume, error) {
	d.inspectCalls++
	if d.mode == "initial-error" {
		return ObservedStateVolume{}, errors.New("state inventory unavailable")
	}
	if d.inspectCalls == 1 {
		return ObservedStateVolume{}, ErrNotFound
	}
	switch d.mode {
	case "create-absent":
		return ObservedStateVolume{}, ErrNotFound
	case "create-ambiguous":
		return ObservedStateVolume{}, errors.New("state inspection lost")
	case "verify-drift":
		return ObservedStateVolume{StateVolumeSpec: d.want, Managed: false}, nil
	default:
		return ObservedStateVolume{StateVolumeSpec: d.want, Managed: true}, nil
	}
}

func (d *stateFailureDocker) CreateStateVolume(_ context.Context, spec StateVolumeSpec) error {
	d.want = spec
	if strings.HasPrefix(d.mode, "create-") {
		return errors.New("state create failed")
	}
	return nil
}

func (d *stateFailureDocker) RemoveStateVolume(context.Context, string) error { return nil }

type absentCreateDocker struct {
	*secureDocker
}

func (d *absentCreateDocker) Create(context.Context, string, Workload) error {
	return errors.New("docker rejected create")
}

type topologyProvisionDocker struct {
	*secureDocker
	createNetworkErr error
	createRelayErr   error
	retainNetwork    bool
}

func (d *topologyProvisionDocker) CreateNetwork(ctx context.Context, spec NetworkSpec) error {
	if d.createNetworkErr != nil {
		return d.createNetworkErr
	}
	return d.secureDocker.CreateNetwork(ctx, spec)
}

func (d *topologyProvisionDocker) CreateRelay(ctx context.Context, spec RelaySpec) error {
	if d.createRelayErr != nil {
		return d.createRelayErr
	}
	return d.secureDocker.CreateRelay(ctx, spec)
}

func (d *topologyProvisionDocker) RemoveNetwork(ctx context.Context, name string) error {
	if d.retainNetwork {
		return nil
	}
	return d.secureDocker.RemoveNetwork(ctx, name)
}

type reconciliationFailureDocker struct {
	*reconcileDocker
	startErr         error
	stopErr          error
	stopAppliesOnErr bool
	stopNoop         bool
	stopTarget       string
	inspectErr       error
}

func (d *reconciliationFailureDocker) Start(ctx context.Context, name string) error {
	if d.startErr != nil {
		return d.startErr
	}
	return d.reconcileDocker.Start(ctx, name)
}

func (d *reconciliationFailureDocker) Stop(ctx context.Context, name string) error {
	targeted := d.stopTarget == "" || d.stopTarget == name
	if targeted && d.stopNoop {
		return d.stopErr
	}
	if targeted && d.stopErr != nil {
		if d.stopAppliesOnErr {
			if err := d.reconcileDocker.Stop(ctx, name); err != nil {
				return err
			}
		}
		return d.stopErr
	}
	return d.reconcileDocker.Stop(ctx, name)
}

func (d *reconciliationFailureDocker) Inspect(ctx context.Context, name string) (ObservedWorkload, error) {
	if d.inspectErr != nil {
		return ObservedWorkload{}, d.inspectErr
	}
	return d.reconcileDocker.Inspect(ctx, name)
}

type reconciliationFailureGateway struct {
	*reconcileGateway
	registerErr    error
	deactivateNoop bool
	afterActivate  func()
}

func (g *reconciliationFailureGateway) Register(ctx context.Context, grant gateway.Grant) error {
	if g.registerErr != nil {
		return g.registerErr
	}
	return g.reconcileGateway.Register(ctx, grant)
}

func (g *reconciliationFailureGateway) Deactivate(ctx context.Context, id string) error {
	if g.deactivateNoop {
		return nil
	}
	return g.reconcileGateway.Deactivate(ctx, id)
}

func (g *reconciliationFailureGateway) Activate(ctx context.Context, id string) error {
	err := g.reconcileGateway.Activate(ctx, id)
	if g.afterActivate != nil {
		g.afterActivate()
	}
	return err
}

func submitCoverageAdmission(t *testing.T, server *Server, capsule []byte, intent admission.InstanceIntent) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func enableCoverageAdmission(t *testing.T, docker Docker, config SecureAdmissionConfig) *Server {
	t.Helper()
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	return server
}

func TestSecureProvisionFailsClosedAcrossStateBoundaries(t *testing.T) {
	t.Run("inventory failure", func(t *testing.T) {
		docker := &countFailureDocker{secureDocker: &secureDocker{}}
		capsule, intent, config := secureAdmissionFixture(t)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusBadGateway || len(config.Journal.Pending()) != 0 {
			t.Fatalf("status=%d pending=%#v body=%s", response.Code, config.Journal.Pending(), response.Body.String())
		}
	})

	for _, test := range []struct {
		name    string
		mode    string
		want    int
		pending int
	}{
		{name: "initial inspection failure", mode: "initial-error", want: http.StatusBadGateway},
		{name: "failed create is proven absent", mode: "create-absent", want: http.StatusBadGateway},
		{name: "failed create is ambiguous", mode: "create-ambiguous", want: http.StatusServiceUnavailable, pending: 1},
		{name: "created volume verification drift", mode: "verify-drift", want: http.StatusServiceUnavailable, pending: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := &stateFailureDocker{secureDocker: &secureDocker{}, mode: test.mode}
			capsule, intent, config := secureAdmissionFixture(t)
			intent.Capabilities.State = true
			intent.StateDisposition = "new"
			server := enableCoverageAdmission(t, docker, config)
			response := submitCoverageAdmission(t, server, capsule, intent)
			if response.Code != test.want || len(config.Journal.Pending()) != test.pending || len(docker.created) != 0 {
				t.Fatalf("status=%d pending=%#v creates=%d body=%s", response.Code, config.Journal.Pending(), len(docker.created), response.Body.String())
			}
		})
	}
}

func secureTopologyConfig(t *testing.T, docker TopologyDocker, control GatewayControl) ([]byte, admission.InstanceIntent, SecureAdmissionConfig) {
	t.Helper()
	capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{Inference: true})
	config.Topology, config.Gateway = docker, control
	config.RelayImage = "sha256:" + strings.Repeat("d", 64)
	config.GrantRoot, config.RelayGID = "/run/steward-gateway/grants", 65531
	return capsule, intent, config
}

func TestSecureProvisionCompensatesCreationFailures(t *testing.T) {
	t.Run("topology prepare", func(t *testing.T) {
		docker := &topologyProvisionDocker{secureDocker: &secureDocker{}, createNetworkErr: errors.New("network create failed")}
		control := &gatewayFixture{grants: make(map[string]gateway.Grant)}
		capsule, intent, config := secureTopologyConfig(t, docker, control)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 0 || docker.network != nil {
			t.Fatalf("status=%d pending=%#v network=%#v body=%s", response.Code, config.Journal.Pending(), docker.network, response.Body.String())
		}
	})

	t.Run("ambiguous topology rollback", func(t *testing.T) {
		docker := &topologyProvisionDocker{secureDocker: &secureDocker{}, retainNetwork: true}
		control := &gatewayFixture{grants: make(map[string]gateway.Grant), registerErr: errors.New("gateway unavailable")}
		capsule, intent, config := secureTopologyConfig(t, docker, control)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 || docker.network == nil {
			t.Fatalf("status=%d pending=%#v network=%#v body=%s", response.Code, config.Journal.Pending(), docker.network, response.Body.String())
		}
	})

	t.Run("docker create proven absent", func(t *testing.T) {
		docker := &absentCreateDocker{secureDocker: &secureDocker{}}
		capsule, intent, config := secureAdmissionFixture(t)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusBadGateway || len(config.Journal.Pending()) != 0 {
			t.Fatalf("status=%d pending=%#v body=%s", response.Code, config.Journal.Pending(), response.Body.String())
		}
	})

	t.Run("topology completion", func(t *testing.T) {
		docker := &topologyProvisionDocker{secureDocker: &secureDocker{}, createRelayErr: errors.New("relay create failed")}
		control := &gatewayFixture{grants: make(map[string]gateway.Grant)}
		capsule, intent, config := secureTopologyConfig(t, docker, control)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 0 || docker.observed != nil || docker.network != nil {
			t.Fatalf("status=%d pending=%#v workload=%#v network=%#v body=%s", response.Code, config.Journal.Pending(), docker.observed, docker.network, response.Body.String())
		}
	})

	t.Run("created workload enforcement drift", func(t *testing.T) {
		docker := &secureDocker{}
		docker.onCreate = func() { docker.observed.Hardened = false }
		capsule, intent, config := secureAdmissionFixture(t)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusInternalServerError || len(config.Journal.Pending()) != 0 || docker.observed != nil {
			t.Fatalf("status=%d pending=%#v workload=%#v body=%s", response.Code, config.Journal.Pending(), docker.observed, response.Body.String())
		}
	})

	t.Run("gateway policy inspection", func(t *testing.T) {
		docker := &topologyProvisionDocker{secureDocker: &secureDocker{}}
		control := &gatewayFixture{grants: make(map[string]gateway.Grant), inspectErr: errors.New("gateway inspection failed")}
		capsule, intent, config := secureTopologyConfig(t, docker, control)
		server := enableCoverageAdmission(t, docker, config)
		response := submitCoverageAdmission(t, server, capsule, intent)
		if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 0 || docker.observed != nil {
			t.Fatalf("status=%d pending=%#v workload=%#v body=%s", response.Code, config.Journal.Pending(), docker.observed, response.Body.String())
		}
	})
}

func TestSecureProvisionLeavesJournalPendingWhenRollbackCannotBeProven(t *testing.T) {
	for _, target := range []string{"enforcement", "commit receipt", "fence"} {
		t.Run(target, func(t *testing.T) {
			docker := &secureDocker{removeErr: errors.New("remove response lost")}
			capsule, intent, config := secureAdmissionFixture(t)
			switch target {
			case "enforcement":
				docker.onCreate = func() { docker.observed.Hardened = false }
			case "commit receipt":
				docker.onCreate = func() { _ = config.Evidence.Close() }
			case "fence":
				docker.onCreate = func() {
					err := config.Fences.Commit(admission.FenceRecord{
						TenantID: intent.TenantID, InstanceID: intent.InstanceID, Generation: intent.Generation,
						CapsuleDigest: intent.CapsuleDigest, PolicyDigest: dsse.Digest(config.PolicyEnvelope), LineageID: intent.LineageID,
						WorkloadDigest: "sha256:" + strings.Repeat("c", 64), ImageConfigDigest: "sha256:" + strings.Repeat("b", 64), Present: true,
					}, 1)
					if err != nil {
						t.Errorf("install conflicting fence: %v", err)
					}
				}
			}
			server := enableCoverageAdmission(t, docker, config)
			response := submitCoverageAdmission(t, server, capsule, intent)
			if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 || docker.observed == nil {
				t.Fatalf("status=%d pending=%#v workload=%#v body=%s", response.Code, config.Journal.Pending(), docker.observed, response.Body.String())
			}
		})
	}
}

func TestReconciliationMutationFailuresRemainPrepared(t *testing.T) {
	t.Run("relay start", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.setRelayStatus("exited")
		rig.gateway.remove(rig.recordGrantID())
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		docker := &reconciliationFailureDocker{reconcileDocker: rig.docker, startErr: errors.New("start failed")}
		rig.server.docker, rig.server.secure.topology = docker, docker
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "start trusted relay") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	t.Run("grant registration", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.gateway.remove(rig.recordGrantID())
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		control := &reconciliationFailureGateway{reconcileGateway: rig.gateway, registerErr: errors.New("register failed")}
		rig.server.secure.gateway = control
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "restore gateway grant") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	t.Run("restored route policy mismatch", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.gateway.remove(rig.recordGrantID())
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		rig.gateway.setPolicyDigest("sha256:" + strings.Repeat("f", 64))
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "does not match") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
		if _, ok := rig.gateway.grant(rig.recordGrantID()); ok {
			t.Fatal("mismatched restored grant was retained")
		}
	})

	t.Run("inactive relay stop", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.agent.Status = "exited"
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		docker := &reconciliationFailureDocker{reconcileDocker: rig.docker, stopErr: errors.New("stop failed")}
		rig.server.docker, rig.server.secure.topology = docker, docker
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "stop trusted relay") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	t.Run("inactive grant registration", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.agent.Status = "exited"
		rig.docker.setRelayStatus("exited")
		rig.gateway.remove(rig.recordGrantID())
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		control := &reconciliationFailureGateway{reconcileGateway: rig.gateway, registerErr: errors.New("register failed")}
		rig.server.secure.gateway = control
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "restore inactive gateway grant") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})
}

func TestReconciliationVerificationAndDurabilityFailures(t *testing.T) {
	t.Run("containment workload cannot be verified", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.driftNetwork()
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		docker := &reconciliationFailureDocker{reconcileDocker: rig.docker, inspectErr: errors.New("inspect failed")}
		rig.server.docker, rig.server.secure.topology = docker, docker
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "inspect stopped workload") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	t.Run("containment grant remains active", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		rig.docker.driftNetwork()
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		control := &reconciliationFailureGateway{reconcileGateway: rig.gateway, deactivateNoop: true}
		rig.server.secure.gateway = control
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "remains active") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	for _, target := range []string{"evidence", "journal"} {
		t.Run("commit "+target, func(t *testing.T) {
			rig := newReconcileRig(t, true)
			grant := rig.gateway.grants[rig.recordGrantID()]
			grant.Active = false
			rig.gateway.grants[rig.recordGrantID()] = grant
			plan, err := rig.server.planReconciliation(context.Background(), rig.record)
			if err != nil {
				t.Fatal(err)
			}
			control := &reconciliationFailureGateway{reconcileGateway: rig.gateway, afterActivate: func() {
				if target == "evidence" {
					_ = rig.config.Evidence.Close()
				} else {
					_ = rig.config.Journal.Close()
				}
			}}
			rig.server.secure.gateway = control
			err = rig.server.applyReconciliation(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), target) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	t.Run("prepare evidence failure compensates journal", func(t *testing.T) {
		rig := newReconcileRig(t, true)
		grant := rig.gateway.grants[rig.recordGrantID()]
		grant.Active = false
		rig.gateway.grants[rig.recordGrantID()] = grant
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		_ = rig.config.Evidence.Close()
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "append reconciliation prepare") || len(rig.config.Journal.Pending()) != 0 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})

	t.Run("revocation aggregates mutation failures", func(t *testing.T) {
		rig := newReconcileRig(t, false)
		plan, err := rig.server.planReconciliation(context.Background(), rig.record)
		if err != nil {
			t.Fatal(err)
		}
		docker := &reconciliationFailureDocker{reconcileDocker: rig.docker, stopErr: errors.New("stop failed")}
		control := &reconciliationFailureGateway{reconcileGateway: rig.gateway}
		control.deactivateErr = errors.New("deactivate failed")
		rig.server.docker, rig.server.secure.topology, rig.server.secure.gateway = docker, docker, control
		if err := rig.server.applyReconciliation(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "revoke runtime") || len(rig.config.Journal.Pending()) != 1 {
			t.Fatalf("err=%v pending=%#v", err, rig.config.Journal.Pending())
		}
	})
}
