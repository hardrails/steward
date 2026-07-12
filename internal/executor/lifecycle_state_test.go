package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestClassifyDockerLifecycleIsClosed(t *testing.T) {
	tests := []struct {
		status string
		want   dockerLifecycleState
	}{
		{status: "running", want: dockerLifecycleRunning},
		{status: "created", want: dockerLifecycleStopped},
		{status: "exited", want: dockerLifecycleStopped},
		{status: "paused", want: dockerLifecycleAmbiguous},
		{status: "restarting", want: dockerLifecycleAmbiguous},
		{status: "removing", want: dockerLifecycleAmbiguous},
		{status: "dead", want: dockerLifecycleAmbiguous},
		{status: "", want: dockerLifecycleAmbiguous},
		{status: "unknown", want: dockerLifecycleAmbiguous},
		{status: "RUNNING", want: dockerLifecycleAmbiguous},
	}
	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			if got := classifyDockerLifecycle(test.status); got != test.want {
				t.Fatalf("classifyDockerLifecycle(%q) = %d, want %d", test.status, got, test.want)
			}
		})
	}
}

func TestLegacyStopIsIdempotentOnlyForExactStoppedState(t *testing.T) {
	for _, status := range []string{"created", "exited"} {
		t.Run(status, func(t *testing.T) {
			docker, server, runtimeRef := legacyLifecycleRig(t, status)
			response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", context.Background())
			if response.Code != http.StatusOK || docker.stopCalls != 0 {
				t.Fatalf("status=%d stops=%d body=%s", response.Code, docker.stopCalls, response.Body.String())
			}
		})
	}

	for _, status := range []string{"paused", "restarting", "removing", "dead", "unknown"} {
		t.Run(status, func(t *testing.T) {
			docker, server, runtimeRef := legacyLifecycleRig(t, status)
			response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", context.Background())
			if response.Code != http.StatusOK || docker.stopCalls != 1 || docker.observed.Status != "exited" {
				t.Fatalf("status=%d stops=%d final=%q body=%s", response.Code, docker.stopCalls, docker.observed.Status, response.Body.String())
			}
		})
	}
}

func TestLegacyStopUsesExactReinspectionAfterLostOrNoopResponse(t *testing.T) {
	t.Run("lost response after applied stop", func(t *testing.T) {
		docker, server, runtimeRef := legacyLifecycleRig(t, "running")
		docker.stopErr = errors.New("response lost")
		docker.stopAppliesOnError = true
		response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", context.Background())
		if response.Code != http.StatusOK || docker.stopCalls != 1 || docker.observed.Status != "exited" {
			t.Fatalf("status=%d stops=%d final=%q body=%s", response.Code, docker.stopCalls, docker.observed.Status, response.Body.String())
		}
	})

	t.Run("ambiguous no-op remains unavailable", func(t *testing.T) {
		docker, server, runtimeRef := legacyLifecycleRig(t, "paused")
		docker.stopNoop = true
		response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", context.Background())
		if response.Code != http.StatusServiceUnavailable || docker.stopCalls != 1 ||
			!strings.Contains(response.Body.String(), `"error":"reconciliation_required"`) {
			t.Fatalf("status=%d stops=%d body=%s", response.Code, docker.stopCalls, response.Body.String())
		}
	})

	t.Run("start contains ambiguous state before retry", func(t *testing.T) {
		docker, server, runtimeRef := legacyLifecycleRig(t, "restarting")
		response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background())
		if response.Code != http.StatusServiceUnavailable || docker.stopCalls != 1 || docker.starts != 0 ||
			docker.observed.Status != "exited" || !strings.Contains(response.Body.String(), `"error":"reconciliation_required"`) {
			t.Fatalf("status=%d starts=%d stops=%d final=%q body=%s", response.Code, docker.starts, docker.stopCalls, docker.observed.Status, response.Body.String())
		}
	})
}

func TestSecureTransitionConfirmsAmbiguousAndLostStopResults(t *testing.T) {
	tests := []struct {
		name        string
		initial     string
		action      string
		stopNoop    bool
		stopErr     error
		applyOnErr  bool
		wantStatus  int
		wantStopped bool
		wantPending bool
	}{
		{name: "ambiguous stop contained", initial: "paused", action: "stop", wantStatus: http.StatusOK, wantStopped: true},
		{name: "dead stop contained", initial: "dead", action: "stop", wantStatus: http.StatusOK, wantStopped: true},
		{name: "lost stop response", initial: "running", action: "stop", stopErr: errors.New("response lost"), applyOnErr: true, wantStatus: http.StatusOK, wantStopped: true},
		{name: "ambiguous no-op", initial: "restarting", action: "stop", stopNoop: true, wantStatus: http.StatusServiceUnavailable, wantPending: true},
		{name: "ambiguous start contained", initial: "removing", action: "start", wantStatus: http.StatusServiceUnavailable, wantStopped: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			docker := &secureDocker{}
			server, _, config, runtimeRef := admittedSecureServer(t, docker)
			docker.observed.Status = test.initial
			docker.stopNoop = test.stopNoop
			docker.stopErr = test.stopErr
			docker.stopAppliesOnError = test.applyOnErr

			response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/"+test.action, context.Background())
			if response.Code != test.wantStatus || docker.stopCalls != 1 {
				t.Fatalf("status=%d want=%d stops=%d body=%s", response.Code, test.wantStatus, docker.stopCalls, response.Body.String())
			}
			if test.wantStopped && !lifecycleMatches(docker.observed.Status, false) {
				t.Fatalf("final Docker status = %q", docker.observed.Status)
			}
			if test.wantPending != (len(config.Journal.Pending()) == 1) {
				t.Fatalf("pending=%#v wantPending=%t", config.Journal.Pending(), test.wantPending)
			}
			if test.wantStatus == http.StatusServiceUnavailable &&
				!strings.Contains(response.Body.String(), `"error":"reconciliation_required"`) {
				t.Fatalf("body=%s", response.Body.String())
			}
		})
	}
}

func TestSecureStopIsIdempotentOnlyForExactStoppedState(t *testing.T) {
	for _, status := range []string{"created", "exited"} {
		t.Run(status, func(t *testing.T) {
			docker := &secureDocker{}
			server, _, config, runtimeRef := admittedSecureServer(t, docker)
			docker.observed.Status = status
			response := lifecycleRequest(server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/stop", context.Background())
			if response.Code != http.StatusOK || docker.stopCalls != 0 || len(config.Journal.Pending()) != 0 {
				t.Fatalf("status=%d stops=%d pending=%#v body=%s", response.Code, docker.stopCalls, config.Journal.Pending(), response.Body.String())
			}
		})
	}
}

func TestRuntimeLifecycleMatchingRequiresExactRelayState(t *testing.T) {
	workload := runtimeTopologyWorkload()
	statuses := []string{"running", "created", "exited", "paused", "restarting", "removing", "dead", "unknown"}
	for _, wantRunning := range []bool{false, true} {
		for _, status := range statuses {
			t.Run(status, func(t *testing.T) {
				docker := &topologyFixture{}
				gatewayControl := &gatewayFixture{grants: map[string]gateway.Grant{}}
				server := runtimeTopologyServer(docker, gatewayControl)
				relay := server.desiredRelay(workload)
				docker.relay = &ObservedRelay{
					Spec: relay, Fingerprint: relayFingerprint(relay), Managed: true, Hardened: true, Status: status,
				}
				serviceURL := ""
				if wantRunning {
					serviceURL = gatewayServiceURL(server, workload)
				}
				grant := server.desiredGatewayGrant(workload, serviceURL)
				grant.Active = wantRunning
				gatewayControl.grants[grant.GrantID] = grant
				want := status == "running" && wantRunning || (status == "created" || status == "exited") && !wantRunning
				if got := server.runtimeLifecycleMatches(context.Background(), workload, wantRunning); got != want {
					t.Fatalf("runtimeLifecycleMatches(status=%q, running=%t) = %t, want %t", status, wantRunning, got, want)
				}
			})
		}
	}
}

func gatewayServiceURL(server *Server, workload Workload) string {
	return gateway.ServiceSocketURL(server.secure.grantRoot, workload.Runtime.GrantID)
}

func legacyLifecycleRig(t *testing.T, status string) (*secureDocker, *Server, string) {
	t.Helper()
	workload := Workload{TenantID: "tenant-a", InstanceID: "agent-1"}
	docker := &secureDocker{fakeDocker: fakeDocker{observed: &ObservedWorkload{
		Workload: workload, Fingerprint: workloadFingerprint(workload), Managed: true, Hardened: true, Status: status,
	}}}
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	return docker, server, RuntimeRef(workload.TenantID, workload.InstanceID)
}

func lifecycleRequest(server *Server, method, target string, ctx context.Context) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}
