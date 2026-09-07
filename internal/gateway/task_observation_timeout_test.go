package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
)

func TestLifecycleObservationTimeoutPreservesOriginalTaskForRecovery(t *testing.T) {
	for _, stage := range []string{"headers", "body", "socket deadline"} {
		t.Run(stage, func(t *testing.T) {
			var dispatches atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					dispatches.Add(1)
					w.WriteHeader(http.StatusAccepted)
					_, _ = io.WriteString(w, `{"run_id":"`+lifecycleTestRunID+`"}`)
					return
				}
				_, _ = io.WriteString(w, `{"run_id":"`+lifecycleTestRunID+`","status":"completed"}`)
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			digest := dispatchLifecycleTask(t, rig, "timeout-recovery", []byte(`{"input":"work"}`))
			originalClient := rig.server.client
			rig.server.client = &http.Client{Transport: lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != rig.operation.StatusPathPrefix+lifecycleTestRunID {
					t.Errorf("unexpected observation: %s %s", r.Method, r.URL.Path)
				}
				failure := errors.Join(context.DeadlineExceeded, errors.New("private-diagnostic"))
				if stage == "socket deadline" {
					return nil, os.ErrDeadlineExceeded
				}
				if stage == "headers" {
					return nil, failure
				}
				return &http.Response{StatusCode: http.StatusOK,
					Header: http.Header{"Content-Type": {"application/json"}}, ContentLength: -1,
					Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"private":"partial"`), iotest.ErrReader(failure))),
				}, nil
			})}
			response := invokeLifecycleTaskEndpoint(rig, http.MethodPost, digest, true, nil)
			if code := requireGatewayErrorCode(t, response, http.StatusGatewayTimeout); code != "task_observation_timeout" {
				t.Fatalf("error code=%q", code)
			}
			if strings.Contains(response.Body.String(), "private") || response.Header().Get("Retry-After") == "" {
				t.Fatalf("unsafe or unactionable timeout response: %s", response.Body.String())
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
			requireLifecycleTaskStatus(t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, digest, false, nil),
				digest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "")
			rig.server.client = originalClient
			rig.server.now = func() time.Time { return rig.now.Add(time.Duration(rig.operation.PollIntervalSeconds) * time.Second) }
			requireLifecycleTaskStatus(t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, digest, true, nil),
				digest, "terminal", "agent_reported_completed", lifecycleTestRunID, string(connectorledger.TaskStatusAgentReportedCompleted))
			if dispatches.Load() != 1 {
				t.Fatalf("timeout redispatched work: %d", dispatches.Load())
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal)
		})
	}
}

func TestLifecycleObservationTimeoutReportsRemainingPollDelay(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 500 * time.Millisecond, 2 * time.Second, 15 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, `{"run_id":"`+lifecycleTestRunID+`"}`)
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			digest := dispatchLifecycleTask(t, rig, "timeout-poll-delay", []byte(`{"input":"work"}`))
			rig.server.client = &http.Client{Transport: lifecycleRoundTripper(func(_ *http.Request) (*http.Response, error) {
				rig.server.now = func() time.Time { return rig.now.Add(elapsed) }
				return nil, context.DeadlineExceeded
			})}
			response := invokeLifecycleTaskEndpoint(rig, http.MethodPost, digest, true, nil)
			requireGatewayErrorCode(t, response, http.StatusGatewayTimeout)
			remaining := time.Duration(rig.operation.PollIntervalSeconds)*time.Second - elapsed
			want := "0"
			if remaining > 0 {
				want = strconv.Itoa(int((remaining + time.Second - 1) / time.Second))
			}
			if got := response.Header().Get("Retry-After"); got != want {
				t.Fatalf("Retry-After=%q, want remaining interval %q", got, want)
			}
		})
	}
}
