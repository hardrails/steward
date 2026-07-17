package executoruplink

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskprotocol"
)

func TestActivationCanarySubmissionClassifiesRetryAndRejection(t *testing.T) {
	fixture := newNodeCanaryFixture(t)

	for _, code := range []string{
		"invalid_task_submission",
		"method_not_allowed",
		"service_operation_not_found",
	} {
		t.Run(code, func(t *testing.T) {
			gatewayFixture := newNodeCanaryGateway(fixture)
			cause := &gateway.ControlAPIError{Code: code, Message: "rejected for test"}
			gatewayFixture.submitErr = cause
			dispatch := dispatcher{activationGateway: gatewayFixture}

			_, err := dispatch.submitActivationCanary(context.Background(), fixture.verified)
			var rejected activationCanaryRejectedError
			if !errors.As(err, &rejected) || !errors.Is(err, cause) ||
				!strings.Contains(err.Error(), "rejected before dispatch") {
				t.Fatalf("rejected error=%v", err)
			}
		})
	}

	t.Run("default busy delay then exact retry", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.submitErr = &gateway.ControlAPIError{
			Code: "service_busy", Message: "busy",
		}
		var waited time.Duration
		dispatch := dispatcher{
			activationGateway: gatewayFixture,
			wait: func(_ context.Context, delay time.Duration) error {
				waited = delay
				gatewayFixture.submitErr = nil
				return nil
			},
		}
		submission, err := dispatch.submitActivationCanary(context.Background(), fixture.verified)
		if err != nil || submission.RunID != fixture.submission.RunID ||
			waited != activationCanarySubmissionRetryMinimum || gatewayFixture.submitCalls != 2 {
			t.Fatalf("retry submission=%#v err=%v waited=%s calls=%d", submission, err, waited, gatewayFixture.submitCalls)
		}
	})

	t.Run("server supplied busy delay is cancellable", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.submitErr = &gateway.ControlAPIError{
			Code: "service_busy", Message: "busy", RetryAfter: 3 * time.Second,
		}
		waitErr := errors.New("coordinator stopped")
		dispatch := dispatcher{
			activationGateway: gatewayFixture,
			wait: func(_ context.Context, delay time.Duration) error {
				if delay != 3*time.Second {
					t.Fatalf("delay=%s", delay)
				}
				return waitErr
			},
		}
		_, err := dispatch.submitActivationCanary(context.Background(), fixture.verified)
		if !errors.Is(err, waitErr) || gatewayFixture.submitCalls != 1 {
			t.Fatalf("busy cancellation error=%v calls=%d", err, gatewayFixture.submitCalls)
		}
	})

	t.Run("unstructured failure is not retried", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		cause := errors.New("transport failed")
		gatewayFixture.submitErr = cause
		dispatch := dispatcher{activationGateway: gatewayFixture}
		_, err := dispatch.submitActivationCanary(context.Background(), fixture.verified)
		if !errors.Is(err, cause) || !strings.Contains(err.Error(), "submit activation canary task") ||
			gatewayFixture.submitCalls != 1 {
			t.Fatalf("transport error=%v calls=%d", err, gatewayFixture.submitCalls)
		}
	})
}

func TestActivationCanaryObservationClassifiesEveryFailureBoundary(t *testing.T) {
	fixture := newNodeCanaryFixture(t)

	t.Run("initial status transport", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.statusErr = errors.New("status transport")
		dispatch := dispatcher{activationGateway: gatewayFixture}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if err == nil || !strings.Contains(err.Error(), "read activation canary task status") {
			t.Fatalf("initial status error=%v", err)
		}
	})

	t.Run("invalid initial status", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.status.RunID = "run_ffffffffffffffffffffffffffffffff"
		dispatch := dispatcher{activationGateway: gatewayFixture}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if err == nil || !strings.Contains(err.Error(), "changed the activation canary identity") {
			t.Fatalf("changed status identity error=%v", err)
		}
	})

	t.Run("unsupported terminal status", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.status = gateway.TaskLifecycleStatus{
			SchemaVersion: gateway.TaskStatusSchemaV1,
			TaskDigest:    fixture.submission.TaskDigest, PermitDigest: fixture.submission.PermitDigest,
			Phase: connectorledger.Terminal, State: "invented_terminal",
			RunID: fixture.submission.RunID, TaskStatus: "invented_terminal",
		}
		dispatch := dispatcher{activationGateway: gatewayFixture}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if err == nil || !strings.Contains(err.Error(), "unsupported terminal") {
			t.Fatalf("unsupported terminal error=%v", err)
		}
	})

	for _, code := range []string{"task_observation_throttled", "service_busy"} {
		t.Run("retry "+code, func(t *testing.T) {
			gatewayFixture := newNodeCanaryGateway(fixture)
			gatewayFixture.observeErr = &gateway.ControlAPIError{
				Code: code, Message: "retry", RetryAfter: 2 * time.Second,
			}
			var waits int
			dispatch := dispatcher{
				activationGateway: gatewayFixture,
				wait: func(_ context.Context, delay time.Duration) error {
					waits++
					if delay != 2*time.Second {
						t.Fatalf("delay=%s", delay)
					}
					gatewayFixture.observeErr = nil
					return nil
				},
			}
			raw, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
			if err != nil || len(raw) == 0 || waits != 1 || gatewayFixture.observeCalls != 2 {
				t.Fatalf("observation bytes=%d err=%v waits=%d calls=%d", len(raw), err, waits, gatewayFixture.observeCalls)
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "unstructured", err: errors.New("observe transport")},
		{name: "zero retry", err: &gateway.ControlAPIError{Code: "service_busy", Message: "busy"}},
		{name: "unrecognized code", err: &gateway.ControlAPIError{Code: "forbidden", Message: "no"}},
	} {
		t.Run("reject "+test.name, func(t *testing.T) {
			gatewayFixture := newNodeCanaryGateway(fixture)
			gatewayFixture.observeErr = test.err
			dispatch := dispatcher{activationGateway: gatewayFixture}
			_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
			if err == nil || !strings.Contains(err.Error(), "observe activation canary task") {
				t.Fatalf("observe error=%v", err)
			}
		})
	}

	t.Run("throttle wait failure", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.observeErr = &gateway.ControlAPIError{
			Code: "task_observation_throttled", Message: "retry", RetryAfter: time.Second,
		}
		waitErr := errors.New("observation deadline")
		dispatch := dispatcher{
			activationGateway: gatewayFixture,
			wait:              func(context.Context, time.Duration) error { return waitErr },
		}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if !errors.Is(err, waitErr) {
			t.Fatalf("throttle wait error=%v", err)
		}
	})

	t.Run("nonterminal observation wait failure", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.observed = gatewayFixture.status
		waitErr := errors.New("poll deadline")
		dispatch := dispatcher{
			activationGateway: gatewayFixture,
			wait:              func(context.Context, time.Duration) error { return waitErr },
		}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if !errors.Is(err, waitErr) {
			t.Fatalf("nonterminal wait error=%v", err)
		}
	})

	t.Run("refresh status transport", func(t *testing.T) {
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.observed = gatewayFixture.status
		dispatch := dispatcher{
			activationGateway: gatewayFixture,
			wait: func(context.Context, time.Duration) error {
				gatewayFixture.statusErr = errors.New("refresh transport")
				return nil
			},
		}
		_, err := dispatch.observeActivationCanary(context.Background(), fixture.submission)
		if err == nil || !strings.Contains(err.Error(), "refresh activation canary task status") {
			t.Fatalf("refresh error=%v", err)
		}
	})
}

func TestActivationCanaryStatusAndObservationValidationFailClosed(t *testing.T) {
	fixture := newNodeCanaryFixture(t)
	dispatchStatus := newNodeCanaryGateway(fixture).status
	terminalStatus := newNodeCanaryGateway(fixture).observed

	for name, mutate := range map[string]func(*gateway.TaskLifecycleStatus){
		"identity": func(value *gateway.TaskLifecycleStatus) {
			value.PermitDigest = controlprotocol.ExecutorEvidencePublicKeySHA256([]byte("changed"))
		},
		"dispatch shape": func(value *gateway.TaskLifecycleStatus) {
			value.ResultDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"unknown phase": func(value *gateway.TaskLifecycleStatus) {
			value.Phase = connectorledger.Authorize
		},
	} {
		t.Run(name, func(t *testing.T) {
			status := dispatchStatus
			mutate(&status)
			if err := validateActivationCanaryStatus(fixture.submission, status); err == nil {
				t.Fatal("invalid dispatch status accepted")
			}
		})
	}

	for name, mutate := range map[string]func(*gateway.TaskLifecycleStatus){
		"nonterminal observation": func(value *gateway.TaskLifecycleStatus) {
			value.ObservedStatus = taskprotocol.StatusRunning
		},
		"disagrees with task status": func(value *gateway.TaskLifecycleStatus) {
			value.ObservedStatus = taskprotocol.StatusFailed
		},
		"missing result binding": func(value *gateway.TaskLifecycleStatus) {
			value.ResultDigest = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			status := terminalStatus
			mutate(&status)
			if err := validateActivationCanaryStatus(fixture.submission, status); err == nil {
				t.Fatal("invalid terminal status accepted")
			}
		})
	}

	t.Run("ambiguous terminal shape", func(t *testing.T) {
		status := gateway.TaskLifecycleStatus{
			SchemaVersion: gateway.TaskStatusSchemaV1,
			TaskDigest:    fixture.submission.TaskDigest, PermitDigest: fixture.submission.PermitDigest,
			Phase: connectorledger.Terminal, State: gateway.TaskStateObservationFailed,
			RunID: fixture.submission.RunID, RetrySafety: gateway.TaskRetryReplacementUnsafe,
			ResponseBytes: 1,
		}
		if err := validateActivationCanaryStatus(fixture.submission, status); err == nil {
			t.Fatal("inconsistent ambiguous terminal accepted")
		}
	})

	t.Run("invalid observation binding", func(t *testing.T) {
		status := terminalStatus
		status.ResultDigest = "sha256:" + strings.Repeat("0", 64)
		if _, err := decodeActivationCanaryObservation(fixture.submission, status); err == nil {
			t.Fatal("changed observation digest accepted")
		}
	})

	t.Run("observation is not completed", func(t *testing.T) {
		status := terminalStatus
		status.ObservedStatus = taskprotocol.StatusFailed
		if _, err := decodeActivationCanaryObservation(fixture.submission, status); err == nil {
			t.Fatal("non-completed observation accepted")
		}
	})
}

func TestActivationCanaryTimingAndLocalProjectionBoundaries(t *testing.T) {
	fixture := newNodeCanaryFixture(t)

	if validActivationCanaryRunID("run_short") ||
		validActivationCanaryRunID("run_0123456789abcdef0123456789abcdeg") ||
		!validActivationCanaryRunID(nodeCanaryRunID) {
		t.Fatal("activation canary run ID grammar changed")
	}
	if _, err := projectActivationCanaryResult(activationcanary.ResultV1{}); err == nil {
		t.Fatal("invalid canary result projected")
	}

	dispatch := dispatcher{}
	if err := dispatch.waitActivationCanary(context.Background(), 0); err == nil {
		t.Fatal("zero retry delay accepted")
	}
	waitErr := errors.New("injected wait")
	dispatch.wait = func(context.Context, time.Duration) error { return waitErr }
	if err := dispatch.waitActivationCanary(context.Background(), time.Second); !errors.Is(err, waitErr) {
		t.Fatalf("injected wait error=%v", err)
	}
	dispatch.wait = nil
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dispatch.waitActivationCanary(canceled, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled timer error=%v", err)
	}
	if err := dispatch.waitActivationCanary(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("elapsed timer error=%v", err)
	}

	admitted := fixture.command.Admission
	live := admitted
	live.Status = "created"
	if err := correlateLiveActivationAdmission(admitted, live); err == nil {
		t.Fatal("non-running live workload accepted")
	}

	for _, test := range []struct {
		name string
		body string
	}{
		{name: "oversized", body: strings.Repeat("x", controlprotocol.MaxExecutorReportBytes+1)},
		{name: "malformed", body: `{`},
		{name: "invalid projection", body: `{}`},
	} {
		t.Run("preflight "+test.name, func(t *testing.T) {
			dispatch := dispatcher{
				token: "local-token",
				handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusOK)
					_, _ = writer.Write([]byte(test.body))
				}),
			}
			if _, err := dispatch.preflightActivationCanary(
				context.Background(), fixture.runtimeRef,
				activationCanaryPreflightRequest{},
			); err == nil {
				t.Fatal("invalid local preflight accepted")
			}
		})
	}

	t.Run("checkpoint response overflow", func(t *testing.T) {
		dispatch := dispatcher{
			token: "local-token",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusCreated)
				_, _ = writer.Write([]byte(strings.Repeat("x", maxActivationCheckpointResponseBytes+1)))
			}),
		}
		err := dispatch.appendActivationCheckpoint(
			context.Background(), fixture.runtimeRef, activationCheckpointRequest{},
		)
		if !errors.Is(err, errLocalResponseLimit) {
			t.Fatalf("checkpoint overflow error=%v", err)
		}
	})
}

func TestApplyActivationCanarySeparatesRejectionFromUncertainEffects(t *testing.T) {
	fixture := newNodeCanaryFixture(t)
	apply := func(dispatch dispatcher, command command) error {
		_, _, err := dispatch.applyActivationCanary(
			context.Background(), command,
			fixture.statement.TenantID,
			fixture.statement.InstanceID,
			fixture.runtimeRef,
		)
		return err
	}

	if err := apply(dispatcher{}, fixture.outer); err == nil || effectMayHaveOccurred(err) {
		t.Fatalf("unavailable runtime error=%v", err)
	}

	t.Run("zero node time", func(t *testing.T) {
		dispatch := dispatcher{
			activationGateway: newNodeCanaryGateway(fixture),
			now:               func() time.Time { return time.Time{} },
		}
		if err := apply(dispatch, fixture.outer); err == nil || effectMayHaveOccurred(err) {
			t.Fatalf("zero time error=%v", err)
		}
	})

	t.Run("outer generation substitution", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, newNodeCanaryGateway(fixture))
		command := fixture.outer
		command.InstanceGeneration++
		if err := apply(dispatch, command); err == nil || effectMayHaveOccurred(err) || handler.preflightCalls != 0 {
			t.Fatalf("generation substitution error=%v preflights=%d", err, handler.preflightCalls)
		}
	})

	t.Run("local preflight failure", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{
			t: t, live: fixture.live, preflightStatus: http.StatusServiceUnavailable,
		}
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, newNodeCanaryGateway(fixture))
		if err := apply(dispatch, fixture.outer); err == nil || effectMayHaveOccurred(err) {
			t.Fatalf("preflight error=%v", err)
		}
	})

	t.Run("gateway rejects before dispatch", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.submitErr = &gateway.ControlAPIError{
			Code: "invalid_task_submission", Message: "bad request",
		}
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)
		err := apply(dispatch, fixture.outer)
		var rejected activationCanaryRejectedError
		if !errors.As(err, &rejected) || effectMayHaveOccurred(err) {
			t.Fatalf("rejected apply error=%v", err)
		}
	})

	t.Run("gateway transport is uncertain", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.submitErr = errors.New("ambiguous submit")
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)
		if err := apply(dispatch, fixture.outer); err == nil || !effectMayHaveOccurred(err) {
			t.Fatalf("ambiguous submit error=%v", err)
		}
	})

	t.Run("evidence export is uncertain", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.exportErr = errors.New("ambiguous export")
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)
		if err := apply(dispatch, fixture.outer); err == nil || !effectMayHaveOccurred(err) {
			t.Fatalf("ambiguous export error=%v", err)
		}
	})

	t.Run("invalid exported evidence is uncertain", func(t *testing.T) {
		handler := &nodeCanaryLocalHandler{t: t, live: fixture.live}
		gatewayFixture := newNodeCanaryGateway(fixture)
		gatewayFixture.evidence = []byte("not evidence")
		dispatch := newNodeCanaryDispatcher(t, fixture, handler, gatewayFixture)
		if err := apply(dispatch, fixture.outer); err == nil || !effectMayHaveOccurred(err) {
			t.Fatalf("invalid evidence error=%v", err)
		}
	})
}
