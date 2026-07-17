package executoruplink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

func TestActivationCanaryRunnerSerializesDeduplicatesAndDefersAdditionalWork(t *testing.T) {
	runner := newActivationCanaryRunner(true)
	if !runner.available() {
		t.Fatal("idle activation canary runner did not advertise availability")
	}

	first := activationCanaryJobForTest(0)
	start, accepted := runner.schedule(first)
	if !start || !accepted || runner.available() || !runner.owns(first.delivery) {
		t.Fatalf(
			"schedule first = (start=%v accepted=%v available=%v owns=%v)",
			start,
			accepted,
			runner.available(),
			runner.owns(first.delivery),
		)
	}
	if start, accepted := runner.schedule(first); start || !accepted {
		t.Fatalf(
			"duplicate active schedule = (start=%v accepted=%v)",
			start,
			accepted,
		)
	}
	bumpedGeneration := first.delivery
	bumpedGeneration.DeliveryGeneration++
	if runner.owns(bumpedGeneration) {
		t.Fatal("runner ownership widened across delivery generations")
	}

	deferred := activationCanaryJobForTest(1)
	if start, accepted := runner.schedule(deferred); start || accepted || runner.owns(deferred.delivery) {
		t.Fatalf(
			"additional schedule = (start=%v accepted=%v owns=%v), want durable lease redelivery",
			start,
			accepted,
			runner.owns(deferred.delivery),
		)
	}

	if next, ok := runner.complete(first.delivery.DeliveryID); ok || next.delivery.DeliveryID != "" {
		t.Fatalf("complete final job selected next=%#v ok=%v", next, ok)
	}
	if !runner.available() {
		t.Fatal("drained activation canary runner did not restore availability")
	}
	if start, accepted := runner.schedule(deferred); !start || !accepted || !runner.owns(deferred.delivery) {
		t.Fatalf(
			"redelivered schedule = (start=%v accepted=%v owns=%v)",
			start,
			accepted,
			runner.owns(deferred.delivery),
		)
	}
	runner.stop(deferred.delivery.DeliveryID)
	if !runner.available() {
		t.Fatal("stopped activation canary runner did not restore availability")
	}
}

func TestActivationCanaryRunnerShutdownLeavesDeferredDeliveryRetryable(t *testing.T) {
	fixture := newNodeCanaryFixture(t)
	baseGateway := newNodeCanaryGateway(fixture)
	blockingGateway := &blockingActivationCanaryGateway{
		submission: baseGateway.submission,
		status:     baseGateway.status,
		observed:   baseGateway.observed,
		evidence:   append([]byte(nil), baseGateway.evidence...),
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseGateway := func() { releaseOnce.Do(func() { close(blockingGateway.release) }) }
	defer releaseGateway()

	state := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := state.advance(
		fixture.statement.TenantID,
		fixture.statement.InstanceID,
		position{
			ClaimGeneration: fixture.outer.ClaimGeneration,
			Generation:      fixture.outer.InstanceGeneration,
			Sequence:        4,
			ReportedStatus:  "running",
		},
	); err != nil {
		t.Fatal(err)
	}

	controller := httptest.NewTLSServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV4{
			ProtocolVersion: controlprotocol.ExecutorProtocolV4,
			Applied:         true,
		})
	}))
	defer controller.Close()

	deliveryPath := filepath.Join(t.TempDir(), "deliveries.json")
	deliveryState := newDeliveryStore(t, deliveryPath)
	runner := newActivationCanaryRunner(true)
	poller := &Poller{
		reportURL:     controller.URL,
		client:        controller.Client(),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		deliveryState: deliveryState,
		canaryRunner:  runner,
		dispatcher: dispatcher{
			handler: &concurrentActivationCanaryHandler{
				live:       fixture.live,
				runtimeRef: fixture.runtimeRef,
			},
			token:             "local-token",
			nodeID:            fixture.statement.NodeID,
			nodeScoped:        true,
			projectAdmission:  true,
			activationGateway: blockingGateway,
			now:               func() time.Time { return fixture.now },
			wait: func(context.Context, time.Duration) error {
				return nil
			},
			state: state,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstCommand := fixture.outer
	firstDelivery := nodeCanaryDelivery(fixture)
	if decision, terminal, err := deliveryState.AcceptV4(
		firstDelivery,
		firstCommand.TenantID,
		firstCommand.ClaimGeneration,
		firstCommand.Kind,
	); err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf("accept active delivery decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	if err := poller.startActivationCanary(ctx, "bearer", firstDelivery, firstCommand); err != nil {
		t.Fatalf("start active canary: %v", err)
	}
	waitForSignal(t, blockingGateway.entered, "active canary to block in Gateway task status")

	deferredCommand := fixture.outer
	deferredCommand.CommandID = "activation-canary-command-shutdown-deferred"
	deferredCommand.CommandSequence = 6
	deferredDelivery := firstDelivery
	deferredDelivery.DeliveryID = "activation-canary-delivery-shutdown-deferred"
	deferredDelivery.CommandID = deferredCommand.CommandID
	deferredDelivery.CommandDigest = dsse.Digest([]byte(deferredCommand.CommandID))
	if decision, terminal, err := deliveryState.AcceptV4(
		deferredDelivery,
		deferredCommand.TenantID,
		deferredCommand.ClaimGeneration,
		deferredCommand.Kind,
	); err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf("accept deferred delivery decision=%v terminal=%#v err=%v", decision, terminal, err)
	}
	if err := poller.startActivationCanary(ctx, "bearer", deferredDelivery, deferredCommand); err != nil {
		t.Fatalf("defer second canary: %v", err)
	}
	if runner.owns(deferredDelivery) {
		t.Fatal("runner retained deferred delivery in memory")
	}
	if record := deliveryState.records[deferredDelivery.DeliveryID]; record.Phase != deliveryPhaseAccepted || record.Terminal != nil {
		t.Fatalf("deferred delivery was not durably accepted: %#v", record)
	}

	cancel()
	waitForRunnerAvailable(t, runner)
	runner.mu.Lock()
	active := runner.active
	runner.mu.Unlock()
	if active != nil {
		t.Fatalf("stopped runner active=%#v", active)
	}
	record := deliveryState.records[deferredDelivery.DeliveryID]
	if record.Phase != deliveryPhaseAccepted || record.Terminal != nil {
		t.Fatalf("deferred shutdown delivery became ambiguous: %#v", record)
	}

	reopened, err := LoadDeliveryStore(deliveryPath, deliveryState.NodeID())
	if err != nil {
		t.Fatalf("reopen delivery state: %v", err)
	}
	if err := reopened.PrepareProtocol(controlprotocol.ExecutorProtocolV4, false); err != nil {
		t.Fatalf("prepare reopened protocol: %v", err)
	}
	if err := reopened.RecoverExecuting(); err != nil {
		t.Fatalf("recover reopened delivery state: %v", err)
	}
	recovered := reopened.records[deferredDelivery.DeliveryID]
	if recovered.Phase != deliveryPhaseAccepted || recovered.Terminal != nil {
		t.Fatalf("recovery changed deferred delivery: %#v", recovered)
	}
	decision, terminal, err := reopened.AcceptV4(
		deferredDelivery,
		deferredCommand.TenantID,
		deferredCommand.ClaimGeneration,
		deferredCommand.Kind,
	)
	if err != nil || decision != deliveryExecute || terminal != nil {
		t.Fatalf(
			"redeliver recovered deferred command decision=%v terminal=%#v err=%v",
			decision,
			terminal,
			err,
		)
	}
}

func TestActivationCanaryWorkerKeepsPollingAndContainmentResponsive(t *testing.T) {
	fixture := newNodeCanaryFixture(t)
	baseGateway := newNodeCanaryGateway(fixture)
	blockingGateway := &blockingActivationCanaryGateway{
		submission: baseGateway.submission,
		status:     baseGateway.status,
		observed:   baseGateway.observed,
		evidence:   append([]byte(nil), baseGateway.evidence...),
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseGateway := func() { releaseOnce.Do(func() { close(blockingGateway.release) }) }
	defer releaseGateway()

	local := &concurrentActivationCanaryHandler{
		live:       fixture.live,
		runtimeRef: fixture.runtimeRef,
	}
	state := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := state.advance(
		fixture.statement.TenantID,
		fixture.statement.InstanceID,
		position{
			ClaimGeneration: fixture.outer.ClaimGeneration,
			Generation:      fixture.outer.InstanceGeneration,
			Sequence:        4,
			ReportedStatus:  "running",
		},
	); err != nil {
		t.Fatal(err)
	}

	commandPublic, commandPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(
		t,
		commandPublic,
		[]string{"activation-canary", "stop"},
	)
	credential := &stewarduplink.Credential{
		Version:    2,
		Scope:      "node",
		NodeID:     fixture.statement.NodeID,
		Credential: "bearer",
	}
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	credentialRaw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, credentialRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	reports := make(chan controlprotocol.ExecutorReportV4, 8)
	polls := make(chan controlprotocol.ExecutorPollRequestV4, 2)
	controllerErrors := make(chan error, 8)
	controller := httptest.NewTLSServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("Authorization") != "Bearer bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/executor-uplink/poll":
			var poll controlprotocol.ExecutorPollRequestV4
			raw, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				controllerErrors <- readErr
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if decodeErr := dsse.DecodeStrictInto(raw, maxWireBytes, &poll); decodeErr != nil {
				controllerErrors <- decodeErr
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			polls <- poll
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV4{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				Deliveries:      []json.RawMessage{},
			})
		case "/executor-uplink/report":
			raw, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				controllerErrors <- readErr
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			report, decodeErr := controlprotocol.DecodeExecutorReportV4(raw)
			if decodeErr != nil {
				controllerErrors <- decodeErr
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reports <- report
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV4{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				Applied:         true,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controller.Close()

	runner := newActivationCanaryRunner(true)
	deliveryState := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	poller := &Poller{
		pollURL:        controller.URL + "/executor-uplink/poll",
		reportURL:      controller.URL + "/executor-uplink/report",
		credentialPath: credentialPath,
		expected:       credential,
		client:         controller.Client(),
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		security: stewarduplink.CredentialSecurity{
			SecureExecutor:     true,
			ProtectedTransport: true,
		},
		commandPolicy:   &policy,
		now:             func() time.Time { return fixture.now },
		protocolVersion: controlprotocol.ExecutorProtocolV4,
		deliveryState:   deliveryState,
		canaryRunner:    runner,
		dispatcher: dispatcher{
			handler:           local,
			token:             "local-token",
			nodeID:            fixture.statement.NodeID,
			nodeScoped:        true,
			projectAdmission:  true,
			activationGateway: blockingGateway,
			now:               func() time.Time { return fixture.now },
			wait: func(context.Context, time.Duration) error {
				return nil
			},
			state: state,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	firstCommand := fixture.outer
	firstDelivery, firstRaw := signedDeliveryV4ForTest(
		t,
		firstCommand,
		fixture.now,
		commandPrivate,
	)
	firstDone := processDeliveryV4Async(ctx, poller, credential, firstRaw)
	waitForSignal(t, blockingGateway.entered, "first canary to block in Gateway task status")
	if err := waitForProcessDelivery(t, firstDone, "schedule first canary"); err != nil {
		t.Fatal(err)
	}
	if runner.available() || !runner.owns(firstDelivery) {
		t.Fatalf("active runner available=%v owns-first=%v", runner.available(), runner.owns(firstDelivery))
	}

	secondCommand := fixture.outer
	secondCommand.CommandID = "activation-canary-command-queued"
	secondCommand.CommandSequence = 6
	secondDelivery, secondRaw := signedDeliveryV4ForTest(
		t,
		secondCommand,
		fixture.now,
		commandPrivate,
	)
	secondDone := processDeliveryV4Async(ctx, poller, credential, secondRaw)
	if err := waitForProcessDelivery(t, secondDone, "defer second nonconforming canary"); err != nil {
		t.Fatal(err)
	}
	if runner.owns(secondDelivery) {
		t.Fatal("runner retained a second nonconforming canary in memory")
	}
	deferredRecord := deliveryState.records[secondDelivery.DeliveryID]
	if deferredRecord.Phase != deliveryPhaseAccepted || deferredRecord.Terminal != nil {
		t.Fatalf("second canary was not left durably accepted: %#v", deferredRecord)
	}
	select {
	case report := <-reports:
		t.Fatalf("blocked or deferred canary reported before execution: %#v", report)
	default:
	}

	if err := poller.pollOnce(ctx); err != nil {
		t.Fatalf("poll while canary pending: %v", err)
	}
	select {
	case poll := <-polls:
		if slices.Contains(
			poll.Capabilities,
			controlprotocol.ExecutorCapabilityActivationCanaryV1,
		) {
			t.Fatalf("busy node advertised activation canary capability: %#v", poll.Capabilities)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not receive poll while canary was blocked")
	}

	stopCommand := fixture.outer
	stopCommand.CommandID = "containment-stop-command"
	stopCommand.Kind = "stop"
	stopCommand.Payload = json.RawMessage(`{}`)
	stopCommand.CommandSequence = 7
	_, stopRaw := signedDeliveryV4ForTest(
		t,
		stopCommand,
		fixture.now,
		commandPrivate,
	)
	stopDone := processDeliveryV4Async(ctx, poller, credential, stopRaw)
	if err := waitForProcessDelivery(t, stopDone, "execute containment stop"); err != nil {
		t.Fatal(err)
	}
	if local.stopCalls.Load() != 1 {
		t.Fatalf("containment stop calls = %d, want 1", local.stopCalls.Load())
	}
	stopReport := waitForExecutorReportV4(t, reports, "containment stop report")
	if stopReport.CommandID != stopCommand.CommandID ||
		stopReport.Status != controlprotocol.ExecutorStatusDone ||
		stopReport.ReportedStatus != "stopped" {
		t.Fatalf("containment report = %#v", stopReport)
	}

	releaseGateway()
	firstReport := waitForExecutorReportV4(t, reports, "first activation canary report")
	if firstReport.CommandID != firstCommand.CommandID ||
		firstReport.Status != controlprotocol.ExecutorStatusDone ||
		firstReport.Result.ActivationCanary == nil {
		t.Fatalf("first activation canary report = %#v", firstReport)
	}
	if blockingGateway.statusCalls.Load() != 1 {
		t.Fatalf(
			"Gateway task status calls = %d, want only the pre-containment canary",
			blockingGateway.statusCalls.Load(),
		)
	}
	waitForRunnerAvailable(t, runner)
	deferredRecord = deliveryState.records[secondDelivery.DeliveryID]
	if deferredRecord.Phase != deliveryPhaseAccepted || deferredRecord.Terminal != nil {
		t.Fatalf("deferred canary changed after active completion: %#v", deferredRecord)
	}
	select {
	case report := <-reports:
		t.Fatalf("deferred canary produced an unsolicited report: %#v", report)
	default:
	}

	unavailableCommand := fixture.outer
	unavailableCommand.CommandID = "activation-canary-command-unavailable"
	unavailableCommand.CommandSequence = 8
	_, unavailableRaw := signedDeliveryV4ForTest(
		t,
		unavailableCommand,
		fixture.now,
		commandPrivate,
	)
	poller.canaryRunner = nil
	if err := poller.processDeliveryV4(ctx, credential, unavailableRaw); err != nil {
		t.Fatalf("reject unavailable canary: %v", err)
	}
	unavailableReport := waitForExecutorReportV4(t, reports, "unavailable canary report")
	if unavailableReport.CommandID != unavailableCommand.CommandID ||
		unavailableReport.Status != controlprotocol.ExecutorStatusRejected ||
		unavailableReport.ErrorCode != "activation_canary_unavailable" {
		t.Fatalf("unavailable activation canary report = %#v", unavailableReport)
	}

	select {
	case err := <-controllerErrors:
		t.Fatalf("controller fixture error: %v", err)
	default:
	}
}

type blockingActivationCanaryGateway struct {
	submission  gateway.ControlTaskSubmission
	status      gateway.TaskLifecycleStatus
	observed    gateway.TaskLifecycleStatus
	evidence    []byte
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	statusCalls atomic.Int32
}

func (gatewayFixture *blockingActivationCanaryGateway) SubmitTask(
	context.Context,
	string,
	string,
	string,
	[]byte,
) (gateway.ControlTaskSubmission, error) {
	return gatewayFixture.submission, nil
}

func (gatewayFixture *blockingActivationCanaryGateway) TaskStatus(
	ctx context.Context,
	_, _ string,
) (gateway.TaskLifecycleStatus, error) {
	gatewayFixture.statusCalls.Add(1)
	gatewayFixture.enterOnce.Do(func() { close(gatewayFixture.entered) })
	select {
	case <-gatewayFixture.release:
		return gatewayFixture.status, nil
	case <-ctx.Done():
		return gateway.TaskLifecycleStatus{}, ctx.Err()
	}
}

func (gatewayFixture *blockingActivationCanaryGateway) ObserveTask(
	context.Context,
	string,
	string,
) (gateway.TaskLifecycleStatus, error) {
	return gatewayFixture.observed, nil
}

func (gatewayFixture *blockingActivationCanaryGateway) ExportTaskEvidence(
	context.Context,
	string,
	string,
) ([]byte, error) {
	return append([]byte(nil), gatewayFixture.evidence...), nil
}

type concurrentActivationCanaryHandler struct {
	live       executorAdmissionResponse
	runtimeRef string
	stopCalls  atomic.Int32
}

func (handler *concurrentActivationCanaryHandler) ServeHTTP(
	w http.ResponseWriter,
	request *http.Request,
) {
	if request.Header.Get("Authorization") != "Bearer local-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	workloadPath := "/v1/workloads/" + handler.runtimeRef
	switch {
	case request.Method == http.MethodPost &&
		request.URL.Path == workloadPath+"/activation-canary-preflight":
		var preflight activationCanaryPreflightRequest
		if err := json.NewDecoder(request.Body).Decode(&preflight); err != nil ||
			preflight.SchemaVersion != activationCanaryPreflightRequestSchema ||
			preflight.ActivationID != handler.live.ActivationID ||
			preflight.ActivationBeginDigest !=
				handler.live.ActivationBeginDigest {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(handler.live)
	case request.Method == http.MethodPost && request.URL.Path == workloadPath+"/stop":
		handler.stopCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"runtime_ref": handler.runtimeRef,
			"status":      "stopped",
		})
	case request.Method == http.MethodPost &&
		request.URL.Path == workloadPath+"/activation-checkpoints":
		var checkpoint activationCheckpointRequest
		decoder := json.NewDecoder(io.LimitReader(
			request.Body,
			maxActivationCheckpointResponseBytes+1,
		))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&checkpoint); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(checkpoint)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func activationCanaryJobForTest(index int) activationCanaryJob {
	delivery := deliveryFixtureV4(fmt.Sprintf("runner-delivery-%02d", index), 1)
	delivery.CommandID = fmt.Sprintf("runner-command-%02d", index)
	delivery.CommandDigest = dsse.Digest([]byte(delivery.CommandID))
	return activationCanaryJob{
		ctx:        context.Background(),
		credential: "bearer",
		delivery:   delivery,
		command: command{
			CommandID: delivery.CommandID,
			TenantID:  "tenant-a",
			Kind:      "activation-canary",
			Payload:   json.RawMessage(`{"schema_version":"test"}`),
		},
	}
}

func signedDeliveryV4ForTest(
	t *testing.T,
	cmd command,
	now time.Time,
	private ed25519.PrivateKey,
) (controlprotocol.ExecutorDeliveryV4, []byte) {
	t.Helper()
	statement := admission.CommandStatement{
		SchemaVersion:      admission.CommandSchemaV2,
		CommandID:          cmd.CommandID,
		TenantID:           cmd.TenantID,
		NodeID:             cmd.NodeID,
		InstanceID:         cmd.InstanceID,
		RuntimeRef:         cmd.RuntimeRef,
		Kind:               cmd.Kind,
		Payload:            append(json.RawMessage(nil), cmd.Payload...),
		ClaimGeneration:    cmd.ClaimGeneration,
		InstanceGeneration: cmd.InstanceGeneration,
		CommandSequence:    cmd.CommandSequence,
		IssuedAt:           now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signed := signCommand(t, statement, "tenant-command", private)
	deliveryID, err := controlprotocol.ExecutorDeliveryID(
		cmd.TenantID,
		cmd.NodeID,
		cmd.CommandID,
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery := controlprotocol.ExecutorDeliveryV4{
		DeliveryID:         deliveryID,
		DeliveryGeneration: 1,
		CommandID:          cmd.CommandID,
		CommandDigest:      dsse.Digest(signed),
		CommandDSSEBase64:  base64.StdEncoding.EncodeToString(signed),
	}
	return delivery, mustJSON(t, delivery)
}

func processDeliveryV4Async(
	ctx context.Context,
	poller *Poller,
	credential *stewarduplink.Credential,
	raw []byte,
) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- poller.processDeliveryV4(ctx, credential, raw)
	}()
	return done
}

func waitForProcessDelivery(t *testing.T, done <-chan error, operation string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting to %s", operation)
		return nil
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func waitForExecutorReportV4(
	t *testing.T,
	reports <-chan controlprotocol.ExecutorReportV4,
	operation string,
) controlprotocol.ExecutorReportV4 {
	t.Helper()
	select {
	case report := <-reports:
		return report
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return controlprotocol.ExecutorReportV4{}
	}
}

func waitForRunnerAvailable(t *testing.T, runner *activationCanaryRunner) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !runner.available() {
		if time.Now().After(deadline) {
			t.Fatal("activation canary runner did not drain")
		}
		time.Sleep(time.Millisecond)
	}
}
