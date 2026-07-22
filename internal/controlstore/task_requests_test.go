package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestAsyncTaskCourierIsIdempotentDurableAndMetadataOnly(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	body := []byte(`{"input":"find the current primary source"}`)
	input := signedTaskRequestInput(t, fixture.now.Add(2*time.Minute), deployment, instance, "research-1", body)

	created, changed, err := fixture.store.SubmitTaskRequest(fixture.admin, input, fixture.now.Add(2*time.Minute))
	if err != nil || !changed || created.State != TaskRequestQueued || created.Validate() != nil {
		t.Fatalf("submit task = (%+v, %v, %v)", created, changed, err)
	}
	replayed, changed, err := fixture.store.SubmitTaskRequest(fixture.admin, input, fixture.now.Add(3*time.Minute))
	if err != nil || changed || replayed != created {
		t.Fatalf("idempotent submit = (%+v, %v, %v)", replayed, changed, err)
	}
	rawView, err := json.Marshal(created)
	if err != nil || strings.Contains(string(rawView), "find the current") || strings.Contains(string(rawView), "task_permit") ||
		strings.Contains(string(rawView), "request_base64") {
		t.Fatalf("public task view exposed courier material: %s (%v)", rawView, err)
	}

	deliveries, err := fixture.store.PollTaskRequests(node, fixture.now.Add(4*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].Action != controlprotocol.ExecutorTaskActionSubmit ||
		deliveries[0].Validate() != nil {
		t.Fatalf("submit delivery = (%+v, %v)", deliveries, err)
	}
	taskDigest := taskpermit.TaskDigest("tenant-a", instance.InstanceID, "research-1")
	accepted := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "research-1",
		Status: controlprotocol.ExecutorTaskReportAccepted, TaskDigest: taskDigest,
		PermitDigest: created.PermitDigest, RunID: "run_research_1",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, accepted, fixture.now.Add(4*time.Minute+time.Second)); err != nil || !applied {
		t.Fatalf("accepted report = (%v, %v)", applied, err)
	}

	observations, err := fixture.store.PollTaskRequests(node, fixture.now.Add(4*time.Minute+4*time.Second), time.Minute, 1)
	if err != nil || len(observations) != 1 || observations[0].Action != controlprotocol.ExecutorTaskActionObserve ||
		observations[0].TaskDigest != taskDigest || observations[0].TaskPermit != "" || observations[0].RequestBase64 != "" {
		t.Fatalf("observation delivery = (%+v, %v)", observations, err)
	}
	result := []byte(`{"answer":"primary source"}`)
	resultDigest := dsse.Digest(result)
	terminal := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    observations[0].DeliveryID, DeliveryGeneration: observations[0].DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "research-1",
		Status: controlprotocol.ExecutorTaskReportObserved, TaskDigest: taskDigest,
		PermitDigest: created.PermitDigest, RunID: "run_research_1",
		LifecycleState: "agent_reported_completed", TaskStatus: "agent_reported_completed",
		ResultDigest: resultDigest, ResponseBytes: int64(len(result)),
		ResultBase64: base64.StdEncoding.EncodeToString(result),
	}
	if applied, err := fixture.store.ApplyTaskReport(node, terminal, fixture.now.Add(4*time.Minute+5*time.Second)); err != nil || !applied {
		t.Fatalf("terminal report = (%v, %v)", applied, err)
	}
	final, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "research-1")
	if err != nil || !found || final.State != TaskRequestCompleted || final.ResultDigest != resultDigest ||
		final.ResponseBytes != int64(len(result)) || !final.ResultAvailable || final.TerminalAt == "" {
		t.Fatalf("terminal task = (%+v, %v, %v)", final, found, err)
	}
	rawResult, found, err := fixture.store.GetTaskResult(fixture.admin, "tenant-a", "research-1")
	if err != nil || !found || string(rawResult.Result) != string(result) || rawResult.ResultDigest != resultDigest {
		t.Fatalf("task result = (%+v, %v, %v)", rawResult, found, err)
	}
	publicFinal, err := json.Marshal(final)
	if err != nil || strings.Contains(string(publicFinal), "primary source") || strings.Contains(string(publicFinal), "result_base64") {
		t.Fatalf("public terminal task exposed result: %s (%v)", publicFinal, err)
	}
	if applied, err := fixture.store.ApplyTaskReport(node, accepted, fixture.now.Add(5*time.Minute)); err != nil || applied {
		t.Fatalf("stale accepted report = (%v, %v)", applied, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	final, found, err = reopened.GetTaskRequest(fixture.admin, "tenant-a", "research-1")
	if err != nil || !found || final.State != TaskRequestCompleted || final.ResultDigest != resultDigest || !final.ResultAvailable {
		t.Fatalf("reopened task = (%+v, %v, %v)", final, found, err)
	}
	rawResult, found, err = reopened.GetTaskResult(fixture.admin, "tenant-a", "research-1")
	if err != nil || !found || string(rawResult.Result) != string(result) {
		t.Fatalf("reopened task result = (%+v, %v, %v)", rawResult, found, err)
	}
}

func TestAsyncTaskCancellationDistinguishesQueuedFromDispatched(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)

	queuedInput := signedTaskRequestInput(t, now, deployment, instance, "queued-task", []byte(`{"input":"queued"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, queuedInput, now); err != nil {
		t.Fatal(err)
	}
	cancelled, changed, err := fixture.store.CancelTaskRequest(fixture.admin, "tenant-a", "queued-task", now.Add(time.Second))
	if err != nil || !changed || cancelled.State != TaskRequestCancelled || cancelled.OutcomeMayContinue {
		t.Fatalf("queued cancellation = (%+v, %v, %v)", cancelled, changed, err)
	}

	dispatchedInput := signedTaskRequestInput(t, now, deployment, instance, "dispatched-task", []byte(`{"input":"dispatched"}`))
	created, _, err := fixture.store.SubmitTaskRequest(fixture.admin, dispatchedInput, now)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.PollTaskRequests(node, now.Add(2*time.Second), time.Minute, 2)
	if err != nil || len(deliveries) != 1 || deliveries[0].TaskID != "dispatched-task" {
		t.Fatalf("dispatch poll = (%+v, %v)", deliveries, err)
	}
	requested, changed, err := fixture.store.CancelTaskRequest(fixture.admin, "tenant-a", "dispatched-task", now.Add(3*time.Second))
	if err != nil || !changed || requested.State != TaskRequestCancelRequested || !requested.OutcomeMayContinue ||
		requested.PermitDigest != created.PermitDigest {
		t.Fatalf("in-flight cancellation = (%+v, %v, %v)", requested, changed, err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(2*time.Minute), time.Minute, 2)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("cancelled ambiguous submit was redelivered = (%+v, %v)", deliveries, err)
	}
	uncertain, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "dispatched-task")
	if err != nil || !found || uncertain.State != TaskRequestOutcomeUnknown || !uncertain.OutcomeMayContinue {
		t.Fatalf("expired cancelled delivery = (%+v, %v, %v)", uncertain, found, err)
	}
}

func TestAsyncTaskUncertainObservationIsTerminalAndQuarantineStopsNewLeases(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)
	input := signedTaskRequestInput(t, now, deployment, instance, "uncertain-task", []byte(`{"input":"observe"}`))
	created, _, err := fixture.store.SubmitTaskRequest(fixture.admin, input, now)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.PollTaskRequests(node, now.Add(time.Second), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("submit poll = (%+v, %v)", deliveries, err)
	}
	taskDigest := taskpermit.TaskDigest("tenant-a", instance.InstanceID, "uncertain-task")
	accepted := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "uncertain-task",
		Status: controlprotocol.ExecutorTaskReportAccepted, TaskDigest: taskDigest,
		PermitDigest: created.PermitDigest, RunID: "run_uncertain",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, accepted, now.Add(2*time.Second)); err != nil || !applied {
		t.Fatalf("accepted report = (%v, %v)", applied, err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(5*time.Second), time.Minute, 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].Action != controlprotocol.ExecutorTaskActionObserve {
		t.Fatalf("observation poll = (%+v, %v)", deliveries, err)
	}
	uncertainReport := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "uncertain-task",
		Status: controlprotocol.ExecutorTaskReportUncertain, TaskDigest: taskDigest,
		PermitDigest: created.PermitDigest, ErrorCode: "task_not_found",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, uncertainReport, now.Add(6*time.Second)); err != nil || !applied {
		t.Fatalf("uncertain report = (%v, %v)", applied, err)
	}
	status, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "uncertain-task")
	if err != nil || !found || status.State != TaskRequestOutcomeUnknown || !status.OutcomeMayContinue || status.TerminalAt == "" {
		t.Fatalf("uncertain task = (%+v, %v, %v)", status, found, err)
	}

	second := signedTaskRequestInput(t, now, deployment, instance, "quarantined-task", []byte(`{"input":"blocked"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, second, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.ChangeNodePlacement(
		fixture.admin, "node-1", NodePlacementQuarantine, "investigate node integrity", now.Add(7*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(8*time.Second), time.Minute, 1)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("quarantined node received task = (%+v, %v)", deliveries, err)
	}
}

func TestAsyncTaskCourierBoundsAggregateBytesAndPollResponse(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)
	body := make([]byte, taskpermit.MaxRequestBytes)
	for index := range 16 {
		input := signedTaskRequestInput(t, now, deployment, instance, fmt.Sprintf("large-%02d", index), body)
		if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, input, now); err != nil {
			t.Fatal(err)
		}
	}
	deliveries, err := fixture.store.PollTaskRequests(node, now.Add(time.Second), time.Minute, 32)
	if err != nil || len(deliveries) == 0 || len(deliveries) >= 16 {
		t.Fatalf("bounded poll deliveries=%d err=%v", len(deliveries), err)
	}
	raw, err := json.Marshal(controlprotocol.ExecutorTaskPollResponseV1{
		SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, Deliveries: deliveries,
	})
	if err != nil || len(raw)+1 > controlprotocol.MaxExecutorTaskPollResponseBytes {
		t.Fatalf("poll response bytes=%d err=%v", len(raw)+1, err)
	}
	if _, err := fixture.store.taskCapacityMutationsLocked("tenant-a", MaxTaskCourierBytesPerTenant+1); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("oversized courier admission error=%v", err)
	}
	fixture.store.current.taskRequests = make(map[string]storedTaskRequest)
	for index := range MaxTaskResultBytesPerTenant / controlprotocol.MaxExecutorTaskResultBytes {
		key := fmt.Sprintf("retained-%03d", index)
		fixture.store.current.taskRequests[key] = storedTaskRequest{TaskRequest: TaskRequest{
			TenantID: "tenant-a", ResponseBytes: controlprotocol.MaxExecutorTaskResultBytes, ResultAvailable: true,
		}}
	}
	if fixture.store.taskResultCapacityAvailableLocked("tenant-a", "new", 1) {
		t.Fatal("result byte cap accepted another byte")
	}
}

func TestAsyncTaskReportsDistinguishRetryRunningAndRejection(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)

	retryInput := signedTaskRequestInput(t, now, deployment, instance, "retry-task", []byte(`{"input":"retry"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, retryInput, now); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.PollTaskRequests(node, now.Add(time.Second), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("retry delivery=(%+v, %v)", deliveries, err)
	}
	retry := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "retry-task",
		Status: controlprotocol.ExecutorTaskReportRetryable, PermitDigest: deliveries[0].PermitDigest,
		ErrorCode: "gateway_transport_unavailable",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, retry, now.Add(2*time.Second)); err != nil || !applied {
		t.Fatalf("retry report=(%v, %v)", applied, err)
	}
	retried, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "retry-task")
	if err != nil || !found || retried.State != TaskRequestQueued || retried.LastErrorCode != retry.ErrorCode {
		t.Fatalf("retried task=(%+v, %v, %v)", retried, found, err)
	}

	rejectedInput := signedTaskRequestInput(t, now, deployment, instance, "rejected-task", []byte(`{"input":"reject"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, rejectedInput, now); err != nil {
		t.Fatal(err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(3*time.Second), time.Minute, 2)
	var rejectedDelivery controlprotocol.ExecutorTaskDeliveryV1
	for _, delivery := range deliveries {
		if delivery.TaskID == "rejected-task" {
			rejectedDelivery = delivery
		}
	}
	if rejectedDelivery.TaskID == "" {
		t.Fatalf("rejected task was not leased: %+v (%v)", deliveries, err)
	}
	rejected := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    rejectedDelivery.DeliveryID, DeliveryGeneration: rejectedDelivery.DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "rejected-task",
		Status: controlprotocol.ExecutorTaskReportRejected, PermitDigest: rejectedDelivery.PermitDigest,
		ErrorCode: "permit_rejected",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, rejected, now.Add(4*time.Second)); err != nil || !applied {
		t.Fatalf("rejected report=(%v, %v)", applied, err)
	}
	failed, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "rejected-task")
	if err != nil || !found || failed.State != TaskRequestFailed || failed.TerminalAt == "" {
		t.Fatalf("rejected task=(%+v, %v, %v)", failed, found, err)
	}

	runningInput := signedTaskRequestInput(t, now, deployment, instance, "running-task", []byte(`{"input":"run"}`))
	created, _, err := fixture.store.SubmitTaskRequest(fixture.admin, runningInput, now)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(5*time.Second), time.Minute, 4)
	var runningDelivery controlprotocol.ExecutorTaskDeliveryV1
	for _, delivery := range deliveries {
		if delivery.TaskID == "running-task" {
			runningDelivery = delivery
		}
	}
	taskDigest := taskpermit.TaskDigest("tenant-a", instance.InstanceID, "running-task")
	accepted := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    runningDelivery.DeliveryID, DeliveryGeneration: runningDelivery.DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "running-task",
		Status: controlprotocol.ExecutorTaskReportAccepted, PermitDigest: created.PermitDigest,
		TaskDigest: taskDigest, RunID: "run-active",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, accepted, now.Add(6*time.Second)); err != nil || !applied {
		t.Fatalf("accepted report=(%v, %v)", applied, err)
	}
	wrongPermit := accepted
	wrongPermit.PermitDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := fixture.store.ApplyTaskReport(node, wrongPermit, now.Add(7*time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong permit report error=%v", err)
	}
	future := accepted
	future.DeliveryGeneration++
	if _, err := fixture.store.ApplyTaskReport(node, future, now.Add(7*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("future report error=%v", err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(9*time.Second), time.Minute, 4)
	for _, delivery := range deliveries {
		if delivery.TaskID == "running-task" {
			runningDelivery = delivery
		}
	}
	observed := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    runningDelivery.DeliveryID, DeliveryGeneration: runningDelivery.DeliveryGeneration,
		TenantID: "tenant-a", NodeID: "node-1", TaskID: "running-task",
		Status: controlprotocol.ExecutorTaskReportObserved, PermitDigest: created.PermitDigest,
		TaskDigest: taskDigest, RunID: "run-active", LifecycleState: "running", TaskStatus: "agent_running",
	}
	if applied, err := fixture.store.ApplyTaskReport(node, observed, now.Add(10*time.Second)); err != nil || !applied {
		t.Fatalf("running report=(%v, %v)", applied, err)
	}
	running, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "running-task")
	if err != nil || !found || running.State != TaskRequestRunning || running.ObservationAttempts != 1 {
		t.Fatalf("running task=(%+v, %v, %v)", running, found, err)
	}
}

func TestAsyncTaskCapacityEvictsOldestTerminalRecord(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.store.current.taskRequests = make(map[string]storedTaskRequest, MaxTaskRequestsPerTenant)
	for index := range MaxTaskRequestsPerTenant {
		taskID := fmt.Sprintf("terminal-%04d", index)
		terminalAt := fixture.now.Add(time.Duration(index) * time.Second).Format(time.RFC3339Nano)
		fixture.store.current.taskRequests[taskRequestKey("tenant-a", taskID)] = storedTaskRequest{
			TaskRequest: TaskRequest{TenantID: "tenant-a", TaskID: taskID, State: TaskRequestCompleted, TerminalAt: terminalAt},
			TaskPermit:  "p", RequestBase64: "cg==",
		}
	}
	mutations, err := fixture.store.taskCapacityMutationsLocked("tenant-a", 2)
	if err != nil || len(mutations) != 1 || mutations[0].Kind != mutationTaskRequestDelete ||
		mutations[0].TaskRequestRef == nil || mutations[0].TaskRequestRef.TaskID != "terminal-0000" {
		t.Fatalf("capacity eviction=(%+v, %v)", mutations, err)
	}
}

func TestAsyncTaskStoreFailsClosedForNilInvalidAndClosedState(t *testing.T) {
	var unavailable *Store
	actor := controlauth.Identity{Role: controlauth.RoleSiteAdmin}
	node := controlauth.NodeIdentity{NodeID: "node-1", TenantIDs: []string{"tenant-a"}}
	report := controlprotocol.ExecutorTaskReportV1{}
	if _, _, err := unavailable.SubmitTaskRequest(actor, TaskRequestInput{}, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil submit error=%v", err)
	}
	if _, err := unavailable.ListTaskRequests(actor, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil list error=%v", err)
	}
	if _, _, err := unavailable.GetTaskRequest(actor, "tenant-a", "task-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil get error=%v", err)
	}
	if _, _, err := unavailable.GetTaskResult(actor, "tenant-a", "task-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil result error=%v", err)
	}
	if _, _, err := unavailable.CancelTaskRequest(actor, "tenant-a", "task-a", time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil cancel error=%v", err)
	}
	if _, err := unavailable.PollTaskRequests(node, time.Now(), time.Minute, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil poll error=%v", err)
	}
	if _, err := unavailable.ApplyTaskReport(node, report, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil report error=%v", err)
	}

	fixture := newRecordsFixture(t, DefaultLimits())
	if _, _, err := fixture.store.SubmitTaskRequest(actor, TaskRequestInput{}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid submit error=%v", err)
	}
	if _, _, err := fixture.store.CancelTaskRequest(actor, "tenant-a", "task-a", time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid cancel error=%v", err)
	}
	if _, err := fixture.store.PollTaskRequests(node, time.Time{}, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid poll error=%v", err)
	}
	if _, err := fixture.store.ApplyTaskReport(node, report, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid report error=%v", err)
	}
	if _, err := fixture.store.ListTaskRequests(controlauth.Identity{}, "tenant-a"); err == nil {
		t.Fatalf("unauthenticated list error=%v", err)
	}
	if _, _, err := fixture.store.GetTaskRequest(controlauth.Identity{}, "tenant-a", "task-a"); err == nil {
		t.Fatalf("unauthenticated get error=%v", err)
	}
	if _, _, err := fixture.store.GetTaskResult(controlauth.Identity{}, "tenant-a", "task-a"); err == nil {
		t.Fatalf("unauthenticated result error=%v", err)
	}
	validNode := controlauth.NodeIdentity{CredentialID: "missing", NodeID: "node-1", TenantIDs: []string{"tenant-a"}}
	if _, err := fixture.store.PollTaskRequests(validNode, time.Now(), time.Minute, 1); err == nil {
		t.Fatalf("unauthenticated poll error=%v", err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ListTaskRequests(actor, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed list error=%v", err)
	}
	if _, _, err := fixture.store.GetTaskRequest(actor, "tenant-a", "task-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed get error=%v", err)
	}
	if _, _, err := fixture.store.GetTaskResult(actor, "tenant-a", "task-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed result error=%v", err)
	}
	if _, _, err := fixture.store.CancelTaskRequest(actor, "tenant-a", "task-a", time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed cancel error=%v", err)
	}
	if _, err := fixture.store.PollTaskRequests(node, time.Now(), time.Minute, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed poll error=%v", err)
	}
	validReport := controlprotocol.ExecutorTaskReportV1{
		SchemaVersion: controlprotocol.ExecutorTaskReportSchemaV1,
		DeliveryID:    "delivery", DeliveryGeneration: 1, TenantID: "tenant-a", NodeID: "node-1", TaskID: "task-a",
		Status:       controlprotocol.ExecutorTaskReportUncertain,
		PermitDigest: "sha256:" + strings.Repeat("a", 64), ErrorCode: "unknown",
	}
	if _, err := fixture.store.ApplyTaskReport(node, validReport, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed report error=%v", err)
	}
	if (TaskRequest{}).Validate() == nil || validTaskRequestState("not-a-state") {
		t.Fatal("invalid task projection state was accepted")
	}
}

func TestAsyncTaskLeaseExpiryAndDeadlinePreserveUncertainty(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)
	input := signedTaskRequestInput(t, now, deployment, instance, "lease-task", []byte(`{"input":"lease"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, input, now); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.PollTaskRequests(node, now.Add(time.Second), time.Second, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("initial lease=(%+v, %v)", deliveries, err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(3*time.Second), time.Minute, 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].DeliveryGeneration != 2 {
		t.Fatalf("expired lease redelivery=(%+v, %v)", deliveries, err)
	}
	deliveries, err = fixture.store.PollTaskRequests(node, now.Add(11*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("expired permit poll=(%+v, %v)", deliveries, err)
	}
	expired, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "lease-task")
	if err != nil || !found || expired.State != TaskRequestDeadlineExceeded || !expired.OutcomeMayContinue {
		t.Fatalf("expired task=(%+v, %v, %v)", expired, found, err)
	}
}

func TestAsyncTaskSubmissionRejectsMalformedConflictAndMissingTarget(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, _ = fixture.createNode(t, "tenant-a")
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, TaskRequestInput{
		TenantID: "tenant-a", TaskPermit: "malformed", Request: []byte("request"),
	}, fixture.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed permit error=%v", err)
	}
	structurallyInvalid, err := taskpermit.EncodeHeader([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, TaskRequestInput{
		TenantID: "tenant-a", TaskPermit: structurallyInvalid, Request: []byte("request"),
	}, fixture.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid permit structure error=%v", err)
	}
	deployment, instance := taskReadyDeployment(t, &fixture)
	now := fixture.now.Add(2 * time.Minute)
	input := signedTaskRequestInput(t, now, deployment, instance, "conflict-task", []byte(`{"input":"one"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(controlauth.Identity{}, input, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unauthorized submission error=%v", err)
	}
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, input, now.Add(11*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired submission error=%v", err)
	}
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, input, now); err != nil {
		t.Fatal(err)
	}
	conflict := signedTaskRequestInput(t, now, deployment, instance, "conflict-task", []byte(`{"input":"two"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting submission error=%v", err)
	}
	second := signedTaskRequestInput(t, now, deployment, instance, "delivered-task", []byte(`{"input":"delivered"}`))
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, second, now); err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	deliveredKey := taskRequestKey("tenant-a", "delivered-task")
	delivered := fixture.store.current.taskRequests[deliveredKey]
	delivered.DispatchAttempts = 1
	fixture.store.current.taskRequests[deliveredKey] = delivered
	fixture.store.mu.Unlock()
	ambiguous, changed, err := fixture.store.CancelTaskRequest(fixture.admin, "tenant-a", "delivered-task", now.Add(time.Second))
	if err != nil || !changed || ambiguous.State != TaskRequestOutcomeUnknown || !ambiguous.OutcomeMayContinue {
		t.Fatalf("previously delivered cancellation=(%+v, %v, %v)", ambiguous, changed, err)
	}
	if replayed, changed, err := fixture.store.CancelTaskRequest(fixture.admin, "tenant-a", "delivered-task", now.Add(2*time.Second)); err != nil || changed || replayed.State != TaskRequestOutcomeUnknown {
		t.Fatalf("terminal cancellation retry=(%+v, %v, %v)", replayed, changed, err)
	}
	fixture.store.mu.Lock()
	corrupt := fixture.store.current.taskRequests[deliveredKey]
	corrupt.ResultBase64, corrupt.ResultAvailable = "!!!!", true
	fixture.store.current.taskRequests[deliveredKey] = corrupt
	fixture.store.mu.Unlock()
	if _, _, err := fixture.store.GetTaskResult(fixture.admin, "tenant-a", "delivered-task"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("corrupt retained result error=%v", err)
	}
	fixture.store.mu.Lock()
	corrupt.ResultBase64, corrupt.ResultAvailable = "", false
	fixture.store.current.taskRequests[deliveredKey] = corrupt
	fixture.store.mu.Unlock()
	missing := signedTaskRequestInput(t, now, deployment, instance, "missing-task", []byte(`{"input":"missing"}`))
	missing.TenantID = "missing-tenant"
	if _, _, err := fixture.store.SubmitTaskRequest(fixture.admin, missing, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched tenant error=%v", err)
	}
	tasks, err := fixture.store.ListTaskRequests(fixture.admin, "tenant-a")
	if err != nil || len(tasks) != 2 || tasks[0].TaskID != "delivered-task" || tasks[1].TaskID != "conflict-task" {
		t.Fatalf("task list=(%+v, %v)", tasks, err)
	}
}

func taskReadyDeployment(t *testing.T, fixture *recordsFixture) (Deployment, DeploymentInstance) {
	t.Helper()
	input := deploymentApplyFixtureWithInstanceCount(t, fixture.now, "task-agent", 1, 1)
	deployment, _, err := fixture.store.ApplyDeployment(fixture.admin, input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	instance := deployment.Instances[0]
	instance.NodeID = "node-1"
	instance.Phase = DeploymentInstanceRunning
	instance.TransitionedAt = canonicalTimestamp(fixture.now.Add(time.Minute))
	instance.Intent = &admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-1", InstanceID: instance.InstanceID, LineageID: instance.LineageID,
		Generation: instance.Generation, CapsuleDigest: dsse.Digest(deployment.CapsuleDSSE),
		Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
		StateDisposition: "none",
	}
	runtimeRef := executor.RuntimeRef("tenant-a", instance.InstanceID)
	projection := minimalStoreAdmissionProjection(runtimeRef, instance.Generation)
	projection.CapsuleDigest = instance.Intent.CapsuleDigest
	instance.Admission = &projection
	deployment.Instances[0] = instance
	deployment.Phase = DeploymentReady
	deployment.Revision++
	deployment.UpdatedAt = instance.TransitionedAt
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", deployment.ID)] = deployment
	fixture.store.mu.Unlock()
	return deployment, instance
}

func signedTaskRequestInput(
	t *testing.T,
	now time.Time,
	deployment Deployment,
	instance DeploymentInstance,
	taskID string,
	body []byte,
) TaskRequestInput {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1, NodeID: instance.NodeID, TenantID: deployment.TenantID,
		InstanceID: instance.InstanceID, RuntimeRef: instance.Admission.RuntimeRef,
		GrantID: "grant-" + strings.Repeat("a", 64), Generation: instance.Generation,
		CapsuleDigest: instance.Admission.CapsuleDigest, PolicyDigest: instance.Admission.PolicyDigest,
		RoutePolicyDigest: "sha256:" + strings.Repeat("b", 64), ServiceID: "hermes",
		OperationID: "hermes.run", OperationPolicyDigest: "sha256:" + strings.Repeat("c", 64),
		TaskID: taskID, RequestDigest: taskpermit.RequestDigest(body), RequestBytes: int64(len(body)),
		ContentType: "application/json", NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, err := taskpermit.EncodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return TaskRequestInput{TenantID: deployment.TenantID, TaskPermit: header, Request: body}
}
