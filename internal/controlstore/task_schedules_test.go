package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/schedulepermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestTaskScheduleDurablyMaterializesFiniteRuns(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	start := fixture.now.Add(3 * time.Minute).UTC().Truncate(time.Second)
	input := signedTaskScheduleInput(
		t, deployment, instance, "daily-research", start, 60, 2, []byte(`{"input":"research primary sources"}`),
	)

	created, changed, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now.Add(time.Minute))
	if err != nil || !changed || created.State != TaskScheduleActive ||
		created.NextOrdinal != 1 || created.Validate() != nil {
		t.Fatalf("create schedule = (%+v, %v, %v)", created, changed, err)
	}
	replayed, changed, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now.Add(2*time.Minute))
	if err != nil || changed || replayed.PermitDigest != created.PermitDigest {
		t.Fatalf("idempotent schedule = (%+v, %v, %v)", replayed, changed, err)
	}
	if deliveries, err := fixture.store.PollTaskRequests(node, start.Add(-time.Second), time.Minute, 4); err != nil || len(deliveries) != 0 {
		t.Fatalf("early poll = (%+v, %v)", deliveries, err)
	}
	first, err := fixture.store.PollTaskRequests(node, start, time.Minute, 4)
	if err != nil || len(first) != 1 || first[0].TaskID != "daily-research-1" ||
		first[0].Action != controlprotocol.ExecutorTaskActionSubmit {
		t.Fatalf("first scheduled delivery = (%+v, %v)", first, err)
	}
	firstTask, found, err := fixture.store.GetTaskRequest(fixture.admin, "tenant-a", "daily-research-1")
	if err != nil || !found || firstTask.ScheduleID != "daily-research" ||
		firstTask.ScheduleOrdinal != 1 || firstTask.State != TaskRequestLeased {
		t.Fatalf("first scheduled task = (%+v, %v, %v)", firstTask, found, err)
	}
	active, found, err := fixture.store.GetTaskSchedule(fixture.admin, "tenant-a", "daily-research")
	if err != nil || !found || active.NextOrdinal != 2 || active.EnqueuedRuns != 1 ||
		len(active.Runs) != 1 || active.Runs[0].State != TaskRequestLeased || active.Validate() != nil {
		t.Fatalf("active schedule = (%+v, %v, %v)", active, found, err)
	}

	// The signed max-concurrency limit prevents the second run from overlapping
	// the still-leased first run.
	if deliveries, err := fixture.store.PollTaskRequests(node, start.Add(time.Minute), time.Minute, 4); err != nil || len(deliveries) != 0 {
		t.Fatalf("overlap poll = (%+v, %v)", deliveries, err)
	}
	finished, found, err := fixture.store.GetTaskSchedule(fixture.admin, "tenant-a", "daily-research")
	if err != nil || !found || finished.State != TaskScheduleCompleted ||
		finished.SkippedRuns != 1 || finished.Runs[1].Reason != "overlap_limit" {
		t.Fatalf("completed schedule = (%+v, %v, %v)", finished, found, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted, found, err := reopened.GetTaskSchedule(fixture.admin, "tenant-a", "daily-research")
	if err != nil || !found || persisted.State != TaskScheduleCompleted ||
		persisted.EnqueuedRuns != 1 || persisted.SkippedRuns != 1 {
		t.Fatalf("reopened schedule = (%+v, %v, %v)", persisted, found, err)
	}
}

func TestTaskScheduleCancellationAndMissedWindowsNarrowAuthority(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	start := fixture.now.Add(2 * time.Minute).UTC().Truncate(time.Second)
	input := signedTaskScheduleInput(t, deployment, instance, "finite", start, 60, 3, []byte(`{"input":"bounded"}`))
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now); err != nil {
		t.Fatal(err)
	}
	cancelled, changed, err := fixture.store.CancelTaskSchedule(
		fixture.admin, "tenant-a", "finite", fixture.now.Add(time.Minute),
	)
	if err != nil || !changed || cancelled.State != TaskScheduleCancelled || cancelled.CancelledAt == "" {
		t.Fatalf("cancel schedule = (%+v, %v, %v)", cancelled, changed, err)
	}
	if deliveries, err := fixture.store.PollTaskRequests(node, start, time.Minute, 4); err != nil || len(deliveries) != 0 {
		t.Fatalf("cancelled schedule dispatched = (%+v, %v)", deliveries, err)
	}

	missed := signedTaskScheduleInput(t, deployment, instance, "missed", start, 60, 2, []byte(`{"input":"bounded"}`))
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, missed, fixture.now); err != nil {
		t.Fatal(err)
	}
	if deliveries, err := fixture.store.PollTaskRequests(node, start.Add(2*time.Minute), time.Minute, 4); err != nil || len(deliveries) != 0 {
		t.Fatalf("missed schedule poll = (%+v, %v)", deliveries, err)
	}
	status, found, err := fixture.store.GetTaskSchedule(fixture.admin, "tenant-a", "missed")
	if err != nil || !found || status.State != TaskScheduleCompleted ||
		status.SkippedRuns != 2 || status.NextOrdinal != 3 {
		t.Fatalf("missed schedule = (%+v, %v, %v)", status, found, err)
	}
}

func TestTaskScheduleRejectsConflictUnknownTargetAndExpiredAuthority(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	start := fixture.now.Add(2 * time.Minute).UTC().Truncate(time.Second)
	input := signedTaskScheduleInput(t, deployment, instance, "finite", start, 0, 1, []byte(`{"input":"one"}`))
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now); err != nil {
		t.Fatal(err)
	}
	conflict := signedTaskScheduleInput(t, deployment, instance, "finite", start, 0, 1, []byte(`{"input":"different"}`))
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, conflict, fixture.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting schedule error = %v", err)
	}
	missing := signedTaskScheduleInput(t, deployment, instance, "missing", start, 0, 1, []byte(`{"input":"one"}`))
	fixture.store.mu.Lock()
	delete(fixture.store.current.deployments, deploymentKey("tenant-a", deployment.ID))
	fixture.store.mu.Unlock()
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, missing, fixture.now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing target error = %v", err)
	}
	fixture.store.mu.Lock()
	fixture.store.current.deployments[deploymentKey("tenant-a", deployment.ID)] = deployment
	fixture.store.mu.Unlock()
	expired := signedTaskScheduleInput(t, deployment, instance, "expired", start, 0, 1, []byte(`{"input":"one"}`))
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, expired, start.Add(31*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired schedule error = %v", err)
	}
}

func TestTaskScheduleSnapshotVersionFence(t *testing.T) {
	current, limits := populatedControlState(t)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != stateFormatTaskScheduleVersion || snapshot.Schedules == nil {
		t.Fatalf("schedule snapshot fence = (%d, nil=%v)", snapshot.Version, snapshot.Schedules == nil)
	}
	snapshot.Version = stateFormatInteractionVersion
	snapshot.Schedules = nil
	legacy, _ := json.Marshal(snapshot)
	if _, err := decodeState(legacy, limits.MaxStateBytes); err != nil {
		t.Fatalf("legacy snapshot migration failed: %v", err)
	}
}

func signedTaskScheduleInput(
	t *testing.T,
	deployment Deployment,
	instance DeploymentInstance,
	scheduleID string,
	start time.Time,
	intervalSeconds int64,
	runCount uint64,
	request []byte,
) TaskScheduleInput {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statement := schedulepermit.Statement{
		SchemaVersion: schedulepermit.SchemaV1, ScheduleID: scheduleID,
		NodeID: instance.NodeID, TenantID: deployment.TenantID,
		InstanceID: instance.InstanceID, RuntimeRef: instance.Admission.RuntimeRef,
		GrantID: "grant-" + strings.Repeat("a", 64), Generation: instance.Generation,
		CapsuleDigest: instance.Admission.CapsuleDigest, PolicyDigest: instance.Admission.PolicyDigest,
		RoutePolicyDigest: "sha256:" + strings.Repeat("b", 64), ServiceID: "hermes",
		OperationID: "hermes.run", OperationPolicyDigest: "sha256:" + strings.Repeat("c", 64),
		RequestDigest: taskpermit.RequestDigest(request), RequestBytes: int64(len(request)),
		ContentType: "application/json", StartsAt: start.Format(time.RFC3339),
		IntervalSeconds: intervalSeconds, RunCount: runCount, WindowSeconds: 30,
		MaxConcurrency: 1, OverlapPolicy: "skip", MissedRunPolicy: "catch_up_one",
	}
	raw, err := schedulepermit.Sign(statement, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	return TaskScheduleInput{TenantID: deployment.TenantID, SchedulePermit: raw, Request: request}
}
