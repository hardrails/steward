package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
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

func TestTaskScheduleCarriesWorkroomContextIntoTasksAndInteractions(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	project, changed, err := fixture.store.ApplyWorkroomProject(fixture.admin, WorkroomProject{
		TenantID: "tenant-a", ID: "research", Name: "Research",
		Sessions: []WorkroomSession{{
			ID: "session-a", Title: "Primary research", TaskIDs: []string{},
		}},
		Artifacts: []WorkroomArtifact{}, MemoryRefs: []WorkroomMemoryReference{},
	}, 0, fixture.now)
	if err != nil || !changed || project.Sessions[0].State != "active" {
		t.Fatalf("create workroom=(%+v, %v, %v)", project, changed, err)
	}
	start := fixture.now.Add(time.Minute).UTC().Truncate(time.Second)
	input := signedTaskScheduleInputForWorkroom(
		t, deployment, instance, "workroom", start, 0, 1,
		[]byte(`{"input":"research"}`), "research", "session-a",
	)
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.PollTaskRequests(node, start, time.Minute, 4)
	if err != nil || len(deliveries) != 1 || deliveries[0].TaskID != "workroom-1" {
		t.Fatalf("workroom delivery=(%+v, %v)", deliveries, err)
	}
	project, err = fixture.store.GetWorkroomProject(fixture.admin, "tenant-a", "research")
	if err != nil || len(project.Sessions[0].TaskIDs) != 1 ||
		project.Sessions[0].TaskIDs[0] != "workroom-1" {
		t.Fatalf("workroom task link=(%+v, %v)", project, err)
	}

	request := storedInteractionRequest(start)
	request.TaskID = "workroom-1"
	request.NodeID = instance.NodeID
	request.InstanceID = instance.InstanceID
	request.Generation = instance.Generation
	request.RuntimeRef = instance.Admission.RuntimeRef
	request.InteractionID = interactionTestID(request.GrantID, request.IdempotencyKey)
	request.RequestDigest = controlprotocol.InteractionRequestDigest(request)
	if _, err := fixture.store.RetainInteractions(node, controlprotocol.InteractionRequestBatchV1{
		SchemaVersion: controlprotocol.InteractionBatchSchemaV1,
		NodeID:        node.NodeID, Interactions: []controlprotocol.InteractionRequestV1{request},
	}, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	linked, found, err := fixture.store.GetInteraction(
		fixture.admin, "tenant-a", request.InteractionID, start.Add(time.Minute),
	)
	if err != nil || !found || linked.ProjectID != "research" || linked.SessionID != "session-a" {
		t.Fatalf("interaction workroom link=(%+v, %v, %v)", linked, found, err)
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

func TestTaskScheduleRetentionEvictsOnlyCompletedOldestEntries(t *testing.T) {
	value := func(tenant string, index int, state string) storedTaskSchedule {
		created := time.Date(2026, 7, 23, 15, 0, index%60, 0, time.UTC).Format(time.RFC3339)
		return storedTaskSchedule{TaskSchedule: TaskSchedule{
			TenantID: tenant,
			Statement: schedulepermit.Statement{ScheduleID: "schedule-" + strings.Repeat("a", 70) +
				string(rune('a'+index/26)) + string(rune('a'+index%26))},
			State: state, CreatedAt: created, UpdatedAt: created,
		}}
	}
	perTenant := make(map[string]storedTaskSchedule)
	for index := 0; index <= MaxTaskSchedulesPerTenant; index++ {
		item := value("tenant-a", index, TaskScheduleCompleted)
		perTenant[taskScheduleKey(item.TenantID, item.Statement.ScheduleID)] = item
	}
	evicted, err := taskScheduleRetentionEvictions(perTenant)
	if err != nil || len(evicted) != 1 {
		t.Fatalf("per-tenant schedule eviction=(%+v, %v)", evicted, err)
	}
	oldest := value("tenant-a", 0, TaskScheduleActive)
	perTenant[taskScheduleKey(oldest.TenantID, oldest.Statement.ScheduleID)] = oldest
	if _, err := taskScheduleRetentionEvictions(perTenant); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("active per-tenant overflow error=%v", err)
	}

	global := make(map[string]storedTaskSchedule)
	for index := 0; index <= MaxTaskSchedulesRetained; index++ {
		tenant := "tenant-" + string(rune('a'+index/MaxTaskSchedulesPerTenant))
		item := value(tenant, index, TaskScheduleCancelled)
		global[taskScheduleKey(item.TenantID, item.Statement.ScheduleID)] = item
	}
	evicted, err = taskScheduleRetentionEvictions(global)
	if err != nil || len(evicted) != 1 {
		t.Fatalf("global schedule eviction=(%+v, %v)", evicted, err)
	}
}

func TestTaskScheduleRetentionEnforcesCourierBytesAndWorkroomState(t *testing.T) {
	now := "2026-07-23T15:00:00Z"
	old := storedTaskSchedule{TaskSchedule: TaskSchedule{
		TenantID:  "tenant-a",
		Statement: schedulepermit.Statement{ScheduleID: "old"},
		State:     TaskScheduleCompleted, CreatedAt: now, UpdatedAt: now,
	}, SchedulePermitBase64: strings.Repeat("p", 8<<20), RequestBase64: strings.Repeat("r", 8<<20)}
	replacement := storedTaskSchedule{TaskSchedule: TaskSchedule{
		TenantID:  "tenant-a",
		Statement: schedulepermit.Statement{ScheduleID: "new"},
		State:     TaskScheduleActive, CreatedAt: "2026-07-23T15:01:00Z", UpdatedAt: "2026-07-23T15:01:00Z",
	}, SchedulePermitBase64: "permit", RequestBase64: "request"}
	values := map[string]storedTaskSchedule{
		taskScheduleKey(old.TenantID, old.Statement.ScheduleID):                 old,
		taskScheduleKey(replacement.TenantID, replacement.Statement.ScheduleID): replacement,
	}
	evicted, err := taskScheduleRetentionEvictions(values)
	if err != nil || len(evicted) != 1 || evicted[0].ScheduleID != "old" {
		t.Fatalf("schedule byte eviction=(%+v, %v)", evicted, err)
	}
	old.State = TaskScheduleActive
	values[taskScheduleKey(old.TenantID, old.Statement.ScheduleID)] = old
	if _, err := taskScheduleRetentionEvictions(values); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("active byte overflow error=%v", err)
	}
	projects := map[string]WorkroomProject{
		workroomProjectKey("tenant-a", "project-a"): {
			TenantID: "tenant-a", ID: "project-a",
			Sessions: []WorkroomSession{{ID: "ended", State: "completed"}, {ID: "active", State: "active"}},
		},
	}
	if !activeWorkroomSession(projects, "tenant-a", "project-a", "active") ||
		activeWorkroomSession(projects, "tenant-a", "project-a", "ended") ||
		activeWorkroomSession(projects, "tenant-a", "missing", "active") {
		t.Fatal("active Workroom session lookup was not exact")
	}
	deletion := taskScheduleDeleteMutation("tenant-a", "old")
	if deletion.Kind != mutationTaskScheduleDelete || deletion.TaskScheduleRef == nil ||
		deletion.TaskScheduleRef.ScheduleID != "old" {
		t.Fatalf("schedule deletion=%+v", deletion)
	}
}

func TestTaskScheduleTransactionDeletionIsVersionedAndExact(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	input := signedTaskScheduleInput(
		t, deployment, instance, "finite",
		fixture.now.Add(time.Minute).UTC().Truncate(time.Second), 0, 1,
		[]byte(`{"input":"one"}`),
	)
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now); err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	current := fixture.store.current.clone()
	fixture.store.mu.Unlock()
	deletion := taskScheduleDeleteMutation("tenant-a", "finite")
	next, err := applyTransaction(current, transaction{
		Version: transactionFormatWriteVersion, Mutations: []mutation{deletion},
	})
	if err != nil || len(next.taskSchedules) != 0 {
		t.Fatalf("schedule deletion state=(%d, %v)", len(next.taskSchedules), err)
	}
	if _, err := applyTransaction(next, transaction{
		Version: transactionFormatWriteVersion, Mutations: []mutation{deletion},
	}); err == nil {
		t.Fatal("missing schedule deletion was accepted")
	}
	if _, err := applyTransaction(current, transaction{
		Version: transactionTaskScheduleVersion - 1, Mutations: []mutation{deletion},
	}); err == nil {
		t.Fatal("legacy schedule deletion was accepted")
	}
}

func TestTaskScheduleStoreRejectsInvalidBoundaryCalls(t *testing.T) {
	var unavailable *Store
	if _, _, err := unavailable.CreateTaskSchedule(controlauth.Identity{}, TaskScheduleInput{}, time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil create error=%v", err)
	}
	if _, err := unavailable.ListTaskSchedules(controlauth.Identity{}, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil list error=%v", err)
	}
	if _, _, err := unavailable.GetTaskSchedule(controlauth.Identity{}, "tenant-a", "schedule"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil get error=%v", err)
	}
	if _, _, err := unavailable.CancelTaskSchedule(controlauth.Identity{}, "tenant-a", "schedule", time.Now()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil cancel error=%v", err)
	}
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	if _, _, err := fixture.store.CreateTaskSchedule(fixture.admin, TaskScheduleInput{
		TenantID: "tenant-a",
	}, fixture.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty create error=%v", err)
	}
	if _, _, err := fixture.store.CancelTaskSchedule(fixture.admin, "tenant-a", "missing", time.Time{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero-time cancel error=%v", err)
	}
	if _, _, err := fixture.store.GetTaskSchedule(fixture.admin, "tenant-a", "missing"); err != nil {
		t.Fatalf("missing get error=%v", err)
	}
}

func TestTaskScheduleProjectionValidationRejectsStateAndRunCorruption(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	fixture.createNode(t, "tenant-a")
	deployment, instance := taskReadyDeployment(t, &fixture)
	start := fixture.now.Add(time.Minute).UTC().Truncate(time.Second)
	input := signedTaskScheduleInput(t, deployment, instance, "finite", start, 0, 1, []byte(`{"input":"one"}`))
	valid, _, err := fixture.store.CreateTaskSchedule(fixture.admin, input, fixture.now)
	if err != nil || valid.Validate() != nil {
		t.Fatalf("valid projection=(%+v, %v)", valid, err)
	}
	for name, mutate := range map[string]func(*TaskSchedule){
		"state": func(value *TaskSchedule) { value.State = "unknown" },
		"updated before created": func(value *TaskSchedule) {
			value.UpdatedAt = fixture.now.Add(-time.Minute).Format(time.RFC3339Nano)
		},
		"cancelled without time": func(value *TaskSchedule) {
			value.State = TaskScheduleCancelled
		},
		"completed too early": func(value *TaskSchedule) {
			value.State = TaskScheduleCompleted
		},
		"invalid run": func(value *TaskSchedule) {
			value.NextOrdinal, value.EnqueuedRuns = 2, 1
			value.Runs = []ScheduleRun{{
				Ordinal: 1, DueAt: "wrong", TaskID: "finite-1",
				State: TaskRequestQueued, CreatedAt: fixture.now.Format(time.RFC3339Nano),
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Runs = append([]ScheduleRun(nil), valid.Runs...)
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("corrupt task schedule projection was accepted")
			}
		})
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
	return signedTaskScheduleInputForWorkroom(
		t, deployment, instance, scheduleID, start, intervalSeconds, runCount, request, "", "",
	)
}

func signedTaskScheduleInputForWorkroom(
	t *testing.T,
	deployment Deployment,
	instance DeploymentInstance,
	scheduleID string,
	start time.Time,
	intervalSeconds int64,
	runCount uint64,
	request []byte,
	projectID, sessionID string,
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
		MaxConcurrency: 1, OverlapPolicy: "skip", MissedRunPolicy: "skip",
		ProjectID: projectID, SessionID: sessionID,
	}
	raw, err := schedulepermit.Sign(statement, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	return TaskScheduleInput{TenantID: deployment.TenantID, SchedulePermit: raw, Request: request}
}
