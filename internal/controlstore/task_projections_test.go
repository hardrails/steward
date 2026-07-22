package controlstore

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestTaskProjectionsAggregateUntrustedEventsWithoutRegressingTerminalState(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	base := fixture.now.Add(time.Minute)
	events := []controlprotocol.InstanceEventV1{
		taskProjectionEvent("tenant-a", node.NodeID, "task-start", "status", "task_started", "info", "Started.", "task-a", "run-a", base),
		taskProjectionEvent("tenant-a", node.NodeID, "task-find", "finding", "source_confirmed", "warning", "Found a source.", "task-a", "run-a", base.Add(time.Second)),
		taskProjectionEvent("tenant-a", node.NodeID, "task-done", "status", "task_completed", "info", "Completed.", "task-a", "run-a", base.Add(2*time.Second)),
		taskProjectionEvent("tenant-a", node.NodeID, "task-late", "status", "task_progress", "info", "Late progress.", "task-a", "run-a", base.Add(3*time.Second)),
		taskProjectionEvent("tenant-a", node.NodeID, "task-conflict", "status", "task_failed", "critical", "Conflicting terminal.", "task-a", "run-b", base.Add(4*time.Second)),
	}
	for index, event := range events {
		batch := controlprotocol.InstanceEventBatchRequestV1{
			SchemaVersion: controlprotocol.InstanceEventBatchV1,
			NodeID:        node.NodeID,
			Events:        []controlprotocol.InstanceEventV1{event},
		}
		if applied, err := fixture.store.RetainInstanceEvents(node, batch, base.Add(time.Duration(10+index)*time.Second)); err != nil || applied != 1 {
			t.Fatalf("retain event %d = (%d, %v)", index, applied, err)
		}
	}

	projections, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a")
	if err != nil || len(projections) != 1 {
		t.Fatalf("projections=%+v err=%v", projections, err)
	}
	projection := projections[0]
	if projection.Validate() != nil || projection.TaskID != "task-a" || projection.InstanceID != "researcher-a" ||
		projection.State != TaskStateCompleted || projection.EventCount != len(events) || projection.FindingCount != 1 ||
		projection.RunID != "run-a" || projection.LatestCode != "task_failed" || projection.HighestSeverity != "critical" ||
		!slices.Equal(projection.Conditions, []string{TaskConditionRunIdentityConflict, TaskConditionTerminalConflict}) {
		t.Fatalf("projection=%+v", projection)
	}
	if projection.FirstObservedAt != base.Add(10*time.Second).Format(time.RFC3339Nano) ||
		projection.LastObservedAt != base.Add(14*time.Second).Format(time.RFC3339Nano) ||
		projection.LatestEventID != events[len(events)-1].EventID {
		t.Fatalf("projection ordering=%+v", projection)
	}

	unauthorized := controlauth.Identity{Role: controlauth.RoleTenantOperator, TenantID: "tenant-b"}
	if _, err := fixture.store.ListTaskProjections(unauthorized, "tenant-a"); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("unauthorized projection list error=%v", err)
	}
}

func TestTaskProjectionsSeparateReusedTaskIDsByInstanceGeneration(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	first := taskProjectionEvent("tenant-a", node.NodeID, "task-one", "status", "task_started", "info", "One.", "shared-task", "run-one", fixture.now)
	second := taskProjectionEvent("tenant-a", node.NodeID, "task-two", "status", "task_started", "info", "Two.", "shared-task", "run-two", fixture.now.Add(time.Second))
	second.InstanceID = "researcher-b"
	for index, event := range []controlprotocol.InstanceEventV1{first, second} {
		batch := controlprotocol.InstanceEventBatchRequestV1{
			SchemaVersion: controlprotocol.InstanceEventBatchV1, NodeID: node.NodeID,
			Events: []controlprotocol.InstanceEventV1{event},
		}
		if _, err := fixture.store.RetainInstanceEvents(node, batch, fixture.now.Add(time.Duration(index+1)*time.Minute)); err != nil {
			fixture.store.mu.Lock()
			projections := maps.Clone(fixture.store.current.taskProjections)
			fixture.store.mu.Unlock()
			t.Fatalf("retain event %d: %v; projections=%+v", index, err, projections)
		}
	}
	projections, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a")
	if err != nil || len(projections) != 2 || projections[0].ProjectionID == projections[1].ProjectionID {
		t.Fatalf("projections=%+v err=%v", projections, err)
	}
}

func TestTaskProjectionListOrdersFractionalTimestampAfterWholeSecond(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	for index, retained := range []struct {
		taskID string
		now    time.Time
	}{
		{taskID: "task-older", now: base},
		{taskID: "task-newer", now: base.Add(time.Nanosecond)},
	} {
		event := taskProjectionEvent(
			"tenant-a", node.NodeID, "fractional-"+strconv.Itoa(index), "status",
			controlprotocol.InstanceEventCodeTaskStarted, "info", "Started.", retained.taskID, "run-a", retained.now,
		)
		batch := controlprotocol.InstanceEventBatchRequestV1{
			SchemaVersion: controlprotocol.InstanceEventBatchV1, NodeID: node.NodeID,
			Events: []controlprotocol.InstanceEventV1{event},
		}
		if _, err := fixture.store.RetainInstanceEvents(node, batch, retained.now); err != nil {
			t.Fatal(err)
		}
	}
	projections, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a")
	if err != nil || len(projections) != 2 || projections[0].TaskID != "task-newer" {
		t.Fatalf("ordered projections=%+v err=%v", projections, err)
	}
}

func TestTaskProjectionListFailsClosed(t *testing.T) {
	var unavailable *Store
	if _, err := unavailable.ListTaskProjections(controlauth.Identity{}, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil store error=%v", err)
	}
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed store error=%v", err)
	}
}

func TestTaskProjectionValidationRejectsNoncanonicalOrUnboundedFields(t *testing.T) {
	valid := TaskProjection{
		TenantID: "tenant-a", TaskID: "task-a", InstanceID: "researcher-a", Generation: 1,
		NodeID: "node-a", RuntimeRef: "executor-" + strings.Repeat("a", 64), RunID: "run-a",
		State: TaskStateRunning, LatestCode: "task_progress", LatestSeverity: "info", HighestSeverity: "warning",
		LatestSummary: "Research is running.", EventCount: 2, FindingCount: 1,
		FirstObservedAt: "2026-07-21T01:00:00Z", LastObservedAt: "2026-07-21T01:00:01Z",
		LatestEventID: "event-" + strings.Repeat("b", 64), Conditions: []string{},
	}
	valid.ProjectionID = taskProjectionID(valid.TenantID, valid.TaskID, valid.InstanceID, valid.Generation)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*TaskProjection)
	}{
		{name: "identity digest", mutate: func(value *TaskProjection) { value.TaskID = "task-b" }},
		{name: "task control", mutate: func(value *TaskProjection) { value.TaskID = "task\n" }},
		{name: "runtime", mutate: func(value *TaskProjection) { value.RuntimeRef = "executor-invalid" }},
		{name: "reversed time", mutate: func(value *TaskProjection) { value.FirstObservedAt = "2026-07-21T01:00:02Z" }},
		{name: "severity regression", mutate: func(value *TaskProjection) { value.LatestSeverity = "critical" }},
		{name: "event count", mutate: func(value *TaskProjection) { value.EventCount = MaxTaskProjectionEventCount + 1 }},
		{name: "nil conditions", mutate: func(value *TaskProjection) { value.Conditions = nil }},
		{name: "condition order", mutate: func(value *TaskProjection) {
			value.Conditions = []string{TaskConditionWorkloadIdentityConflict, TaskConditionRunIdentityConflict}
		}},
		{name: "duplicate condition", mutate: func(value *TaskProjection) {
			value.Conditions = []string{TaskConditionRunIdentityConflict, TaskConditionRunIdentityConflict}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Conditions = append([]string{}, valid.Conditions...)
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid projection accepted: %+v", candidate)
			}
		})
	}
}

func TestTaskProjectionSurvivesSourceEventDeletionAndSnapshotRoundTrip(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	event := taskProjectionEvent(
		"tenant-a", node.NodeID, "terminal", "status", controlprotocol.InstanceEventCodeTaskCompleted,
		"info", "Completed.", "task-a", "run-a", fixture.now,
	)
	batch := controlprotocol.InstanceEventBatchRequestV1{
		SchemaVersion: controlprotocol.InstanceEventBatchV1,
		NodeID:        node.NodeID,
		Events:        []controlprotocol.InstanceEventV1{event},
	}
	if applied, err := fixture.store.RetainInstanceEvents(node, batch, fixture.now.Add(time.Minute)); err != nil || applied != 1 {
		t.Fatalf("retain terminal event=(%d, %v)", applied, err)
	}
	if err := fixture.store.applyMutations(mutation{Kind: mutationInstanceEventDelete, EventID: event.EventID}); err != nil {
		t.Fatalf("delete source event: %v", err)
	}
	if events, err := fixture.store.ListInstanceEvents(fixture.admin, "tenant-a"); err != nil || len(events) != 0 {
		t.Fatalf("source events=%+v err=%v", events, err)
	}
	projections, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a")
	if err != nil || len(projections) != 1 || projections[0].State != TaskStateCompleted || projections[0].EventCount != 1 {
		t.Fatalf("durable projections=%+v err=%v", projections, err)
	}

	raw, err := encodeState(fixture.store.current, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := decodeState(raw, fixture.limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	projection := recovered.taskProjections[projections[0].ProjectionID]
	if projection.State != TaskStateCompleted || projection.EventCount != 1 {
		t.Fatalf("recovered projection=%+v", projection)
	}
}

func TestTaskProjectionStateFormatMigratesEventsAndRejectsSmuggling(t *testing.T) {
	current, limits := populatedControlState(t)
	nodeID := "node-a"
	event := taskProjectionEvent(
		"tenant-a", nodeID, "migration", "status", controlprotocol.InstanceEventCodeTaskCompleted,
		"info", "Completed.", "task-a", "run-a", time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
	)
	retained := InstanceEvent{Event: event, ReceivedAt: "2026-07-21T12:01:00Z"}
	current.events[event.EventID] = retained
	observeTaskProjection(current.taskProjections, retained)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotState
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tasks) != 1 {
		t.Fatalf("current snapshot tasks=%+v", snapshot.Tasks)
	}

	legacy := snapshot
	legacy.Version = stateFormatTaskProjectionVersion - 1
	legacy.Tasks = nil
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := decodeState(legacyRaw, limits.MaxStateBytes)
	if err != nil || len(migrated.taskProjections) != 1 {
		t.Fatalf("legacy migration tasks=%+v err=%v", migrated.taskProjections, err)
	}

	legacy.Tasks = snapshot.Tasks
	smuggled, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(smuggled, limits.MaxStateBytes); err == nil {
		t.Fatal("legacy snapshot smuggled task projection state")
	}

	snapshot.Tasks = append(snapshot.Tasks, snapshot.Tasks[0])
	duplicate, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(duplicate, limits.MaxStateBytes); err == nil {
		t.Fatal("snapshot accepted duplicate task projection identity")
	}
}

func TestTaskProjectionRetentionIsBoundedPerTenantAndSite(t *testing.T) {
	projections := make(map[string]TaskProjection)
	for index := 0; index <= MaxTaskProjectionsPerTenant; index++ {
		projection := retainedTaskProjection("tenant-a", index)
		projections[projection.ProjectionID] = projection
	}
	for tenantIndex := 0; tenantIndex < 3; tenantIndex++ {
		for index := 0; index < MaxTaskProjectionsPerTenant; index++ {
			projection := retainedTaskProjection("tenant-"+string(rune('b'+tenantIndex)), index)
			projections[projection.ProjectionID] = projection
		}
	}
	evicted := taskProjectionEvictions(projections)
	if len(evicted) != 1 || evicted[0] != retainedTaskProjection("tenant-a", 0).ProjectionID {
		t.Fatalf("per-tenant evictions=%+v", evicted)
	}

	extra := retainedTaskProjection("tenant-e", 0)
	projections[extra.ProjectionID] = extra
	for _, id := range evicted {
		delete(projections, id)
	}
	evicted = taskProjectionEvictions(projections)
	if len(evicted) != 1 {
		t.Fatalf("site evictions=%+v", evicted)
	}
}

func retainedTaskProjection(tenantID string, index int) TaskProjection {
	taskID := "task-" + strconv.Itoa(index)
	observedAt := time.Date(2026, 7, 21, 12, 0, 0, index, time.UTC).Format(time.RFC3339Nano)
	projection := TaskProjection{
		TenantID: tenantID, TaskID: taskID, InstanceID: "researcher-a", Generation: 1,
		NodeID: "node-a", RuntimeRef: "executor-" + strings.Repeat("a", 64), State: TaskStateActivity,
		LatestCode: "activity", LatestSeverity: "info", HighestSeverity: "info", LatestSummary: "Activity.",
		EventCount: 1, FirstObservedAt: observedAt, LastObservedAt: observedAt,
		LatestEventID: "event-" + strings.Repeat("b", 64), Conditions: []string{},
	}
	projection.ProjectionID = taskProjectionID(tenantID, taskID, projection.InstanceID, projection.Generation)
	return projection
}

func taskProjectionEvent(
	tenantID, nodeID, key, kind, code, severity, summary, taskID, runID string,
	observed time.Time,
) controlprotocol.InstanceEventV1 {
	event := testControllerEvent(tenantID, nodeID, key, observed)
	event.Kind = kind
	event.Code = code
	event.Severity = severity
	event.Summary = summary
	event.TaskID = taskID
	event.RunID = runID
	return event
}
