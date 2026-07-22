package controlstore

import (
	"errors"
	"slices"
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
			t.Fatal(err)
		}
	}
	projections, err := fixture.store.ListTaskProjections(fixture.admin, "tenant-a")
	if err != nil || len(projections) != 2 || projections[0].ProjectionID == projections[1].ProjectionID {
		t.Fatalf("projections=%+v err=%v", projections, err)
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
