package controlstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

const (
	TaskStateActivity                     = "agent_reported_activity"
	TaskStateRunning                      = "agent_reported_running"
	TaskStateCompleted                    = "agent_reported_completed"
	TaskStateFailed                       = "agent_reported_failed"
	TaskStateCancelled                    = "agent_reported_cancelled"
	TaskConditionRunIdentityConflict      = "run_identity_conflict"
	TaskConditionWorkloadIdentityConflict = "workload_identity_conflict"
	TaskConditionTerminalConflict         = "terminal_state_conflict"
)

// TaskProjection is a bounded read model over untrusted instance events. It is
// operational visibility, not task authority or proof that work was correct.
type TaskProjection struct {
	ProjectionID    string   `json:"projection_id"`
	TenantID        string   `json:"tenant_id"`
	TaskID          string   `json:"task_id"`
	InstanceID      string   `json:"instance_id"`
	Generation      uint64   `json:"generation"`
	NodeID          string   `json:"node_id"`
	RuntimeRef      string   `json:"runtime_ref"`
	RunID           string   `json:"run_id,omitempty"`
	State           string   `json:"state"`
	LatestCode      string   `json:"latest_code"`
	LatestSeverity  string   `json:"latest_severity"`
	HighestSeverity string   `json:"highest_severity"`
	LatestSummary   string   `json:"latest_summary"`
	EventCount      int      `json:"event_count"`
	FindingCount    int      `json:"finding_count"`
	FirstObservedAt string   `json:"first_observed_at"`
	LastObservedAt  string   `json:"last_observed_at"`
	LatestEventID   string   `json:"latest_event_id"`
	Conditions      []string `json:"conditions"`
}

func (projection TaskProjection) Validate() error {
	firstObservedAt, firstErr := time.Parse(time.RFC3339Nano, projection.FirstObservedAt)
	lastObservedAt, lastErr := time.Parse(time.RFC3339Nano, projection.LastObservedAt)
	if !validTaskProjectionID(projection.ProjectionID) ||
		projection.ProjectionID != taskProjectionID(projection.TenantID, projection.TaskID, projection.InstanceID, projection.Generation) ||
		!validRecordID(projection.TenantID, 128) || !validProjectionText(projection.TaskID, 256) ||
		!validProjectionText(projection.InstanceID, 256) || projection.Generation == 0 ||
		!validRecordID(projection.NodeID, 128) || !validExecutorRuntimeRef(projection.RuntimeRef) ||
		projection.RunID != "" && !validProjectionText(projection.RunID, 256) || !validRecordID(projection.LatestCode, 128) ||
		!validProjectionText(projection.LatestSummary, controlprotocol.MaxInstanceEventSummary) ||
		projection.EventCount <= 0 || projection.FindingCount < 0 || projection.FindingCount > projection.EventCount ||
		firstErr != nil || lastErr != nil || !validTimestamp(projection.FirstObservedAt) ||
		!validTimestamp(projection.LastObservedAt) || firstObservedAt.After(lastObservedAt) ||
		!validEventIdentifier(projection.LatestEventID) || !validTaskProjectionState(projection.State) ||
		!validEventSeverity(projection.LatestSeverity) || !validEventSeverity(projection.HighestSeverity) ||
		severityRank(projection.HighestSeverity) < severityRank(projection.LatestSeverity) || projection.Conditions == nil {
		return errors.New("task projection is invalid")
	}
	seen := make(map[string]struct{}, len(projection.Conditions))
	previous := ""
	for _, condition := range projection.Conditions {
		if condition != TaskConditionRunIdentityConflict && condition != TaskConditionWorkloadIdentityConflict &&
			condition != TaskConditionTerminalConflict {
			return errors.New("task projection condition is invalid")
		}
		if _, duplicate := seen[condition]; duplicate || previous != "" && condition < previous {
			return errors.New("task projection condition is duplicated")
		}
		seen[condition] = struct{}{}
		previous = condition
	}
	return nil
}

func (store *Store) ListTaskProjections(actor controlauth.Identity, tenantID string) ([]TaskProjection, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return nil, ErrNotFound
	}
	events := make([]InstanceEvent, 0)
	for _, event := range store.current.events {
		if event.Event.TenantID == tenantID && event.Event.TaskID != "" {
			events = append(events, cloneInstanceEvent(event))
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].ReceivedAt != events[j].ReceivedAt {
			return events[i].ReceivedAt < events[j].ReceivedAt
		}
		return events[i].Event.EventID < events[j].Event.EventID
	})

	byID := make(map[string]*taskProjectionAccumulator)
	for _, retained := range events {
		event := retained.Event
		id := taskProjectionID(event.TenantID, event.TaskID, event.InstanceID, event.Generation)
		accumulator := byID[id]
		if accumulator == nil {
			accumulator = &taskProjectionAccumulator{projection: TaskProjection{
				ProjectionID: id, TenantID: event.TenantID, TaskID: event.TaskID,
				InstanceID: event.InstanceID, Generation: event.Generation, NodeID: event.NodeID,
				RuntimeRef: event.RuntimeRef, State: TaskStateActivity,
				FirstObservedAt: retained.ReceivedAt,
			}}
			byID[id] = accumulator
		}
		accumulator.observe(retained)
	}

	result := make([]TaskProjection, 0, len(byID))
	for _, accumulator := range byID {
		projection := accumulator.finish()
		if err := projection.Validate(); err != nil {
			return nil, ErrUnavailable
		}
		result = append(result, projection)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LastObservedAt != result[j].LastObservedAt {
			return result[i].LastObservedAt > result[j].LastObservedAt
		}
		return result[i].ProjectionID > result[j].ProjectionID
	})
	return result, nil
}

type taskProjectionAccumulator struct {
	projection       TaskProjection
	terminalState    string
	runConflict      bool
	workloadConflict bool
	terminalConflict bool
}

func (accumulator *taskProjectionAccumulator) observe(retained InstanceEvent) {
	event := retained.Event
	projection := &accumulator.projection
	projection.EventCount++
	if event.Kind == "finding" {
		projection.FindingCount++
	}
	if projection.RunID == "" {
		projection.RunID = event.RunID
	} else if event.RunID != "" && event.RunID != projection.RunID {
		accumulator.runConflict = true
	}
	if event.NodeID != projection.NodeID || event.RuntimeRef != projection.RuntimeRef {
		accumulator.workloadConflict = true
	}
	state := taskStateForCode(event.Code)
	if isTerminalTaskState(state) {
		if accumulator.terminalState == "" {
			accumulator.terminalState = state
			projection.State = state
		} else if accumulator.terminalState != state {
			accumulator.terminalConflict = true
		}
	} else if accumulator.terminalState == "" && state == TaskStateRunning {
		projection.State = state
	}
	projection.LatestCode = event.Code
	projection.LatestSeverity = event.Severity
	if severityRank(event.Severity) > severityRank(projection.HighestSeverity) {
		projection.HighestSeverity = event.Severity
	}
	projection.LatestSummary = event.Summary
	projection.LastObservedAt = retained.ReceivedAt
	projection.LatestEventID = event.EventID
}

func (accumulator *taskProjectionAccumulator) finish() TaskProjection {
	projection := accumulator.projection
	projection.Conditions = make([]string, 0, 3)
	if accumulator.runConflict {
		projection.Conditions = append(projection.Conditions, TaskConditionRunIdentityConflict)
	}
	if accumulator.terminalConflict {
		projection.Conditions = append(projection.Conditions, TaskConditionTerminalConflict)
	}
	if accumulator.workloadConflict {
		projection.Conditions = append(projection.Conditions, TaskConditionWorkloadIdentityConflict)
	}
	sort.Strings(projection.Conditions)
	return projection
}

func taskProjectionID(tenantID, taskID, instanceID string, generation uint64) string {
	digest := sha256.Sum256([]byte(
		"steward-task-projection-v1\x00" + tenantID + "\x00" + taskID + "\x00" + instanceID + "\x00" +
			strconv.FormatUint(generation, 10),
	))
	return "task-" + hex.EncodeToString(digest[:])
}

func validTaskProjectionID(value string) bool {
	if len(value) != len("task-")+64 || value[:len("task-")] != "task-" {
		return false
	}
	_, err := hex.DecodeString(value[len("task-"):])
	return err == nil
}

func validEventIdentifier(value string) bool {
	if len(value) != len("event-")+64 || value[:len("event-")] != "event-" {
		return false
	}
	_, err := hex.DecodeString(value[len("event-"):])
	return err == nil
}

func validProjectionText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validTaskProjectionState(value string) bool {
	return value == TaskStateActivity || value == TaskStateRunning || value == TaskStateCompleted ||
		value == TaskStateFailed || value == TaskStateCancelled
}

func validEventSeverity(value string) bool {
	return value == "info" || value == "warning" || value == "critical"
}

func taskStateForCode(code string) string {
	switch code {
	case controlprotocol.InstanceEventCodeTaskStarted, controlprotocol.InstanceEventCodeTaskProgress:
		return TaskStateRunning
	case controlprotocol.InstanceEventCodeTaskCompleted:
		return TaskStateCompleted
	case controlprotocol.InstanceEventCodeTaskFailed:
		return TaskStateFailed
	case controlprotocol.InstanceEventCodeTaskCancelled:
		return TaskStateCancelled
	default:
		return TaskStateActivity
	}
}

func isTerminalTaskState(value string) bool {
	return value == TaskStateCompleted || value == TaskStateFailed || value == TaskStateCancelled
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
