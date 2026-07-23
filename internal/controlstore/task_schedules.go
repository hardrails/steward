package controlstore

import (
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/schedulepermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	MaxTaskSchedulesRetained      = 512
	MaxTaskSchedulesPerTenant     = 128
	MaxTaskScheduleBytesRetained  = 64 << 20
	MaxTaskScheduleBytesPerTenant = 16 << 20
	MaxTaskScheduleRunHistory     = 256

	TaskScheduleActive    = "active"
	TaskScheduleCancelled = "cancelled"
	TaskScheduleCompleted = "completed"

	ScheduleRunQueued  = "queued"
	ScheduleRunSkipped = "skipped"
)

type ScheduleRun struct {
	Ordinal   uint64 `json:"ordinal"`
	DueAt     string `json:"due_at"`
	TaskID    string `json:"task_id"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at"`
}

type TaskSchedule struct {
	TenantID     string                   `json:"tenant_id"`
	Statement    schedulepermit.Statement `json:"schedule"`
	PermitDigest string                   `json:"permit_digest"`
	PermitKeyID  string                   `json:"permit_key_id"`
	State        string                   `json:"state"`
	NextOrdinal  uint64                   `json:"next_ordinal"`
	EnqueuedRuns uint64                   `json:"enqueued_runs"`
	SkippedRuns  uint64                   `json:"skipped_runs"`
	Runs         []ScheduleRun            `json:"runs"`
	CreatedAt    string                   `json:"created_at"`
	UpdatedAt    string                   `json:"updated_at"`
	CancelledAt  string                   `json:"cancelled_at,omitempty"`
}

type storedTaskSchedule struct {
	TaskSchedule         `json:"task_schedule"`
	SchedulePermitBase64 string `json:"schedule_permit_base64"`
	RequestBase64        string `json:"request_base64"`
}

type TaskScheduleInput struct {
	TenantID       string
	SchedulePermit []byte
	Request        []byte
}

func (schedule TaskSchedule) Validate() error {
	if schedule.Statement.Validate() != nil || schedule.TenantID != schedule.Statement.TenantID ||
		!validSHA256Digest(schedule.PermitDigest) || !validRecordID(schedule.PermitKeyID, 128) ||
		(schedule.State != TaskScheduleActive && schedule.State != TaskScheduleCancelled &&
			schedule.State != TaskScheduleCompleted) ||
		schedule.NextOrdinal == 0 || schedule.NextOrdinal > schedule.Statement.RunCount+1 ||
		schedule.EnqueuedRuns+schedule.SkippedRuns != schedule.NextOrdinal-1 ||
		len(schedule.Runs) > MaxTaskScheduleRunHistory ||
		!validTimestamp(schedule.CreatedAt) || !validTimestamp(schedule.UpdatedAt) {
		return errors.New("task schedule projection is invalid")
	}
	created, _ := parseTimestamp(schedule.CreatedAt)
	updated, _ := parseTimestamp(schedule.UpdatedAt)
	if updated.Before(created) ||
		schedule.State == TaskScheduleCompleted && schedule.NextOrdinal != schedule.Statement.RunCount+1 ||
		(schedule.State == TaskScheduleCancelled) != (schedule.CancelledAt != "") ||
		schedule.CancelledAt != "" && !validTimestamp(schedule.CancelledAt) {
		return errors.New("task schedule state is invalid")
	}
	var previous uint64
	for _, run := range schedule.Runs {
		due, taskID, err := schedule.Statement.Run(run.Ordinal)
		if err != nil || run.Ordinal <= previous || run.DueAt != due.Format(time.RFC3339) ||
			run.TaskID != taskID || (run.State != ScheduleRunSkipped && !validTaskRequestState(run.State)) ||
			run.State != ScheduleRunSkipped && run.Reason != "" ||
			run.State == ScheduleRunSkipped && !validRecordID(run.Reason, 128) ||
			!validTimestamp(run.CreatedAt) {
			return errors.New("task schedule run history is invalid")
		}
		previous = run.Ordinal
	}
	return nil
}

func (store *Store) CreateTaskSchedule(
	actor controlauth.Identity,
	input TaskScheduleInput,
	now time.Time,
) (TaskSchedule, bool, error) {
	if store == nil {
		return TaskSchedule{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, input.TenantID) ||
		len(input.SchedulePermit) == 0 || len(input.SchedulePermit) > schedulepermit.MaxEnvelopeBytes ||
		len(input.Request) == 0 || int64(len(input.Request)) > taskpermit.MaxRequestBytes {
		return TaskSchedule{}, false, invalid("task schedule input is invalid or exceeds its bound")
	}
	inspected, err := schedulepermit.InspectUnverified(input.SchedulePermit)
	if err != nil || inspected.Statement.TenantID != input.TenantID ||
		inspected.Statement.RequestDigest != taskpermit.RequestDigest(input.Request) ||
		inspected.Statement.RequestBytes != int64(len(input.Request)) {
		return TaskSchedule{}, false, invalid("signed schedule does not bind this tenant and exact request")
	}
	lastDue, _, err := inspected.Statement.Run(inspected.Statement.RunCount)
	if err != nil || !now.Before(lastDue.Add(time.Duration(inspected.Statement.WindowSeconds)*time.Second)) {
		return TaskSchedule{}, false, invalid("signed schedule has no remaining dispatch window")
	}
	stored := storedTaskSchedule{
		TaskSchedule: TaskSchedule{
			TenantID: input.TenantID, Statement: inspected.Statement,
			PermitDigest: inspected.EnvelopeDigest, PermitKeyID: inspected.KeyID,
			State: TaskScheduleActive, NextOrdinal: 1, Runs: []ScheduleRun{},
			CreatedAt: canonicalTimestamp(now), UpdatedAt: canonicalTimestamp(now),
		},
		SchedulePermitBase64: base64.StdEncoding.EncodeToString(input.SchedulePermit),
		RequestBase64:        base64.StdEncoding.EncodeToString(input.Request),
	}
	if !validStoredTaskSchedule(stored) {
		return TaskSchedule{}, false, invalid("task schedule courier is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskSchedule{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskSchedule{}, false, err
	}
	statement := inspected.Statement
	if tenant, found := store.current.tenants[input.TenantID]; !found || !tenant.Active ||
		!scheduleTargetExists(store.current.deployments, statement) {
		return TaskSchedule{}, false, ErrNotFound
	}
	if statement.ProjectID != "" && !activeWorkroomSession(
		store.current.workroomProjects, statement.TenantID, statement.ProjectID, statement.SessionID,
	) {
		return TaskSchedule{}, false, ErrNotFound
	}
	key := taskScheduleKey(input.TenantID, statement.ScheduleID)
	if existing, found := store.current.taskSchedules[key]; found {
		if reflect.DeepEqual(existing.Statement, stored.Statement) &&
			existing.SchedulePermitBase64 == stored.SchedulePermitBase64 &&
			existing.RequestBase64 == stored.RequestBase64 {
			return projectTaskSchedule(existing, store.current.taskRequests), false, nil
		}
		return TaskSchedule{}, false, ErrConflict
	}
	candidates := make(map[string]storedTaskSchedule, len(store.current.taskSchedules)+1)
	for candidateKey, schedule := range store.current.taskSchedules {
		candidates[candidateKey] = cloneStoredTaskSchedule(schedule)
	}
	candidates[key] = stored
	evictions, err := taskScheduleRetentionEvictions(candidates)
	if err != nil {
		return TaskSchedule{}, false, err
	}
	mutations := make([]mutation, 0, len(evictions)+1)
	for _, ref := range evictions {
		if _, exists := store.current.taskSchedules[taskScheduleKey(ref.TenantID, ref.ScheduleID)]; exists {
			mutations = append(mutations, taskScheduleDeleteMutation(ref.TenantID, ref.ScheduleID))
		}
	}
	mutations = append(mutations, taskScheduleMutation(stored))
	if len(mutations) > maxMutationsPerRecord {
		return TaskSchedule{}, false, ErrCapacityExceeded
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return TaskSchedule{}, false, err
	}
	return projectTaskSchedule(stored, store.current.taskRequests), true, nil
}

func (store *Store) ListTaskSchedules(
	actor controlauth.Identity,
	tenantID string,
) ([]TaskSchedule, error) {
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
	result := make([]TaskSchedule, 0)
	for _, schedule := range store.current.taskSchedules {
		if schedule.TenantID == tenantID {
			result = append(result, projectTaskSchedule(schedule, store.current.taskRequests))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt != result[j].CreatedAt {
			return result[i].CreatedAt > result[j].CreatedAt
		}
		return result[i].Statement.ScheduleID > result[j].Statement.ScheduleID
	})
	return result, nil
}

func (store *Store) GetTaskSchedule(
	actor controlauth.Identity,
	tenantID, scheduleID string,
) (TaskSchedule, bool, error) {
	if store == nil {
		return TaskSchedule{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskSchedule{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskSchedule{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return TaskSchedule{}, false, ErrNotFound
	}
	schedule, found := store.current.taskSchedules[taskScheduleKey(tenantID, scheduleID)]
	return projectTaskSchedule(schedule, store.current.taskRequests), found, nil
}

func (store *Store) CancelTaskSchedule(
	actor controlauth.Identity,
	tenantID, scheduleID string,
	now time.Time,
) (TaskSchedule, bool, error) {
	if store == nil {
		return TaskSchedule{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, tenantID) {
		return TaskSchedule{}, false, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskSchedule{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskSchedule{}, false, err
	}
	key := taskScheduleKey(tenantID, scheduleID)
	schedule, found := store.current.taskSchedules[key]
	if !found {
		return TaskSchedule{}, false, ErrNotFound
	}
	if schedule.State != TaskScheduleActive {
		return projectTaskSchedule(schedule, store.current.taskRequests), false, nil
	}
	schedule.State = TaskScheduleCancelled
	schedule.CancelledAt, schedule.UpdatedAt = canonicalTimestamp(now), canonicalTimestamp(now)
	if err := store.applyMutationsLocked(taskScheduleMutation(schedule)); err != nil {
		return TaskSchedule{}, false, err
	}
	return projectTaskSchedule(schedule, store.current.taskRequests), true, nil
}

// materializeDueTaskSchedule is called only while Store.mu is held after the
// node identity is revalidated. At most one run is enqueued per node poll, which
// bounds transaction size and lets ordinary task delivery provide backpressure.
func (store *Store) materializeDueTaskSchedule(
	identity controlauth.NodeIdentity,
	now time.Time,
) error {
	keys := make([]string, 0)
	for key, schedule := range store.current.taskSchedules {
		if schedule.State == TaskScheduleActive && schedule.Statement.NodeID == identity.NodeID &&
			controlauth.NodeAuthorizedTenant(identity, schedule.TenantID) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		schedule := cloneStoredTaskSchedule(store.current.taskSchedules[key])
		changed, enqueue, err := advanceTaskSchedule(&schedule, store.current.taskRequests, now)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		if enqueue == nil {
			return store.applyMutationsLocked(taskScheduleMutation(schedule))
		}
		task, projectMutation, err := store.scheduledTaskMutations(schedule, *enqueue, now)
		if err != nil {
			if errors.Is(err, ErrCapacityExceeded) || errors.Is(err, ErrConflict) ||
				errors.Is(err, ErrNotFound) {
				reason := "courier_capacity"
				if errors.Is(err, ErrNotFound) {
					reason = "target_unavailable"
				}
				appendScheduleRun(&schedule, ScheduleRun{
					Ordinal: enqueue.Ordinal, DueAt: enqueue.DueAt.Format(time.RFC3339),
					TaskID: enqueue.TaskID, State: ScheduleRunSkipped,
					Reason: reason, CreatedAt: canonicalTimestamp(now),
				})
				schedule.NextOrdinal++
				schedule.SkippedRuns++
				finishTaskSchedule(&schedule, now)
				return store.applyMutationsLocked(taskScheduleMutation(schedule))
			}
			return err
		}
		appendScheduleRun(&schedule, ScheduleRun{
			Ordinal: enqueue.Ordinal, DueAt: enqueue.DueAt.Format(time.RFC3339),
			TaskID: enqueue.TaskID, State: ScheduleRunQueued,
			CreatedAt: canonicalTimestamp(now),
		})
		schedule.NextOrdinal++
		schedule.EnqueuedRuns++
		finishTaskSchedule(&schedule, now)
		mutations, err := store.taskCapacityMutationsLocked(schedule.TenantID, taskCourierBytes(task))
		if err != nil {
			return err
		}
		if projectMutation != nil {
			mutations = append(mutations, *projectMutation)
		}
		mutations = append(mutations, taskRequestMutation(task), taskScheduleMutation(schedule))
		return store.applyMutationsLocked(mutations...)
	}
	return nil
}

type dueScheduleRun struct {
	Ordinal uint64
	DueAt   time.Time
	TaskID  string
}

func advanceTaskSchedule(
	schedule *storedTaskSchedule,
	tasks map[string]storedTaskRequest,
	now time.Time,
) (bool, *dueScheduleRun, error) {
	changed := false
	for schedule.NextOrdinal <= schedule.Statement.RunCount {
		due, taskID, err := schedule.Statement.Run(schedule.NextOrdinal)
		if err != nil {
			return false, nil, err
		}
		windowEnd := due.Add(time.Duration(schedule.Statement.WindowSeconds) * time.Second)
		if !now.Before(windowEnd) {
			appendScheduleRun(schedule, ScheduleRun{
				Ordinal: schedule.NextOrdinal, DueAt: due.Format(time.RFC3339),
				TaskID: taskID, State: ScheduleRunSkipped,
				Reason: "missed_window", CreatedAt: canonicalTimestamp(now),
			})
			schedule.NextOrdinal++
			schedule.SkippedRuns++
			changed = true
			continue
		}
		if now.Before(due) {
			break
		}
		active := activeScheduleTasks(*schedule, tasks)
		if active >= schedule.Statement.MaxConcurrency {
			if schedule.Statement.OverlapPolicy == "queue" {
				break
			}
			appendScheduleRun(schedule, ScheduleRun{
				Ordinal: schedule.NextOrdinal, DueAt: due.Format(time.RFC3339),
				TaskID: taskID, State: ScheduleRunSkipped,
				Reason: "overlap_limit", CreatedAt: canonicalTimestamp(now),
			})
			schedule.NextOrdinal++
			schedule.SkippedRuns++
			changed = true
			continue
		}
		return true, &dueScheduleRun{Ordinal: schedule.NextOrdinal, DueAt: due, TaskID: taskID}, nil
	}
	if schedule.NextOrdinal > schedule.Statement.RunCount {
		finishTaskSchedule(schedule, now)
		changed = true
	}
	if changed {
		schedule.UpdatedAt = canonicalTimestamp(now)
	}
	return changed, nil, nil
}

func (store *Store) scheduledTaskMutations(
	schedule storedTaskSchedule,
	run dueScheduleRun,
	now time.Time,
) (storedTaskRequest, *mutation, error) {
	scheduleRaw, err := base64.StdEncoding.DecodeString(schedule.SchedulePermitBase64)
	if err != nil {
		return storedTaskRequest{}, nil, ErrUnavailable
	}
	runRaw, err := schedulepermit.BuildRunPermit(scheduleRaw, run.Ordinal)
	if err != nil {
		return storedTaskRequest{}, nil, ErrUnavailable
	}
	inspected, err := schedulepermit.InspectRunUnverified(runRaw)
	if err != nil || inspected.TaskID != run.TaskID {
		return storedTaskRequest{}, nil, ErrUnavailable
	}
	request, err := base64.StdEncoding.DecodeString(schedule.RequestBase64)
	if err != nil {
		return storedTaskRequest{}, nil, ErrUnavailable
	}
	deadline := run.DueAt.Add(time.Duration(schedule.Statement.WindowSeconds) * time.Second)
	task := storedTaskRequest{
		TaskRequest: TaskRequest{
			TenantID:  schedule.TenantID,
			ProjectID: schedule.Statement.ProjectID, SessionID: schedule.Statement.SessionID,
			TaskID: run.TaskID, NodeID: schedule.Statement.NodeID,
			InstanceID:         schedule.Statement.InstanceID,
			InstanceGeneration: schedule.Statement.Generation,
			RuntimeRef:         schedule.Statement.RuntimeRef, ServiceID: schedule.Statement.ServiceID,
			OperationID:   schedule.Statement.OperationID,
			RequestDigest: schedule.Statement.RequestDigest, RequestBytes: int64(len(request)),
			PermitDigest: inspected.RunPermitDigest, PermitKeyID: inspected.KeyID,
			Deadline: deadline.Format(time.RFC3339), State: TaskRequestQueued,
			ScheduleID: schedule.Statement.ScheduleID, ScheduleOrdinal: run.Ordinal,
			CreatedAt: canonicalTimestamp(now), UpdatedAt: canonicalTimestamp(now),
		},
		GrantID:       schedule.Statement.GrantID,
		TaskPermit:    base64.RawURLEncoding.EncodeToString(runRaw),
		RequestBase64: schedule.RequestBase64,
	}
	key := taskRequestKey(task.TenantID, task.TaskID)
	if existing, found := store.current.taskRequests[key]; found {
		if taskRequestInputEqual(existing, task) &&
			existing.ScheduleID == task.ScheduleID && existing.ScheduleOrdinal == task.ScheduleOrdinal {
			return existing, nil, nil
		}
		return storedTaskRequest{}, nil, ErrConflict
	}
	if !scheduleTargetExists(store.current.deployments, schedule.Statement) {
		return storedTaskRequest{}, nil, ErrNotFound
	}
	var projectMutation *mutation
	if schedule.Statement.ProjectID != "" {
		projectKey := workroomProjectKey(
			schedule.TenantID, schedule.Statement.ProjectID,
		)
		project, found := store.current.workroomProjects[projectKey]
		if !found {
			return storedTaskRequest{}, nil, ErrNotFound
		}
		for index := range project.Sessions {
			if project.Sessions[index].ID != schedule.Statement.SessionID ||
				project.Sessions[index].State != "active" ||
				len(project.Sessions[index].TaskIDs) >= MaxWorkroomTasksPerSession {
				continue
			}
			project.Sessions[index].TaskIDs = append(
				project.Sessions[index].TaskIDs, task.TaskID,
			)
			project.Sessions[index].TaskIDs = canonicalStringSet(project.Sessions[index].TaskIDs)
			project.Sessions[index].UpdatedAt = canonicalTimestamp(now)
			project.Revision++
			project.UpdatedAt = canonicalTimestamp(now)
			value := workroomProjectMutation(project)
			projectMutation = &value
			break
		}
		if projectMutation == nil {
			return storedTaskRequest{}, nil, ErrCapacityExceeded
		}
	}
	if !validStoredTaskRequest(task) {
		return storedTaskRequest{}, nil, ErrUnavailable
	}
	return task, projectMutation, nil
}

func activeScheduleTasks(schedule storedTaskSchedule, tasks map[string]storedTaskRequest) int {
	active := 0
	for _, task := range tasks {
		if task.TenantID == schedule.TenantID &&
			task.ScheduleID == schedule.Statement.ScheduleID &&
			!taskTerminal(task.State) {
			active++
		}
	}
	return active
}

func finishTaskSchedule(schedule *storedTaskSchedule, now time.Time) {
	schedule.UpdatedAt = canonicalTimestamp(now)
	if schedule.NextOrdinal > schedule.Statement.RunCount {
		schedule.State = TaskScheduleCompleted
	}
}

func appendScheduleRun(schedule *storedTaskSchedule, run ScheduleRun) {
	schedule.Runs = append(schedule.Runs, run)
	if len(schedule.Runs) > MaxTaskScheduleRunHistory {
		schedule.Runs = append([]ScheduleRun(nil), schedule.Runs[len(schedule.Runs)-MaxTaskScheduleRunHistory:]...)
	}
}

func projectTaskSchedule(
	stored storedTaskSchedule,
	tasks map[string]storedTaskRequest,
) TaskSchedule {
	result := cloneStoredTaskSchedule(stored).TaskSchedule
	for index := range result.Runs {
		if result.Runs[index].State != ScheduleRunQueued {
			continue
		}
		if task, found := tasks[taskRequestKey(result.TenantID, result.Runs[index].TaskID)]; found {
			result.Runs[index].State = task.State
		}
	}
	return result
}

func scheduleTargetExists(
	deployments map[string]Deployment,
	statement schedulepermit.Statement,
) bool {
	taskStatement := taskpermit.Statement{
		TenantID: statement.TenantID, NodeID: statement.NodeID,
		InstanceID: statement.InstanceID, Generation: statement.Generation,
		RuntimeRef: statement.RuntimeRef,
	}
	return taskTargetExists(deployments, taskStatement)
}

func activeWorkroomSession(
	projects map[string]WorkroomProject,
	tenantID, projectID, sessionID string,
) bool {
	project, found := projects[workroomProjectKey(tenantID, projectID)]
	if !found {
		return false
	}
	for _, session := range project.Sessions {
		if session.ID == sessionID && session.State == "active" {
			return true
		}
	}
	return false
}

func cloneStoredTaskSchedule(value storedTaskSchedule) storedTaskSchedule {
	value.Runs = append([]ScheduleRun(nil), value.Runs...)
	return value
}

func validStoredTaskSchedule(value storedTaskSchedule) bool {
	if value.TaskSchedule.Validate() != nil {
		return false
	}
	for _, run := range value.Runs {
		if run.State != ScheduleRunQueued && run.State != ScheduleRunSkipped {
			return false
		}
	}
	permit, err := base64.StdEncoding.DecodeString(value.SchedulePermitBase64)
	if err != nil || base64.StdEncoding.EncodeToString(permit) != value.SchedulePermitBase64 {
		return false
	}
	inspected, err := schedulepermit.InspectUnverified(permit)
	if err != nil || inspected.Statement != value.Statement ||
		inspected.EnvelopeDigest != value.PermitDigest || inspected.KeyID != value.PermitKeyID {
		return false
	}
	request, err := base64.StdEncoding.DecodeString(value.RequestBase64)
	return err == nil && len(request) > 0 && int64(len(request)) == value.Statement.RequestBytes &&
		base64.StdEncoding.EncodeToString(request) == value.RequestBase64 &&
		taskpermit.RequestDigest(request) == value.Statement.RequestDigest
}

func taskScheduleMutation(value storedTaskSchedule) mutation {
	cloned := cloneStoredTaskSchedule(value)
	return mutation{Kind: mutationTaskSchedule, TaskSchedule: &cloned}
}

func taskScheduleDeleteMutation(tenantID, scheduleID string) mutation {
	return mutation{
		Kind:            mutationTaskScheduleDelete,
		TaskScheduleRef: &taskScheduleReference{TenantID: tenantID, ScheduleID: scheduleID},
	}
}

func taskScheduleKey(tenantID, scheduleID string) string {
	return tenantID + "\x00" + scheduleID
}

func taskScheduleCourierBytes(value storedTaskSchedule) int64 {
	return int64(len(value.SchedulePermitBase64) + len(value.RequestBase64))
}

func taskScheduleRetentionEvictions(
	values map[string]storedTaskSchedule,
) ([]taskScheduleReference, error) {
	byTenant := make(map[string][]storedTaskSchedule)
	var totalBytes int64
	tenantBytes := make(map[string]int64)
	for _, value := range values {
		byTenant[value.TenantID] = append(byTenant[value.TenantID], value)
		size := taskScheduleCourierBytes(value)
		totalBytes += size
		tenantBytes[value.TenantID] += size
	}
	evicted := make(map[string]taskScheduleReference)
	terminal := func(value storedTaskSchedule) bool { return value.State != TaskScheduleActive }
	oldest := func(values []storedTaskSchedule) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].CreatedAt != values[j].CreatedAt {
				return values[i].CreatedAt < values[j].CreatedAt
			}
			return values[i].Statement.ScheduleID < values[j].Statement.ScheduleID
		})
	}
	for tenantID, schedules := range byTenant {
		oldest(schedules)
		for len(schedules) > MaxTaskSchedulesPerTenant ||
			tenantBytes[tenantID] > MaxTaskScheduleBytesPerTenant {
			candidate := schedules[0]
			if !terminal(candidate) {
				return nil, ErrCapacityExceeded
			}
			ref := taskScheduleReference{TenantID: tenantID, ScheduleID: candidate.Statement.ScheduleID}
			evicted[taskScheduleKey(ref.TenantID, ref.ScheduleID)] = ref
			size := taskScheduleCourierBytes(candidate)
			tenantBytes[tenantID] -= size
			totalBytes -= size
			schedules = schedules[1:]
		}
	}
	remaining := make([]storedTaskSchedule, 0, len(values)-len(evicted))
	for key, value := range values {
		if _, removed := evicted[key]; !removed {
			remaining = append(remaining, value)
		}
	}
	oldest(remaining)
	for len(remaining) > MaxTaskSchedulesRetained ||
		totalBytes > MaxTaskScheduleBytesRetained {
		candidate := remaining[0]
		if !terminal(candidate) {
			return nil, ErrCapacityExceeded
		}
		ref := taskScheduleReference{
			TenantID: candidate.TenantID, ScheduleID: candidate.Statement.ScheduleID,
		}
		evicted[taskScheduleKey(ref.TenantID, ref.ScheduleID)] = ref
		totalBytes -= taskScheduleCourierBytes(candidate)
		remaining = remaining[1:]
	}
	result := make([]taskScheduleReference, 0, len(evicted))
	for _, ref := range evicted {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		return taskScheduleKey(result[i].TenantID, result[i].ScheduleID) <
			taskScheduleKey(result[j].TenantID, result[j].ScheduleID)
	})
	return result, nil
}

type storedTaskPermitInspection struct {
	TenantID, NodeID, InstanceID, RuntimeRef, GrantID string
	ServiceID, OperationID, TaskID, Deadline, KeyID   string
	Generation                                        uint64
	RequestDigest, PermitDigest                       string
	RequestBytes                                      int64
	ScheduleID                                        string
	ScheduleOrdinal                                   uint64
}

func inspectStoredTaskPermit(raw []byte) (storedTaskPermitInspection, error) {
	if exact, err := taskpermit.InspectUnverified(raw); err == nil {
		return storedTaskPermitInspection{
			TenantID: exact.Statement.TenantID, NodeID: exact.Statement.NodeID,
			InstanceID: exact.Statement.InstanceID, RuntimeRef: exact.Statement.RuntimeRef,
			GrantID: exact.Statement.GrantID, ServiceID: exact.Statement.ServiceID,
			OperationID: exact.Statement.OperationID, TaskID: exact.Statement.TaskID,
			Deadline: exact.Statement.ExpiresAt, KeyID: exact.KeyID,
			Generation: exact.Statement.Generation, RequestDigest: exact.Statement.RequestDigest,
			RequestBytes: exact.Statement.RequestBytes, PermitDigest: exact.EnvelopeDigest,
		}, nil
	}
	run, err := schedulepermit.InspectRunUnverified(raw)
	if err != nil {
		return storedTaskPermitInspection{}, err
	}
	return storedTaskPermitInspection{
		TenantID: run.Statement.TenantID, NodeID: run.Statement.NodeID,
		InstanceID: run.Statement.InstanceID, RuntimeRef: run.Statement.RuntimeRef,
		GrantID: run.Statement.GrantID, ServiceID: run.Statement.ServiceID,
		OperationID: run.Statement.OperationID, TaskID: run.TaskID,
		Deadline: run.DueAt.Add(time.Duration(run.Statement.WindowSeconds) * time.Second).Format(time.RFC3339),
		KeyID:    run.KeyID, Generation: run.Statement.Generation,
		RequestDigest: run.Statement.RequestDigest, RequestBytes: run.Statement.RequestBytes,
		PermitDigest: run.RunPermitDigest, ScheduleID: run.Statement.ScheduleID,
		ScheduleOrdinal: run.Ordinal,
	}, nil
}

func decodeStoredTaskPermitHeader(value string) ([]byte, error) {
	maximum := schedulepermit.MaxRunPermitBytes
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("task permit header exceeds its bound")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maximum ||
		base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("task permit header is not canonical")
	}
	return raw, nil
}
