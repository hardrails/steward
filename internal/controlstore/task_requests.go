package controlstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	MaxTaskRequestsRetained      = 4096
	MaxTaskRequestsPerTenant     = 1024
	MaxTaskCourierBytesRetained  = 64 << 20
	MaxTaskCourierBytesPerTenant = 16 << 20
	MaxTaskResultBytesRetained   = 64 << 20
	MaxTaskResultBytesPerTenant  = 16 << 20
	MaxTaskDeliveryLease         = 2 * time.Minute
	TaskObservationDelay         = 2 * time.Second

	TaskRequestQueued           = "queued"
	TaskRequestLeased           = "leased"
	TaskRequestDispatched       = "dispatched"
	TaskRequestRunning          = "running"
	TaskRequestCancelRequested  = "cancel_requested"
	TaskRequestCompleted        = "completed"
	TaskRequestFailed           = "failed"
	TaskRequestCancelled        = "cancelled"
	TaskRequestDeadlineExceeded = "deadline_exceeded"
	TaskRequestOutcomeUnknown   = "outcome_unknown"
)

// TaskRequest is Control's durable, non-secret view of one exact task permit.
// The request body and signed permit are retained only in storedTaskRequest so
// list/get APIs, logs, metrics, and support bundles cannot disclose prompts or
// replayable authority. Gateway remains the only component that authenticates
// the permit and authorizes dispatch.
type TaskRequest struct {
	TenantID            string `json:"tenant_id"`
	ProjectID           string `json:"project_id,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	TaskID              string `json:"task_id"`
	NodeID              string `json:"node_id"`
	InstanceID          string `json:"instance_id"`
	InstanceGeneration  uint64 `json:"instance_generation"`
	RuntimeRef          string `json:"runtime_ref"`
	ServiceID           string `json:"service_id"`
	OperationID         string `json:"operation_id"`
	RequestDigest       string `json:"request_digest"`
	RequestBytes        int64  `json:"request_bytes"`
	PermitDigest        string `json:"permit_digest"`
	PermitKeyID         string `json:"permit_key_id"`
	Deadline            string `json:"deadline"`
	State               string `json:"state"`
	DeliveryGeneration  uint64 `json:"delivery_generation"`
	DispatchAttempts    uint64 `json:"dispatch_attempts"`
	ObservationAttempts uint64 `json:"observation_attempts"`
	TaskDigest          string `json:"task_digest,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	ResultDigest        string `json:"result_digest,omitempty"`
	ResponseBytes       int64  `json:"response_bytes,omitempty"`
	ResultAvailable     bool   `json:"result_available,omitempty"`
	TaskStatus          string `json:"task_status,omitempty"`
	LastErrorCode       string `json:"last_error_code,omitempty"`
	CancelRequestedAt   string `json:"cancel_requested_at,omitempty"`
	OutcomeMayContinue  bool   `json:"outcome_may_continue,omitempty"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
	TerminalAt          string `json:"terminal_at,omitempty"`
}

func (task TaskRequest) Validate() error {
	deadline, deadlineErr := time.Parse(time.RFC3339, task.Deadline)
	created, createdErr := time.Parse(time.RFC3339Nano, task.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, task.UpdatedAt)
	if deadlineErr != nil || createdErr != nil || updatedErr != nil || created.After(updated) ||
		!validRecordID(task.TenantID, 128) || !validRecordID(task.TaskID, 128) ||
		(task.ProjectID == "") != (task.SessionID == "") ||
		task.ProjectID != "" && !validRecordID(task.ProjectID, 128) ||
		task.SessionID != "" && !validRecordID(task.SessionID, 128) ||
		!validRecordID(task.NodeID, 128) || !validRecordID(task.InstanceID, 256) ||
		task.InstanceGeneration == 0 || !validExecutorRuntimeRef(task.RuntimeRef) ||
		!validRecordID(task.ServiceID, 128) || !validRecordID(task.OperationID, 128) ||
		!validSHA256Digest(task.RequestDigest) || task.RequestBytes <= 0 || task.RequestBytes > taskpermit.MaxRequestBytes ||
		!validSHA256Digest(task.PermitDigest) || !validRecordID(task.PermitKeyID, 128) ||
		!deadline.After(created) || !validTaskRequestState(task.State) ||
		task.TaskDigest != "" && !validSHA256Digest(task.TaskDigest) ||
		task.RunID != "" && !validRecordID(task.RunID, 128) ||
		task.ResultDigest != "" && !validSHA256Digest(task.ResultDigest) || task.ResponseBytes < 0 ||
		task.LastErrorCode != "" && !validRecordID(task.LastErrorCode, controlprotocol.MaxExecutorTaskErrorCodeBytes) ||
		task.CancelRequestedAt != "" && !validTimestamp(task.CancelRequestedAt) ||
		taskTerminal(task.State) != (task.TerminalAt != "") || task.TerminalAt != "" && !validTimestamp(task.TerminalAt) {
		return errors.New("task request projection is invalid")
	}
	return nil
}

type storedTaskRequest struct {
	TaskRequest     `json:"task"`
	GrantID         string `json:"grant_id"`
	TaskPermit      string `json:"task_permit"`
	RequestBase64   string `json:"request_base64"`
	ResultBase64    string `json:"result_base64,omitempty"`
	LeaseUntil      string `json:"lease_until,omitempty"`
	DeliveryID      string `json:"delivery_id,omitempty"`
	DeliveryAction  string `json:"delivery_action,omitempty"`
	ResumeState     string `json:"resume_state,omitempty"`
	NextObservation string `json:"next_observation,omitempty"`
}

type TaskRequestInput struct {
	TenantID   string
	ProjectID  string
	SessionID  string
	TaskPermit string
	Request    []byte
}

func (store *Store) SubmitTaskRequest(actor controlauth.Identity, input TaskRequestInput, now time.Time) (TaskRequest, bool, error) {
	if store == nil {
		return TaskRequest{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, input.TenantID) ||
		(input.ProjectID == "") != (input.SessionID == "") ||
		input.ProjectID != "" && !validRecordID(input.ProjectID, 128) ||
		input.SessionID != "" && !validRecordID(input.SessionID, 128) ||
		len(input.Request) == 0 || int64(len(input.Request)) > taskpermit.MaxRequestBytes {
		return TaskRequest{}, false, invalid("task request is invalid or exceeds its bound")
	}
	rawPermit, err := taskpermit.DecodeHeader(input.TaskPermit)
	if err != nil {
		return TaskRequest{}, false, invalid("task permit encoding is invalid")
	}
	inspected, err := taskpermit.InspectUnverified(rawPermit)
	if err != nil {
		return TaskRequest{}, false, invalid("task permit structure is invalid")
	}
	statement := inspected.Statement
	deadline, err := time.Parse(time.RFC3339, statement.ExpiresAt)
	if err != nil || statement.TenantID != input.TenantID || statement.RequestBytes != int64(len(input.Request)) ||
		statement.RequestDigest != taskpermit.RequestDigest(input.Request) || !now.Before(deadline) {
		return TaskRequest{}, false, invalid("task permit does not bind this tenant, request, or active deadline")
	}
	stored := storedTaskRequest{
		TaskRequest: TaskRequest{
			TenantID: statement.TenantID, ProjectID: input.ProjectID, SessionID: input.SessionID,
			TaskID: statement.TaskID, NodeID: statement.NodeID,
			InstanceID: statement.InstanceID, InstanceGeneration: statement.Generation,
			RuntimeRef: statement.RuntimeRef, ServiceID: statement.ServiceID, OperationID: statement.OperationID,
			RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
			PermitDigest: inspected.EnvelopeDigest, PermitKeyID: inspected.KeyID,
			Deadline: statement.ExpiresAt, State: TaskRequestQueued,
			CreatedAt: canonicalTimestamp(now), UpdatedAt: canonicalTimestamp(now),
		},
		GrantID: statement.GrantID, TaskPermit: input.TaskPermit,
		RequestBase64: base64.StdEncoding.EncodeToString(input.Request),
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskRequest{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskRequest{}, false, err
	}
	tenant, found := store.current.tenants[input.TenantID]
	node, nodeFound := store.current.nodes[statement.NodeID]
	if !found || !tenant.Active || !nodeFound || !node.Active || !tenantMember(node.TenantIDs, input.TenantID) ||
		!taskTargetExists(store.current.deployments, statement) {
		return TaskRequest{}, false, ErrNotFound
	}
	key := taskRequestKey(input.TenantID, statement.TaskID)
	if existing, exists := store.current.taskRequests[key]; exists {
		if taskRequestInputEqual(existing, stored) {
			return cloneTaskRequestView(existing), false, nil
		}
		return TaskRequest{}, false, ErrConflict
	}
	var projectMutation mutation
	if input.ProjectID != "" {
		projectKey := workroomProjectKey(input.TenantID, input.ProjectID)
		project, found := store.current.workroomProjects[projectKey]
		if !found {
			return TaskRequest{}, false, ErrNotFound
		}
		sessionFound := false
		for index := range project.Sessions {
			if project.Sessions[index].ID != input.SessionID {
				continue
			}
			if project.Sessions[index].State != "active" ||
				len(project.Sessions[index].TaskIDs) >= MaxWorkroomTasksPerSession {
				return TaskRequest{}, false, ErrConflict
			}
			project.Sessions[index].TaskIDs = append(project.Sessions[index].TaskIDs, statement.TaskID)
			project.Sessions[index].TaskIDs = canonicalStringSet(project.Sessions[index].TaskIDs)
			project.Sessions[index].UpdatedAt = canonicalTimestamp(now)
			sessionFound = true
			break
		}
		if !sessionFound || project.Revision == ^uint64(0) {
			return TaskRequest{}, false, ErrNotFound
		}
		project.Revision++
		project.UpdatedAt = canonicalTimestamp(now)
		projectMutation = workroomProjectMutation(project)
	}
	mutations, err := store.taskCapacityMutationsLocked(input.TenantID, taskCourierBytes(stored))
	if err != nil {
		return TaskRequest{}, false, err
	}
	if input.ProjectID != "" {
		mutations = append(mutations, projectMutation)
	}
	mutations = append(mutations, taskRequestMutation(stored))
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return TaskRequest{}, false, err
	}
	return cloneTaskRequestView(stored), true, nil
}

func taskTargetExists(deployments map[string]Deployment, statement taskpermit.Statement) bool {
	for _, deployment := range deployments {
		if deployment.TenantID != statement.TenantID || deployment.DesiredState != DeploymentRunning {
			continue
		}
		for _, instance := range deployment.Instances {
			if instance.InstanceID == statement.InstanceID && instance.Generation == statement.Generation &&
				instance.NodeID == statement.NodeID && instance.Admission != nil &&
				instance.Admission.RuntimeRef == statement.RuntimeRef &&
				instance.Phase == DeploymentInstanceRunning {
				return true
			}
		}
	}
	return false
}

func (store *Store) ListTaskRequests(actor controlauth.Identity, tenantID string) ([]TaskRequest, error) {
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
	result := make([]TaskRequest, 0)
	for _, task := range store.current.taskRequests {
		if task.TenantID == tenantID {
			result = append(result, cloneTaskRequestView(task))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt != result[j].CreatedAt {
			return timestampBefore(result[j].CreatedAt, result[i].CreatedAt)
		}
		return result[i].TaskID > result[j].TaskID
	})
	return result, nil
}

func (store *Store) GetTaskRequest(actor controlauth.Identity, tenantID, taskID string) (TaskRequest, bool, error) {
	if store == nil {
		return TaskRequest{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskRequest{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskRequest{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return TaskRequest{}, false, ErrNotFound
	}
	task, found := store.current.taskRequests[taskRequestKey(tenantID, taskID)]
	return cloneTaskRequestView(task), found, nil
}

type TaskResult struct {
	TaskID        string
	ResultDigest  string
	ResponseBytes int64
	Result        []byte
}

func (store *Store) GetTaskResult(actor controlauth.Identity, tenantID, taskID string) (TaskResult, bool, error) {
	if store == nil {
		return TaskResult{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskResult{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskResult{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return TaskResult{}, false, ErrNotFound
	}
	task, found := store.current.taskRequests[taskRequestKey(tenantID, taskID)]
	if !found {
		return TaskResult{}, false, nil
	}
	if task.ResultBase64 == "" {
		return TaskResult{TaskID: taskID, ResultDigest: task.ResultDigest, ResponseBytes: task.ResponseBytes}, true, nil
	}
	raw, err := base64.StdEncoding.DecodeString(task.ResultBase64)
	if err != nil {
		return TaskResult{}, false, ErrUnavailable
	}
	return TaskResult{
		TaskID: taskID, ResultDigest: task.ResultDigest, ResponseBytes: task.ResponseBytes,
		Result: append([]byte(nil), raw...),
	}, true, nil
}

func (store *Store) CancelTaskRequest(actor controlauth.Identity, tenantID, taskID string, now time.Time) (TaskRequest, bool, error) {
	if store == nil {
		return TaskRequest{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, tenantID) {
		return TaskRequest{}, false, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return TaskRequest{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return TaskRequest{}, false, err
	}
	key := taskRequestKey(tenantID, taskID)
	task, found := store.current.taskRequests[key]
	if !found {
		return TaskRequest{}, false, ErrNotFound
	}
	if taskTerminal(task.State) {
		return cloneTaskRequestView(task), false, nil
	}
	task.CancelRequestedAt = canonicalTimestamp(now)
	task.UpdatedAt = task.CancelRequestedAt
	if task.State == TaskRequestQueued && task.DispatchAttempts == 0 {
		task.State, task.TerminalAt = TaskRequestCancelled, task.UpdatedAt
	} else if task.State == TaskRequestQueued {
		task.State, task.TerminalAt = TaskRequestOutcomeUnknown, task.UpdatedAt
		task.OutcomeMayContinue = true
	} else {
		task.State = TaskRequestCancelRequested
		if task.LeaseUntil != "" {
			task.ResumeState = TaskRequestCancelRequested
		}
		task.OutcomeMayContinue = task.TaskDigest != "" || task.DeliveryAction == controlprotocol.ExecutorTaskActionSubmit
	}
	if err := store.applyMutationsLocked(taskRequestMutation(task)); err != nil {
		return TaskRequest{}, false, err
	}
	return cloneTaskRequestView(task), true, nil
}

func (store *Store) PollTaskRequests(identity controlauth.NodeIdentity, now time.Time, lease time.Duration, limit int) ([]controlprotocol.ExecutorTaskDeliveryV1, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	if now.IsZero() || lease <= 0 || lease > MaxTaskDeliveryLease || limit <= 0 ||
		limit > controlprotocol.MaxExecutorTaskDeliveries {
		return nil, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return nil, err
	}
	if node, ok := store.current.nodes[identity.NodeID]; !ok || EffectiveNodePlacement(node).Mode == NodeQuarantined {
		return []controlprotocol.ExecutorTaskDeliveryV1{}, nil
	}
	mutations := make([]mutation, 0, limit)
	candidates := make([]storedTaskRequest, 0)
	for _, retained := range store.current.taskRequests {
		if retained.NodeID != identity.NodeID || !controlauth.NodeAuthorizedTenant(identity, retained.TenantID) {
			continue
		}
		task := cloneStoredTaskRequest(retained)
		changed := normalizeTaskForPoll(&task, now)
		if changed {
			mutations = append(mutations, taskRequestMutation(task))
		}
		if taskTerminal(task.State) || task.LeaseUntil != "" ||
			task.NextObservation != "" && timestampAfter(task.NextObservation, now) {
			continue
		}
		if task.State == TaskRequestQueued || task.State == TaskRequestDispatched ||
			task.State == TaskRequestRunning || task.State == TaskRequestCancelRequested {
			candidates = append(candidates, task)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt != candidates[j].CreatedAt {
			return timestampBefore(candidates[i].CreatedAt, candidates[j].CreatedAt)
		}
		return candidates[i].TaskID < candidates[j].TaskID
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	deliveries := make([]controlprotocol.ExecutorTaskDeliveryV1, 0, len(candidates))
	for _, task := range candidates {
		action := controlprotocol.ExecutorTaskActionObserve
		if task.TaskDigest == "" {
			action = controlprotocol.ExecutorTaskActionSubmit
		}
		if task.DeliveryGeneration == ^uint64(0) {
			return nil, ErrCapacityExceeded
		}
		task.ResumeState = task.State
		task.State = TaskRequestLeased
		task.DeliveryGeneration++
		task.DeliveryAction = action
		task.DeliveryID = taskDeliveryID(task.TenantID, task.TaskID)
		task.LeaseUntil = canonicalTimestamp(now.Add(lease))
		task.UpdatedAt = canonicalTimestamp(now)
		if action == controlprotocol.ExecutorTaskActionSubmit {
			task.DispatchAttempts++
		} else {
			task.ObservationAttempts++
		}
		delivery := taskDelivery(task)
		candidate := append(append([]controlprotocol.ExecutorTaskDeliveryV1(nil), deliveries...), delivery)
		raw, err := json.Marshal(controlprotocol.ExecutorTaskPollResponseV1{
			SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, Deliveries: candidate,
		})
		if err != nil {
			return nil, err
		}
		if len(raw)+1 > controlprotocol.MaxExecutorTaskPollResponseBytes {
			if len(deliveries) == 0 {
				return nil, ErrCapacityExceeded
			}
			break
		}
		mutations = append(mutations, taskRequestMutation(task))
		deliveries = candidate
	}
	if len(mutations) > 0 {
		if err := store.applyMutationsLocked(mutations...); err != nil {
			return nil, err
		}
	}
	return deliveries, nil
}

func (store *Store) ApplyTaskReport(identity controlauth.NodeIdentity, report controlprotocol.ExecutorTaskReportV1, now time.Time) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if now.IsZero() || report.Validate() != nil || report.NodeID != identity.NodeID ||
		!controlauth.NodeAuthorizedTenant(identity, report.TenantID) {
		return false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return false, err
	}
	key := taskRequestKey(report.TenantID, report.TaskID)
	task, found := store.current.taskRequests[key]
	if !found || task.NodeID != identity.NodeID || task.PermitDigest != report.PermitDigest {
		return false, ErrNotFound
	}
	if report.DeliveryGeneration < task.DeliveryGeneration {
		return false, nil
	}
	if taskTerminal(task.State) && report.DeliveryGeneration <= task.DeliveryGeneration {
		return false, nil
	}
	if task.State != TaskRequestLeased && task.State != TaskRequestCancelRequested || report.DeliveryID != task.DeliveryID ||
		report.DeliveryGeneration != task.DeliveryGeneration {
		return false, ErrConflict
	}
	if report.TaskDigest != "" && task.TaskDigest != "" && report.TaskDigest != task.TaskDigest ||
		report.RunID != "" && task.RunID != "" && report.RunID != task.RunID {
		return false, ErrConflict
	}
	task.LeaseUntil, task.DeliveryAction, task.DeliveryID = "", "", ""
	task.UpdatedAt = canonicalTimestamp(now)
	switch report.Status {
	case controlprotocol.ExecutorTaskReportAccepted:
		task.TaskDigest, task.RunID = report.TaskDigest, report.RunID
		if task.ResumeState == TaskRequestCancelRequested {
			task.State, task.OutcomeMayContinue = TaskRequestCancelRequested, true
		} else {
			task.State = TaskRequestDispatched
		}
		task.NextObservation = canonicalTimestamp(now.Add(TaskObservationDelay))
		task.LastErrorCode = ""
	case controlprotocol.ExecutorTaskReportObserved:
		task.TaskDigest, task.RunID = report.TaskDigest, report.RunID
		task.TaskStatus, task.ResultDigest, task.ResponseBytes = report.TaskStatus, report.ResultDigest, report.ResponseBytes
		if report.ResultBase64 != "" && store.taskResultCapacityAvailableLocked(task.TenantID, key, report.ResponseBytes) {
			task.ResultBase64, task.ResultAvailable = report.ResultBase64, true
		}
		task.LastErrorCode = report.ErrorCode
		switch report.TaskStatus {
		case "agent_reported_completed":
			task.State = TaskRequestCompleted
		case "agent_reported_failed":
			task.State = TaskRequestFailed
		case "agent_reported_cancelled":
			task.State = TaskRequestCancelled
		default:
			if task.ResumeState == TaskRequestCancelRequested {
				task.State, task.OutcomeMayContinue = TaskRequestCancelRequested, true
			} else {
				task.State = TaskRequestRunning
			}
			task.NextObservation = canonicalTimestamp(now.Add(TaskObservationDelay))
		}
		if taskTerminal(task.State) {
			task.TerminalAt, task.NextObservation = task.UpdatedAt, ""
		}
	case controlprotocol.ExecutorTaskReportRetryable:
		task.LastErrorCode = report.ErrorCode
		task.State = task.ResumeState
		if task.State == TaskRequestLeased || task.State == "" {
			task.State = TaskRequestOutcomeUnknown
			task.TerminalAt = task.UpdatedAt
		}
		task.NextObservation = canonicalTimestamp(now.Add(TaskObservationDelay))
	case controlprotocol.ExecutorTaskReportUncertain:
		task.LastErrorCode = report.ErrorCode
		task.State, task.TerminalAt = TaskRequestOutcomeUnknown, task.UpdatedAt
		task.OutcomeMayContinue = true
		task.NextObservation = ""
	case controlprotocol.ExecutorTaskReportRejected:
		task.LastErrorCode = report.ErrorCode
		task.State, task.TerminalAt = TaskRequestFailed, task.UpdatedAt
		task.NextObservation = ""
	}
	task.ResumeState = ""
	if deadline, _ := time.Parse(time.RFC3339, task.Deadline); !now.Before(deadline) && !taskTerminal(task.State) {
		task.State, task.TerminalAt = TaskRequestDeadlineExceeded, task.UpdatedAt
		task.OutcomeMayContinue = task.OutcomeMayContinue || task.TaskDigest != "" || task.DispatchAttempts > 0
		task.NextObservation = ""
	}
	if err := store.applyMutationsLocked(taskRequestMutation(task)); err != nil {
		return false, err
	}
	return true, nil
}

func normalizeTaskForPoll(task *storedTaskRequest, now time.Time) bool {
	changed := false
	if task.LeaseUntil != "" && !timestampAfter(task.LeaseUntil, now) {
		if task.ResumeState == TaskRequestCancelRequested && task.DeliveryAction == controlprotocol.ExecutorTaskActionSubmit {
			task.State = TaskRequestOutcomeUnknown
			task.TerminalAt = canonicalTimestamp(now)
			task.OutcomeMayContinue = true
		} else {
			task.State = task.ResumeState
			if task.State == "" || task.State == TaskRequestLeased {
				task.State = TaskRequestOutcomeUnknown
				task.TerminalAt = canonicalTimestamp(now)
			}
		}
		task.LeaseUntil, task.DeliveryID, task.DeliveryAction, task.ResumeState = "", "", "", ""
		task.UpdatedAt = canonicalTimestamp(now)
		changed = true
	}
	deadline, _ := time.Parse(time.RFC3339, task.Deadline)
	if !taskTerminal(task.State) && !now.Before(deadline) {
		task.State, task.TerminalAt, task.UpdatedAt = TaskRequestDeadlineExceeded, canonicalTimestamp(now), canonicalTimestamp(now)
		task.OutcomeMayContinue = task.OutcomeMayContinue || task.TaskDigest != "" || task.DispatchAttempts > 0 ||
			task.DeliveryAction == controlprotocol.ExecutorTaskActionSubmit
		task.LeaseUntil, task.DeliveryID, task.DeliveryAction, task.ResumeState, task.NextObservation = "", "", "", "", ""
		changed = true
	}
	return changed
}

func (store *Store) taskCapacityMutationsLocked(tenantID string, incomingBytes int64) ([]mutation, error) {
	total, tenantTotal := len(store.current.taskRequests), 0
	var totalBytes, tenantBytes int64
	terminal := make([]storedTaskRequest, 0)
	for _, task := range store.current.taskRequests {
		bytes := taskCourierBytes(task)
		totalBytes += bytes
		if task.TenantID == tenantID {
			tenantTotal++
			tenantBytes += bytes
		}
		if taskTerminal(task.State) {
			terminal = append(terminal, task)
		}
	}
	sort.Slice(terminal, func(i, j int) bool {
		if terminal[i].TerminalAt != terminal[j].TerminalAt {
			return timestampBefore(terminal[i].TerminalAt, terminal[j].TerminalAt)
		}
		return taskRequestKey(terminal[i].TenantID, terminal[i].TaskID) < taskRequestKey(terminal[j].TenantID, terminal[j].TaskID)
	})
	mutations := make([]mutation, 0)
	removed := make(map[string]struct{})
	if incomingBytes <= 0 || incomingBytes > MaxTaskCourierBytesPerTenant || incomingBytes > MaxTaskCourierBytesRetained {
		return nil, ErrCapacityExceeded
	}
	for total >= MaxTaskRequestsRetained || tenantTotal >= MaxTaskRequestsPerTenant ||
		totalBytes+incomingBytes > MaxTaskCourierBytesRetained || tenantBytes+incomingBytes > MaxTaskCourierBytesPerTenant {
		index := -1
		for candidateIndex, candidate := range terminal {
			_, already := removed[taskRequestKey(candidate.TenantID, candidate.TaskID)]
			if !already && (total >= MaxTaskRequestsRetained ||
				totalBytes+incomingBytes > MaxTaskCourierBytesRetained ||
				candidate.TenantID == tenantID && (tenantTotal >= MaxTaskRequestsPerTenant ||
					tenantBytes+incomingBytes > MaxTaskCourierBytesPerTenant)) {
				index = candidateIndex
				break
			}
		}
		if index < 0 {
			return nil, ErrCapacityExceeded
		}
		candidate := terminal[index]
		key := taskRequestKey(candidate.TenantID, candidate.TaskID)
		removed[key] = struct{}{}
		mutations = append(mutations, taskRequestDeleteMutation(candidate.TenantID, candidate.TaskID))
		total--
		totalBytes -= taskCourierBytes(candidate)
		if candidate.TenantID == tenantID {
			tenantTotal--
			tenantBytes -= taskCourierBytes(candidate)
		}
	}
	return mutations, nil
}

func taskCourierBytes(task storedTaskRequest) int64 {
	return int64(len(task.TaskPermit) + len(task.RequestBase64))
}

func (store *Store) taskResultCapacityAvailableLocked(tenantID, replacingKey string, incomingBytes int64) bool {
	if incomingBytes <= 0 || incomingBytes > MaxTaskResultBytesPerTenant || incomingBytes > MaxTaskResultBytesRetained {
		return false
	}
	var total, tenant int64
	for key, task := range store.current.taskRequests {
		if key == replacingKey || !task.ResultAvailable {
			continue
		}
		total += task.ResponseBytes
		if task.TenantID == tenantID {
			tenant += task.ResponseBytes
		}
	}
	return total+incomingBytes <= MaxTaskResultBytesRetained &&
		tenant+incomingBytes <= MaxTaskResultBytesPerTenant
}

func taskRequestInputEqual(left, right storedTaskRequest) bool {
	return left.TenantID == right.TenantID && left.TaskID == right.TaskID &&
		left.ProjectID == right.ProjectID && left.SessionID == right.SessionID &&
		left.PermitDigest == right.PermitDigest && left.RequestDigest == right.RequestDigest &&
		left.TaskPermit == right.TaskPermit && left.RequestBase64 == right.RequestBase64
}

func taskDelivery(task storedTaskRequest) controlprotocol.ExecutorTaskDeliveryV1 {
	delivery := controlprotocol.ExecutorTaskDeliveryV1{
		SchemaVersion: controlprotocol.ExecutorTaskDeliverySchemaV1,
		DeliveryID:    task.DeliveryID, DeliveryGeneration: task.DeliveryGeneration,
		Action: task.DeliveryAction, TenantID: task.TenantID, NodeID: task.NodeID,
		TaskID: task.TaskID, PermitDigest: task.PermitDigest,
	}
	if task.DeliveryAction == controlprotocol.ExecutorTaskActionSubmit {
		delivery.GrantID, delivery.OperationID = task.GrantID, task.OperationID
		delivery.TaskPermit, delivery.RequestBase64 = task.TaskPermit, task.RequestBase64
	} else {
		delivery.TaskDigest = task.TaskDigest
	}
	return delivery
}

func taskRequestKey(tenantID, taskID string) string { return tenantID + "\x00" + taskID }

func taskDeliveryID(tenantID, taskID string) string {
	return "task-delivery-" + dsse.Digest([]byte(taskRequestKey(tenantID, taskID)))[len("sha256:"):]
}

func taskTerminal(state string) bool {
	switch state {
	case TaskRequestCompleted, TaskRequestFailed, TaskRequestCancelled,
		TaskRequestDeadlineExceeded, TaskRequestOutcomeUnknown:
		return true
	default:
		return false
	}
}

func cloneTaskRequestView(task storedTaskRequest) TaskRequest { return task.TaskRequest }

func cloneStoredTaskRequest(task storedTaskRequest) storedTaskRequest { return task }

func taskRequestMutation(task storedTaskRequest) mutation {
	cloned := cloneStoredTaskRequest(task)
	return mutation{Kind: mutationTaskRequest, TaskRequest: &cloned}
}

func taskRequestDeleteMutation(tenantID, taskID string) mutation {
	return mutation{Kind: mutationTaskRequestDelete, TaskRequestRef: &taskRequestReference{TenantID: tenantID, TaskID: taskID}}
}

func timestampAfter(value string, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.After(now)
}

func validStoredTaskRequest(task storedTaskRequest) bool {
	deadline, deadlineErr := time.Parse(time.RFC3339, task.Deadline)
	created, createdErr := time.Parse(time.RFC3339Nano, task.CreatedAt)
	updated, updatedErr := time.Parse(time.RFC3339Nano, task.UpdatedAt)
	rawRequest, requestErr := base64.StdEncoding.DecodeString(task.RequestBase64)
	rawPermit, permitErr := taskpermit.DecodeHeader(task.TaskPermit)
	inspected, inspectErr := taskpermit.InspectUnverified(rawPermit)
	if deadlineErr != nil || createdErr != nil || updatedErr != nil || requestErr != nil || permitErr != nil || inspectErr != nil ||
		created.After(updated) || task.RequestBytes != int64(len(rawRequest)) ||
		base64.StdEncoding.EncodeToString(rawRequest) != task.RequestBase64 ||
		task.RequestDigest != taskpermit.RequestDigest(rawRequest) || task.PermitDigest != inspected.EnvelopeDigest ||
		task.TenantID != inspected.Statement.TenantID || task.TaskID != inspected.Statement.TaskID ||
		task.NodeID != inspected.Statement.NodeID || task.InstanceID != inspected.Statement.InstanceID ||
		task.InstanceGeneration != inspected.Statement.Generation || task.RuntimeRef != inspected.Statement.RuntimeRef ||
		task.GrantID != inspected.Statement.GrantID || task.ServiceID != inspected.Statement.ServiceID ||
		task.OperationID != inspected.Statement.OperationID || task.PermitKeyID != inspected.KeyID ||
		task.Deadline != inspected.Statement.ExpiresAt || !deadline.After(created) || !validTaskRequestState(task.State) {
		return false
	}
	if task.LeaseUntil != "" {
		if task.DeliveryGeneration == 0 || task.DeliveryID != taskDeliveryID(task.TenantID, task.TaskID) ||
			(task.DeliveryAction != controlprotocol.ExecutorTaskActionSubmit && task.DeliveryAction != controlprotocol.ExecutorTaskActionObserve) ||
			!validTimestamp(task.LeaseUntil) || task.ResumeState == "" ||
			task.State != TaskRequestLeased && task.State != TaskRequestCancelRequested {
			return false
		}
	} else if task.LeaseUntil != "" || task.DeliveryID != "" || task.DeliveryAction != "" || task.ResumeState != "" {
		return false
	}
	if task.TaskDigest != "" && !validSHA256Digest(task.TaskDigest) || task.ResultDigest != "" && !validSHA256Digest(task.ResultDigest) ||
		task.RunID != "" && !validRecordID(task.RunID, 128) || task.ResponseBytes < 0 ||
		task.LastErrorCode != "" && !validRecordID(task.LastErrorCode, controlprotocol.MaxExecutorTaskErrorCodeBytes) ||
		task.CancelRequestedAt != "" && !validTimestamp(task.CancelRequestedAt) ||
		task.NextObservation != "" && !validTimestamp(task.NextObservation) {
		return false
	}
	if task.ResultAvailable != (task.ResultBase64 != "") {
		return false
	}
	if task.ResultBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(task.ResultBase64)
		if err != nil || len(raw) == 0 || len(raw) > controlprotocol.MaxExecutorTaskResultBytes ||
			base64.StdEncoding.EncodeToString(raw) != task.ResultBase64 || int64(len(raw)) != task.ResponseBytes ||
			dsse.Digest(raw) != task.ResultDigest || !taskTerminal(task.State) {
			return false
		}
	}
	if taskTerminal(task.State) != (task.TerminalAt != "") || task.TerminalAt != "" && !validTimestamp(task.TerminalAt) {
		return false
	}
	return true
}

func validTaskRequestState(state string) bool {
	switch state {
	case TaskRequestQueued, TaskRequestLeased, TaskRequestDispatched, TaskRequestRunning,
		TaskRequestCancelRequested, TaskRequestCompleted, TaskRequestFailed, TaskRequestCancelled,
		TaskRequestDeadlineExceeded, TaskRequestOutcomeUnknown:
		return true
	default:
		return false
	}
}
