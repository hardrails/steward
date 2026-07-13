package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskprotocol"
)

const TaskStatusSchemaV1 = "steward.task-status.v1"

const (
	TaskStateAuthorizationRecorded  = "authorization_recorded"
	TaskStateDispatchAccepted       = "dispatch_accepted"
	TaskStateFailedBeforeDispatch   = "failed_before_dispatch"
	TaskStateObservationFailed      = "observation_failed"
	maxTaskObservationResponseBytes = int64(taskprotocol.MaxReportBytes)
)

var serviceTaskDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// TaskLifecycleStatus reports durable Gateway evidence. ObservedStatus and
// ObservationBase64 exist only in a response that made a live observation.
// Gateway does not persist those raw bytes; a later observation may recover
// terminal bytes only when they still match the durable digest and length.
type TaskLifecycleStatus struct {
	SchemaVersion     string                     `json:"schema_version"`
	TaskDigest        string                     `json:"task_digest"`
	PermitDigest      string                     `json:"permit_digest"`
	Phase             connectorledger.Phase      `json:"phase"`
	State             string                     `json:"state"`
	RunID             string                     `json:"run_id,omitempty"`
	TaskStatus        connectorledger.TaskStatus `json:"task_status,omitempty"`
	ResultDigest      string                     `json:"result_digest,omitempty"`
	ResponseBytes     int64                      `json:"response_bytes,omitempty"`
	ErrorCode         string                     `json:"error_code,omitempty"`
	ObservedStatus    taskprotocol.Status        `json:"observed_status,omitempty"`
	ObservationBase64 string                     `json:"observation_base64,omitempty"`
}

type taskObservation struct {
	taskDigest   string
	permitDigest string
	state        serviceTaskReceipt
	grant        Grant
	operation    ServiceOperation
	lease        context.Context
	semaphore    chan struct{}
}

var (
	errTaskNotFound          = errors.New("lifecycle task not found")
	errTaskEvidence          = errors.New("lifecycle task evidence is unavailable")
	errTaskNotDispatched     = errors.New("lifecycle task has no durable dispatch")
	errTaskObservationActive = errors.New("lifecycle task observation is already active")
)

func (s *Server) handleTaskLifecycle(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	taskDigest, permitDigest, observe, ok := parseTaskLifecycleRoute(request)
	if !ok {
		writeGatewayError(w, http.StatusNotFound, "task_not_found", "lifecycle task not found")
		return
	}
	if (!observe && request.Method != http.MethodGet) || (observe && request.Method != http.MethodPost) {
		if observe {
			w.Header().Set("Allow", http.MethodPost)
		} else {
			w.Header().Set("Allow", http.MethodGet)
		}
		writeGatewayError(w, http.StatusMethodNotAllowed, "method_not_allowed", "task lifecycle method is not allowed")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 1)
	body, err := io.ReadAll(request.Body)
	if err != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(body) != 0 {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_observation", "task lifecycle requests have no body")
		return
	}
	if !observe {
		state, exists := s.lifecycleTaskSnapshot(taskDigest, permitDigest)
		if !exists {
			writeGatewayError(w, http.StatusNotFound, "task_not_found", "lifecycle task not found")
			return
		}
		if taskEvidenceUnavailable(state) {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task evidence is unavailable; restart Gateway to reconcile it")
			return
		}
		writeTaskLifecycleStatus(w, http.StatusOK, lifecycleStatus(taskDigest, state))
		return
	}
	s.observeTaskLifecycle(w, request, taskDigest, permitDigest)
}

func parseTaskLifecycleRoute(request *http.Request) (string, string, bool, bool) {
	if request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.RequestURI != request.URL.Path {
		return "", "", false, false
	}
	rest := strings.TrimPrefix(request.URL.Path, "/v1/tasks/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return "", "", false, false
	}
	observe := len(parts) == 4
	if (observe && parts[3] != "observe") || parts[1] != "permits" ||
		!serviceTaskDigestPattern.MatchString(parts[0]) || !serviceTaskDigestPattern.MatchString(parts[2]) {
		return "", "", false, false
	}
	return parts[0], parts[2], observe, true
}

func (s *Server) lifecycleTaskSnapshot(taskDigest, permitDigest string) (serviceTaskReceipt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.serviceTasks[taskDigest]
	boundTask, bound := s.serviceTaskPermits[permitDigest]
	return state, exists && bound && boundTask == taskDigest && state.Authorization.PermitDigest == permitDigest &&
		state.Authorization.TaskProtocol == connectorledger.TaskProtocolLifecycleV1
}

func lifecycleStatus(taskDigest string, state serviceTaskReceipt) TaskLifecycleStatus {
	status := TaskLifecycleStatus{SchemaVersion: TaskStatusSchemaV1, TaskDigest: taskDigest, PermitDigest: state.Authorization.PermitDigest, Phase: connectorledger.Authorize,
		State: TaskStateAuthorizationRecorded}
	if state.Dispatch.Phase == connectorledger.Dispatch {
		status.Phase, status.State, status.RunID = connectorledger.Dispatch, TaskStateDispatchAccepted, state.Dispatch.RunID
	}
	if state.Terminal.Phase == connectorledger.Terminal {
		status.Phase, status.RunID = connectorledger.Terminal, state.Terminal.RunID
		status.TaskStatus, status.ResultDigest = state.Terminal.TaskStatus, state.Terminal.ResultDigest
		status.ResponseBytes, status.ErrorCode = state.Terminal.ResponseBytes, state.Terminal.ErrorCode
		switch {
		case state.Terminal.TaskStatus != "":
			status.State = string(state.Terminal.TaskStatus)
		case state.Dispatch.Phase == connectorledger.Dispatch:
			status.State = TaskStateObservationFailed
		default:
			status.State = TaskStateFailedBeforeDispatch
		}
	}
	return status
}

func taskEvidenceUnavailable(state serviceTaskReceipt) bool {
	return state.authorizationAmbiguous || state.dispatchAmbiguous || state.terminalUnavailable
}

func writeTaskLifecycleStatus(w http.ResponseWriter, status int, value TaskLifecycleStatus) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(w, status, value)
}

func (s *Server) observeTaskLifecycle(w http.ResponseWriter, request *http.Request, taskDigest, permitDigest string) {
	observation, retryAfter, err := s.beginTaskObservation(taskDigest, permitDigest)
	if err != nil {
		switch {
		case errors.Is(err, errTaskNotFound):
			writeGatewayError(w, http.StatusNotFound, "task_not_found", "lifecycle task not found")
		case errors.Is(err, errTaskEvidence):
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task evidence is unavailable; restart Gateway to reconcile it")
		case errors.Is(err, errTaskNotDispatched):
			writeGatewayError(w, http.StatusConflict, "task_not_dispatched", "task has no durable dispatch to observe")
		case errors.Is(err, errTaskObservationActive):
			writeGatewayError(w, http.StatusConflict, "task_observation_in_progress", "another observation is already in progress")
		default:
			if retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				writeGatewayError(w, http.StatusTooManyRequests, "task_observation_throttled", "task observation is limited by host policy")
				return
			}
			writeGatewayError(w, http.StatusServiceUnavailable, "task_observation_unavailable", "active task observation policy is unavailable")
		}
		return
	}
	if observation.state.Terminal.Phase == connectorledger.Terminal && observation.state.Terminal.TaskStatus == "" {
		writeTaskLifecycleStatus(w, http.StatusOK, lifecycleStatus(taskDigest, observation.state))
		return
	}
	defer s.finishTaskObservation(taskDigest)
	select {
	case observation.semaphore <- struct{}{}:
		defer func() { <-observation.semaphore }()
	default:
		writeGatewayError(w, http.StatusTooManyRequests, "service_busy", "service grant concurrency limit reached")
		return
	}
	if !s.startTaskObservation(observation) {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_observation_revoked", "task authority changed before observation")
		return
	}
	requestContext, cancel := context.WithTimeout(request.Context(), time.Duration(observation.operation.StatusMaxSeconds)*time.Second)
	defer cancel()
	stopRevocation := context.AfterFunc(observation.lease, cancel)
	defer stopRevocation()
	raw, report, err := s.fetchTaskObservation(requestContext, observation)
	if err != nil {
		if !s.taskObservationStillActive(observation) {
			writeGatewayError(w, http.StatusServiceUnavailable, "task_observation_revoked", "task authority changed during observation")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "invalid_task_status", "agent service returned no valid bounded task status")
		return
	}
	status := lifecycleStatus(taskDigest, observation.state)
	status.ObservedStatus = report.Status
	if observation.state.Terminal.Phase == connectorledger.Terminal {
		matches := terminalObservationMatches(observation.state.Terminal, raw, report)
		if !s.taskObservationCanReturnResult(observation) {
			writeGatewayError(w, http.StatusServiceUnavailable, "task_observation_revoked", "task authority changed before the recovered result could be returned")
			return
		}
		if !matches {
			writeGatewayError(w, http.StatusBadGateway, "terminal_result_mismatch", "agent terminal result no longer matches durable task evidence")
			return
		}
		status.ObservationBase64 = base64.StdEncoding.EncodeToString(raw)
		writeTaskLifecycleStatus(w, http.StatusOK, status)
		return
	}
	if !report.Status.Terminal() {
		writeTaskLifecycleStatus(w, http.StatusOK, status)
		return
	}
	terminal := observation.state.Dispatch
	terminal.Phase, terminal.Outcome = connectorledger.Terminal, connectorledger.Responded
	terminal.HTTPStatus, terminal.ResponseBytes = http.StatusOK, int64(len(raw))
	terminal.TaskStatus = terminalTaskStatus(report.Status)
	if terminal.TaskStatus == "" {
		writeGatewayError(w, http.StatusBadGateway, "invalid_task_status", "agent service returned a nonterminal task status")
		return
	}
	terminal.ResultDigest = dsse.Digest(raw)
	if err := s.commitTaskObservation(observation, terminal); errors.Is(err, errTaskObservationRevoked) {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_observation_revoked", "task authority changed before terminal evidence could be recorded")
		return
	} else if err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task terminal evidence could not be recorded")
		return
	}
	state, _ := s.lifecycleTaskSnapshot(taskDigest, permitDigest)
	status = lifecycleStatus(taskDigest, state)
	status.ObservedStatus = report.Status
	status.ObservationBase64 = base64.StdEncoding.EncodeToString(raw)
	writeTaskLifecycleStatus(w, http.StatusOK, status)
}

func (s *Server) beginTaskObservation(taskDigest, permitDigest string) (taskObservation, int, error) {
	// Task receipt mutation and this health check use the same outer lock. A
	// poisoned shared ledger therefore fences later agent contact before it
	// starts, without holding Server.mu while Failed waits for an in-flight
	// fsync to resolve.
	s.serviceTaskMutationMu.Lock()
	defer s.serviceTaskMutationMu.Unlock()
	s.mu.Lock()
	state, exists := s.serviceTasks[taskDigest]
	boundTask, bound := s.serviceTaskPermits[permitDigest]
	if !exists || !bound || boundTask != taskDigest || state.Authorization.PermitDigest != permitDigest ||
		state.Authorization.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		s.mu.Unlock()
		return taskObservation{}, 0, errTaskNotFound
	}
	if taskEvidenceUnavailable(state) {
		s.mu.Unlock()
		return taskObservation{}, 0, errTaskEvidence
	}
	if state.Dispatch.Phase != connectorledger.Dispatch {
		s.mu.Unlock()
		return taskObservation{}, 0, errTaskNotDispatched
	}
	if state.Terminal.Phase == connectorledger.Terminal && state.Terminal.TaskStatus == "" {
		s.mu.Unlock()
		return taskObservation{taskDigest: taskDigest, permitDigest: permitDigest, state: state}, 0, nil
	}
	ledger := s.connectorLedger
	terminal := state.Terminal.Phase == connectorledger.Terminal
	s.mu.Unlock()
	if !terminal && (ledger == nil || ledger.Failed()) {
		return taskObservation{}, 0, errTaskEvidence
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists = s.serviceTasks[taskDigest]
	boundTask, bound = s.serviceTaskPermits[permitDigest]
	if !exists || !bound || boundTask != taskDigest || state.Authorization.PermitDigest != permitDigest ||
		state.Authorization.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		return taskObservation{}, 0, errTaskNotFound
	}
	if taskEvidenceUnavailable(state) {
		return taskObservation{}, 0, errTaskEvidence
	}
	if state.Dispatch.Phase != connectorledger.Dispatch {
		return taskObservation{}, 0, errTaskNotDispatched
	}
	if state.observing {
		return taskObservation{}, 0, errTaskObservationActive
	}
	authorized := state.Authorization
	grant, active := s.grants[authorized.GrantID]
	operation, configured := s.serviceOperations[authorized.ServiceID][authorized.OperationID]
	if !active || !grant.Active || !serviceTaskReceiptMatchesGrant(authorized, grant) ||
		!configured || ServiceOperationDigest(operation) != authorized.OperationPolicyDigest ||
		operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 ||
		s.policyDigests[authorized.GrantID] != authorized.RoutePolicyDigest {
		return taskObservation{}, 0, errors.New("task observation policy is unavailable")
	}
	now := s.now()
	if now.Before(state.nextObservationAt) {
		delay := state.nextObservationAt.Sub(now)
		seconds := int((delay + time.Second - 1) / time.Second)
		return taskObservation{}, seconds, errors.New("task observation is throttled")
	}
	state.observing = true
	s.serviceTasks[taskDigest] = state
	return taskObservation{taskDigest: taskDigest, permitDigest: permitDigest, state: state, grant: grant, operation: operation,
		lease: s.grantLeaseLocked(grant.GrantID), semaphore: s.serviceSemaphoreLocked(grant.GrantID)}, 0, nil
}

func (s *Server) startTaskObservation(observation taskObservation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.taskObservationStillActiveLocked(observation) {
		return false
	}
	state := s.serviceTasks[observation.taskDigest]
	state.nextObservationAt = s.now().Add(time.Duration(observation.operation.PollIntervalSeconds) * time.Second)
	s.serviceTasks[observation.taskDigest] = state
	return true
}

var errTaskObservationRevoked = errors.New("task observation authority was revoked")

func (s *Server) commitTaskObservation(observation taskObservation, terminal connectorledger.Event) error {
	// A terminal receipt and grant revocation share this barrier. The reader
	// side covers the final active-policy check and fsync; deactivation and
	// removal take the writer side. Whichever acquires it first is the defined
	// linearization order, without holding Server.mu across durable I/O.
	s.taskObservationCommitMu.RLock()
	defer s.taskObservationCommitMu.RUnlock()
	if !s.taskObservationStillActive(observation) {
		return errTaskObservationRevoked
	}
	return s.finishServiceTask(observation.taskDigest, terminal)
}

// taskObservationCanReturnResult gives terminal recovery the same ordering
// against grant deactivation as a terminal receipt commit. Once this check
// succeeds, result disclosure linearizes before a later deactivation; an ABA
// deactivate/reactivate still fails because the original lease stays canceled.
func (s *Server) taskObservationCanReturnResult(observation taskObservation) bool {
	s.taskObservationCommitMu.RLock()
	defer s.taskObservationCommitMu.RUnlock()
	return s.taskObservationStillActive(observation)
}

func (s *Server) finishTaskObservation(taskDigest string) {
	s.mu.Lock()
	if state, exists := s.serviceTasks[taskDigest]; exists {
		state.observing = false
		s.serviceTasks[taskDigest] = state
	}
	s.mu.Unlock()
}

func serviceTaskReceiptMatchesGrant(event connectorledger.Event, grant Grant) bool {
	return event.GrantID == grant.GrantID && event.TenantID == grant.TenantID && event.RuntimeRef == grant.RuntimeRef &&
		event.CapsuleDigest == grant.CapsuleDigest && event.PolicyDigest == grant.PolicyDigest &&
		event.Generation == grant.Generation && event.ServiceID == grant.ServiceID
}

func (s *Server) taskObservationStillActive(observation taskObservation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.taskObservationStillActiveLocked(observation)
}

func (s *Server) taskObservationStillActiveLocked(observation taskObservation) bool {
	state, exists := s.serviceTasks[observation.taskDigest]
	boundTask, bound := s.serviceTaskPermits[observation.permitDigest]
	grant, active := s.grants[observation.grant.GrantID]
	operation, configured := s.serviceOperations[observation.operation.ServiceID][observation.operation.ID]
	return observation.lease.Err() == nil && exists && bound && boundTask == observation.taskDigest &&
		state.Authorization == observation.state.Authorization && state.Authorization.PermitDigest == observation.permitDigest &&
		state.Dispatch == observation.state.Dispatch &&
		state.Terminal == observation.state.Terminal && state.observing &&
		active && grant.Active && grantsEqual(grant, observation.grant) && configured && operation == observation.operation &&
		s.policyDigests[observation.grant.GrantID] == observation.state.Authorization.RoutePolicyDigest
}

func (s *Server) fetchTaskObservation(ctx context.Context, observation taskObservation) ([]byte, taskprotocol.Report, error) {
	base, client, transport, err := s.serviceUpstream(observation.grant.ServiceURL)
	if err != nil {
		return nil, taskprotocol.Report{}, err
	}
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	target := *base
	target.Path = observation.operation.StatusPathPrefix + observation.state.Dispatch.RunID
	target.RawPath, target.RawQuery, target.Fragment, target.ForceQuery = "", "", "", false
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, taskprotocol.Report{}, err
	}
	request.Header = http.Header{
		"Accept":          {"application/json"},
		"Accept-Encoding": {"identity"},
	}
	request.Header.Set("User-Agent", "")
	response, err := client.Do(request)
	if err != nil {
		return nil, taskprotocol.Report{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !serviceTaskJSONResponse(response.Header) {
		return nil, taskprotocol.Report{}, errors.New("task status response has invalid status or content type")
	}
	encodings := response.Header.Values("Content-Encoding")
	maximum := observation.operation.MaxResponseBytes
	if maximum > maxTaskObservationResponseBytes {
		maximum = maxTaskObservationResponseBytes
	}
	if response.ContentLength > maximum || len(encodings) > 1 ||
		len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return nil, taskprotocol.Report{}, errors.New("task status response encoding or length is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(raw)) > maximum || response.ContentLength >= 0 && response.ContentLength != int64(len(raw)) {
		return nil, taskprotocol.Report{}, errors.New("task status response exceeds its limit")
	}
	report, err := taskprotocol.ParseReport(raw, int(maximum), observation.state.Dispatch.RunID)
	if err != nil {
		return nil, taskprotocol.Report{}, err
	}
	return raw, report, nil
}

func terminalTaskStatus(status taskprotocol.Status) connectorledger.TaskStatus {
	switch status {
	case taskprotocol.StatusCompleted:
		return connectorledger.TaskStatusAgentReportedCompleted
	case taskprotocol.StatusFailed:
		return connectorledger.TaskStatusAgentReportedFailed
	case taskprotocol.StatusCancelled:
		return connectorledger.TaskStatusAgentReportedCancelled
	default:
		return ""
	}
}

func terminalObservationMatches(terminal connectorledger.Event, raw []byte, report taskprotocol.Report) bool {
	return terminal.Phase == connectorledger.Terminal && terminal.Outcome == connectorledger.Responded &&
		terminal.HTTPStatus == http.StatusOK && terminal.ErrorCode == "" && terminal.TaskStatus != "" &&
		report.Status.Terminal() && terminal.RunID == report.RunID &&
		terminal.TaskStatus == terminalTaskStatus(report.Status) && terminal.ResponseBytes == int64(len(raw)) &&
		terminal.ResultDigest == dsse.Digest(raw)
}
