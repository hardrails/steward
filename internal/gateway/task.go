package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const taskPermitHeader = "X-Steward-Task-Permit"
const taskReceiptHeader = "X-Steward-Task-Receipt"

var serviceRunIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (s *Server) serviceTaskOperation(grant Grant, method, path string) (ServiceOperation, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(grant.TaskAuthorities) == 0 {
		return ServiceOperation{}, "", false
	}
	current, active := s.grants[grant.GrantID]
	if !active || !current.Active || !grantsEqual(current, grant) {
		return ServiceOperation{}, "", false
	}
	for _, operation := range s.serviceOperations[grant.ServiceID] {
		if operation.Method == method && operation.Path == path {
			return operation, s.policyDigests[grant.GrantID], true
		}
	}
	return ServiceOperation{}, "", false
}

func (s *Server) proxyServiceTask(w http.ResponseWriter, incoming *http.Request, grant Grant, operation ServiceOperation, routePolicyDigest string) {
	if incoming.URL == nil || incoming.URL.RawPath != "" || incoming.URL.RawQuery != "" || incoming.URL.ForceQuery ||
		incoming.RequestURI != incoming.URL.Path || websocketAttempt(incoming) || len(incoming.TransferEncoding) != 0 ||
		incoming.ContentLength <= 0 || incoming.ContentLength > operation.MaxRequestBytes ||
		len(incoming.Header.Values("Content-Type")) != 1 || incoming.Header.Get("Content-Type") != operation.ContentType {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_request", "task request must use the configured exact method, path, content type, length, and no query")
		return
	}
	permitValues := incoming.Header.Values(taskPermitHeader)
	if len(permitValues) != 1 {
		writeGatewayError(w, http.StatusUnauthorized, "task_permit_required", "one task permit is required")
		return
	}
	incoming.Body = http.MaxBytesReader(w, incoming.Body, operation.MaxRequestBytes)
	body, err := io.ReadAll(incoming.Body)
	if err != nil || int64(len(body)) != incoming.ContentLength || !validTaskJSON(body, int(operation.MaxRequestBytes)) {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_request", "task request body is incomplete, oversized, or ambiguous JSON")
		return
	}
	rawPermit, err := taskpermit.DecodeHeader(permitValues[0])
	if err != nil {
		writeGatewayError(w, http.StatusUnauthorized, "invalid_task_permit", "task permit header is invalid")
		return
	}
	permitDigest := dsse.Digest(rawPermit)
	if state, exists := s.existingServiceTaskByPermit(grant, operation, routePolicyDigest, body, permitDigest); exists {
		s.writeExistingServiceTask(w, state, permitDigest)
		return
	}
	trusted, err := taskAuthorityKeys(grant.TaskAuthorities)
	if err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_authority_unavailable", "task authority could not be loaded from the active grant")
		return
	}
	now := s.now().UTC()
	verified, err := taskpermit.Verify(rawPermit, trusted, now, time.Duration(operation.MaxPermitSeconds)*time.Second)
	if err != nil || !taskPermitMatches(verified, grant, routePolicyDigest, operation, body) {
		writeGatewayError(w, http.StatusForbidden, "task_permit_denied", "task permit does not authorize this exact active service request")
		return
	}
	taskDigest := taskpermit.TaskDigest(grant.TenantID, grant.InstanceID, verified.Statement.TaskID)
	event := serviceTaskReceiptEvent(grant, routePolicyDigest, operation, taskDigest, verified, body)
	state, existed, err := s.beginServiceTask(taskDigest, event)
	if existed {
		s.writeExistingServiceTask(w, state, verified.EnvelopeDigest)
		return
	}
	if err != nil {
		if errors.Is(err, connectorledger.ErrTenantQuotaExceeded) || errors.Is(err, connectorledger.ErrTenantUnbudgeted) {
			writeGatewayError(w, http.StatusServiceUnavailable, "task_evidence_quota_exhausted", "tenant task receipt capacity is exhausted")
			return
		}
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task authorization could not be recorded")
		return
	}

	// Authorization is durable now. Recheck time and lifecycle immediately
	// before dispatch so a slow fsync cannot extend authority or outrun revoke.
	if _, err := taskpermit.Verify(rawPermit, trusted, s.now().UTC(), time.Duration(operation.MaxPermitSeconds)*time.Second); err != nil {
		s.finishServiceTaskKnownFailure(w, taskDigest, event, "permit_expired", http.StatusForbidden, "task permit expired before dispatch")
		return
	}
	if !s.serviceTaskGrantStillActive(grant) {
		s.finishServiceTaskKnownFailure(w, taskDigest, event, "grant_revoked", http.StatusServiceUnavailable, "service grant was revoked before dispatch")
		return
	}

	response, responseBody, errorCode := s.dispatchServiceTask(incoming.Context(), grant, operation, body)
	if errorCode != "" {
		terminal := event
		terminal.Phase, terminal.Outcome, terminal.ErrorCode = connectorledger.Terminal, connectorledger.Failed, errorCode
		if err := s.finishServiceTask(taskDigest, terminal); err != nil {
			writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task result could not be recorded")
			return
		}
		w.Header().Set(taskReceiptHeader, "recorded")
		writeGatewayError(w, http.StatusBadGateway, errorCode, "service task outcome is unknown; automatic retry is unsafe")
		return
	}

	if successfulServiceTaskStatus(response.StatusCode) {
		runID, ok := serviceRunID(responseBody)
		if !ok || !serviceTaskJSONResponse(response.Header) {
			terminal := serviceTaskFailureEvent(event, response.StatusCode, int64(len(responseBody)), "outcome_unknown")
			if err := s.finishServiceTask(taskDigest, terminal); err != nil {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task result could not be recorded")
				return
			}
			w.Header().Set(taskReceiptHeader, "recorded")
			writeGatewayError(w, http.StatusBadGateway, "outcome_unknown", "service returned no bounded run ID; automatic retry is unsafe")
			return
		}
		dispatch := event
		dispatch.Phase, dispatch.Outcome = connectorledger.Dispatch, connectorledger.Responded
		dispatch.HTTPStatus, dispatch.ResponseBytes, dispatch.RunID = response.StatusCode, int64(len(responseBody)), runID
		ambiguous, err := s.recordServiceTaskDispatch(taskDigest, dispatch)
		if errors.Is(err, connectorledger.ErrRunIDConflict) {
			terminal := serviceTaskFailureEvent(event, response.StatusCode, int64(len(responseBody)), "run_id_conflict")
			if finishErr := s.finishServiceTask(taskDigest, terminal); finishErr != nil {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task result could not be recorded")
				return
			}
			w.Header().Set(taskReceiptHeader, "recorded")
			writeGatewayError(w, http.StatusConflict, "run_id_conflict", "service reused a run ID already bound to another signed task")
			return
		}
		if err != nil {
			if ambiguous {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task dispatch evidence is ambiguous; restart Gateway to reconcile it")
				return
			}
			terminal := serviceTaskFailureEvent(event, response.StatusCode, int64(len(responseBody)), "outcome_unknown")
			if finishErr := s.finishServiceTask(taskDigest, terminal); finishErr != nil {
				writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task result could not be recorded")
				return
			}
			w.Header().Set(taskReceiptHeader, "recorded")
			writeGatewayError(w, http.StatusBadGateway, "outcome_unknown", "service task dispatch could not be recorded; automatic retry is unsafe")
			return
		}
		writeServiceTaskResponse(w, response.StatusCode, runID, "recorded")
		return
	}

	code, message := serviceTaskRejection(response.StatusCode)
	terminal := serviceTaskFailureEvent(event, response.StatusCode, int64(len(responseBody)), code)
	if err := s.finishServiceTask(taskDigest, terminal); err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task result could not be recorded")
		return
	}
	w.Header().Set(taskReceiptHeader, "recorded")
	writeGatewayError(w, http.StatusBadGateway, code, message)
}

func serviceTaskFailureEvent(event connectorledger.Event, status int, responseBytes int64, code string) connectorledger.Event {
	event.Phase, event.Outcome, event.ErrorCode = connectorledger.Terminal, connectorledger.Failed, code
	event.HTTPStatus, event.ResponseBytes = status, responseBytes
	return event
}

func validTaskJSON(raw []byte, maxBytes int) bool {
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	return dsse.DecodeStrictInto(wrapper, maxBytes+10, &decoded) == nil
}

func taskAuthorityKeys(authorities []TaskAuthority) (map[string]ed25519.PublicKey, error) {
	if !validTaskAuthorities(authorities) {
		return nil, errors.New("invalid task authority grant")
	}
	keys := make(map[string]ed25519.PublicKey, len(authorities))
	for _, authority := range authorities {
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil {
			return nil, err
		}
		keys[authority.KeyID] = ed25519.PublicKey(public)
	}
	return keys, nil
}

func taskPermitMatches(verified taskpermit.Verified, grant Grant, routePolicyDigest string, operation ServiceOperation, body []byte) bool {
	statement := verified.Statement
	return statement.NodeID == grant.NodeID && statement.TenantID == grant.TenantID &&
		statement.InstanceID == grant.InstanceID && statement.RuntimeRef == grant.RuntimeRef &&
		statement.GrantID == grant.GrantID && statement.Generation == grant.Generation &&
		statement.CapsuleDigest == grant.CapsuleDigest && statement.PolicyDigest == grant.PolicyDigest &&
		statement.RoutePolicyDigest == routePolicyDigest && statement.ServiceID == grant.ServiceID &&
		statement.OperationID == operation.ID && statement.OperationPolicyDigest == ServiceOperationDigest(operation) &&
		statement.RequestDigest == taskpermit.RequestDigest(body) && statement.RequestBytes == int64(len(body)) &&
		statement.ContentType == operation.ContentType
}

func serviceTaskReceiptEvent(grant Grant, routePolicyDigest string, operation ServiceOperation, taskDigest string, verified taskpermit.Verified, body []byte) connectorledger.Event {
	return connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed, Kind: connectorledger.ServiceTask,
		TenantID: grant.TenantID, RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest,
		PolicyDigest: grant.PolicyDigest, RoutePolicyDigest: routePolicyDigest, Generation: grant.Generation,
		GrantID: grant.GrantID, ServiceID: grant.ServiceID, OperationID: operation.ID,
		OperationPolicyDigest: ServiceOperationDigest(operation), TaskDigest: taskDigest,
		AuthorityKeyID: verified.KeyID, PermitDigest: verified.EnvelopeDigest,
		RequestDigest: taskpermit.RequestDigest(body), RequestBytes: int64(len(body)),
		TaskProtocol: operation.TaskProtocol,
	}
}

func (s *Server) policyDigestFor(grantID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyDigests[grantID]
}

func (s *Server) existingServiceTaskByPermit(
	grant Grant,
	operation ServiceOperation,
	routePolicyDigest string,
	body []byte,
	permitDigest string,
) (serviceTaskReceipt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	taskDigest, exists := s.serviceTaskPermits[permitDigest]
	if !exists {
		return serviceTaskReceipt{}, false
	}
	state, exists := s.serviceTasks[taskDigest]
	authorized := state.Authorization
	if !exists || authorized.PermitDigest != permitDigest || authorized.GrantID != grant.GrantID ||
		authorized.TenantID != grant.TenantID || authorized.RuntimeRef != grant.RuntimeRef ||
		authorized.CapsuleDigest != grant.CapsuleDigest || authorized.PolicyDigest != grant.PolicyDigest ||
		authorized.RoutePolicyDigest != routePolicyDigest || authorized.Generation != grant.Generation ||
		authorized.ServiceID != grant.ServiceID || authorized.OperationID != operation.ID ||
		authorized.OperationPolicyDigest != ServiceOperationDigest(operation) ||
		authorized.TaskProtocol != operation.TaskProtocol ||
		authorized.RequestDigest != taskpermit.RequestDigest(body) || authorized.RequestBytes != int64(len(body)) {
		return serviceTaskReceipt{}, false
	}
	return state, true
}

func (s *Server) beginServiceTask(taskDigest string, event connectorledger.Event) (serviceTaskReceipt, bool, error) {
	// The ledger already serializes durable appends. Serialize this surrounding
	// failure check and process-local reservation too, so one ambiguous append
	// cannot leave an attacker-selected number of concurrent task fences.
	s.serviceTaskMutationMu.Lock()
	defer s.serviceTaskMutationMu.Unlock()

	s.mu.Lock()
	if s.serviceTasks == nil {
		s.serviceTasks = make(map[string]serviceTaskReceipt)
	}
	if s.serviceTaskPermits == nil {
		s.serviceTaskPermits = make(map[string]string)
	}
	if state, exists := s.serviceTasks[taskDigest]; exists {
		s.mu.Unlock()
		return state, true, nil
	}
	if existingTask, exists := s.serviceTaskPermits[event.PermitDigest]; exists && existingTask != taskDigest {
		s.mu.Unlock()
		return serviceTaskReceipt{}, false, errors.New("task permit is already bound to a different task identity")
	}
	ledger := s.connectorLedger // Fixed for this Server's lifetime; Reload does not replace it.
	s.mu.Unlock()
	if ledger == nil {
		return serviceTaskReceipt{}, false, errors.New("task receipt ledger is unavailable")
	}
	// Failed takes the ledger lock and can wait for an in-flight fsync. Keep
	// that wait outside the Server mutex, then repeat the replay checks before
	// reserving so concurrent callers cannot cross this gap.
	if ledger.Failed() {
		return serviceTaskReceipt{}, false, errors.New("task receipt ledger requires reopen after an ambiguous write")
	}
	s.mu.Lock()
	if state, exists := s.serviceTasks[taskDigest]; exists {
		s.mu.Unlock()
		return state, true, nil
	}
	if existingTask, exists := s.serviceTaskPermits[event.PermitDigest]; exists && existingTask != taskDigest {
		s.mu.Unlock()
		return serviceTaskReceipt{}, false, errors.New("task permit is already bound to a different task identity")
	}
	reserved := serviceTaskReceipt{Authorization: event}
	s.serviceTasks[taskDigest] = reserved
	s.serviceTaskPermits[event.PermitDigest] = taskDigest
	s.mu.Unlock()

	// Reserve replay identity in memory before the durable append. This keeps a
	// slow fsync from blocking unrelated grants while still preventing two
	// concurrent copies of one signed task from reaching the service.
	if _, err := ledger.Begin(event); err != nil {
		ambiguous := ledger.Failed()
		s.mu.Lock()
		if current, exists := s.serviceTasks[taskDigest]; exists && current.Authorization.PermitDigest == event.PermitDigest && current.Terminal.Phase == "" {
			if ambiguous {
				// The service was not contacted, but the authorization may be
				// durable. Retain its replay identity until reopen verifies the
				// ledger; the failed-ledger check above prevents later distinct
				// tasks from accumulating process-local reservations meanwhile.
				current.authorizationAmbiguous = true
				s.serviceTasks[taskDigest] = current
			} else {
				delete(s.serviceTasks, taskDigest)
				if s.serviceTaskPermits[event.PermitDigest] == taskDigest {
					delete(s.serviceTaskPermits, event.PermitDigest)
				}
			}
		}
		s.mu.Unlock()
		return serviceTaskReceipt{}, false, err
	}
	return reserved, false, nil
}

func (s *Server) serviceTaskGrantStillActive(grant Grant) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.grants[grant.GrantID]
	return ok && current.Active && grantsEqual(current, grant)
}

func (s *Server) writeExistingServiceTask(w http.ResponseWriter, state serviceTaskReceipt, permitDigest string) {
	if state.Authorization.PermitDigest != permitDigest {
		writeGatewayError(w, http.StatusConflict, "task_id_conflict", "task ID is already bound to different signed authority")
		return
	}
	if state.authorizationAmbiguous {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task authorization evidence is ambiguous; restart Gateway to reconcile it")
		return
	}
	if state.dispatchAmbiguous {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task dispatch evidence is ambiguous; restart Gateway to reconcile it")
		return
	}
	if state.terminalUnavailable {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task terminal evidence is unavailable; restart Gateway to reconcile it")
		return
	}
	if state.Dispatch.Phase == connectorledger.Dispatch {
		writeServiceTaskResponse(w, state.Dispatch.HTTPStatus, state.Dispatch.RunID, "replayed")
		return
	}
	if state.Terminal.Phase == "" {
		writeGatewayError(w, http.StatusConflict, "task_in_progress", "task authorization is already in progress")
		return
	}
	code := state.Terminal.ErrorCode
	if code == "" {
		code = "task_already_spent"
	}
	message := "task was already dispatched and cannot be retried safely"
	if state.Terminal.HTTPStatus != 0 {
		message = fmt.Sprintf("task was already dispatched; upstream returned HTTP %d; the signed task cannot be retried safely", state.Terminal.HTTPStatus)
	}
	writeGatewayError(w, http.StatusConflict, code, message)
}

func (s *Server) finishServiceTaskKnownFailure(w http.ResponseWriter, taskDigest string, event connectorledger.Event, code string, status int, message string) {
	terminal := event
	terminal.Phase, terminal.Outcome, terminal.ErrorCode = connectorledger.Terminal, connectorledger.Failed, code
	if err := s.finishServiceTask(taskDigest, terminal); err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task denial could not be recorded")
		return
	}
	w.Header().Set(taskReceiptHeader, "recorded")
	writeGatewayError(w, status, code, message)
}

func (s *Server) finishServiceTask(taskDigest string, terminal connectorledger.Event) error {
	s.serviceTaskMutationMu.Lock()
	defer s.serviceTaskMutationMu.Unlock()
	if s.connectorLedger == nil {
		return errors.New("task receipt ledger is unavailable")
	}
	if _, err := s.connectorLedger.Finish(terminal); err != nil {
		s.mu.Lock()
		state := s.serviceTasks[taskDigest]
		state.terminalUnavailable = true
		s.serviceTasks[taskDigest] = state
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	state := s.serviceTasks[taskDigest]
	state.Terminal = terminal
	s.serviceTasks[taskDigest] = state
	s.mu.Unlock()
	return nil
}

func (s *Server) recordServiceTaskDispatch(taskDigest string, dispatch connectorledger.Event) (bool, error) {
	s.serviceTaskMutationMu.Lock()
	defer s.serviceTaskMutationMu.Unlock()
	if s.connectorLedger == nil {
		return false, errors.New("task receipt ledger is unavailable")
	}
	if _, err := s.connectorLedger.Dispatch(dispatch); err != nil {
		ambiguous := s.connectorLedger.Failed()
		if ambiguous {
			s.mu.Lock()
			state := s.serviceTasks[taskDigest]
			state.dispatchAmbiguous = true
			s.serviceTasks[taskDigest] = state
			s.mu.Unlock()
		}
		return ambiguous, err
	}
	s.mu.Lock()
	state := s.serviceTasks[taskDigest]
	state.Dispatch = dispatch
	s.serviceTasks[taskDigest] = state
	s.mu.Unlock()
	return false, nil
}

func (s *Server) dispatchServiceTask(ctx context.Context, grant Grant, operation ServiceOperation, body []byte) (*http.Response, []byte, string) {
	base, client, transport, err := s.serviceUpstream(grant.ServiceURL)
	if err != nil {
		return nil, nil, "outcome_unknown"
	}
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	target := *base
	target.Path, target.RawQuery = operation.Path, ""
	requestContext, cancel := context.WithTimeout(ctx, time.Duration(operation.MaxSeconds)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, operation.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, "outcome_unknown"
	}
	request.Header.Set("Content-Type", operation.ContentType)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "")
	request.ContentLength = int64(len(body))
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, "outcome_unknown"
	}
	defer response.Body.Close()
	contentEncodings := response.Header.Values("Content-Encoding")
	if response.ContentLength > operation.MaxResponseBytes || len(contentEncodings) > 1 ||
		len(contentEncodings) == 1 && !strings.EqualFold(strings.TrimSpace(contentEncodings[0]), "identity") {
		return nil, nil, "outcome_unknown"
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, operation.MaxResponseBytes+1))
	if err != nil || int64(len(responseBody)) > operation.MaxResponseBytes {
		return nil, nil, "outcome_unknown"
	}
	return response, responseBody, ""
}

func serviceRunID(raw []byte) (string, bool) {
	if !validTaskJSON(raw, int(maxServiceTaskResponseBytes)) {
		return "", false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return "", false
	}
	var runID string
	if err := json.Unmarshal(object["run_id"], &runID); err != nil || !serviceRunIDPattern.MatchString(runID) {
		return "", false
	}
	return runID, true
}

func successfulServiceTaskStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted
}

func serviceTaskRejection(status int) (string, string) {
	code := "service_task_unexpected_status"
	switch status {
	case http.StatusUnauthorized:
		code = "service_task_upstream_unauthorized"
	case http.StatusForbidden:
		code = "service_task_upstream_forbidden"
	case http.StatusNotFound:
		code = "service_task_upstream_not_found"
	case http.StatusTooManyRequests:
		code = "service_task_upstream_rate_limited"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		code = "service_task_upstream_timeout"
	default:
		switch {
		case status >= 300 && status < 400:
			return "redirect_denied", fmt.Sprintf("upstream service returned HTTP %d; redirects are denied; the signed task is spent", status)
		case status >= 400 && status < 500:
			code = "service_task_upstream_client_error"
		case status >= 500 && status < 600:
			code = "service_task_upstream_server_error"
		}
	}
	return code, fmt.Sprintf("upstream service returned HTTP %d; the signed task is spent; inspect task status or signed audit evidence before issuing new authority", status)
}

func serviceTaskJSONResponse(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json"
}

func writeServiceTaskResponse(w http.ResponseWriter, status int, runID string, receipt string) {
	body, _ := json.Marshal(map[string]string{"run_id": runID})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Steward-Service-Grant", "active")
	w.Header().Set(taskReceiptHeader, receipt)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
