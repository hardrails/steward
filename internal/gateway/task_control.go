package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	controlTaskSubmitSchemaV1     = "steward.gateway-control-task-submit.v1"
	ControlTaskSubmissionSchemaV1 = "steward.gateway-control-task-submission.v1"
	controlTaskEvidenceMediaType  = "application/x-ndjson"
	maxControlTaskProxyResponse   = 16 << 10
)

var maxControlTaskSubmitBytes = int64(
	base64.RawURLEncoding.EncodedLen(taskpermit.MaxEnvelopeBytes) +
		base64.StdEncoding.EncodedLen(int(taskpermit.MaxRequestBytes)) +
		2048,
)

func connectorReceiptPublicKey(private ed25519.PrivateKey) ed25519.PublicKey {
	if len(private) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
}

type controlTaskSubmitRequest struct {
	SchemaVersion string `json:"schema_version"`
	GrantID       string `json:"grant_id"`
	OperationID   string `json:"operation_id"`
	TaskPermit    string `json:"task_permit"`
	RequestBase64 string `json:"request_base64"`
}

type wireControlTaskSubmitRequest struct {
	SchemaVersion *string `json:"schema_version"`
	GrantID       *string `json:"grant_id"`
	OperationID   *string `json:"operation_id"`
	TaskPermit    *string `json:"task_permit"`
	RequestBase64 *string `json:"request_base64"`
}

// ControlTaskSubmission identifies one exact lifecycle task accepted through
// the host-local Gateway control socket. Replayed means the same signed permit
// and request returned the already-recorded run without contacting the agent.
type ControlTaskSubmission struct {
	SchemaVersion string `json:"schema_version"`
	TaskDigest    string `json:"task_digest"`
	PermitDigest  string `json:"permit_digest"`
	RunID         string `json:"run_id"`
	Replayed      bool   `json:"replayed"`
}

type controlTaskResponseWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func newControlTaskResponseWriter() *controlTaskResponseWriter {
	return &controlTaskResponseWriter{header: make(http.Header)}
}

func (w *controlTaskResponseWriter) Header() http.Header {
	return w.header
}

func (w *controlTaskResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *controlTaskResponseWriter) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(value) > maxControlTaskProxyResponse-w.body.Len() {
		w.overflow = true
		return 0, errors.New("control task response exceeds limit")
	}
	return w.body.Write(value)
}

func (s *Server) handleControlTaskSubmit(w http.ResponseWriter, request *http.Request) {
	setControlTaskHeaders(w)
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method_not_allowed", "task submission method is not allowed")
		return
	}
	if request.URL == nil || request.URL.Path != "/v1/tasks" || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.RequestURI != request.URL.Path ||
		len(request.Header.Values("Content-Type")) != 1 ||
		request.Header.Get("Content-Type") != "application/json" ||
		request.ContentLength <= 0 || request.ContentLength > maxControlTaskSubmitBytes ||
		len(request.TransferEncoding) != 0 {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_submission", "task submission must be one bounded JSON request without a query")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, maxControlTaskSubmitBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || int64(len(raw)) != request.ContentLength {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_submission", "task submission is incomplete or exceeds its byte limit")
		return
	}
	submission, body, rawPermit, err := decodeControlTaskSubmitRequest(raw)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_submission", "task submission is invalid")
		return
	}

	s.mu.Lock()
	grant, active := s.grants[submission.GrantID]
	operation, configured := s.serviceOperations[grant.ServiceID][submission.OperationID]
	var lease context.Context
	var semaphore chan struct{}
	if active && grant.Active && grant.Service && grant.ServiceURL != "" && configured &&
		operation.TaskProtocol == connectorledger.TaskProtocolLifecycleV1 {
		lease = s.grantLeaseLocked(grant.GrantID)
		semaphore = s.serviceSemaphoreLocked(grant.GrantID)
	}
	s.mu.Unlock()
	if !active || !grant.Active || !grant.Service || grant.ServiceURL == "" || !configured ||
		operation.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		writeGatewayError(w, http.StatusNotFound, "service_operation_not_found", "active configured service operation not found")
		return
	}

	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	default:
		writeGatewayError(w, http.StatusTooManyRequests, "service_busy", "service grant concurrency limit reached")
		return
	}

	requestContext, cancel := context.WithTimeout(request.Context(), maxServiceLifetime)
	defer cancel()
	stopRevocation := context.AfterFunc(lease, cancel)
	defer stopRevocation()
	incoming, err := http.NewRequestWithContext(
		requestContext,
		operation.Method,
		"http://gateway"+operation.Path,
		bytes.NewReader(body),
	)
	if err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_submission_unavailable", "configured service operation could not be constructed")
		return
	}
	incoming.Header.Set("Content-Type", operation.ContentType)
	incoming.Header.Set(taskPermitHeader, submission.TaskPermit)
	incoming.ContentLength = int64(len(body))
	incoming.RequestURI = incoming.URL.Path

	captured := newControlTaskResponseWriter()
	s.proxyService(captured, incoming, grant, operation.Path)
	if captured.overflow {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_submission_unavailable", "task submission response exceeded its internal limit")
		return
	}
	if !successfulServiceTaskStatus(captured.status) {
		s.writeControlTaskProxyError(w, captured)
		return
	}
	runID, ok := serviceRunID(captured.body.Bytes())
	receipt := captured.header.Get(taskReceiptHeader)
	if !ok || receipt != "recorded" && receipt != "replayed" {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task dispatch response did not match durable Gateway evidence")
		return
	}
	permitDigest := dsse.Digest(rawPermit)
	routePolicyDigest := s.policyDigestFor(grant.GrantID)
	state, exists := s.existingServiceTaskByPermit(grant, operation, routePolicyDigest, body, permitDigest)
	s.mu.Lock()
	taskDigest, bound := s.serviceTaskPermits[permitDigest]
	s.mu.Unlock()
	if !exists || !bound || state.Dispatch.Phase != connectorledger.Dispatch ||
		state.Dispatch.RunID != runID || taskEvidenceUnavailable(state) ||
		taskDigest != state.Authorization.TaskDigest {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task dispatch response did not match durable Gateway evidence")
		return
	}
	writeJSON(w, http.StatusOK, ControlTaskSubmission{
		SchemaVersion: ControlTaskSubmissionSchemaV1,
		TaskDigest:    taskDigest,
		PermitDigest:  permitDigest,
		RunID:         runID,
		Replayed:      receipt == "replayed",
	})
}

func decodeControlTaskSubmitRequest(raw []byte) (controlTaskSubmitRequest, []byte, []byte, error) {
	var wire wireControlTaskSubmitRequest
	if err := dsse.DecodeStrictInto(raw, int(maxControlTaskSubmitBytes), &wire); err != nil ||
		wire.SchemaVersion == nil || wire.GrantID == nil || wire.OperationID == nil ||
		wire.TaskPermit == nil || wire.RequestBase64 == nil {
		return controlTaskSubmitRequest{}, nil, nil, errors.New("task submission omits a required field")
	}
	submission := controlTaskSubmitRequest{
		SchemaVersion: *wire.SchemaVersion,
		GrantID:       *wire.GrantID,
		OperationID:   *wire.OperationID,
		TaskPermit:    *wire.TaskPermit,
		RequestBase64: *wire.RequestBase64,
	}
	if submission.SchemaVersion != controlTaskSubmitSchemaV1 ||
		!validGrantID(submission.GrantID) || !routeID(submission.OperationID) {
		return controlTaskSubmitRequest{}, nil, nil, errors.New("task submission identity is invalid")
	}
	body, err := base64.StdEncoding.DecodeString(submission.RequestBase64)
	if err != nil || len(body) == 0 || int64(len(body)) > taskpermit.MaxRequestBytes ||
		base64.StdEncoding.EncodeToString(body) != submission.RequestBase64 ||
		!validTaskJSON(body, int(taskpermit.MaxRequestBytes)) {
		return controlTaskSubmitRequest{}, nil, nil, errors.New("task submission body is invalid")
	}
	rawPermit, err := taskpermit.DecodeHeader(submission.TaskPermit)
	if err != nil {
		return controlTaskSubmitRequest{}, nil, nil, err
	}
	return submission, body, rawPermit, nil
}

func (s *Server) writeControlTaskProxyError(w http.ResponseWriter, captured *controlTaskResponseWriter) {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if captured.status < 400 || captured.status > 599 ||
		dsse.DecodeStrictInto(captured.body.Bytes(), maxControlTaskProxyResponse, &payload) != nil ||
		payload.Error == "" || payload.Message == "" {
		writeGatewayError(w, http.StatusServiceUnavailable, "task_submission_unavailable", "task submission failed without a valid Gateway error")
		return
	}
	if retryAfter := captured.header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
			w.Header().Set("Retry-After", retryAfter)
		}
	}
	writeGatewayError(w, captured.status, payload.Error, payload.Message)
}

func (s *Server) handleControlTask(w http.ResponseWriter, request *http.Request) {
	setControlTaskHeaders(w)
	taskDigest, permitDigest, action, ok := parseControlTaskRoute(request)
	if !ok {
		writeGatewayError(w, http.StatusNotFound, "task_not_found", "lifecycle task not found")
		return
	}
	if action != "evidence" {
		s.handleTaskLifecycle(w, request)
		return
	}
	if request.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method_not_allowed", "task evidence method is not allowed")
		return
	}
	if !emptyControlTaskBody(w, request) {
		return
	}
	s.exportControlTaskEvidence(w, taskDigest, permitDigest)
}

func setControlTaskHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func parseControlTaskRoute(request *http.Request) (string, string, string, bool) {
	if request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.URL.ForceQuery || request.RequestURI != request.URL.Path {
		return "", "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/tasks/"), "/")
	if len(parts) != 3 && len(parts) != 4 ||
		parts[1] != "permits" ||
		!serviceTaskDigestPattern.MatchString(parts[0]) ||
		!serviceTaskDigestPattern.MatchString(parts[2]) {
		return "", "", "", false
	}
	action := ""
	if len(parts) == 4 {
		action = parts[3]
		if action != "observe" && action != "evidence" {
			return "", "", "", false
		}
	}
	return parts[0], parts[2], action, true
}

func emptyControlTaskBody(w http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(w, request.Body, 1)
	body, err := io.ReadAll(request.Body)
	if err != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(body) != 0 {
		writeGatewayError(w, http.StatusBadRequest, "invalid_task_evidence_request", "task evidence requests have no body")
		return false
	}
	return true
}

func (s *Server) exportControlTaskEvidence(w http.ResponseWriter, taskDigest, permitDigest string) {
	s.serviceTaskMutationMu.Lock()
	defer s.serviceTaskMutationMu.Unlock()

	s.mu.Lock()
	state, exists := s.serviceTasks[taskDigest]
	boundTask, bound := s.serviceTaskPermits[permitDigest]
	ledger := s.connectorLedger
	public := append(ed25519.PublicKey(nil), s.connectorReceiptPublic...)
	path := s.config.ConnectorReceiptFile
	nodeID := s.config.ConnectorReceiptNodeID
	epoch := s.config.ConnectorReceiptEpoch
	s.mu.Unlock()
	if !exists || !bound || boundTask != taskDigest ||
		state.Authorization.PermitDigest != permitDigest ||
		state.Authorization.TaskProtocol != connectorledger.TaskProtocolLifecycleV1 {
		writeGatewayError(w, http.StatusNotFound, "task_not_found", "lifecycle task not found")
		return
	}
	if taskEvidenceUnavailable(state) || ledger == nil || ledger.Failed() ||
		len(public) != ed25519.PublicKeySize {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task evidence is unavailable; restart Gateway to reconcile it")
		return
	}
	if state.Dispatch.Phase != connectorledger.Dispatch ||
		state.Terminal.Phase != connectorledger.Terminal {
		writeGatewayError(w, http.StatusConflict, "task_evidence_incomplete", "task evidence is not complete")
		return
	}

	selected := make([]connectorledger.VerifiedReceipt, 0, 3)
	_, err := connectorledger.VerifyRecords(
		path,
		public,
		nodeID,
		epoch,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			taskMatch := event.TaskDigest == taskDigest
			permitMatch := event.PermitDigest == permitDigest
			if taskMatch != permitMatch {
				return errors.New("Gateway ledger contains a partial task or permit identity collision")
			}
			if taskMatch {
				if len(selected) == 3 {
					return errors.New("Gateway ledger contains too many receipts for one lifecycle task")
				}
				selected = append(selected, record)
			}
			return nil
		},
	)
	if err != nil {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task receipt ledger could not be verified")
		return
	}
	raw, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		code, status, message := "evidence_unavailable", http.StatusServiceUnavailable, "task receipt evidence is invalid"
		if errors.Is(err, connectorledger.ErrPortableTaskEvidenceIncomplete) {
			code, status, message = "task_evidence_incomplete", http.StatusConflict, "task evidence is not complete"
		}
		writeGatewayError(w, status, code, message)
		return
	}
	verified, err := connectorledger.VerifyPortableTaskEvidence(
		raw,
		public,
		nodeID,
		epoch,
		taskDigest,
		permitDigest,
	)
	if err != nil || len(verified.Records) != 3 ||
		verified.Records[0].Receipt.Event != state.Authorization ||
		verified.Records[1].Receipt.Event != state.Dispatch ||
		verified.Records[2].Receipt.Event != state.Terminal {
		writeGatewayError(w, http.StatusServiceUnavailable, "evidence_unavailable", "task receipt evidence does not match durable Gateway state")
		return
	}
	w.Header().Set("Content-Type", controlTaskEvidenceMediaType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(raw)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
