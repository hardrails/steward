package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

func invokeControlTaskSubmit(
	t *testing.T,
	rig *serviceTaskRig,
	body []byte,
	permit string,
) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(controlTaskSubmitRequest{
		SchemaVersion: controlTaskSubmitSchemaV1,
		GrantID:       rig.grant.GrantID,
		OperationID:   rig.operation.ID,
		TaskPermit:    permit,
		RequestBase64: base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return invokeControlTaskRaw(rig, http.MethodPost, "/v1/tasks", "application/json", raw)
}

func invokeControlTaskRaw(
	rig *serviceTaskRig,
	method string,
	path string,
	contentType string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(response, request)
	return response
}

func controlTaskPathFor(taskDigest, permitDigest, action string) string {
	path := "/v1/tasks/" + taskDigest + "/permits/" + permitDigest
	if action != "" {
		path += "/" + action
	}
	return path
}

func decodeControlTaskSubmission(t *testing.T, response *httptest.ResponseRecorder) ControlTaskSubmission {
	t.Helper()
	var submission ControlTaskSubmission
	if err := json.Unmarshal(response.Body.Bytes(), &submission); err != nil {
		t.Fatalf("decode task submission status=%d body=%q: %v", response.Code, response.Body.String(), err)
	}
	return submission
}

func TestControlTaskLifecycleUsesExistingAuthorizationObservationAndEvidence(t *testing.T) {
	var dispatches atomic.Int64
	terminal := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed","result":"workspace-clean"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/runs":
			dispatches.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/v1/runs/"+lifecycleTestRunID:
			_, _ = w.Write(terminal)
		default:
			t.Errorf("unexpected upstream request %s %s", request.Method, request.URL.String())
			http.NotFound(w, request)
		}
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"audit workspace","session_id":"control-canary"}`)
	permit := taskPermitFor(t, rig, "task-control-canary", body, nil)

	first := invokeControlTaskSubmit(t, rig, body, permit)
	if first.Code != http.StatusOK {
		t.Fatalf("first submission status=%d body=%s", first.Code, first.Body.String())
	}
	submitted := decodeControlTaskSubmission(t, first)
	public := rig.config.connectorReceiptKey.Public().(ed25519.PublicKey)
	publicBase64 := base64.StdEncoding.EncodeToString(public)
	if submitted.SchemaVersion != ControlTaskSubmissionSchemaV1 ||
		submitted.RunID != lifecycleTestRunID || submitted.Replayed ||
		submitted.ReceiptNodeID != rig.config.ConnectorReceiptNodeID ||
		submitted.ReceiptEpoch != rig.config.ConnectorReceiptEpoch ||
		submitted.ReceiptPublicKey != publicBase64 ||
		dispatches.Load() != 1 {
		t.Fatalf("first submission=%#v dispatches=%d", submitted, dispatches.Load())
	}

	replay := invokeControlTaskSubmit(t, rig, body, permit)
	replayed := decodeControlTaskSubmission(t, replay)
	if replay.Code != http.StatusOK || !replayed.Replayed ||
		replayed.TaskDigest != submitted.TaskDigest ||
		replayed.PermitDigest != submitted.PermitDigest ||
		replayed.RunID != submitted.RunID ||
		replayed.ReceiptNodeID != submitted.ReceiptNodeID ||
		replayed.ReceiptEpoch != submitted.ReceiptEpoch ||
		replayed.ReceiptPublicKey != submitted.ReceiptPublicKey ||
		dispatches.Load() != 1 {
		t.Fatalf("replay=%#v status=%d dispatches=%d body=%s", replayed, replay.Code, dispatches.Load(), replay.Body.String())
	}

	statusPath := controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "")
	status := invokeControlTaskRaw(rig, http.MethodGet, statusPath, "", nil)
	decoded := decodeLifecycleTaskStatus(t, status)
	requireLifecycleTaskStatus(
		t,
		status,
		submitted.TaskDigest,
		"dispatch",
		TaskStateDispatchAccepted,
		lifecycleTestRunID,
		"",
	)
	if decoded.ObservationBase64 != "" {
		t.Fatal("durable task status disclosed live observation bytes")
	}

	evidencePath := controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "evidence")
	incomplete := invokeControlTaskRaw(rig, http.MethodGet, evidencePath, "", nil)
	if code := requireGatewayErrorCode(t, incomplete, http.StatusConflict); code != "task_evidence_incomplete" {
		t.Fatalf("incomplete evidence code=%q", code)
	}

	observed := invokeControlTaskRaw(
		rig,
		http.MethodPost,
		controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "observe"),
		"",
		nil,
	)
	requireLifecycleTaskStatus(
		t,
		observed,
		submitted.TaskDigest,
		"terminal",
		string(connectorledger.TaskStatusAgentReportedCompleted),
		lifecycleTestRunID,
		string(connectorledger.TaskStatusAgentReportedCompleted),
	)
	throttled := invokeControlTaskRaw(
		rig,
		http.MethodPost,
		controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "observe"),
		"",
		nil,
	)
	if code := requireGatewayErrorCode(t, throttled, http.StatusTooManyRequests); code != "task_observation_throttled" {
		t.Fatalf("throttled observation code=%q", code)
	}

	exported := invokeControlTaskRaw(rig, http.MethodGet, evidencePath, "", nil)
	if exported.Code != http.StatusOK ||
		exported.Header().Get("Content-Type") != controlTaskEvidenceMediaType ||
		exported.Body.Len() > connectorledger.MaxPortableTaskEvidenceBytes {
		t.Fatalf("evidence status=%d headers=%v bytes=%d body=%s", exported.Code, exported.Header(), exported.Body.Len(), exported.Body.String())
	}
	verified, err := connectorledger.VerifyPortableTaskEvidence(
		exported.Body.Bytes(),
		public,
		rig.config.ConnectorReceiptNodeID,
		rig.config.ConnectorReceiptEpoch,
		submitted.TaskDigest,
		submitted.PermitDigest,
	)
	if err != nil || len(verified.Records) != 3 {
		t.Fatalf("portable evidence records=%d err=%v", len(verified.Records), err)
	}
	for index, phase := range []connectorledger.Phase{
		connectorledger.Authorize,
		connectorledger.Dispatch,
		connectorledger.Terminal,
	} {
		event := verified.Records[index].Receipt.Event
		if event.Phase != phase || event.TaskDigest != submitted.TaskDigest ||
			event.PermitDigest != submitted.PermitDigest {
			t.Fatalf("portable receipt %d=%#v", index, event)
		}
	}
}

func TestControlClientCoversTypedTaskLifecycleOverUnixSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)

	directory, err := os.MkdirTemp("/tmp", "gateway-task-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	controlServer := &http.Server{Handler: rig.server.ControlHandler()}
	go func() { _ = controlServer.Serve(listener) }()
	t.Cleanup(func() { _ = controlServer.Close() })

	client, err := NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"input":"audit workspace","session_id":"typed-control-client"}`)
	permit := taskPermitFor(t, rig, "task-typed-control-client", body, nil)
	submitted, err := client.SubmitTask(
		context.Background(),
		rig.grant.GrantID,
		rig.operation.ID,
		permit,
		body,
	)
	if err != nil || submitted.RunID != lifecycleTestRunID || submitted.Replayed {
		t.Fatalf("submitted=%#v err=%v", submitted, err)
	}
	replayed, err := client.SubmitTask(
		context.Background(),
		rig.grant.GrantID,
		rig.operation.ID,
		permit,
		body,
	)
	if err != nil || !replayed.Replayed || replayed.TaskDigest != submitted.TaskDigest ||
		replayed.PermitDigest != submitted.PermitDigest || replayed.RunID != submitted.RunID ||
		replayed.ReceiptNodeID != submitted.ReceiptNodeID ||
		replayed.ReceiptEpoch != submitted.ReceiptEpoch ||
		replayed.ReceiptPublicKey != submitted.ReceiptPublicKey {
		t.Fatalf("replayed=%#v err=%v submitted=%#v", replayed, err, submitted)
	}
	publicRaw, err := base64.StdEncoding.DecodeString(submitted.ReceiptPublicKey)
	if err != nil || submitted.ReceiptNodeID != rig.config.ConnectorReceiptNodeID ||
		submitted.ReceiptEpoch != rig.config.ConnectorReceiptEpoch {
		t.Fatalf("receipt authority=%#v decode=%v", submitted, err)
	}
	status, err := client.TaskStatus(context.Background(), submitted.TaskDigest, submitted.PermitDigest)
	if err != nil || status.Phase != connectorledger.Dispatch {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	observed, err := client.ObserveTask(context.Background(), submitted.TaskDigest, submitted.PermitDigest)
	if err != nil || observed.Phase != connectorledger.Terminal ||
		observed.ObservedStatus == "" || observed.ObservationBase64 == "" {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	_, err = client.ObserveTask(context.Background(), submitted.TaskDigest, submitted.PermitDigest)
	var apiError *ControlAPIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusTooManyRequests ||
		apiError.Code != "task_observation_throttled" || apiError.RetryAfter != time.Duration(rig.operation.PollIntervalSeconds)*time.Second ||
		apiError.Error() != "gateway task_observation_throttled: task observation is limited by host policy" {
		t.Fatalf("throttled observation error=%v typed=%#v", err, apiError)
	}
	evidence, err := client.ExportTaskEvidence(context.Background(), submitted.TaskDigest, submitted.PermitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if verified, verifyErr := connectorledger.VerifyPortableTaskEvidence(
		evidence,
		ed25519.PublicKey(publicRaw),
		submitted.ReceiptNodeID,
		submitted.ReceiptEpoch,
		submitted.TaskDigest,
		submitted.PermitDigest,
	); verifyErr != nil || len(verified.Records) != 3 {
		t.Fatalf("typed client evidence records=%d err=%v", len(verified.Records), verifyErr)
	}
	if _, err := client.TaskStatus(context.Background(), "sha256:bad", submitted.PermitDigest); err == nil {
		t.Fatal("typed client accepted an invalid task identity")
	}
}

func TestControlClientStrictlyValidatesTaskReceiptAuthority(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"audit workspace","session_id":"receipt-authority"}`)
	permit := taskPermitFor(t, rig, "task-receipt-authority", body, nil)
	rawPermit, err := taskpermit.DecodeHeader(permit)
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := ControlTaskSubmission{
		SchemaVersion:    ControlTaskSubmissionSchemaV1,
		TaskDigest:       "sha256:" + strings.Repeat("a", 64),
		PermitDigest:     dsse.Digest(rawPermit),
		RunID:            lifecycleTestRunID,
		ReceiptNodeID:    "node-a/gateway",
		ReceiptEpoch:     7,
		ReceiptPublicKey: base64.StdEncoding.EncodeToString(public),
	}
	for name, mutate := range map[string]func(*ControlTaskSubmission){
		"missing receipt identity": func(value *ControlTaskSubmission) { value.ReceiptNodeID = "" },
		"wrong receipt suffix":     func(value *ControlTaskSubmission) { value.ReceiptNodeID = "node-a/relay" },
		"padded receipt identity":  func(value *ControlTaskSubmission) { value.ReceiptNodeID = " node-a/gateway" },
		"oversized node identity": func(value *ControlTaskSubmission) {
			value.ReceiptNodeID = strings.Repeat("n", 129) + "/gateway"
		},
		"zero receipt epoch": func(value *ControlTaskSubmission) { value.ReceiptEpoch = 0 },
		"short receipt key": func(value *ControlTaskSubmission) {
			value.ReceiptPublicKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))
		},
		"noncanonical receipt key": func(value *ControlTaskSubmission) {
			value.ReceiptPublicKey = strings.TrimRight(value.ReceiptPublicKey, "=")
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := valid
			mutate(&response)
			client := newTestControlClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, response)
			}))
			if _, err := client.SubmitTask(context.Background(), rig.grant.GrantID, rig.operation.ID, permit, body); err == nil {
				t.Fatal("invalid receipt authority was accepted")
			}
		})
	}
}

func TestControlTaskSurfaceRejectsWideningMismatchAndUnavailableEvidence(t *testing.T) {
	var dispatches atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			dispatches.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed"}`))
		}
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"audit workspace","session_id":"adversarial-control"}`)
	permit := taskPermitFor(t, rig, "task-adversarial-control", body, nil)

	validRaw, err := json.Marshal(controlTaskSubmitRequest{
		SchemaVersion: controlTaskSubmitSchemaV1,
		GrantID:       rig.grant.GrantID,
		OperationID:   rig.operation.ID,
		TaskPermit:    permit,
		RequestBase64: base64.StdEncoding.EncodeToString(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), validRaw[:len(validRaw)-1]...)
	unknown = append(unknown, []byte(`,"url":"http://attacker.invalid/"}`)...)
	duplicate := []byte(strings.Replace(
		string(validRaw),
		`"operation_id":"`+rig.operation.ID+`"`,
		`"operation_id":"`+rig.operation.ID+`","operation_id":"`+rig.operation.ID+`"`,
		1,
	))
	for _, test := range []struct {
		name        string
		method      string
		path        string
		contentType string
		raw         []byte
		wantStatus  int
		wantCode    string
	}{
		{name: "unknown field", method: http.MethodPost, path: "/v1/tasks", contentType: "application/json", raw: unknown, wantStatus: http.StatusBadRequest, wantCode: "invalid_task_submission"},
		{name: "duplicate field", method: http.MethodPost, path: "/v1/tasks", contentType: "application/json", raw: duplicate, wantStatus: http.StatusBadRequest, wantCode: "invalid_task_submission"},
		{name: "wrong content type", method: http.MethodPost, path: "/v1/tasks", contentType: "text/plain", raw: validRaw, wantStatus: http.StatusBadRequest, wantCode: "invalid_task_submission"},
		{name: "query widening", method: http.MethodPost, path: "/v1/tasks?url=http://attacker.invalid/", contentType: "application/json", raw: validRaw, wantStatus: http.StatusBadRequest, wantCode: "invalid_task_submission"},
		{name: "wrong method", method: http.MethodPut, path: "/v1/tasks", contentType: "application/json", raw: validRaw, wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed"},
		{name: "oversized", method: http.MethodPost, path: "/v1/tasks", contentType: "application/json", raw: bytes.Repeat([]byte{'x'}, int(maxControlTaskSubmitBytes)+1), wantStatus: http.StatusBadRequest, wantCode: "invalid_task_submission"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := invokeControlTaskRaw(rig, test.method, test.path, test.contentType, test.raw)
			if code := requireGatewayErrorCode(t, response, test.wantStatus); code != test.wantCode {
				t.Fatalf("code=%q want=%q", code, test.wantCode)
			}
		})
	}
	if dispatches.Load() != 0 {
		t.Fatalf("invalid control requests dispatched %d times", dispatches.Load())
	}

	wrongOperation := controlTaskSubmitRequest{
		SchemaVersion: controlTaskSubmitSchemaV1,
		GrantID:       rig.grant.GrantID,
		OperationID:   "arbitrary.proxy",
		TaskPermit:    permit,
		RequestBase64: base64.StdEncoding.EncodeToString(body),
	}
	rawWrongOperation, _ := json.Marshal(wrongOperation)
	response := invokeControlTaskRaw(rig, http.MethodPost, "/v1/tasks", "application/json", rawWrongOperation)
	if code := requireGatewayErrorCode(t, response, http.StatusNotFound); code != "service_operation_not_found" {
		t.Fatalf("wrong-operation code=%q", code)
	}

	rig.server.mu.Lock()
	notLifecycle := rig.server.serviceOperations[rig.operation.ServiceID][rig.operation.ID]
	notLifecycle.TaskProtocol = ""
	rig.server.serviceOperations[rig.operation.ServiceID][rig.operation.ID] = notLifecycle
	rig.server.mu.Unlock()
	response = invokeControlTaskSubmit(t, rig, body, permit)
	if code := requireGatewayErrorCode(t, response, http.StatusNotFound); code != "service_operation_not_found" {
		t.Fatalf("non-lifecycle operation code=%q", code)
	}
	rig.server.mu.Lock()
	rig.server.serviceOperations[rig.operation.ServiceID][rig.operation.ID] = rig.operation
	rig.server.mu.Unlock()

	mismatchedBody := []byte(`{"input":"different work","session_id":"adversarial-control"}`)
	response = invokeControlTaskSubmit(t, rig, mismatchedBody, permit)
	if code := requireGatewayErrorCode(t, response, http.StatusForbidden); code != "task_permit_denied" {
		t.Fatalf("mismatched-body code=%q", code)
	}
	if dispatches.Load() != 0 {
		t.Fatalf("mismatched task dispatched %d times", dispatches.Load())
	}

	rig.server.mu.Lock()
	originalReceiptPublic := append(ed25519.PublicKey(nil), rig.server.connectorReceiptPublic...)
	rig.server.connectorReceiptPublic = nil
	rig.server.mu.Unlock()
	response = invokeControlTaskSubmit(t, rig, body, permit)
	if code := requireGatewayErrorCode(t, response, http.StatusServiceUnavailable); code != "evidence_unavailable" {
		t.Fatalf("missing receipt key code=%q", code)
	}
	rig.server.mu.Lock()
	rig.server.connectorReceiptPublic = originalReceiptPublic
	originalReceiptNodeID := rig.server.config.ConnectorReceiptNodeID
	rig.server.config.ConnectorReceiptNodeID = "other-node/gateway"
	rig.server.mu.Unlock()
	response = invokeControlTaskSubmit(t, rig, body, permit)
	if code := requireGatewayErrorCode(t, response, http.StatusServiceUnavailable); code != "evidence_unavailable" {
		t.Fatalf("wrong receipt identity code=%q", code)
	}
	rig.server.mu.Lock()
	rig.server.config.ConnectorReceiptNodeID = originalReceiptNodeID
	rig.server.mu.Unlock()
	if dispatches.Load() != 0 {
		t.Fatalf("unavailable receipt authority dispatched %d tasks", dispatches.Load())
	}

	submit := invokeControlTaskSubmit(t, rig, body, permit)
	submitted := decodeControlTaskSubmission(t, submit)
	if submit.Code != http.StatusOK || dispatches.Load() != 1 {
		t.Fatalf("valid submit status=%d dispatches=%d body=%s", submit.Code, dispatches.Load(), submit.Body.String())
	}
	evidencePath := controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "evidence")
	for _, test := range []struct {
		name       string
		method     string
		path       string
		body       []byte
		wantStatus int
		wantCode   string
	}{
		{name: "evidence query", method: http.MethodGet, path: evidencePath + "?all=true", wantStatus: http.StatusNotFound, wantCode: "task_not_found"},
		{name: "evidence method", method: http.MethodPost, path: evidencePath, wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed"},
		{name: "evidence body", method: http.MethodGet, path: evidencePath, body: []byte(`{}`), wantStatus: http.StatusBadRequest, wantCode: "invalid_task_evidence_request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := invokeControlTaskRaw(rig, test.method, test.path, "", test.body)
			if code := requireGatewayErrorCode(t, result, test.wantStatus); code != test.wantCode {
				t.Fatalf("code=%q want=%q", code, test.wantCode)
			}
		})
	}

	observed := invokeControlTaskRaw(
		rig,
		http.MethodPost,
		controlTaskPathFor(submitted.TaskDigest, submitted.PermitDigest, "observe"),
		"",
		nil,
	)
	if observed.Code != http.StatusOK {
		t.Fatalf("observe status=%d body=%s", observed.Code, observed.Body.String())
	}
	exported := invokeControlTaskRaw(rig, http.MethodGet, evidencePath, "", nil)
	if exported.Code != http.StatusOK {
		t.Fatalf("evidence status=%d body=%s", exported.Code, exported.Body.String())
	}

	moved := rig.config.ConnectorReceiptFile + ".moved"
	if err := os.Rename(rig.config.ConnectorReceiptFile, moved); err != nil {
		t.Fatal(err)
	}
	unavailable := invokeControlTaskRaw(rig, http.MethodGet, evidencePath, "", nil)
	if code := requireGatewayErrorCode(t, unavailable, http.StatusServiceUnavailable); code != "evidence_unavailable" {
		t.Fatalf("unavailable evidence code=%q", code)
	}
}

func TestControlTaskProxyErrorsForwardOnlyBoundedCanonicalRetryAdvice(t *testing.T) {
	server := &Server{}
	newCaptured := func(code, message string, retryAfter ...string) *controlTaskResponseWriter {
		captured := newControlTaskResponseWriter()
		captured.status = http.StatusTooManyRequests
		for _, value := range retryAfter {
			captured.header.Add("Retry-After", value)
		}
		raw, err := json.Marshal(map[string]string{"error": code, "message": message})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = captured.body.Write(raw)
		return captured
	}

	valid := httptest.NewRecorder()
	setControlTaskHeaders(valid)
	server.writeControlTaskProxyError(valid, newCaptured("task_observation_throttled", "wait", "7"))
	if code := requireGatewayErrorCode(t, valid, http.StatusTooManyRequests); code != "task_observation_throttled" ||
		valid.Header().Get("Retry-After") != "7" {
		t.Fatalf("valid proxy error code=%q retry=%q", code, valid.Header().Get("Retry-After"))
	}

	for _, values := range [][]string{{"0"}, {"01"}, {"3601"}, {"1", "2"}} {
		response := httptest.NewRecorder()
		setControlTaskHeaders(response)
		server.writeControlTaskProxyError(response, newCaptured("task_observation_throttled", "wait", values...))
		if code := requireGatewayErrorCode(t, response, http.StatusTooManyRequests); code != "task_observation_throttled" ||
			response.Header().Get("Retry-After") != "" {
			t.Fatalf("invalid retry %v code=%q forwarded=%q", values, code, response.Header().Get("Retry-After"))
		}
	}

	for name, captured := range map[string]*controlTaskResponseWriter{
		"overlong code": newCaptured(strings.Repeat("a", maxControlErrorCodeBytes+1), "wait"),
		"overlong message": newCaptured(
			"task_observation_throttled", strings.Repeat("m", maxControlErrorMessageBytes+1),
		),
		"control message": newCaptured("task_observation_throttled", "wait\nnow"),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			setControlTaskHeaders(response)
			server.writeControlTaskProxyError(response, captured)
			if code := requireGatewayErrorCode(t, response, http.StatusServiceUnavailable); code != "task_submission_unavailable" {
				t.Fatalf("invalid proxy error code=%q", code)
			}
		})
	}
}
