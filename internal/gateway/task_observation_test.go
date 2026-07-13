package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

type blockingLifecycleTerminalLog struct {
	connectorReceiptLog
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type failedLifecycleReceiptLog struct{ connectorReceiptLog }

func (failedLifecycleReceiptLog) Failed() bool { return true }

func (log *blockingLifecycleTerminalLog) Finish(event connectorledger.Event) (connectorledger.Head, error) {
	log.once.Do(func() { close(log.entered) })
	<-log.release
	return log.connectorReceiptLog.Finish(event)
}

type lifecycleTaskStatusResponse struct {
	SchemaVersion     string `json:"schema_version"`
	TaskDigest        string `json:"task_digest"`
	PermitDigest      string `json:"permit_digest"`
	Phase             string `json:"phase"`
	State             string `json:"state"`
	RunID             string `json:"run_id,omitempty"`
	TaskStatus        string `json:"task_status,omitempty"`
	ObservedStatus    string `json:"observed_status,omitempty"`
	ResultDigest      string `json:"result_digest,omitempty"`
	ResponseBytes     int64  `json:"response_bytes,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	ObservationBase64 string `json:"observation_base64,omitempty"`
}

func lifecycleTaskDigest(rig *serviceTaskRig, taskID string) string {
	return taskpermit.TaskDigest(rig.grant.TenantID, rig.grant.InstanceID, taskID)
}

func dispatchLifecycleTask(t *testing.T, rig *serviceTaskRig, taskID string, body []byte) string {
	t.Helper()
	permit := taskPermitFor(t, rig, taskID, body, nil)
	response := invokeServiceTask(rig, body, permit)
	if response.Code != http.StatusAccepted || response.Header().Get(taskReceiptHeader) != "recorded" {
		t.Fatalf("lifecycle dispatch status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	return lifecycleTaskDigest(rig, taskID)
}

func invokeLifecycleTaskEndpoint(rig *serviceTaskRig, method, taskDigest string, observe bool, body []byte) *httptest.ResponseRecorder {
	permitDigest := taskDigest
	rig.server.mu.Lock()
	if state, exists := rig.server.serviceTasks[taskDigest]; exists && state.Authorization.PermitDigest != "" {
		permitDigest = state.Authorization.PermitDigest
	}
	rig.server.mu.Unlock()
	return invokeLifecycleTaskReferenceEndpoint(rig, method, taskDigest, permitDigest, observe, body)
}

func invokeLifecycleTaskReferenceEndpoint(
	rig *serviceTaskRig,
	method, taskDigest, permitDigest string,
	observe bool,
	body []byte,
) *httptest.ResponseRecorder {
	target := "/v1/tasks/" + taskDigest + "/permits/" + permitDigest
	if observe {
		target += "/observe"
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Authorization", "Bearer service-token")
	request.Header.Set("Cookie", "admin=true")
	request.Header.Set("Forwarded", "for=192.0.2.10;host=admin.internal")
	request.Header.Set("X-Forwarded-For", "192.0.2.10")
	request.Header.Set("Idempotency-Key", "caller-controlled")
	request.Header.Set("Prefer", "wait=999")
	request.Header.Set("X-Hermes-Admin", "true")
	request.Header.Set(taskPermitHeader, "caller-controlled")
	request.Header.Set(taskReceiptHeader, "caller-controlled")
	response := httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(response, request)
	return response
}

func decodeLifecycleTaskStatus(t *testing.T, response *httptest.ResponseRecorder) lifecycleTaskStatusResponse {
	t.Helper()
	var status lifecycleTaskStatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode lifecycle task status=%d body=%q: %v", response.Code, response.Body.String(), err)
	}
	return status
}

func requireLifecycleTaskStatus(
	t *testing.T,
	response *httptest.ResponseRecorder,
	taskDigest, phase, state, runID, taskStatus string,
) lifecycleTaskStatusResponse {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("task status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("task status cache headers=%v", response.Header())
	}
	status := decodeLifecycleTaskStatus(t, response)
	if status.SchemaVersion != "steward.task-status.v1" || status.TaskDigest != taskDigest ||
		!serviceTaskDigestPattern.MatchString(status.PermitDigest) ||
		status.Phase != phase || status.State != state || status.RunID != runID || status.TaskStatus != taskStatus {
		t.Fatalf("task status response=%#v", status)
	}
	return status
}

func requireGatewayErrorCode(t *testing.T, response *httptest.ResponseRecorder, wantStatus int) string {
	t.Helper()
	if response.Code != wantStatus {
		t.Fatalf("gateway error status=%d want=%d body=%s", response.Code, wantStatus, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("task error cache headers=%v", response.Header())
	}
	var result struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error == "" || result.Message == "" {
		t.Fatalf("gateway error body=%q result=%#v err=%v", response.Body.String(), result, err)
	}
	return result.Error
}

func TestLifecycleTaskObservationUsesFixedBodylessRequest(t *testing.T) {
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			dispatchCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
		case http.MethodGet:
			observationCalls.Add(1)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read observation body: %v", err)
			}
			if request.URL.Path != "/v1/runs/"+lifecycleTestRunID || request.URL.RawQuery != "" ||
				request.RequestURI != "/v1/runs/"+lifecycleTestRunID || len(body) != 0 || request.ContentLength != 0 {
				t.Errorf("observation target=%q request_uri=%q content_length=%d body=%q", request.URL.String(), request.RequestURI, request.ContentLength, body)
			}
			for _, header := range []string{
				"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "Idempotency-Key", "Prefer",
				"X-Hermes-Admin", taskPermitHeader, taskReceiptHeader,
			} {
				if value := request.Header.Get(header); value != "" {
					t.Errorf("observation forwarded caller header %s=%q", header, value)
				}
			}
			if request.UserAgent() != "" || request.Header.Get("Accept") != "application/json" ||
				request.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf("observation controlled headers=%v", request.Header)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"running"}`))
		default:
			t.Errorf("unexpected upstream method %s", request.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"fixed-observation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-fixed-observation", body)

	observed := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if observed.ObservedStatus != "running" {
		t.Fatalf("nonterminal observation=%#v", observed)
	}
	requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if dispatchCalls.Load() != 1 || observationCalls.Load() != 1 {
		t.Fatalf("dispatch calls=%d observation calls=%d", dispatchCalls.Load(), observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)

	bodyRequest := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, []byte(`{}`))
	requireGatewayErrorCode(t, bodyRequest, http.StatusBadRequest)
	rig.server.mu.Lock()
	permitDigest := rig.server.serviceTasks[taskDigest].Authorization.PermitDigest
	rig.server.mu.Unlock()
	queryRequest := httptest.NewRequest(http.MethodPost, "/v1/tasks/"+taskDigest+"/permits/"+permitDigest+"/observe?url=http://admin.internal", nil)
	queryRequest.Header.Set("Authorization", "Bearer service-token")
	queryResponse := httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(queryResponse, queryRequest)
	requireGatewayErrorCode(t, queryResponse, http.StatusNotFound)
	if observationCalls.Load() != 1 {
		t.Fatalf("invalid observation requests reached upstream: %d", observationCalls.Load())
	}
}

func TestLifecycleTaskReferenceBindsExactPermitAndRequest(t *testing.T) {
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	terminalBody := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			dispatchCalls.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		observationCalls.Add(1)
		_, _ = w.Write(terminalBody)
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	taskID := "task-exact-permit-reference"
	firstBody := []byte(`{"input":"first","session_id":"exact-permit"}`)
	taskDigest := dispatchLifecycleTask(t, rig, taskID, firstBody)
	rig.server.mu.Lock()
	firstPermitDigest := rig.server.serviceTasks[taskDigest].Authorization.PermitDigest
	rig.server.mu.Unlock()

	secondBody := []byte(`{"input":"second","session_id":"exact-permit"}`)
	secondPermit := taskPermitFor(t, rig, taskID, secondBody, nil)
	secondRaw, err := taskpermit.DecodeHeader(secondPermit)
	if err != nil {
		t.Fatal(err)
	}
	secondPermitDigest := dsse.Digest(secondRaw)
	if secondPermitDigest == firstPermitDigest {
		t.Fatal("different request unexpectedly produced the same permit digest")
	}
	conflict := invokeServiceTask(rig, secondBody, secondPermit)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"error":"task_id_conflict"`) || dispatchCalls.Load() != 1 {
		t.Fatalf("conflicting permit status=%d body=%s dispatch_calls=%d", conflict.Code, conflict.Body.String(), dispatchCalls.Load())
	}
	for _, response := range []*httptest.ResponseRecorder{
		invokeLifecycleTaskReferenceEndpoint(rig, http.MethodGet, taskDigest, secondPermitDigest, false, nil),
		invokeLifecycleTaskReferenceEndpoint(rig, http.MethodPost, taskDigest, secondPermitDigest, true, nil),
	} {
		if code := requireGatewayErrorCode(t, response, http.StatusNotFound); code != "task_not_found" {
			t.Fatalf("conflicting permit reference error=%q", code)
		}
	}
	if observationCalls.Load() != 0 {
		t.Fatalf("conflicting permit reached upstream %d times", observationCalls.Load())
	}

	observed := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskReferenceEndpoint(rig, http.MethodPost, taskDigest, firstPermitDigest, true, nil),
		taskDigest, "terminal", "agent_reported_completed", lifecycleTestRunID,
		string(connectorledger.TaskStatusAgentReportedCompleted),
	)
	if observed.PermitDigest != firstPermitDigest || observed.ObservedStatus != "completed" ||
		observed.ResultDigest != dsse.Digest(terminalBody) || observationCalls.Load() != 1 {
		t.Fatalf("exact permit observation=%#v calls=%d", observed, observationCalls.Load())
	}
}

func TestLifecycleTaskRoutesRejectAlternateTargetsMethodsAndTransferCoding(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"route-validation"}`)
	permit := taskPermitFor(t, rig, "task-route-validation", body, nil)
	event := lifecycleAuthorizationEvent(t, rig, body, permit)
	if _, existed, err := rig.server.beginServiceTask(event.TaskDigest, event); err != nil || existed {
		t.Fatalf("begin route fixture existed=%t err=%v", existed, err)
	}
	base := "/v1/tasks/" + event.TaskDigest + "/permits/" + event.PermitDigest

	for _, test := range []struct {
		name, method, target, allow string
		status                      int
	}{
		{name: "post status", method: http.MethodPost, target: base, allow: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "get observe", method: http.MethodGet, target: base + "/observe", allow: http.MethodPost, status: http.StatusMethodNotAllowed},
		{name: "put status", method: http.MethodPut, target: base, allow: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "empty query", method: http.MethodGet, target: base + "?", status: http.StatusNotFound},
		{name: "query", method: http.MethodGet, target: base + "?url=http://admin.internal", status: http.StatusNotFound},
		{name: "encoded separators", method: http.MethodGet, target: "/v1/tasks/" + event.TaskDigest + "%2Fpermits%2F" + event.PermitDigest, status: http.StatusNotFound},
		{name: "extra suffix", method: http.MethodGet, target: base + "/extra", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			request.Header.Set("Authorization", "Bearer service-token")
			response := httptest.NewRecorder()
			rig.server.ServiceHandler().ServeHTTP(response, request)
			requireGatewayErrorCode(t, response, test.status)
			if response.Header().Get("Allow") != test.allow {
				t.Fatalf("Allow=%q want=%q", response.Header().Get("Allow"), test.allow)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, base, nil)
	request.Header.Set("Authorization", "Bearer service-token")
	request.TransferEncoding = []string{"chunked"}
	request.ContentLength = -1
	response := httptest.NewRecorder()
	rig.server.ServiceHandler().ServeHTTP(response, request)
	if code := requireGatewayErrorCode(t, response, http.StatusBadRequest); code != "invalid_task_observation" {
		t.Fatalf("transfer-coded request error=%q", code)
	}
}

func TestLifecycleTaskObservationRecordsTerminalOnceAndReplaysImmutably(t *testing.T) {
	queued := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"queued"}`)
	completed := []byte("{\n  \"run_id\": \"" + lifecycleTestRunID + "\",\n  \"status\": \"completed\"\n}\n")
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			dispatchCalls.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		if request.Method != http.MethodGet {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if observationCalls.Add(1) == 1 {
			_, _ = w.Write(queued)
			return
		}
		_, _ = w.Write(completed)
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"terminal-observation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-terminal-observation", body)

	first := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if first.ObservedStatus != "queued" {
		t.Fatalf("queued observation=%#v", first)
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
	rig.server.now = func() time.Time { return rig.now.Add(time.Duration(rig.operation.PollIntervalSeconds) * time.Second) }

	second := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "terminal", "agent_reported_completed", lifecycleTestRunID,
		string(connectorledger.TaskStatusAgentReportedCompleted),
	)
	wantDigest := dsse.Digest(completed)
	if second.ResultDigest != wantDigest || second.ResponseBytes != int64(len(completed)) || second.ErrorCode != "" {
		t.Fatalf("completed observation=%#v want_digest=%s bytes=%d", second, wantDigest, len(completed))
	}
	records := lifecycleReceiptRecords(t, rig)
	requireLifecycleTaskChain(t, records, connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal)
	terminal := records[2].Receipt.Event
	if terminal.Outcome != connectorledger.Responded || terminal.HTTPStatus != http.StatusOK ||
		terminal.RunID != lifecycleTestRunID || terminal.TaskStatus != connectorledger.TaskStatusAgentReportedCompleted ||
		terminal.ResultDigest != wantDigest || terminal.ResponseBytes != int64(len(completed)) || terminal.ErrorCode != "" {
		t.Fatalf("terminal receipt=%#v", terminal)
	}

	for _, response := range []*httptest.ResponseRecorder{
		invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
		invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
	} {
		replayed := requireLifecycleTaskStatus(
			t, response, taskDigest, "terminal", "agent_reported_completed", lifecycleTestRunID,
			string(connectorledger.TaskStatusAgentReportedCompleted),
		)
		if replayed.ResultDigest != wantDigest || replayed.ResponseBytes != int64(len(completed)) {
			t.Fatalf("terminal replay=%#v", replayed)
		}
	}
	if dispatchCalls.Load() != 1 || observationCalls.Load() != 2 {
		t.Fatalf("dispatch calls=%d observation calls=%d", dispatchCalls.Load(), observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal)

	reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
	for _, response := range []*httptest.ResponseRecorder{
		invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
		invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
	} {
		requireLifecycleTaskStatus(
			t, response, taskDigest, "terminal", "agent_reported_completed", lifecycleTestRunID,
			string(connectorledger.TaskStatusAgentReportedCompleted),
		)
	}
	if dispatchCalls.Load() != 1 || observationCalls.Load() != 2 {
		t.Fatalf("restart redispatched=%d reobserved=%d", dispatchCalls.Load(), observationCalls.Load())
	}
}

func TestLifecycleTaskObservationEnforcesConfiguredPollInterval(t *testing.T) {
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		status := "queued"
		if observationCalls.Add(1) > 1 {
			status = "running"
		}
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"` + status + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"poll-interval"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-poll-interval", body)

	first := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if first.ObservedStatus != "queued" || observationCalls.Load() != 1 {
		t.Fatalf("first observation=%#v calls=%d", first, observationCalls.Load())
	}

	throttled := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
	if code := requireGatewayErrorCode(t, throttled, http.StatusTooManyRequests); code != "task_observation_throttled" {
		t.Fatalf("throttle error=%q body=%s", code, throttled.Body.String())
	}
	wantRetryAfter := strconv.Itoa(rig.operation.PollIntervalSeconds)
	if throttled.Header().Get("Retry-After") != wantRetryAfter || observationCalls.Load() != 1 {
		t.Fatalf("retry-after=%q want=%q observation calls=%d", throttled.Header().Get("Retry-After"), wantRetryAfter, observationCalls.Load())
	}

	rig.server.now = func() time.Time {
		return rig.now.Add(time.Duration(rig.operation.PollIntervalSeconds) * time.Second)
	}
	retried := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if retried.ObservedStatus != "running" || observationCalls.Load() != 2 {
		t.Fatalf("retried observation=%#v calls=%d", retried, observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
}

func TestLifecycleTaskObservationServiceBusyDoesNotConsumePollInterval(t *testing.T) {
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		observationCalls.Add(1)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"running"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"busy-poll"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-busy-poll", body)

	rig.server.mu.Lock()
	semaphore := rig.server.serviceSemaphoreLocked(rig.grant.GrantID)
	rig.server.mu.Unlock()
	for range cap(semaphore) {
		semaphore <- struct{}{}
	}
	busy := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
	if code := requireGatewayErrorCode(t, busy, http.StatusTooManyRequests); code != "service_busy" {
		t.Fatalf("busy error=%q", code)
	}
	for range cap(semaphore) {
		<-semaphore
	}
	if observationCalls.Load() != 0 {
		t.Fatalf("busy observation reached upstream %d times", observationCalls.Load())
	}

	retried := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if retried.ObservedStatus != "running" || observationCalls.Load() != 1 {
		t.Fatalf("immediate retry=%#v calls=%d", retried, observationCalls.Load())
	}
}

func TestLifecycleTaskObservationFencesPoisonedSharedLedgerBeforeAgentContact(t *testing.T) {
	runIDs := []string{"run_11111111111111111111111111111111", "run_22222222222222222222222222222222"}
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			index := int(dispatchCalls.Add(1)) - 1
			if index >= len(runIDs) {
				t.Errorf("unexpected dispatch %d", index+1)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + runIDs[index] + `"}`))
			return
		}
		observationCalls.Add(1)
		_, _ = w.Write([]byte(`{"run_id":"` + runIDs[0] + `","status":"running"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	firstDigest := dispatchLifecycleTask(t, rig, "task-ledger-fence-a", []byte(`{"input":"a","session_id":"ledger-fence"}`))
	secondDigest := dispatchLifecycleTask(t, rig, "task-ledger-fence-b", []byte(`{"input":"b","session_id":"ledger-fence"}`))
	rig.server.connectorLedger = failedLifecycleReceiptLog{connectorReceiptLog: rig.server.connectorLedger}

	for _, taskDigest := range []string{firstDigest, secondDigest} {
		response := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
		if code := requireGatewayErrorCode(t, response, http.StatusServiceUnavailable); code != "evidence_unavailable" {
			t.Fatalf("poisoned ledger error=%q", code)
		}
	}
	if dispatchCalls.Load() != 2 || observationCalls.Load() != 0 {
		t.Fatalf("dispatch_calls=%d observation_calls=%d", dispatchCalls.Load(), observationCalls.Load())
	}
	requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, secondDigest, false, nil),
		secondDigest, "dispatch", "dispatch_accepted", runIDs[1], "",
	)
}

func TestLifecycleTaskObservationMapsTerminalStates(t *testing.T) {
	for _, test := range []struct {
		upstreamStatus string
		state          string
		taskStatus     connectorledger.TaskStatus
	}{
		{upstreamStatus: "completed", state: "agent_reported_completed", taskStatus: connectorledger.TaskStatusAgentReportedCompleted},
		{upstreamStatus: "failed", state: "agent_reported_failed", taskStatus: connectorledger.TaskStatusAgentReportedFailed},
		{upstreamStatus: "cancelled", state: "agent_reported_cancelled", taskStatus: connectorledger.TaskStatusAgentReportedCancelled},
	} {
		t.Run(test.upstreamStatus, func(t *testing.T) {
			terminalBody := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"` + test.upstreamStatus + `"}`)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if request.Method == http.MethodPost {
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
					return
				}
				_, _ = w.Write(terminalBody)
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"terminal-map-` + test.upstreamStatus + `"}`)
			taskDigest := dispatchLifecycleTask(t, rig, "task-terminal-map-"+test.upstreamStatus, body)
			status := requireLifecycleTaskStatus(
				t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
				taskDigest, "terminal", test.state, lifecycleTestRunID, string(test.taskStatus),
			)
			if status.ResultDigest != dsse.Digest(terminalBody) || status.ResponseBytes != int64(len(terminalBody)) {
				t.Fatalf("mapped terminal status=%#v", status)
			}
			records := lifecycleReceiptRecords(t, rig)
			requireLifecycleTaskChain(t, records, connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal)
			if records[2].Receipt.Event.TaskStatus != test.taskStatus {
				t.Fatalf("terminal receipt=%#v", records[2].Receipt.Event)
			}
		})
	}
}

func TestLifecycleTaskObservationRejectsInvalidOrMismatchedStatus(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		contentType   string
		contentTypes  []string
		encoding      string
		declaredExtra int
		location      string
		body          string
	}{
		{name: "mismatched run id", status: http.StatusOK, contentType: "application/json", body: `{"run_id":"run_other","status":"running"}`},
		{name: "unknown status", status: http.StatusOK, contentType: "application/json", body: `{"run_id":"` + lifecycleTestRunID + `","status":"succeeded"}`},
		{name: "missing status", status: http.StatusOK, contentType: "application/json", body: `{"run_id":"` + lifecycleTestRunID + `"}`},
		{name: "duplicate field", status: http.StatusOK, contentType: "application/json", body: `{"run_id":"` + lifecycleTestRunID + `","status":"queued","status":"running"}`},
		{name: "wrong media type", status: http.StatusOK, contentType: "text/plain", body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "encoded", status: http.StatusOK, contentType: "application/json", encoding: "gzip", body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "non-200", status: http.StatusAccepted, contentType: "application/json", body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "application/json", location: "/stolen", body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "multiple content types", status: http.StatusOK, contentTypes: []string{"application/json", "application/json"}, body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "declared length mismatch", status: http.StatusOK, contentType: "application/json", declaredExtra: 5, body: `{"run_id":"` + lifecycleTestRunID + `","status":"running"}`},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("x", (1<<20)+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var observationCalls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if request.Method == http.MethodPost {
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
					return
				}
				observationCalls.Add(1)
				if len(test.contentTypes) > 0 {
					for _, value := range test.contentTypes {
						w.Header().Add("Content-Type", value)
					}
				} else {
					w.Header().Set("Content-Type", test.contentType)
				}
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				if test.declaredExtra > 0 {
					w.Header().Set("Content-Length", strconv.Itoa(len(test.body)+test.declaredExtra))
				}
				if test.location != "" {
					w.Header().Set("Location", test.location)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"invalid-observation"}`)
			taskDigest := dispatchLifecycleTask(t, rig, "task-invalid-observation-"+strings.ReplaceAll(test.name, " ", "-"), body)

			response := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
			requireGatewayErrorCode(t, response, http.StatusBadGateway)
			if observationCalls.Load() != 1 {
				t.Fatalf("observation calls=%d", observationCalls.Load())
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
			requireLifecycleTaskStatus(
				t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
				taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
			)
		})
	}
}

func TestLifecycleTaskObservationRevocationPreventsTerminalAppend(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		observationCalls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"revoked-observation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-revoked-observation", body)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("observation did not reach upstream")
	}
	deactivated := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(
		deactivated, httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil),
	)
	if deactivated.Code != http.StatusOK {
		close(release)
		t.Fatalf("deactivate status=%d body=%s", deactivated.Code, deactivated.Body.String())
	}
	close(release)
	select {
	case response := <-done:
		requireGatewayErrorCode(t, response, http.StatusServiceUnavailable)
	case <-time.After(2 * time.Second):
		t.Fatal("revoked observation did not return")
	}
	if observationCalls.Load() != 1 {
		t.Fatalf("observation calls=%d", observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)

	inactive := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
	requireGatewayErrorCode(t, inactive, http.StatusServiceUnavailable)
	if observationCalls.Load() != 1 {
		t.Fatalf("inactive task reached upstream: %d", observationCalls.Load())
	}
}

func TestLifecycleTaskTerminalCommitLinearizesBeforeDeactivation(t *testing.T) {
	terminalBody := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		_, _ = w.Write(terminalBody)
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"commit-before-revocation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-commit-before-revocation", body)
	blocking := &blockingLifecycleTerminalLog{
		connectorReceiptLog: rig.server.connectorLedger,
		entered:             make(chan struct{}),
		release:             make(chan struct{}),
	}
	rig.server.connectorLedger = blocking
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocking.release) }) }
	defer release()

	observed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		observed <- invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("terminal commit did not reach the durable append")
	}
	if rig.server.taskObservationCommitMu.TryLock() {
		rig.server.taskObservationCommitMu.Unlock()
		t.Fatal("terminal append did not hold the observation/revocation barrier")
	}

	deactivationStarted := make(chan struct{})
	deactivated := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		close(deactivationStarted)
		response := httptest.NewRecorder()
		rig.server.ControlHandler().ServeHTTP(
			response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil),
		)
		deactivated <- response
	}()
	<-deactivationStarted
	select {
	case response := <-deactivated:
		t.Fatalf("deactivation crossed an in-flight terminal commit: status=%d body=%s", response.Code, response.Body.String())
	case <-time.After(50 * time.Millisecond):
	}

	release()
	select {
	case response := <-observed:
		status := requireLifecycleTaskStatus(
			t, response, taskDigest, "terminal", "agent_reported_completed", lifecycleTestRunID,
			string(connectorledger.TaskStatusAgentReportedCompleted),
		)
		if status.ResultDigest != dsse.Digest(terminalBody) {
			t.Fatalf("terminal result digest=%q", status.ResultDigest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal observation did not complete")
	}
	select {
	case response := <-deactivated:
		if response.Code != http.StatusOK {
			t.Fatalf("deactivate status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deactivation did not complete after terminal commit")
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal)
}

func TestLifecycleTaskObservationLeaseRejectsDeactivateReactivateABA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		t.Error("direct commit fixture unexpectedly observed the upstream")
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"revocation-aba"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-revocation-aba", body)

	rig.server.mu.Lock()
	permitDigest := rig.server.serviceTasks[taskDigest].Authorization.PermitDigest
	rig.server.mu.Unlock()
	observation, retryAfter, err := rig.server.beginTaskObservation(taskDigest, permitDigest)
	if err != nil || retryAfter != 0 {
		t.Fatalf("begin observation retry_after=%d err=%v", retryAfter, err)
	}
	deactivate := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(
		deactivate, httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil),
	)
	if deactivate.Code != http.StatusOK {
		t.Fatalf("deactivate status=%d body=%s", deactivate.Code, deactivate.Body.String())
	}
	activateConnectorGrant(t, rig.server, rig.grant.GrantID)

	terminal := observation.state.Dispatch
	terminal.Phase, terminal.Outcome = connectorledger.Terminal, connectorledger.Responded
	terminal.HTTPStatus, terminal.ResponseBytes = http.StatusOK, 1
	terminal.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	terminal.ResultDigest = dsse.Digest([]byte("x"))
	if err := rig.server.commitTaskObservation(observation, terminal); !errors.Is(err, errTaskObservationRevoked) {
		t.Fatalf("commit after deactivate/reactivate error=%v", err)
	}
	rig.server.finishTaskObservation(taskDigest)
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
	requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
}

func TestLifecycleTaskObservationAllowsOnlyOneConcurrentObserver(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		observationCalls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"running"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"concurrent-observation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-concurrent-observation", body)

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			<-start
			responses <- invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
		}()
	}
	close(start)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("concurrent observation did not reach upstream")
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	results := []*httptest.ResponseRecorder{<-responses, <-responses}
	codes := []int{results[0].Code, results[1].Code}
	sort.Ints(codes)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict {
		t.Fatalf("concurrent observation statuses=%v bodies=%q / %q", codes, results[0].Body.String(), results[1].Body.String())
	}
	if observationCalls.Load() != 1 {
		t.Fatalf("concurrent observations reached upstream %d times", observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
}

func TestLifecycleTaskStatusHandlesUnknownLegacyAndAuthorizationOnly(t *testing.T) {
	t.Run("authentication and unknown", func(t *testing.T) {
		upstream := httptest.NewServer(http.NotFoundHandler())
		defer upstream.Close()
		rig := newLifecycleServiceTaskRig(t, upstream.URL)
		unknown := "sha256:" + strings.Repeat("f", 64)

		unauthorized := httptest.NewRecorder()
		rig.server.ServiceHandler().ServeHTTP(
			unauthorized, httptest.NewRequest(http.MethodGet, "/v1/tasks/"+unknown, nil),
		)
		requireGatewayErrorCode(t, unauthorized, http.StatusUnauthorized)
		requireGatewayErrorCode(t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, unknown, false, nil), http.StatusNotFound)
		requireGatewayErrorCode(t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, unknown, true, nil), http.StatusNotFound)
	})

	t.Run("legacy", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"run_id":"run_legacy"}`))
		}))
		defer upstream.Close()
		rig := newServiceTaskRig(t, upstream.URL)
		body := []byte(`{"input":"work","session_id":"legacy-status"}`)
		permit := taskPermitFor(t, rig, "task-legacy-status", body, nil)
		if response := invokeServiceTask(rig, body, permit); response.Code != http.StatusOK {
			t.Fatalf("legacy dispatch status=%d body=%s", response.Code, response.Body.String())
		}
		taskDigest := lifecycleTaskDigest(rig, "task-legacy-status")
		requireGatewayErrorCode(t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil), http.StatusNotFound)
		requireGatewayErrorCode(t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil), http.StatusNotFound)
	})

	t.Run("authorization only", func(t *testing.T) {
		var upstreamCalls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			upstreamCalls.Add(1)
		}))
		defer upstream.Close()
		rig := newLifecycleServiceTaskRig(t, upstream.URL)
		body := []byte(`{"input":"work","session_id":"authorization-only-status"}`)
		permit := taskPermitFor(t, rig, "task-authorization-only-status", body, nil)
		event := lifecycleAuthorizationEvent(t, rig, body, permit)
		if _, existed, err := rig.server.beginServiceTask(event.TaskDigest, event); err != nil || existed {
			t.Fatalf("begin authorization-only task existed=%t err=%v", existed, err)
		}
		requireLifecycleTaskStatus(
			t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, event.TaskDigest, false, nil),
			event.TaskDigest, "authorize", "authorization_recorded", "", "",
		)
		requireGatewayErrorCode(
			t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, event.TaskDigest, true, nil), http.StatusConflict,
		)
		if upstreamCalls.Load() != 0 {
			t.Fatalf("authorization-only observation reached upstream %d times", upstreamCalls.Load())
		}
		requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize)
	})
}

func TestLifecycleTaskObservationRestoresPendingDispatchAfterRestart(t *testing.T) {
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost {
			dispatchCalls.Add(1)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		observationCalls.Add(1)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"running"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL)
	body := []byte(`{"input":"work","session_id":"restart-observation"}`)
	taskDigest := dispatchLifecycleTask(t, rig, "task-restart-observation", body)
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)

	reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
	requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	observed := requireLifecycleTaskStatus(
		t, invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil),
		taskDigest, "dispatch", "dispatch_accepted", lifecycleTestRunID, "",
	)
	if observed.ObservedStatus != "running" || dispatchCalls.Load() != 1 || observationCalls.Load() != 1 {
		t.Fatalf("restart observation=%#v dispatch_calls=%d observation_calls=%d", observed, dispatchCalls.Load(), observationCalls.Load())
	}
	requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), connectorledger.Authorize, connectorledger.Dispatch)
}

func TestLifecycleTaskObservationWithholdsRawResultUntilTerminalEvidenceIsCertain(t *testing.T) {
	for _, test := range []struct {
		name       string
		durable    bool
		wantPhase  string
		wantState  string
		wantStatus string
		wantPhases []connectorledger.Phase
	}{
		{name: "durable terminal", durable: true, wantPhase: "terminal", wantState: "agent_reported_completed",
			wantStatus: string(connectorledger.TaskStatusAgentReportedCompleted),
			wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Dispatch, connectorledger.Terminal}},
		{name: "absent terminal", wantPhase: "dispatch", wantState: "dispatch_accepted",
			wantPhases: []connectorledger.Phase{connectorledger.Authorize, connectorledger.Dispatch}},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminalBody := []byte(`{"run_id":"` + lifecycleTestRunID + `","status":"completed","result":"sensitive"}`)
			var observationCalls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if request.Method == http.MethodPost {
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
					return
				}
				observationCalls.Add(1)
				_, _ = w.Write(terminalBody)
			}))
			defer upstream.Close()
			rig := newLifecycleServiceTaskRig(t, upstream.URL)
			body := []byte(`{"input":"work","session_id":"ambiguous-terminal-observation"}`)
			taskDigest := dispatchLifecycleTask(t, rig, "task-ambiguous-terminal-observation", body)
			rig.server.connectorLedger = &ambiguousLifecycleTerminalLog{
				connectorReceiptLog: rig.server.connectorLedger, durable: test.durable,
			}

			observed := invokeLifecycleTaskEndpoint(rig, http.MethodPost, taskDigest, true, nil)
			if requireGatewayErrorCode(t, observed, http.StatusServiceUnavailable) != "evidence_unavailable" ||
				strings.Contains(observed.Body.String(), "observation_base64") || strings.Contains(observed.Body.String(), "sensitive") ||
				observationCalls.Load() != 1 {
				t.Fatalf("ambiguous observation headers=%v body=%s calls=%d", observed.Header(), observed.Body.String(), observationCalls.Load())
			}
			uncertain := invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil)
			if requireGatewayErrorCode(t, uncertain, http.StatusServiceUnavailable) != "evidence_unavailable" ||
				strings.Contains(uncertain.Body.String(), "observation_base64") {
				t.Fatalf("uncertain status exposed evidence: %s", uncertain.Body.String())
			}

			reopenLifecycleServiceTaskRig(t, rig, rig.now.Add(24*time.Hour))
			status := requireLifecycleTaskStatus(
				t, invokeLifecycleTaskEndpoint(rig, http.MethodGet, taskDigest, false, nil),
				taskDigest, test.wantPhase, test.wantState, lifecycleTestRunID, test.wantStatus,
			)
			if status.ObservationBase64 != "" {
				t.Fatalf("reconciled status replayed raw observation: %#v", status)
			}
			requireLifecycleTaskChain(t, lifecycleReceiptRecords(t, rig), test.wantPhases...)
		})
	}
}
