package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

type taskRuntimeFixture struct {
	cli          *taskCLIFixture
	taskDigest   string
	permitDigest string
	tokenPath    string
}

func newTaskRuntimeFixture(t *testing.T) taskRuntimeFixture {
	t.Helper()
	fixture := newTaskCLIFixture(t)
	statement := fixture.issue(t)
	bundle, err := readHistoricalLifecycleTaskBundle(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(fixture.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return taskRuntimeFixture{
		cli: fixture, taskDigest: taskpermit.TaskDigest(statement.TenantID, statement.InstanceID, statement.TaskID),
		permitDigest: bundle.Verified.EnvelopeDigest, tokenPath: tokenPath,
	}
}

func (fixture taskRuntimeFixture) arguments(action, gatewayURL string, extra ...string) []string {
	arguments := []string{
		"task", action, "-bundle", fixture.cli.bundlePath, "-gateway-url", gatewayURL, "-token-file", fixture.tokenPath,
	}
	return append(arguments, extra...)
}

func TestTaskSubmitUsesVerifiedBundleAndPrintsOnlySafeDispatchIdentity(t *testing.T) {
	for _, receipt := range []gatewayclient.TaskReceipt{gatewayclient.TaskReceiptRecorded, gatewayclient.TaskReceiptReplayed} {
		t.Run(string(receipt), func(t *testing.T) {
			fixture := newTaskRuntimeFixture(t)
			verified, err := readCurrentLifecycleTaskBundle(fixture.cli.bundlePath)
			if err != nil {
				t.Fatal(err)
			}
			permitHeader, err := taskpermit.EncodeHeader(verified.Permit)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				raw, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					t.Errorf("read request: %v", readErr)
				}
				wantPath := strings.TrimSuffix(verified.Bundle.ServicePath, "/") + verified.Bundle.Operation.Path
				if request.Method != http.MethodPost || request.RequestURI != wantPath || request.URL.RawQuery != "" ||
					request.ContentLength != int64(len(verified.Request)) || !bytes.Equal(raw, verified.Request) {
					t.Errorf("request method=%q URI=%q length=%d body=%q", request.Method, request.RequestURI, request.ContentLength, raw)
				}
				if request.Header.Get("Authorization") != "Bearer gateway-secret" ||
					request.Header.Get("Content-Type") != verified.Bundle.Operation.ContentType ||
					request.Header.Get("X-Steward-Task-Permit") != permitHeader || request.Header.Get("Accept") != "application/json" ||
					request.Header.Get("Accept-Encoding") != "identity" || request.UserAgent() != "steward" {
					t.Errorf("headers=%v", request.Header)
				}
				writeTaskSubmitCLIResponse(w, "run_0123456789abcdef", receipt)
			}))
			defer server.Close()
			var output bytes.Buffer
			if err := run(fixture.arguments("submit", server.URL), &output, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			var submitted struct {
				TaskDigest   string                    `json:"task_digest"`
				PermitDigest string                    `json:"permit_digest"`
				RunID        string                    `json:"run_id"`
				Receipt      gatewayclient.TaskReceipt `json:"receipt"`
			}
			if err := json.Unmarshal(output.Bytes(), &submitted); err != nil {
				t.Fatal(err)
			}
			if submitted.TaskDigest != fixture.taskDigest || submitted.PermitDigest != fixture.permitDigest ||
				submitted.RunID != "run_0123456789abcdef" || submitted.Receipt != receipt || calls.Load() != 1 {
				t.Fatalf("submitted=%#v calls=%d", submitted, calls.Load())
			}
			if bytes.Contains(output.Bytes(), verified.Request) || bytes.Contains(output.Bytes(), []byte("result")) ||
				bytes.Contains(output.Bytes(), []byte("observation_base64")) {
				t.Fatalf("submit output exposed task or result content: %s", output.Bytes())
			}
		})
	}
}

func TestTaskSubmitRejectsExpiredPermitBeforeNetwork(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.cli.now.Add(24 * time.Hour) }
	t.Cleanup(func() { timeNow = priorNow })
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	err := run(fixture.arguments("submit", server.URL), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "expired") || calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestTaskSubmitAcceptsOnlyItsThreeRequiredFlags(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	for _, extra := range [][]string{{"unexpected"}, {"-result-out", "result.json"}, {"-wait-timeout", "1m"}} {
		if err := run(fixture.arguments("submit", server.URL, extra...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("extra arguments %v were accepted", extra)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid submit commands made %d Gateway calls", calls.Load())
	}
}

func TestTaskStatusAuthenticatesExpiredBundleAndUsesExactRoute(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	priorNow := timeNow
	timeNow = func() time.Time { return fixture.cli.now.Add(24 * time.Hour) }
	t.Cleanup(func() { timeNow = priorNow })
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		wantPath := "/v1/tasks/" + fixture.taskDigest + "/permits/" + fixture.permitDigest
		if request.Method != http.MethodGet || request.RequestURI != wantPath || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer gateway-secret" || request.ContentLength != 0 {
			t.Errorf("request method=%q URI=%q headers=%v length=%d", request.Method, request.RequestURI, request.Header, request.ContentLength)
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
			`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(fixture.arguments("status", server.URL), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	status := decodeTaskRuntimeOutput(t, output.Bytes())
	if status.Phase != gatewayclient.PhaseDispatch || status.TaskDigest != fixture.taskDigest ||
		status.PermitDigest != fixture.permitDigest || calls.Load() != 1 {
		t.Fatalf("status=%#v calls=%d", status, calls.Load())
	}
	if bytes.Contains(output.Bytes(), []byte("observation_base64")) {
		t.Fatalf("status exposed raw observation field: %s", output.Bytes())
	}
}

func TestTaskObserveWritesExactOwnerOnlyResultWithoutPrintingIt(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed","result":{"changed":true}}`)
	server := terminalTaskRuntimeServer(t, fixture, raw, "completed")
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "result.json")
	var output bytes.Buffer
	if err := run(fixture.arguments("observe", server.URL, "-result-out", resultPath), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, raw) || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved=%q mode=%#o", saved, info.Mode().Perm())
	}
	status := decodeTaskRuntimeOutput(t, output.Bytes())
	if status.State != string(gatewayclient.AgentReportedCompleted) || status.ObservationBase64 != "" ||
		bytes.Contains(output.Bytes(), raw) || bytes.Contains(output.Bytes(), []byte("observation_base64")) {
		t.Fatalf("output=%s status=%#v", output.Bytes(), status)
	}
}

func TestTaskObserveNeverOverwritesResultAndDoesNotCallGateway(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	resultPath := filepath.Join(fixture.cli.directory, "existing-result.json")
	if err := os.WriteFile(resultPath, []byte("operator-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	err := run(fixture.arguments("observe", server.URL, "-result-out", resultPath), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || calls.Load() != 0 {
		t.Fatalf("error=%v gateway calls=%d", err, calls.Load())
	}
	saved, readErr := os.ReadFile(resultPath)
	if readErr != nil || string(saved) != "operator-owned" {
		t.Fatalf("existing result=%q err=%v", saved, readErr)
	}
}

func TestTaskObserveRefetchesAlreadyTerminalResult(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.RequestURI, "/observe") {
			t.Errorf("request method=%q URI=%q", request.Method, request.RequestURI)
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", true)))
	}))
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "refetched.json")
	var output bytes.Buffer
	if err := run(fixture.arguments("observe", server.URL, "-result-out", resultPath), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if saved, err := os.ReadFile(resultPath); err != nil || !bytes.Equal(saved, raw) {
		t.Fatalf("refetched result=%q error=%v", saved, err)
	}
	if status := decodeTaskRuntimeOutput(t, output.Bytes()); status.Phase != gatewayclient.PhaseTerminal {
		t.Fatalf("status=%#v", status)
	}
}

func TestTaskWaitRefetchesResultWhenInitialStatusIsAlreadyTerminal(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	var statusCalls, observationCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			observationCalls.Add(1)
			writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", true)))
			return
		}
		statusCalls.Add(1)
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", false)))
	}))
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "refetched-by-wait.json")
	var output bytes.Buffer
	err := run(fixture.arguments("wait", server.URL, "-result-out", resultPath), &output, &bytes.Buffer{})
	if err != nil || statusCalls.Load() != 1 || observationCalls.Load() != 1 {
		t.Fatalf("error=%v status calls=%d observation calls=%d", err, statusCalls.Load(), observationCalls.Load())
	}
	if saved, readErr := os.ReadFile(resultPath); readErr != nil || !bytes.Equal(saved, raw) {
		t.Fatalf("refetched result=%q error=%v", saved, readErr)
	}
	if status := decodeTaskRuntimeOutput(t, output.Bytes()); status.Phase != gatewayclient.PhaseTerminal {
		t.Fatalf("status=%#v", status)
	}
}

func TestTaskWaitDiscardStopsAtAlreadyTerminalMetadata(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	var observations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			observations.Add(1)
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", false)))
	}))
	defer server.Close()
	var output bytes.Buffer
	if err := run(fixture.arguments("wait", server.URL, "-discard-result"), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if observations.Load() != 0 {
		t.Fatalf("discard-result made %d unnecessary observations", observations.Load())
	}
	if status := decodeTaskRuntimeOutput(t, output.Bytes()); status.Phase != gatewayclient.PhaseTerminal {
		t.Fatalf("status=%#v", status)
	}
}

func TestTaskObserveRemovesReservationWhenGatewayRawResultIsInvalid(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	fields := terminalTaskRuntimeFields(raw, "completed", true)
	fields = strings.Replace(fields, base64.StdEncoding.EncodeToString(raw), "not-base64!", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, fields))
	}))
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "invalid-result.json")
	var output bytes.Buffer
	err := run(fixture.arguments("observe", server.URL, "-result-out", resultPath), &output, &bytes.Buffer{})
	if err == nil || output.Len() != 0 {
		t.Fatalf("error=%v output=%q", err, output.Bytes())
	}
	if _, statErr := os.Stat(resultPath); !os.IsNotExist(statErr) {
		t.Fatalf("invalid result left output reservation: %v", statErr)
	}
}

func TestTaskWaitHonorsRetryAfterThenReturnsCompletedResult(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	var observations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
				`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
			return
		}
		if call := observations.Add(1); call == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"observation_throttled","message":"wait before observing again"}`)
			return
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "completed", true)))
	}))
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "wait-result.json")
	started := time.Now()
	var output bytes.Buffer
	if err := run(fixture.arguments("wait", server.URL, "-result-out", resultPath, "-wait-timeout", "3s"), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("wait elapsed=%s, Retry-After was not honored", elapsed)
	}
	if observations.Load() != 2 {
		t.Fatalf("observations=%d", observations.Load())
	}
	if saved, err := os.ReadFile(resultPath); err != nil || !bytes.Equal(saved, raw) {
		t.Fatalf("saved=%q err=%v", saved, err)
	}
	if bytes.Contains(output.Bytes(), []byte("observation_base64")) {
		t.Fatalf("wait exposed raw result: %s", output.Bytes())
	}
}

func TestTaskWaitTimeoutCancelsPollingAndRemovesReservation(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	var observations atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
				`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
			return
		}
		observations.Add(1)
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
			`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef","observed_status":"queued"`))
	}))
	defer server.Close()
	resultPath := filepath.Join(fixture.cli.directory, "timed-out-result.json")
	err := run(fixture.arguments("wait", server.URL, "-result-out", resultPath, "-wait-timeout", "20ms"),
		&bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || observations.Load() != 1 {
		t.Fatalf("error=%v observations=%d", err, observations.Load())
	}
	if _, statErr := os.Stat(resultPath); !os.IsNotExist(statErr) {
		t.Fatalf("timeout left empty result reservation: %v", statErr)
	}
}

func TestTaskWaitPrintsFailedTerminalMetadataBeforeReturningError(t *testing.T) {
	fixture := newTaskRuntimeFixture(t)
	raw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"failed","error":"work rejected"}`)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture,
				`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
			return
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, "failed", true)))
	}))
	defer server.Close()
	var output bytes.Buffer
	err := run(fixture.arguments("wait", server.URL, "-discard-result", "-wait-timeout", "1s"), &output, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "agent_reported_failed") {
		t.Fatalf("error=%v", err)
	}
	status := decodeTaskRuntimeOutput(t, output.Bytes())
	if status.State != string(gatewayclient.AgentReportedFailed) || status.ObservationBase64 != "" {
		t.Fatalf("output=%s status=%#v", output.Bytes(), status)
	}
}

func TestTaskRuntimeRejectsLegacyBundlesAndAmbiguousResultChoice(t *testing.T) {
	legacy := newTaskCLIFixture(t)
	legacy.issue(t)
	raw, err := os.ReadFile(legacy.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var legacyBundle taskBundle
	if err := json.Unmarshal(raw, &legacyBundle); err != nil {
		t.Fatal(err)
	}
	legacyBundle.SchemaVersion = "steward.task-bundle.v1"
	writePermitJSONReplace(t, legacy.bundlePath, legacyBundle)
	tokenPath := filepath.Join(legacy.directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	base := []string{"task", "status", "-bundle", legacy.bundlePath, "-gateway-url", server.URL, "-token-file", tokenPath}
	if err := run(base, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("legacy error=%v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("legacy bundle made %d Gateway calls", calls.Load())
	}

	fixture := newTaskRuntimeFixture(t)
	for _, extra := range [][]string{nil, {"-result-out", filepath.Join(fixture.cli.directory, "x"), "-discard-result"}} {
		err := run(fixture.arguments("observe", server.URL, extra...), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("observe options %v error=%v", extra, err)
		}
	}
	if err := run(fixture.arguments("wait", server.URL, "-discard-result", "-wait-timeout", "16m"),
		&bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "at most 15m") {
		t.Fatalf("wait timeout error=%v", err)
	}
}

func terminalTaskRuntimeServer(t *testing.T, fixture taskRuntimeFixture, raw []byte, status string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		wantPath := "/v1/tasks/" + fixture.taskDigest + "/permits/" + fixture.permitDigest + "/observe"
		if request.Method != http.MethodPost || request.RequestURI != wantPath || request.ContentLength != 0 {
			t.Errorf("request method=%q URI=%q length=%d", request.Method, request.RequestURI, request.ContentLength)
		}
		writeTaskRuntimeResponse(t, w, taskRuntimeStatusJSON(fixture, terminalTaskRuntimeFields(raw, status, true)))
	}))
}

func taskRuntimeStatusJSON(fixture taskRuntimeFixture, fields string) string {
	return fmt.Sprintf(`{"schema_version":"steward.task-status.v1","task_digest":%q,"permit_digest":%q,%s}`,
		fixture.taskDigest, fixture.permitDigest, fields)
}

func terminalTaskRuntimeFields(raw []byte, status string, includeRaw bool) string {
	state := "agent_reported_" + status
	fields := fmt.Sprintf(`"phase":"terminal","state":%q,"run_id":"run_0123456789abcdef0123456789abcdef",`+
		`"task_status":%q,"result_digest":%q,"response_bytes":%d`, state, state, dsse.Digest(raw), len(raw))
	if includeRaw {
		fields += fmt.Sprintf(`,"observed_status":%q,"observation_base64":%q`, status, base64.StdEncoding.EncodeToString(raw))
	}
	return fields
}

func writeTaskRuntimeResponse(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(writer, body); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func decodeTaskRuntimeOutput(t *testing.T, raw []byte) gatewayclient.TaskLifecycleStatus {
	t.Helper()
	var status gatewayclient.TaskLifecycleStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode output %q: %v", raw, err)
	}
	return status
}

func writeTaskSubmitCLIResponse(writer http.ResponseWriter, runID string, receipt gatewayclient.TaskReceipt) {
	body := []byte(fmt.Sprintf(`{"run_id":%q}`, runID))
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Steward-Service-Grant", "active")
	writer.Header().Set("X-Steward-Task-Receipt", string(receipt))
	writer.WriteHeader(http.StatusAccepted)
	_, _ = writer.Write(body)
}
