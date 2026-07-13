package mcpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

type fakeTaskGateway struct {
	submission       gatewayclient.TaskSubmission
	submissionResult gatewayclient.TaskSubmissionResult
	submitErr        error
	status           gatewayclient.TaskLifecycleStatus
	statusErr        error
	observation      gatewayclient.TaskLifecycleStatus
	observeErr       error
	observeHook      func() error
	submitCalls      int
	statusCalls      int
	observeCalls     int
}

func (gateway *fakeTaskGateway) Submit(_ context.Context, submission gatewayclient.TaskSubmission) (gatewayclient.TaskSubmissionResult, error) {
	gateway.submitCalls++
	gateway.submission = submission
	return gateway.submissionResult, gateway.submitErr
}

func (gateway *fakeTaskGateway) Status(context.Context, string, string) (gatewayclient.TaskLifecycleStatus, error) {
	gateway.statusCalls++
	return gateway.status, gateway.statusErr
}

func (gateway *fakeTaskGateway) Observe(context.Context, string, string) (gatewayclient.TaskLifecycleStatus, error) {
	gateway.observeCalls++
	if gateway.observeHook != nil {
		if err := gateway.observeHook(); err != nil {
			return gatewayclient.TaskLifecycleStatus{}, err
		}
	}
	return gateway.observation, gateway.observeErr
}

func TestMCPTaskToolsAreOptionalAndSubmissionRequiresAcknowledgment(t *testing.T) {
	nodeOnly, err := New(&fakeNode{}, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if raw := string(mustJSON(t, tools(false))); strings.Contains(raw, "steward_task_") {
		t.Fatalf("node-only MCP registered task tools: %s", raw)
	}
	if _, rpcErr := nodeOnly.callTool(context.Background(), json.RawMessage(`{"name":"steward_task_status","arguments":{}}`)); rpcErr == nil || !strings.Contains(rpcErr.Message, "unknown tool") {
		t.Fatalf("unconfigured task tool error=%#v", rpcErr)
	}

	gateway := &fakeTaskGateway{submissionResult: gatewayclient.TaskSubmissionResult{
		RunID: "run_accepted", Receipt: gatewayclient.TaskReceiptRecorded,
	}}
	server, resultDirectory := newTaskMCPServer(t, gateway)
	listed := tools(true)
	if len(listed) != len(tools(false))+3 {
		t.Fatalf("configured tool count=%d", len(listed))
	}
	var submitTool map[string]any
	for _, candidate := range listed {
		definition := candidate.(map[string]any)
		if definition["name"] == "steward_task_submit" {
			submitTool = definition
		}
	}
	annotations, _ := submitTool["annotations"].(map[string]any)
	if submitTool == nil || annotations["openWorldHint"] != true || annotations["destructiveHint"] != true || annotations["readOnlyHint"] != false {
		t.Fatalf("submission annotations=%#v", annotations)
	}
	toolRaw := string(mustJSON(t, submitTool))
	if !strings.Contains(toolRaw, "acknowledge_external_effects") || !strings.Contains(toolRaw, "not proof of human approval") ||
		strings.Contains(toolRaw, "confirm_irreversible") {
		t.Fatalf("submission definition=%s", toolRaw)
	}

	request := []byte(`{"work":true}`)
	permit := testMCPTaskPermit(t)
	arguments := map[string]any{
		"service_path":   "/v1/services/grant-" + strings.Repeat("b", 64) + "/",
		"operation_path": "/v1/runs", "request_base64": base64.StdEncoding.EncodeToString(request),
		"permit_base64": base64.StdEncoding.EncodeToString(permit), "acknowledge_external_effects": true,
	}
	result := callMCPTaskTool(t, server, "steward_task_submit", arguments)
	resultRaw := string(mustJSON(t, result))
	if strings.Contains(resultRaw, string(request)) || strings.Contains(resultRaw, string(permit)) ||
		!strings.Contains(resultRaw, dsse.Digest(permit)) ||
		!strings.Contains(resultRaw, taskpermit.TaskDigest("tenant", "agent", "task")) || strings.Contains(resultRaw, "run_accepted") ||
		strings.Contains(resultRaw, "run_id") || strings.Contains(resultRaw, "error_code") {
		t.Fatalf("submission result=%s", resultRaw)
	}
	if gateway.submitCalls != 1 || !bytes.Equal(gateway.submission.Request, request) || !bytes.Equal(gateway.submission.Permit, permit) ||
		gateway.submission.ContentType != "application/json" {
		t.Fatalf("submission calls=%d value=%#v", gateway.submitCalls, gateway.submission)
	}
	if entries, readErr := os.ReadDir(resultDirectory); readErr != nil || len(entries) != 0 {
		t.Fatalf("submit created result files: entries=%#v err=%v", entries, readErr)
	}

	arguments["acknowledge_external_effects"] = false
	failure := callMCPTaskTool(t, server, "steward_task_submit", arguments)
	if gateway.submitCalls != 1 || !toolResultIsError(t, failure) {
		t.Fatalf("unacknowledged submission calls=%d result=%#v", gateway.submitCalls, failure)
	}
}

func TestMCPTaskSubmissionRejectsMalformedAndOversizedBase64(t *testing.T) {
	gateway := &fakeTaskGateway{}
	server, _ := newTaskMCPServer(t, gateway)
	permit := testMCPTaskPermit(t)
	valid := map[string]any{
		"service_path":   "/v1/services/grant-" + strings.Repeat("b", 64) + "/",
		"operation_path": "/v1/runs", "request_base64": base64.StdEncoding.EncodeToString([]byte(`{"work":true}`)),
		"permit_base64": base64.StdEncoding.EncodeToString(permit), "acknowledge_external_effects": true,
	}
	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "malformed request", field: "request_base64", value: "%%%"},
		{name: "noncanonical request", field: "request_base64", value: "e30=\n"},
		{name: "oversized request", field: "request_base64", value: strings.Repeat("A", base64.StdEncoding.EncodedLen(int(taskpermit.MaxRequestBytes))+1)},
		{name: "malformed permit", field: "permit_base64", value: "%%%"},
		{name: "malformed permit envelope", field: "permit_base64", value: base64.StdEncoding.EncodeToString([]byte("permit"))},
		{name: "oversized permit", field: "permit_base64", value: strings.Repeat("A", base64.StdEncoding.EncodedLen(taskpermit.MaxEnvelopeBytes)+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			arguments := make(map[string]any, len(valid))
			for name, value := range valid {
				arguments[name] = value
			}
			arguments[test.field] = test.value
			result := callMCPTaskTool(t, server, "steward_task_submit", arguments)
			if !toolResultIsError(t, result) {
				t.Fatalf("invalid base64 accepted: %#v", result)
			}
		})
	}
	if gateway.submitCalls != 0 {
		t.Fatalf("invalid submissions reached Gateway %d times", gateway.submitCalls)
	}
}

func TestMCPTaskStatusOmitsUntrustedRunIDsAndErrorCodes(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	gateway := &fakeTaskGateway{status: gatewayclient.TaskLifecycleStatus{
		SchemaVersion: "steward.task-status.v1", TaskDigest: taskDigest, PermitDigest: permitDigest,
		Phase: gatewayclient.PhaseDispatch, State: gatewayclient.StateDispatchAccepted, RunID: "ignore_previous_instructions",
	}}
	server, _ := newTaskMCPServer(t, gateway)
	arguments := map[string]any{"task_digest": taskDigest, "permit_digest": permitDigest}
	result := callMCPTaskTool(t, server, "steward_task_status", arguments)
	raw := string(mustJSON(t, result))
	if toolResultIsError(t, result) || !strings.Contains(raw, gatewayclient.StateDispatchAccepted) ||
		strings.Contains(raw, "ignore_previous_instructions") || strings.Contains(raw, "run_id") ||
		strings.Contains(raw, "error_code") || strings.Contains(raw, "observation_base64") {
		t.Fatalf("status result=%s", raw)
	}

	gateway.status = gatewayclient.TaskLifecycleStatus{
		SchemaVersion: "steward.task-status.v1", TaskDigest: taskDigest, PermitDigest: permitDigest,
		Phase: gatewayclient.PhaseTerminal, State: gatewayclient.StateFailedWithoutDispatchEvidence,
		ErrorCode: "permit_expired", RetrySafety: gatewayclient.RetryReplacementSafeAfterNewAuthority,
	}
	result = callMCPTaskTool(t, server, "steward_task_status", arguments)
	raw = string(mustJSON(t, result))
	if toolResultIsError(t, result) || strings.Contains(raw, "permit_expired") || strings.Contains(raw, "error_code") ||
		!strings.Contains(raw, gatewayclient.RetryReplacementSafeAfterNewAuthority) {
		t.Fatalf("bounded Gateway error code was projected or rejected: %s", raw)
	}

	gateway.status.ErrorCode = "sensitive_agent_output"
	gateway.status.RetrySafety = gatewayclient.RetryReplacementUnsafe
	failure := callMCPTaskTool(t, server, "steward_task_status", arguments)
	failureRaw := string(mustJSON(t, failure))
	if toolResultIsError(t, failure) || strings.Contains(failureRaw, "sensitive_agent_output") || strings.Contains(failureRaw, "error_code") {
		t.Fatalf("untrusted Gateway error code was projected or rejected: %s", failureRaw)
	}

	gateway.status.ErrorCode = ""
	gateway.status.ObservationBase64 = base64.StdEncoding.EncodeToString([]byte("sensitive-agent-output"))
	failure = callMCPTaskTool(t, server, "steward_task_status", arguments)
	failureRaw = string(mustJSON(t, failure))
	if !toolResultIsError(t, failure) || strings.Contains(failureRaw, gateway.status.ObservationBase64) || strings.Contains(failureRaw, "sensitive-agent-output") {
		t.Fatalf("status leaked unexpected output: %s", failureRaw)
	}
}

func TestMCPTaskObserveWritesVerifiedResultWithoutReturningRawBytes(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	rawResult := []byte(`{"run_id":"run_done","status":"completed","result":"sensitive-agent-output"}`)
	gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
	server, directory := newTaskMCPServer(t, gateway)
	name := mustTaskResultName(t, taskDigest, permitDigest)
	path := filepath.Join(directory, name)
	temporaryPath := filepath.Join(directory, taskResultTemporaryName(name))
	gateway.observeHook = func() error {
		info, err := os.Lstat(temporaryPath)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
			return errors.New("terminal result was not reserved before Gateway observation")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("terminal result became visible before publication")
		}
		return nil
	}
	result := callMCPTaskTool(t, server, "steward_task_observe", map[string]any{
		"task_digest": taskDigest, "permit_digest": permitDigest,
	})
	resultRaw := string(mustJSON(t, result))
	if toolResultIsError(t, result) || !strings.Contains(resultRaw, path) || !strings.Contains(resultRaw, dsse.Digest(rawResult)) ||
		strings.Contains(resultRaw, "observation_base64") || strings.Contains(resultRaw, "sensitive-agent-output") ||
		strings.Contains(resultRaw, base64.StdEncoding.EncodeToString(rawResult)) || strings.Contains(resultRaw, "run_done") ||
		strings.Contains(resultRaw, "run_id") || strings.Contains(resultRaw, "error_code") {
		t.Fatalf("terminal MCP result=%s", resultRaw)
	}
	written, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(written, rawResult) {
		t.Fatalf("written result=%q err=%v", written, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("result mode=%v", info.Mode())
	}
	if gateway.observeCalls != 1 {
		t.Fatalf("observe calls=%d", gateway.observeCalls)
	}
}

func TestMCPTaskObserveUsesHardenedGatewayClientBoundary(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	rawResult := []byte(`{"run_id":"run_done","status":"completed","result":"gateway-verified-secret"}`)
	status := terminalMCPObservation(taskDigest, permitDigest, rawResult)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/tasks/"+taskDigest+"/permits/"+permitDigest+"/observe" ||
			request.Header.Get("Authorization") != "Bearer gateway-secret" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Gateway request method=%s path=%s headers=%v", request.Method, request.URL.Path, request.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer upstream.Close()
	client, err := gatewayclient.New(upstream.URL, "gateway-secret")
	if err != nil {
		t.Fatal(err)
	}
	server, directory := newTaskMCPServer(t, client)
	result := callMCPTaskTool(t, server, "steward_task_observe", map[string]any{
		"task_digest": taskDigest, "permit_digest": permitDigest,
	})
	resultRaw := string(mustJSON(t, result))
	if toolResultIsError(t, result) || strings.Contains(resultRaw, "gateway-verified-secret") ||
		strings.Contains(resultRaw, status.ObservationBase64) {
		t.Fatalf("Gateway-backed result=%s", resultRaw)
	}
	written, err := os.ReadFile(filepath.Join(directory, mustTaskResultName(t, taskDigest, permitDigest)))
	if err != nil || !bytes.Equal(written, rawResult) {
		t.Fatalf("Gateway-backed file=%q err=%v", written, err)
	}
}

func TestMCPTaskObserveCleansReservationForNonterminalErrorsAndInvalidOutput(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	gateway := &fakeTaskGateway{}
	server, directory := newTaskMCPServer(t, gateway)
	arguments := map[string]any{"task_digest": taskDigest, "permit_digest": permitDigest}
	resultName := mustTaskResultName(t, taskDigest, permitDigest)
	gateway.observation = gatewayclient.TaskLifecycleStatus{
		SchemaVersion: "steward.task-status.v1", TaskDigest: taskDigest, PermitDigest: permitDigest,
		Phase: gatewayclient.PhaseDispatch, State: gatewayclient.StateDispatchAccepted,
		RunID: "run_pending", ObservedStatus: gatewayclient.ObservedRunning,
	}
	result := callMCPTaskTool(t, server, "steward_task_observe", arguments)
	if toolResultIsError(t, result) {
		t.Fatalf("nonterminal observation failed: %#v", result)
	}
	requireNoMCPResultFile(t, directory, resultName)

	gateway.observeErr = errors.New("sensitive-agent-output")
	result = callMCPTaskTool(t, server, "steward_task_observe", arguments)
	if errorRaw := string(mustJSON(t, result)); !toolResultIsError(t, result) || strings.Contains(errorRaw, "sensitive-agent-output") {
		t.Fatalf("Gateway error accepted or leaked: %s", errorRaw)
	}
	requireNoMCPResultFile(t, directory, resultName)
	gateway.observeErr = &gatewayclient.APIError{
		Status: 429, Code: "sensitive_agent_output", Message: "sensitive-agent-output", RetryAfter: 2 * time.Second,
	}
	result = callMCPTaskTool(t, server, "steward_task_observe", arguments)
	if errorRaw := string(mustJSON(t, result)); !toolResultIsError(t, result) ||
		!strings.Contains(errorRaw, "HTTP 429") || !strings.Contains(errorRaw, "retry after 2s") ||
		strings.Contains(errorRaw, "sensitive_agent_output") ||
		strings.Contains(errorRaw, "sensitive-agent-output") {
		t.Fatalf("Gateway API error projection=%s", errorRaw)
	}
	requireNoMCPResultFile(t, directory, resultName)
	gateway.observeErr = nil

	base := terminalMCPObservation(taskDigest, permitDigest, []byte(`{"run_id":"run_done","status":"completed","result":"secret"}`))
	for _, test := range []struct {
		name   string
		mutate func(*gatewayclient.TaskLifecycleStatus)
	}{
		{name: "malformed-base64", mutate: func(status *gatewayclient.TaskLifecycleStatus) { status.ObservationBase64 = "%%%" }},
		{name: "oversized", mutate: func(status *gatewayclient.TaskLifecycleStatus) {
			status.ObservationBase64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), maxTaskObservationBytes+1))
			status.ResponseBytes = maxTaskObservationBytes + 1
		}},
		{name: "length-mismatch", mutate: func(status *gatewayclient.TaskLifecycleStatus) { status.ResponseBytes++ }},
		{name: "digest-mismatch", mutate: func(status *gatewayclient.TaskLifecycleStatus) { status.ResultDigest = digestFor('f') }},
		{name: "nonterminal-raw", mutate: func(status *gatewayclient.TaskLifecycleStatus) {
			status.Phase, status.ObservedStatus = gatewayclient.PhaseDispatch, gatewayclient.ObservedRunning
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway.observation = base
			test.mutate(&gateway.observation)
			failure := callMCPTaskTool(t, server, "steward_task_observe", arguments)
			failureRaw := string(mustJSON(t, failure))
			if !toolResultIsError(t, failure) || strings.Contains(failureRaw, "secret") || strings.Contains(failureRaw, base.ObservationBase64) {
				t.Fatalf("invalid observation leaked output: %s", failureRaw)
			}
			requireNoMCPResultFile(t, directory, resultName)
		})
	}
}

func TestMCPTaskObserveUsesOneDeterministicResultPerTaskPermit(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	rawResult := []byte(`{"run_id":"run_done","status":"completed","result":{"ok":true}}`)
	gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
	server, directory := newTaskMCPServer(t, gateway)
	arguments := map[string]any{"task_digest": taskDigest, "permit_digest": permitDigest}
	name := mustTaskResultName(t, taskDigest, permitDigest)
	path := filepath.Join(directory, name)

	withCallerName := map[string]any{
		"task_digest": taskDigest, "permit_digest": permitDigest, "result_name": "caller-selected.result",
	}
	if result := callMCPTaskTool(t, server, "steward_task_observe", withCallerName); !toolResultIsError(t, result) {
		t.Fatalf("observe accepted caller-selected result name: %#v", result)
	}
	if gateway.observeCalls != 0 {
		t.Fatalf("invalid observe reached Gateway %d times", gateway.observeCalls)
	}

	first := callMCPTaskTool(t, server, "steward_task_observe", arguments)
	if firstRaw := string(mustJSON(t, first)); toolResultIsError(t, first) || !strings.Contains(firstRaw, path) {
		t.Fatalf("first deterministic observation=%s", firstRaw)
	}
	written, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(written, rawResult) {
		t.Fatalf("deterministic result=%q err=%v", written, err)
	}
	second := callMCPTaskTool(t, server, "steward_task_observe", arguments)
	if !toolResultIsError(t, second) || gateway.observeCalls != 1 {
		t.Fatalf("duplicate result=%#v Gateway calls=%d", second, gateway.observeCalls)
	}
	written, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(written, rawResult) {
		t.Fatalf("duplicate changed deterministic result=%q err=%v", written, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("deterministic result entries=%#v err=%v", entries, err)
	}
}

func TestMCPTaskResultPublicationIsAtomicAndNoOverwrite(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	name := mustTaskResultName(t, taskDigest, permitDigest)

	t.Run("concurrent deterministic reservation", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		const workers = 12
		stores := make([]*taskResultStore, workers)
		for index := range stores {
			store, err := newTaskResultStore(directory)
			if err != nil {
				t.Fatal(err)
			}
			stores[index] = store
			t.Cleanup(func() { _ = store.close() })
		}
		type outcome struct {
			raw []byte
			err error
		}
		outcomes := make([]outcome, workers)
		start := make(chan struct{})
		var group sync.WaitGroup
		for index := range workers {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				raw := []byte(fmt.Sprintf(`{"worker":%d}`, index))
				reservation, err := stores[index].reserve(taskDigest, permitDigest)
				if err == nil {
					err = reservation.commit(raw)
				}
				outcomes[index] = outcome{raw: raw, err: err}
			}()
		}
		close(start)
		group.Wait()

		var winner []byte
		for _, result := range outcomes {
			if result.err == nil {
				if winner != nil {
					t.Fatalf("multiple deterministic publications succeeded: %q and %q", winner, result.raw)
				}
				winner = result.raw
			}
		}
		if winner == nil {
			t.Fatalf("no deterministic publication succeeded: %#v", outcomes)
		}
		published, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(published, winner) {
			t.Fatalf("published result=%q winner=%q err=%v", published, winner, err)
		}
		if _, err := os.Lstat(filepath.Join(directory, taskResultTemporaryName(name))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary result remained after concurrent publication: %v", err)
		}
	})

	t.Run("raced final is preserved", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		store, err := newTaskResultStore(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		reservation, err := store.reserve(taskDigest, permitDigest)
		if err != nil {
			t.Fatal(err)
		}
		finalPath := filepath.Join(directory, name)
		if err := os.WriteFile(finalPath, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reservation.commit([]byte("do-not-publish")); err == nil {
			t.Fatal("publication overwrote a final created after reservation")
		}
		published, err := os.ReadFile(finalPath)
		if err != nil || string(published) != "keep" {
			t.Fatalf("raced final changed: %q err=%v", published, err)
		}
		if _, err := os.Lstat(filepath.Join(directory, taskResultTemporaryName(name))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed publication left a temporary result: %v", err)
		}
	})
}

func TestMCPTaskResultStoreRecoversCrashAtomicPublication(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	name := mustTaskResultName(t, taskDigest, permitDigest)
	temporaryName := taskResultTemporaryName(name)

	t.Run("partial temporary before publication", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		writeTaskResultTestBytes(t, filepath.Join(directory, temporaryName), []byte("partial-agent-output"))
		store, err := newTaskResultStore(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		if _, err := os.Lstat(filepath.Join(directory, temporaryName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial temporary survived startup cleanup: %v", err)
		}
		if store.files != 0 || store.bytes != 0 {
			t.Fatalf("partial temporary consumed quota: files=%d bytes=%d", store.files, store.bytes)
		}
		reservation, err := store.reserve(taskDigest, permitDigest)
		if err != nil {
			t.Fatal(err)
		}
		complete := []byte(`{"status":"completed"}`)
		if err := reservation.commit(complete); err != nil {
			t.Fatal(err)
		}
		if published, err := os.ReadFile(filepath.Join(directory, name)); err != nil || !bytes.Equal(published, complete) {
			t.Fatalf("result after partial recovery=%q err=%v", published, err)
		}
	})

	t.Run("published link before temporary cleanup", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		complete := []byte(`{"status":"completed","result":"durable"}`)
		temporaryPath := filepath.Join(directory, temporaryName)
		finalPath := filepath.Join(directory, name)
		writeTaskResultTestBytes(t, temporaryPath, complete)
		if err := os.Link(temporaryPath, finalPath); err != nil {
			t.Fatal(err)
		}
		store, err := newTaskResultStore(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		if _, err := os.Lstat(temporaryPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published temporary survived startup cleanup: %v", err)
		}
		published, err := os.ReadFile(finalPath)
		if err != nil || !bytes.Equal(published, complete) {
			t.Fatalf("recovered publication=%q err=%v", published, err)
		}
		info, err := os.Lstat(finalPath)
		links, linkOK := storedTaskResultLinkCount(info)
		if err != nil || !linkOK || links != 1 || store.files != 1 || store.bytes != int64(len(complete)) {
			t.Fatalf("recovered publication info=%#v links=%d files=%d bytes=%d err=%v", info, links, store.files, store.bytes, err)
		}
	})
}

func TestMCPTaskResultReservationRejectsExistingSymlinkAndReplacementRaces(t *testing.T) {
	taskDigest, permitDigest := digestFor('a'), digestFor('b')
	rawResult := []byte(`{"run_id":"run_done","status":"completed"}`)
	arguments := map[string]any{"task_digest": taskDigest, "permit_digest": permitDigest}

	t.Run("existing result", func(t *testing.T) {
		gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
		server, directory := newTaskMCPServer(t, gateway)
		path := filepath.Join(directory, mustTaskResultName(t, taskDigest, permitDigest))
		if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		result := callMCPTaskTool(t, server, "steward_task_observe", arguments)
		if !toolResultIsError(t, result) || gateway.observeCalls != 0 {
			t.Fatalf("existing result=%#v Gateway calls=%d", result, gateway.observeCalls)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "keep" {
			t.Fatalf("existing result changed: %q err=%v", raw, err)
		}
	})

	t.Run("preexisting symlink", func(t *testing.T) {
		gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
		server, directory := newTaskMCPServer(t, gateway)
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, mustTaskResultName(t, taskDigest, permitDigest))
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		result := callMCPTaskTool(t, server, "steward_task_observe", arguments)
		if !toolResultIsError(t, result) || gateway.observeCalls != 0 {
			t.Fatalf("symlink result=%#v Gateway calls=%d", result, gateway.observeCalls)
		}
		if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
			t.Fatalf("symlink target changed: %q err=%v", raw, err)
		}
	})

	t.Run("reservation replacement", func(t *testing.T) {
		gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
		server, directory := newTaskMCPServer(t, gateway)
		target := filepath.Join(directory, "race-target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		name := mustTaskResultName(t, taskDigest, permitDigest)
		path := filepath.Join(directory, name)
		temporaryPath := filepath.Join(directory, taskResultTemporaryName(name))
		movedPath := filepath.Join(directory, "moved-reservation")
		gateway.observeHook = func() error {
			if err := os.Rename(temporaryPath, movedPath); err != nil {
				return err
			}
			return os.Symlink(target, temporaryPath)
		}
		result := callMCPTaskTool(t, server, "steward_task_observe", arguments)
		if !toolResultIsError(t, result) || gateway.observeCalls != 1 {
			t.Fatalf("replacement result=%#v Gateway calls=%d", result, gateway.observeCalls)
		}
		if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
			t.Fatalf("replacement target changed: %q err=%v", raw, err)
		}
		if info, err := os.Lstat(movedPath); err != nil || info.Size() != 0 {
			t.Fatalf("moved reservation contains agent bytes: info=%#v err=%v", info, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("replacement race published a result: %v", err)
		}
	})

	t.Run("directory replacement", func(t *testing.T) {
		gateway := &fakeTaskGateway{observation: terminalMCPObservation(taskDigest, permitDigest, rawResult)}
		server, directory := newTaskMCPServer(t, gateway)
		relocated := directory + ".old"
		if err := os.Rename(directory, relocated); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		result := callMCPTaskTool(t, server, "steward_task_observe", arguments)
		if !toolResultIsError(t, result) || gateway.observeCalls != 0 {
			t.Fatalf("directory replacement result=%#v Gateway calls=%d", result, gateway.observeCalls)
		}
		requireNoMCPResultFile(t, directory, mustTaskResultName(t, taskDigest, permitDigest))
	})
}

func TestMCPTaskResultDirectoryRejectsUnsafeConfigurationAndEntries(t *testing.T) {
	gateway := &fakeTaskGateway{}
	if _, err := NewWithTasks(&fakeNode{}, nil, t.TempDir(), "v1"); err == nil {
		t.Fatal("nil Gateway task client accepted")
	}
	if _, err := NewWithTasks(&fakeNode{}, gateway, "relative", "v1"); err == nil {
		t.Fatal("relative result directory accepted")
	}
	permissive := newTaskResultTestDirectory(t)
	if err := os.Chmod(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	requireTaskResultStoreStartupError(t, gateway, permissive, "mode 0700")

	replaceableParent := filepath.Join(t.TempDir(), "replaceable")
	if err := os.Mkdir(replaceableParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replaceableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	replaceableDirectory := filepath.Join(replaceableParent, "results")
	if err := os.Mkdir(replaceableDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	requireTaskResultStoreStartupError(t, gateway, replaceableDirectory, "replaceable ancestor")

	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "unexpected filename", setup: func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory entry", setup: func(t *testing.T, directory string) {
			if err := os.Mkdir(filepath.Join(directory, mustTaskResultName(t, digestFor('a'), digestFor('b'))), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink entry", setup: func(t *testing.T, directory string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directory, mustTaskResultName(t, digestFor('a'), digestFor('b')))); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "permissive result", setup: func(t *testing.T, directory string) {
			path := filepath.Join(directory, mustTaskResultName(t, digestFor('a'), digestFor('b')))
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized result", setup: func(t *testing.T, directory string) {
			writeTaskResultTestFile(t, directory, digestFor('a'), digestFor('b'), maxTaskObservationBytes+1)
		}},
		{name: "symlink temporary", setup: func(t *testing.T, directory string) {
			name := taskResultTemporaryName(mustTaskResultName(t, digestFor('a'), digestFor('b')))
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directory, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "aliased temporary", setup: func(t *testing.T, directory string) {
			name := taskResultTemporaryName(mustTaskResultName(t, digestFor('a'), digestFor('b')))
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, filepath.Join(directory, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized temporary", setup: func(t *testing.T, directory string) {
			name := taskResultTemporaryName(mustTaskResultName(t, digestFor('a'), digestFor('b')))
			file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr := file.Truncate(maxTaskObservationBytes + 1)
			closeErr := file.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatal(errors.Join(truncateErr, closeErr))
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := newTaskResultTestDirectory(t)
			test.setup(t, directory)
			requireTaskResultStoreStartupError(t, gateway, directory, "entry")
		})
	}
}

func TestMCPTaskResultDirectoryRejectsStartupQuotaExcess(t *testing.T) {
	gateway := &fakeTaskGateway{}
	t.Run("file count", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		for index := 0; index <= maxTaskResultFiles; index++ {
			writeTaskResultTestFile(t, directory, numberedDigest(index+1), numberedDigest(index+100_000), 1)
		}
		requireTaskResultStoreStartupError(t, gateway, directory, "file-count limit")
	})

	t.Run("bytes", func(t *testing.T) {
		directory := newTaskResultTestDirectory(t)
		fileSize := int64(maxTaskObservationBytes)
		fileCount := int(maxTaskResultStoreBytes/fileSize) + 1
		for index := 0; index < fileCount; index++ {
			writeTaskResultTestFile(t, directory, numberedDigest(index+1), numberedDigest(index+100_000), fileSize)
		}
		requireTaskResultStoreStartupError(t, gateway, directory, "byte limit")
	})
}

func newTaskMCPServer(t *testing.T, gateway TaskGateway) (*Server, string) {
	t.Helper()
	directory := newTaskResultTestDirectory(t)
	server, err := NewWithTasks(&fakeNode{}, gateway, directory, "v1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if server.resultStore != nil {
			_ = server.resultStore.close()
		}
	})
	return server, server.resultStore.directory
}

func newTaskResultTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "results")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func mustTaskResultName(t *testing.T, taskDigest, permitDigest string) string {
	t.Helper()
	name, err := taskResultName(taskDigest, permitDigest)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func requireTaskResultStoreStartupError(t *testing.T, gateway TaskGateway, directory, want string) {
	t.Helper()
	server, err := NewWithTasks(&fakeNode{}, gateway, directory, "v1")
	if err == nil {
		if server.resultStore != nil {
			_ = server.resultStore.close()
		}
		t.Fatalf("unsafe task result store %q was accepted", directory)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("task result store error=%q want substring %q", err, want)
	}
}

func writeTaskResultTestFile(t *testing.T, directory, taskDigest, permitDigest string, size int64) {
	t.Helper()
	path := filepath.Join(directory, mustTaskResultName(t, taskDigest, permitDigest))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	truncateErr := file.Truncate(size)
	closeErr := file.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatal(errors.Join(truncateErr, closeErr))
	}
}

func writeTaskResultTestBytes(t *testing.T, path string, raw []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, syncErr, closeErr))
	}
}

func numberedDigest(value int) string {
	return fmt.Sprintf("sha256:%064x", value)
}

func callMCPTaskTool(t *testing.T, server *Server, name string, arguments map[string]any) any {
	t.Helper()
	rawArguments, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	rawCall, err := json.Marshal(map[string]any{"name": name, "arguments": json.RawMessage(rawArguments)})
	if err != nil {
		t.Fatal(err)
	}
	result, rpcErr := server.callTool(context.Background(), rawCall)
	if rpcErr != nil {
		t.Fatalf("tool %s RPC error: %#v", name, rpcErr)
	}
	return result
}

func toolResultIsError(t *testing.T, value any) bool {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("tool result type=%T", value)
	}
	isError, _ := result["isError"].(bool)
	return isError
}

func terminalMCPObservation(taskDigest, permitDigest string, raw []byte) gatewayclient.TaskLifecycleStatus {
	return gatewayclient.TaskLifecycleStatus{
		SchemaVersion: "steward.task-status.v1", TaskDigest: taskDigest, PermitDigest: permitDigest,
		Phase: gatewayclient.PhaseTerminal, State: string(gatewayclient.AgentReportedCompleted),
		RunID: "run_done", TaskStatus: gatewayclient.AgentReportedCompleted,
		ResultDigest: dsse.Digest(raw), ResponseBytes: int64(len(raw)),
		ObservedStatus: gatewayclient.ObservedCompleted, ObservationBase64: base64.StdEncoding.EncodeToString(raw),
	}
}

func requireNoMCPResultFile(t *testing.T, directory, name string) {
	t.Helper()
	for _, candidate := range []string{name, taskResultTemporaryName(name)} {
		if _, err := os.Lstat(filepath.Join(directory, candidate)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("result reservation %q remained: %v", candidate, err)
		}
	}
}

func digestFor(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }

func testMCPTaskPermit(t *testing.T) []byte {
	t.Helper()
	payload, err := json.Marshal(taskpermit.Statement{TenantID: "tenant", InstanceID: "agent", TaskID: "task"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(dsse.Envelope{
		PayloadType: taskpermit.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{
			KeyID: "task-authority", Sig: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
