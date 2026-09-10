package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
)

func testStopOperation() ServiceOperation {
	return ServiceOperation{
		ServiceID: "hermes-api", ID: "hermes.stop", Method: http.MethodPost,
		Path: "/steward/v1/run-stop", ContentType: "application/json", MaxRequestBytes: 49,
		MaxResponseBytes: 1 << 20, MaxSeconds: 5, MaxPermitSeconds: 300,
		TaskProtocol: TaskProtocolLifecycleV1, StatusPathPrefix: "/v1/runs/",
		StatusMaxSeconds: 5, PollIntervalSeconds: 1,
	}
}

func TestSignedStopReferencesOriginalTaskAcrossObservationAndRestart(t *testing.T) {
	var calls atomic.Int64
	var stopped atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			calls.Add(1)
			if r.URL.Path == "/steward/v1/run-stop" {
				stopped.Store(true)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
			return
		}
		status := "running"
		if stopped.Load() {
			status = "cancelled"
		}
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `","status":"` + status + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL, testStopOperation())
	work := []byte(`{"input":"work","session_id":"controlled-turn"}`)
	workPermit := taskPermitFor(t, rig, "work-before-stop", work, nil)
	workResponse := invokeControlTaskSubmit(t, rig, work, workPermit)
	if workResponse.Code != http.StatusOK {
		t.Fatal(workResponse.Body.String())
	}
	workSubmission := decodeControlTaskSubmission(t, workResponse)
	rig.operation = testStopOperation()
	body, _ := connectorledger.HermesStopRequest(lifecycleTestRunID)
	permit := taskPermitFor(t, rig, "stop-original-work", body, nil)
	response := invokeControlTaskSubmit(t, rig, body, permit)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	stopSubmission := decodeControlTaskSubmission(t, response)
	if stopSubmission.RunID != workSubmission.RunID || stopSubmission.TaskDigest == workSubmission.TaskDigest {
		t.Fatal("stop lost its separate task identity or original target")
	}
	// A successful stop dispatch is not terminal proof for either task.
	if got := rig.server.serviceTasks[workSubmission.TaskDigest].Terminal.Phase; got != "" {
		t.Fatal(got)
	}
	if got := rig.server.serviceTasks[stopSubmission.TaskDigest].Terminal.Phase; got != "" {
		t.Fatal(got)
	}
	reopenLifecycleServiceTaskRig(t, rig, rig.now)
	if replay := invokeControlTaskSubmit(t, rig, body, permit); replay.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("stop replay redispatched: %s calls=%d", replay.Body.String(), calls.Load())
	}
	for _, submission := range []ControlTaskSubmission{workSubmission, stopSubmission} {
		observed := invokeLifecycleTaskReferenceEndpoint(rig, http.MethodPost, submission.TaskDigest, submission.PermitDigest, true, nil)
		status := decodeLifecycleTaskStatus(t, observed)
		if observed.Code != http.StatusOK || status.TaskStatus != string(connectorledger.TaskStatusAgentReportedCancelled) {
			t.Fatalf("original/control observation: %s", observed.Body.String())
		}
	}
	records := lifecycleReceiptRecords(t, rig)
	controls := 0
	for _, record := range records {
		if record.Receipt.Event.TaskDigest == stopSubmission.TaskDigest {
			controls++
			if record.Receipt.SchemaVersion != connectorledger.SchemaV8 ||
				record.Receipt.Event.TargetTaskDigest != workSubmission.TaskDigest ||
				record.Receipt.Event.TargetRunID != workSubmission.RunID {
				t.Fatal("stop parent was not retained")
			}
		}
	}
	if controls != 3 {
		t.Fatalf("control records=%d", controls)
	}
	for _, submission := range []ControlTaskSubmission{workSubmission, stopSubmission} {
		path := controlTaskPathFor(submission.TaskDigest, submission.PermitDigest, "evidence")
		exported := invokeControlTaskRaw(rig, http.MethodGet, path, "", nil)
		if submission.TaskDigest == workSubmission.TaskDigest {
			if exported.Code != http.StatusOK {
				t.Fatalf("original work lost portable evidence: %s", exported.Body.String())
			}
		} else if code := requireGatewayErrorCode(t, exported, http.StatusUnprocessableEntity); code != "task_evidence_requires_parent" {
			t.Fatalf("linked proof gave misleading recovery advice: %s", exported.Body.String())
		}
	}
	if summary, err := InspectConnectorReceiptFormat(rig.config); err != nil || summary.FormatVersion != 8 {
		t.Fatalf("receipt format=%#v err=%v", summary, err)
	}
	reopenLifecycleServiceTaskRig(t, rig, rig.now)
	// Ordinary work still cannot steal that ID after a stop or a restart.
	rig.operation = rig.config.ServiceOperations[0]
	other := []byte(`{"input":"different work","session_id":"different-turn"}`)
	otherPermit := taskPermitFor(t, rig, "different-work", other, nil)
	conflict := invokeServiceTask(rig, other, otherPermit)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "run_id_conflict") {
		t.Fatalf("ordinary run alias accepted: %s", conflict.Body.String())
	}
}

func TestStopDoesNotDispatchWithoutCanonicalKnownTarget(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + lifecycleTestRunID + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL, testStopOperation())
	rig.operation = testStopOperation()
	body, _ := connectorledger.HermesStopRequest(lifecycleTestRunID)
	for index, raw := range [][]byte{body, []byte(`{"run_id":"run_other"}`), append(append([]byte{}, body...), ' ')} {
		permit := taskPermitFor(t, rig, "unknown-stop-"+string(rune('a'+index)), raw, nil)
		response := invokeServiceTask(rig, raw, permit)
		if response.Code < 400 || calls.Load() != 0 {
			t.Fatalf("invalid stop dispatched: %s", response.Body.String())
		}
	}
}

func TestReservedStopOperationRejectsDifferentRoutesOrLimits(t *testing.T) {
	for name, mutate := range map[string]func(*ServiceOperation){
		"path":     func(o *ServiceOperation) { o.Path = "/other" },
		"size":     func(o *ServiceOperation) { o.MaxRequestBytes = 65536 },
		"status":   func(o *ServiceOperation) { o.StatusPathPrefix = "/other/" },
		"method":   func(o *ServiceOperation) { o.Method = http.MethodGet },
		"protocol": func(o *ServiceOperation) { o.TaskProtocol = "" },
	} {
		t.Run(name, func(t *testing.T) {
			operation := testStopOperation()
			mutate(&operation)
			if err := ValidateServiceOperation(operation); err == nil {
				t.Fatal("invalid reserved operation accepted")
			}
		})
	}
}

func TestStopResponseCannotSubstituteAnotherRun(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		id := lifecycleTestRunID
		if r.URL.Path == "/steward/v1/run-stop" {
			id = "run_ffffffffffffffffffffffffffffffff"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"` + id + `"}`))
	}))
	defer upstream.Close()
	rig := newLifecycleServiceTaskRig(t, upstream.URL, testStopOperation())
	dispatchLifecycleTask(t, rig, "original-work", []byte(`{"input":"work","session_id":"original"}`))
	rig.operation = testStopOperation()
	body, _ := connectorledger.HermesStopRequest(lifecycleTestRunID)
	permit := taskPermitFor(t, rig, "wrong-target-response", body, nil)
	first := invokeServiceTask(rig, body, permit)
	if first.Code != http.StatusBadGateway || !strings.Contains(first.Body.String(), "outcome_unknown") {
		t.Fatalf("wrong run response accepted: %s", first.Body.String())
	}
	reopenLifecycleServiceTaskRig(t, rig, rig.now)
	if replay := invokeServiceTask(rig, body, permit); replay.Code != http.StatusConflict || calls.Load() != 2 {
		t.Fatalf("unknown stop was resubmitted: %s calls=%d", replay.Body.String(), calls.Load())
	}
	for _, record := range lifecycleReceiptRecords(t, rig) {
		if record.Receipt.Event.TargetTaskDigest != "" && record.Receipt.Event.RunID != "" {
			t.Fatal("untrusted stop response claimed another run")
		}
	}
}
