package gatewayclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testTaskDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testPermitDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestStatusAndObserveUseFixedAuthenticatedRequests(t *testing.T) {
	terminalRaw := []byte(`{"run_id":"run_0123456789abcdef0123456789abcdef","status":"completed"}`)
	terminalSum := sha256.Sum256(terminalRaw)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		wantMethod, wantPath := http.MethodGet, "/v1/tasks/"+testTaskDigest+"/permits/"+testPermitDigest
		if call == 2 {
			wantMethod, wantPath = http.MethodPost, wantPath+"/observe"
		}
		if request.Method != wantMethod || request.URL.Path != wantPath || request.URL.RawQuery != "" ||
			request.RequestURI != wantPath || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(body) != 0 {
			t.Errorf("request method=%q target=%q URI=%q length=%d transfer=%v body=%q",
				request.Method, request.URL.String(), request.RequestURI, request.ContentLength, request.TransferEncoding, body)
		}
		if request.Header.Get("Authorization") != "Bearer gateway-secret" || request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Accept-Encoding") != "identity" || request.UserAgent() != "steward" ||
			request.Header.Get("Content-Type") != "" || request.Header.Get("Cookie") != "" {
			t.Errorf("request headers=%v", request.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			_, _ = io.WriteString(w, statusJSON(testTaskDigest, `"phase":"dispatch","state":"dispatch_accepted","run_id":"run_0123456789abcdef0123456789abcdef"`))
			return
		}
		_, _ = io.WriteString(w, statusJSON(testTaskDigest,
			fmt.Sprintf(`"phase":"terminal","state":"agent_reported_completed","run_id":"run_0123456789abcdef0123456789abcdef",`+
				`"task_status":"agent_reported_completed","result_digest":"sha256:%x","response_bytes":%d,`+
				`"observed_status":"completed","observation_base64":%q`, terminalSum[:], len(terminalRaw), base64.StdEncoding.EncodeToString(terminalRaw))))
	}))
	defer server.Close()

	client, err := New(server.URL, "gateway-secret")
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(context.Background(), testTaskDigest, testPermitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != taskStatusSchemaV1 || status.TaskDigest != testTaskDigest || status.PermitDigest != testPermitDigest || status.Phase != PhaseDispatch ||
		status.State != StateDispatchAccepted || status.RunID != "run_0123456789abcdef0123456789abcdef" {
		t.Fatalf("status=%#v", status)
	}
	observed, err := client.Observe(context.Background(), testTaskDigest, testPermitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Phase != PhaseTerminal || observed.TaskStatus != AgentReportedCompleted ||
		observed.ObservedStatus != ObservedCompleted || observed.ResponseBytes != int64(len(terminalRaw)) {
		t.Fatalf("observed=%#v", observed)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

func TestNewUsesHardenedTransportAndValidatesOriginAndToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, statusJSON(testTaskDigest, `"phase":"authorize","state":"authorization_recorded"`))
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type=%T", client.http.Transport)
	}
	if transport.Proxy != nil || !transport.DisableCompression || transport.ResponseHeaderTimeout <= 0 ||
		transport.MaxResponseHeaderBytes != maxGatewayResponseHeader || client.http.Timeout <= 0 || client.http.CheckRedirect == nil {
		t.Fatalf("transport=%#v client timeout=%v", transport, client.http.Timeout)
	}

	invalidURLs := []string{
		"", "https://127.0.0.1:8443", "http://example.test:8080", "http://localhost:8080",
		"http://127.0.0.1", "http://127.0.0.1:08080", "http://127.0.0.1:8080/",
		"http://127.0.0.1:8080?", "http://127.0.0.1:8080?x=1", "http://user@127.0.0.1:8080",
	}
	for _, value := range invalidURLs {
		if _, err := New(value, "secret"); err == nil {
			t.Errorf("New(%q) succeeded", value)
		}
	}
	for _, token := range []string{"", "with space", "line\nbreak", strings.Repeat("x", 4097)} {
		if _, err := New(server.URL, token); err == nil {
			t.Errorf("New accepted token %q", token)
		}
	}
}

func TestClientRefusesRedirectBeforeCredentialCanBeForwarded(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := New(redirect.URL, "redirect-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Status(context.Background(), testTaskDigest, testPermitDigest)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect error=%v, want ErrRedirect", err)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target received %d calls", targetCalls.Load())
	}
}

func TestClientRejectsInvalidTaskDigestsBeforeNetwork(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 64) + "/observe", "sha256:" + strings.Repeat("a", 64) + "?x=1",
	}
	for _, digest := range invalid {
		if _, err := client.Status(context.Background(), digest, testPermitDigest); err == nil {
			t.Errorf("Status accepted digest %q", digest)
		}
		if _, err := client.Observe(context.Background(), testTaskDigest, digest); err == nil {
			t.Errorf("Observe accepted digest %q", digest)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid digests made %d network calls", calls.Load())
	}
}

func TestClientStrictlyBoundsAndDecodesStatusResponses(t *testing.T) {
	valid := statusJSON(testTaskDigest, `"phase":"authorize","state":"authorization_recorded"`)
	tests := []struct {
		name        string
		body        string
		contentType string
		encoding    string
	}{
		{name: "malformed", body: `{"schema_version":`},
		{name: "trailing JSON", body: valid + `{}`},
		{name: "unknown field", body: statusJSON(testTaskDigest, `"phase":"authorize","state":"authorization_recorded","extra":true`)},
		{name: "duplicate field", body: `{"schema_version":"steward.task-status.v1","schema_version":"steward.task-status.v1","task_digest":"` + testTaskDigest + `","permit_digest":"` + testPermitDigest + `","phase":"authorize","state":"authorization_recorded"}`},
		{name: "oversized", body: strings.Repeat("x", maxTaskStatusWireBytes+1)},
		{name: "wrong schema", body: strings.Replace(valid, taskStatusSchemaV1, "steward.task-status.v2", 1)},
		{name: "wrong digest", body: strings.Replace(valid, testTaskDigest, "sha256:"+strings.Repeat("b", 64), 1)},
		{name: "wrong permit digest", body: strings.Replace(valid, testPermitDigest, "sha256:"+strings.Repeat("c", 64), 1)},
		{name: "unsupported phase", body: strings.Replace(valid, `"authorize"`, `"pending"`, 1)},
		{name: "unsupported state", body: strings.Replace(valid, StateAuthorizationRecorded, "mystery", 1)},
		{name: "evidence unavailable is an error not a success state", body: strings.Replace(valid, StateAuthorizationRecorded, "evidence_unavailable", 1)},
		{name: "inconsistent shape", body: statusJSON(testTaskDigest, `"phase":"authorize","state":"dispatch_accepted","run_id":"run_1"`)},
		{name: "unbounded response metadata", body: statusJSON(testTaskDigest, fmt.Sprintf(`"phase":"terminal","state":"failed_without_dispatch_evidence","response_bytes":%d,"error_code":"outcome_unknown","retry_safety":"replacement_unsafe"`, maxObservationBytes+1))},
		{name: "observation failure without dispatched run", body: statusJSON(testTaskDigest, `"phase":"terminal","state":"observation_failed","error_code":"outcome_unknown","retry_safety":"replacement_unsafe"`)},
		{name: "missing retry safety", body: statusJSON(testTaskDigest, `"phase":"terminal","state":"failed_without_dispatch_evidence","error_code":"outcome_unknown"`)},
		{name: "unsafe failure marked safe", body: statusJSON(testTaskDigest, `"phase":"terminal","state":"failed_without_dispatch_evidence","error_code":"outcome_unknown","retry_safety":"replacement_safe_after_new_authority"`)},
		{name: "known pre-dispatch failure marked unsafe", body: statusJSON(testTaskDigest, `"phase":"terminal","state":"failed_without_dispatch_evidence","error_code":"permit_expired","retry_safety":"replacement_unsafe"`)},
		{name: "bad content type", body: valid, contentType: "application/json; charset=utf-8"},
		{name: "compressed", body: valid, encoding: "gzip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				contentType := test.contentType
				if contentType == "" {
					contentType = "application/json"
				}
				w.Header().Set("Content-Type", contentType)
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Status(context.Background(), testTaskDigest, testPermitDigest); err == nil {
				t.Fatal("invalid status response was accepted")
			}
		})
	}
}

func TestClientSeparatesDurableStatusFromLiveObservationResponses(t *testing.T) {
	terminalRaw := []byte(`{"run_id":"run_1","status":"completed"}`)
	terminalSum := sha256.Sum256(terminalRaw)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "transient observed status",
			body: statusJSON(testTaskDigest,
				`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_1","observed_status":"running"`),
		},
		{
			name: "evidence-bound terminal bytes",
			body: statusJSON(testTaskDigest, fmt.Sprintf(
				`"phase":"terminal","state":"agent_reported_completed","run_id":"run_1",`+
					`"task_status":"agent_reported_completed","result_digest":"sha256:%x","response_bytes":%d,`+
					`"observed_status":"completed","observation_base64":%q`,
				terminalSum[:], len(terminalRaw), base64.StdEncoding.EncodeToString(terminalRaw),
			)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := statusServer(t, http.StatusOK, nil, test.body)
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Status(context.Background(), testTaskDigest, testPermitDigest); err == nil {
				t.Fatal("durable Status accepted live observation fields")
			}
			if _, err := client.Observe(context.Background(), testTaskDigest, testPermitDigest); err != nil {
				t.Fatalf("Observe rejected its valid live response: %v", err)
			}
		})
	}
}

func TestClientRejectsPassiveShapesFromObserve(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "authorization only",
			body: statusJSON(testTaskDigest, `"phase":"authorize","state":"authorization_recorded"`),
		},
		{
			name: "dispatch without observation",
			body: statusJSON(testTaskDigest, `"phase":"dispatch","state":"dispatch_accepted","run_id":"run_1"`),
		},
		{
			name: "agent terminal without recovered result",
			body: statusJSON(testTaskDigest, `"phase":"terminal","state":"agent_reported_completed","run_id":"run_1",`+
				`"task_status":"agent_reported_completed","result_digest":"sha256:`+strings.Repeat("a", 64)+`","response_bytes":1`),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := statusServer(t, http.StatusOK, nil, test.body)
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Observe(context.Background(), testTaskDigest, testPermitDigest); err == nil {
				t.Fatal("Observe accepted a response that could not result from a live observation")
			}
		})
	}
}

func TestClientObserveAcceptsDurableObservationFailureWithoutRawResult(t *testing.T) {
	body := statusJSON(testTaskDigest,
		`"phase":"terminal","state":"observation_failed","run_id":"run_1","error_code":"outcome_unknown","retry_safety":"replacement_unsafe"`)
	server := statusServer(t, http.StatusOK, nil, body)
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Observe(context.Background(), testTaskDigest, testPermitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateObservationFailed || status.ObservationBase64 != "" {
		t.Fatalf("status=%#v", status)
	}
}

func TestClientRejectsExplicitEmptyOptionalFields(t *testing.T) {
	terminal := `"phase":"terminal","state":"agent_reported_completed","run_id":"run_1",` +
		`"task_status":"agent_reported_completed","result_digest":"sha256:` + strings.Repeat("c", 64) + `","response_bytes":1`
	tests := []struct {
		name    string
		fields  string
		observe bool
	}{
		{name: "run ID", fields: `"phase":"authorize","state":"authorization_recorded","run_id":""`},
		{name: "task status", fields: `"phase":"authorize","state":"authorization_recorded","task_status":""`},
		{name: "result digest", fields: `"phase":"authorize","state":"authorization_recorded","result_digest":""`},
		{name: "response bytes", fields: `"phase":"authorize","state":"authorization_recorded","response_bytes":0`},
		{name: "error code", fields: `"phase":"authorize","state":"authorization_recorded","error_code":""`},
		{name: "retry safety", fields: `"phase":"authorize","state":"authorization_recorded","retry_safety":""`},
		{name: "observed status", fields: terminal + `,"observed_status":""`, observe: true},
		{name: "raw observation", fields: terminal + `,"observation_base64":""`, observe: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := statusServer(t, http.StatusOK, nil, statusJSON(testTaskDigest, test.fields))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if test.observe {
				_, err = client.Observe(context.Background(), testTaskDigest, testPermitDigest)
			} else {
				_, err = client.Status(context.Background(), testTaskDigest, testPermitDigest)
			}
			if err == nil {
				t.Fatal("explicit empty optional field was accepted as though it were omitted")
			}
		})
	}
}

func TestClientValidatesRawTerminalObservationMetadata(t *testing.T) {
	raw := []byte(`{"run_id":"run_1","status":"failed"}`)
	sum := sha256.Sum256(raw)
	validFields := fmt.Sprintf(`"phase":"terminal","state":"agent_reported_failed","run_id":"run_1",`+
		`"task_status":"agent_reported_failed","result_digest":"sha256:%x","response_bytes":%d,`+
		`"observed_status":"failed","observation_base64":%q`, sum[:], len(raw), base64.StdEncoding.EncodeToString(raw))
	tests := []struct {
		name   string
		fields string
	}{
		{name: "length mismatch", fields: strings.Replace(validFields, fmt.Sprintf(`"response_bytes":%d`, len(raw)), `"response_bytes":1`, 1)},
		{name: "digest mismatch", fields: strings.Replace(validFields, fmt.Sprintf("sha256:%x", sum[:]), "sha256:"+strings.Repeat("b", 64), 1)},
		{name: "invalid base64", fields: strings.Replace(validFields, base64.StdEncoding.EncodeToString(raw), "!!!!", 1)},
		{name: "state mismatch", fields: strings.Replace(validFields, "agent_reported_failed", "agent_reported_completed", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := statusServer(t, http.StatusOK, nil, statusJSON(testTaskDigest, test.fields))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Observe(context.Background(), testTaskDigest, testPermitDigest); err == nil {
				t.Fatal("inconsistent observation was accepted")
			}
		})
	}
}

func TestClientDecodesStructuredGatewayErrors(t *testing.T) {
	headers := http.Header{"Retry-After": {"7"}}
	server := statusServer(t, http.StatusTooManyRequests, headers,
		`{"error":"task_observation_throttled","message":"task observation is limited by host policy"}`)
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Observe(context.Background(), testTaskDigest, testPermitDigest)
	var apiError *APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("error=%v, want APIError", err)
	}
	if apiError.Status != http.StatusTooManyRequests || apiError.Code != "task_observation_throttled" ||
		apiError.Message != "task observation is limited by host policy" || apiError.RetryAfter != 7*time.Second {
		t.Fatalf("APIError=%#v", apiError)
	}
}

func TestClientRejectsInvalidGatewayErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers http.Header
	}{
		{name: "malformed", body: `{"error":`},
		{name: "trailing", body: `{"error":"denied","message":"no"}{}`},
		{name: "unknown field", body: `{"error":"denied","message":"no","detail":"secret"}`},
		{name: "duplicate code", body: `{"error":"denied","error":"other","message":"no"}`},
		{name: "missing code", body: `{"error":"","message":"no"}`},
		{name: "control message", body: "{\"error\":\"denied\",\"message\":\"bad\\u001b[31m\"}"},
		{name: "invalid retry after", body: `{"error":"denied","message":"no"}`, headers: http.Header{"Retry-After": {"0"}}},
		{name: "multiple retry after", body: `{"error":"denied","message":"no"}`, headers: http.Header{"Retry-After": {"1", "2"}}},
		{name: "oversized", body: strings.Repeat("x", maxTaskStatusWireBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := statusServer(t, http.StatusBadRequest, test.headers, test.body)
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Status(context.Background(), testTaskDigest, testPermitDigest)
			var apiError *APIError
			if err == nil || errors.As(err, &apiError) {
				t.Fatalf("error=%v APIError=%#v, want invalid response error", err, apiError)
			}
		})
	}
}

func statusServer(t *testing.T, status int, headers http.Header, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for name, values := range headers {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

func statusJSON(digest, fields string) string {
	return `{"schema_version":"` + taskStatusSchemaV1 + `","task_digest":"` + digest + `","permit_digest":"` + testPermitDigest + `",` + fields + `}`
}

func TestTaskLifecycleStatusJSONShapeMatchesGateway(t *testing.T) {
	status := TaskLifecycleStatus{
		SchemaVersion: taskStatusSchemaV1, TaskDigest: testTaskDigest, PermitDigest: testPermitDigest, Phase: PhaseDispatch,
		State: StateDispatchAccepted, RunID: "run_1", ObservedStatus: ObservedRunning,
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"steward.task-status.v1","task_digest":"` + testTaskDigest + `","permit_digest":"` + testPermitDigest + `",` +
		`"phase":"dispatch","state":"dispatch_accepted","run_id":"run_1","observed_status":"running"}`
	if string(raw) != want {
		t.Fatalf("JSON=%s\nwant=%s", raw, want)
	}
}
