package gatewayclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardrails/steward/internal/taskpermit"
)

const testServicePath = "/v1/services/grant-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"

func TestSubmitSendsOneExactRequestAndAcceptsRecordedOrReplayedReceipt(t *testing.T) {
	for _, receipt := range []TaskReceipt{TaskReceiptRecorded, TaskReceiptReplayed} {
		t.Run(string(receipt), func(t *testing.T) {
			body := []byte(`{"input":"perform bounded work"}`)
			permit := []byte(`{"signed":"permit"}`)
			permitHeader, err := taskpermit.EncodeHeader(permit)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				raw, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					t.Errorf("read body: %v", readErr)
				}
				wantPath := strings.TrimSuffix(testServicePath, "/") + "/v1/runs"
				if request.Method != http.MethodPost || request.RequestURI != wantPath || request.URL.RawQuery != "" ||
					request.ContentLength != int64(len(body)) || len(request.TransferEncoding) != 0 || !bytes.Equal(raw, body) {
					t.Errorf("request method=%q URI=%q length=%d transfer=%v body=%q",
						request.Method, request.RequestURI, request.ContentLength, request.TransferEncoding, raw)
				}
				if request.Header.Get("Authorization") != "Bearer gateway-secret" || request.Header.Get("Accept") != "application/json" ||
					request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Content-Type") != "application/json" ||
					request.Header.Get("X-Steward-Task-Permit") != permitHeader || request.UserAgent() != "steward" ||
					request.Header.Get("Cookie") != "" || request.Header.Get("X-Extra") != "" {
					t.Errorf("request headers=%v", request.Header)
				}
				writeTaskSubmitSuccess(w, http.StatusAccepted, "run_0123456789abcdef", receipt)
			}))
			defer server.Close()
			client, err := New(server.URL, "gateway-secret")
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Submit(context.Background(), TaskSubmission{
				ServicePath: testServicePath, OperationPath: "/v1/runs", ContentType: "application/json",
				Request: body, Permit: permit,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.RunID != "run_0123456789abcdef" || result.Receipt != receipt {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}

func TestSubmitRejectsInvalidInputsBeforeNetwork(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	valid := TaskSubmission{
		ServicePath: testServicePath, OperationPath: "/v1/runs", ContentType: "application/json",
		Request: []byte(`{"input":"work"}`), Permit: []byte("permit"),
	}
	tests := []struct {
		name   string
		change func(*TaskSubmission)
	}{
		{name: "empty service path", change: func(value *TaskSubmission) { value.ServicePath = "" }},
		{name: "wrong grant", change: func(value *TaskSubmission) { value.ServicePath = "/v1/services/grant-short/" }},
		{name: "query", change: func(value *TaskSubmission) { value.OperationPath = "/v1/runs?admin=true" }},
		{name: "traversal", change: func(value *TaskSubmission) { value.OperationPath = "/v1/../admin" }},
		{name: "encoded path", change: func(value *TaskSubmission) { value.OperationPath = "/v1/%2e%2e/admin" }},
		{name: "wrong content type", change: func(value *TaskSubmission) { value.ContentType = "application/json; charset=utf-8" }},
		{name: "empty request", change: func(value *TaskSubmission) { value.Request = nil }},
		{name: "ambiguous request", change: func(value *TaskSubmission) { value.Request = []byte(`{"input":1,"input":2}`) }},
		{name: "oversized request", change: func(value *TaskSubmission) {
			value.Request = bytes.Repeat([]byte("x"), int(taskpermit.MaxRequestBytes)+1)
		}},
		{name: "empty permit", change: func(value *TaskSubmission) { value.Permit = nil }},
		{name: "oversized permit", change: func(value *TaskSubmission) { value.Permit = bytes.Repeat([]byte("p"), taskpermit.MaxEnvelopeBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submission := valid
			test.change(&submission)
			if _, err := client.Submit(context.Background(), submission); err == nil {
				t.Fatal("invalid submission was accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid submissions made %d network calls", calls.Load())
	}
}

func TestSubmitRefusesRedirectBeforeCredentialCanBeForwarded(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := New(redirect.URL, "redirect-secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Submit(context.Background(), validTaskSubmission())
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect error=%v, want ErrRedirect", err)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target received %d calls", targetCalls.Load())
	}
}

func TestSubmitRejectsBadSuccessHeaders(t *testing.T) {
	tests := []struct {
		name   string
		change func(http.Header)
	}{
		{name: "missing active grant", change: func(header http.Header) { header.Del("X-Steward-Service-Grant") }},
		{name: "wrong active grant", change: func(header http.Header) { header.Set("X-Steward-Service-Grant", "stale") }},
		{name: "duplicate active grant", change: func(header http.Header) { header.Add("X-Steward-Service-Grant", "active") }},
		{name: "missing receipt", change: func(header http.Header) { header.Del("X-Steward-Task-Receipt") }},
		{name: "wrong receipt", change: func(header http.Header) { header.Set("X-Steward-Task-Receipt", "pending") }},
		{name: "duplicate receipt", change: func(header http.Header) { header.Add("X-Steward-Task-Receipt", "recorded") }},
		{name: "missing no-store", change: func(header http.Header) { header.Del("Cache-Control") }},
		{name: "missing nosniff", change: func(header http.Header) { header.Del("X-Content-Type-Options") }},
		{name: "content type parameters", change: func(header http.Header) { header.Set("Content-Type", "application/json; charset=utf-8") }},
		{name: "compressed", change: func(header http.Header) { header.Set("Content-Encoding", "gzip") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				setTaskSubmitHeaders(w.Header(), TaskReceiptRecorded)
				test.change(w.Header())
				body := []byte(`{"run_id":"run_1"}`)
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Submit(context.Background(), validTaskSubmission()); err == nil {
				t.Fatal("invalid success headers were accepted")
			}
		})
	}
}

func TestSubmitRejectsNoncanonicalRunIDResponsesAndUnboundedBodies(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed", body: []byte(`{"run_id":`)},
		{name: "missing run ID", body: []byte(`{}`)},
		{name: "unknown field", body: []byte(`{"run_id":"run_1","result":"secret"}`)},
		{name: "duplicate run ID", body: []byte(`{"run_id":"run_1","run_id":"run_2"}`)},
		{name: "invalid run ID", body: []byte(`{"run_id":"../admin"}`)},
		{name: "noncanonical whitespace", body: []byte(`{ "run_id": "run_1" }`)},
		{name: "trailing newline", body: []byte("{\"run_id\":\"run_1\"}\n")},
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxTaskSubmitResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				setTaskSubmitHeaders(w.Header(), TaskReceiptRecorded)
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(test.body)))
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Submit(context.Background(), validTaskSubmission()); err == nil {
				t.Fatal("invalid task submit body was accepted")
			}
		})
	}
}

func TestSubmitRejectsChunkedOrInconsistentResponseLength(t *testing.T) {
	for _, test := range []struct {
		name    string
		chunked bool
	}{
		{name: "chunked", chunked: true},
		{name: "short body"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				setTaskSubmitHeaders(w.Header(), TaskReceiptRecorded)
				body := []byte(`{"run_id":"run_1"}`)
				if test.chunked {
					w.WriteHeader(http.StatusAccepted)
					w.(http.Flusher).Flush()
					_, _ = w.Write(body)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)+10))
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, err := New(server.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Submit(context.Background(), validTaskSubmission()); err == nil {
				t.Fatal("unframed or inconsistent response was accepted")
			}
		})
	}
}

func TestSubmitReturnsStructuredGatewayError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := []byte(`{"error":"task_permit_denied","message":"permit expired"}`)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client, err := New(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Submit(context.Background(), validTaskSubmission())
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusForbidden || apiError.Code != "task_permit_denied" {
		t.Fatalf("error=%v APIError=%#v", err, apiError)
	}
}

func validTaskSubmission() TaskSubmission {
	return TaskSubmission{
		ServicePath: testServicePath, OperationPath: "/v1/runs", ContentType: "application/json",
		Request: []byte(`{"input":"work"}`), Permit: []byte("permit"),
	}
}

func setTaskSubmitHeaders(header http.Header, receipt TaskReceipt) {
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Steward-Service-Grant", "active")
	header.Set("X-Steward-Task-Receipt", string(receipt))
}

func writeTaskSubmitSuccess(writer http.ResponseWriter, status int, runID string, receipt TaskReceipt) {
	body := []byte(fmt.Sprintf(`{"run_id":%q}`, runID))
	setTaskSubmitHeaders(writer.Header(), receipt)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}
