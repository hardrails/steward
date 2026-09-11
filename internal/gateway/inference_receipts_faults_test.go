package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
)

type closingInferenceReceiptLog struct{ connectorReceiptLog }

func TestInferenceExtensionStatusRetainsTerminalWithoutAutomaticRetry(t *testing.T) {
	for _, status := range []int{600, 700, 999} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte("provider-secret-response"))
			}))
			defer upstream.Close()
			rig := newInferenceReceiptRig(t, upstream)
			response := rig.call("/v1/chat/completions", `{"model":"default"}`)
			if response.Code != 422 || response.Header().Get("X-Should-Retry") != "false" ||
				!strings.Contains(response.Body.String(), "inference_attempt_unknown") ||
				strings.Contains(response.Body.String(), "provider-secret-response") || calls.Load() != 1 {
				t.Fatalf("response=%d %s calls=%d", response.Code, response.Body.String(), calls.Load())
			}
			records := rig.records(t)
			if len(records) != 2 || len(rig.ledger.Pending()) != 0 || rig.ledger.Failed() {
				t.Fatal("extension status orphaned a healthy ledger authorization")
			}
			terminal := records[1].Receipt.Event
			if terminal.Phase != connectorledger.Terminal || terminal.Outcome != connectorledger.Failed ||
				terminal.HTTPStatus != 0 || terminal.ErrorCode != fmt.Sprintf("upstream_http_status_%d", status) {
				t.Fatalf("provider response boundary lost: %#v", terminal)
			}
		})
	}
}

func (log closingInferenceReceiptLog) Finish(event connectorledger.Event) (connectorledger.Head, error) {
	_ = log.connectorReceiptLog.Close()
	return log.connectorReceiptLog.Finish(event)
}

func TestInferenceTerminalWriteFailureRetainsAttemptAndRefusesAnotherCall(t *testing.T) {
	for _, status := range []int{0, 200, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			testInferenceTerminalWriteFailure(t, status)
		})
	}
}

func testInferenceTerminalWriteFailure(t *testing.T, status int) {
	t.Helper()
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if status == 0 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("provider-output-must-not-look-confirmed"))
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.server.connectorLedger = closingInferenceReceiptLog{rig.ledger}
	for attempt := range 2 {
		response := rig.call("/v1/chat/completions", `{"model":"default"}`)
		code, boundary := 503, "inference_accounting_unavailable"
		if attempt == 0 {
			code, boundary = 422, "inference_terminal_accounting_failed"
			observed := fmt.Sprintf("provider HTTP status %d was observed", status)
			if status == 0 {
				observed = "no provider response headers were observed"
			}
			records := rig.records(t)
			if len(records) != 1 || !strings.Contains(response.Body.String(), observed) ||
				!strings.Contains(response.Body.String(), records[0].Receipt.Event.TaskDigest) ||
				!strings.Contains(response.Body.String(), "do not retry automatically") {
				t.Fatalf("lost original provider boundary: %d %s", response.Code, response.Body.String())
			}
		}
		if response.Code != code || !strings.Contains(response.Body.String(), boundary) ||
			response.Header().Get("X-Should-Retry") != "false" ||
			strings.Contains(response.Body.String(), "provider-output") {
			t.Fatalf("response=%d %s", response.Code, response.Body.String())
		}
	}
	records := rig.records(t)
	if calls.Load() != 1 || len(records) != 1 || records[0].Receipt.Event.Phase != connectorledger.Authorize {
		t.Fatal("lost terminal write hid or duplicated the potentially paid attempt")
	}
}

func TestInferenceAccountingNeverFollowsProviderRedirects(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/unexpected-second-request", http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	response := rig.call("/v1/chat/completions", `{"model":"default"}`)
	if response.Code != 502 || calls.Load() != 1 || !strings.Contains(response.Body.String(), "redirect_denied") {
		t.Fatalf("status=%d calls=%d", response.Code, calls.Load())
	}
	records := rig.records(t)
	if len(records) != 2 || records[1].Receipt.Event.HTTPStatus != 307 {
		t.Fatal("redirect attempt not retained")
	}
}

func TestInferenceConcurrentCallsHaveOneSignedAttemptPerRequest(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if response := rig.call("/v1/responses", `{"model":"default"}`); response.Code != 200 {
				t.Errorf("status=%d", response.Code)
			}
		}()
	}
	group.Wait()
	records := rig.records(t)
	if calls.Load() != 16 || len(records) != 32 {
		t.Fatalf("calls=%d records=%d", calls.Load(), len(records))
	}
	authorizations := make(map[string]bool)
	for _, record := range records {
		event := record.Receipt.Event
		if event.Phase == connectorledger.Authorize {
			if authorizations[event.TaskDigest] {
				t.Fatal("concurrent attempts shared an identity")
			}
			authorizations[event.TaskDigest] = true
		}
	}
	if len(authorizations) != 16 || len(rig.ledger.Pending()) != 0 {
		t.Fatal("attempt count or lifecycle differs")
	}
}

func TestInferenceAccountingCoversEverySupportedOutboundOperation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	for _, protocol := range []InferenceProtocol{InferenceProtocolOpenAI, InferenceProtocolAnthropic} {
		t.Run(string(protocol), func(t *testing.T) {
			rig := newInferenceReceiptRig(t, upstream)
			rig.route.Protocol = protocol
			paths := openAIInferencePaths
			if protocol == InferenceProtocolAnthropic {
				paths = anthropicInferencePaths
			}
			count := 0
			for path, method := range paths {
				if method != http.MethodPost {
					continue
				}
				response := rig.call(path, `{"model":"default"}`)
				if response.Code != 200 {
					t.Fatalf("path=%s status=%d", path, response.Code)
				}
				count++
			}
			if len(rig.records(t)) != 2*count || count == 0 {
				t.Fatal("supported inference operation bypassed accounting")
			}
		})
	}
}
