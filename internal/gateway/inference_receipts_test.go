package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardrails/steward/internal/connectorledger"
)

type inferenceReceiptRig struct {
	server  *Server
	config  Config
	grant   Grant
	route   loadedRoute
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	ledger  *connectorledger.Log
}

func newInferenceReceiptRig(t *testing.T, upstream *httptest.Server) *inferenceReceiptRig {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		ConnectorReceiptFile:   filepath.Join(t.TempDir(), "receipts.ndjson"),
		ConnectorReceiptNodeID: "node/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []ConnectorReceiptTenantBudget{{TenantID: "tenant", Bytes: 4 << 20}},
		connectorReceiptKey:           private,
	}
	ledger, _, err := openConnectorReceiptLedger(config, private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{
		TenantID: "tenant", InstanceID: "agent", Generation: 1, GrantID: GrantID("tenant", "agent", 1),
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), RouteID: "provider", ModelAlias: "default",
	}
	route := loadedRoute{Route: Route{ID: "provider", MaxConcurrent: 2, RequireAttemptReceipts: true}, base: base, credential: "private-inference-key"}
	config.Routes = []Route{route.Route}
	server := &Server{config: config, client: upstream.Client(), connectorLedger: ledger,
		routes:        map[string]loadedRoute{route.ID: route},
		policyDigests: map[string]string{grant.GrantID: "sha256:" + strings.Repeat("d", 64)},
	}
	return &inferenceReceiptRig{server, config, grant, route, public, private, ledger}
}

func (rig *inferenceReceiptRig) call(path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "http://gateway"+path, strings.NewReader(body))
	request.Header.Set("Idempotency-Key", "untrusted-retry-header")
	request.Header.Set("X-Task-Id", "untrusted-task-identity")
	recorder := httptest.NewRecorder()
	rig.server.proxyInference(recorder, request, rig.grant, rig.route)
	return recorder
}

func (rig *inferenceReceiptRig) records(t *testing.T) []connectorledger.VerifiedReceipt {
	t.Helper()
	var records []connectorledger.VerifiedReceipt
	_, err := connectorledger.VerifyRecords(rig.config.ConnectorReceiptFile, rig.public, rig.config.ConnectorReceiptNodeID, 1,
		func(record connectorledger.VerifiedReceipt) error { records = append(records, record); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestInferenceReceiptsCountProviderAttemptsNotTaskDispatches(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer private-inference-key" {
			t.Error("credential mapping failed")
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	for range 2 {
		response := rig.call("/v1/chat/completions", `{"model":"default","input":"private-prompt"}`)
		if response.Code != 429 {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("actual calls=%d", calls.Load())
	}
	records := rig.records(t)
	if len(records) != 4 || records[0].Receipt.Event.TaskDigest == records[2].Receipt.Event.TaskDigest {
		t.Fatal("two requests sharing an untrusted task hint must have two distinct attempts")
	}
	for _, record := range records {
		event := record.Receipt.Event
		statement, err := json.Marshal(record.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind != connectorledger.InferenceAttempt || event.RuntimeRef != rig.grant.RuntimeRef ||
			event.GrantID != rig.grant.GrantID || event.TenantID != rig.grant.TenantID ||
			event.RoutePolicyDigest != rig.server.policyDigests[rig.grant.GrantID] {
			t.Fatal("attempt did not retain exact grant ownership")
		}
		if event.Phase == connectorledger.Terminal && event.HTTPStatus != 429 {
			t.Fatal("provider rejection disappeared")
		}
		for _, secret := range []string{"private-prompt", "private-inference-key", "untrusted-task-identity", "untrusted-retry-header"} {
			// Inspect the decoded statement, not just its base64 envelope.
			if strings.Contains(string(statement), secret) {
				t.Fatal("secret entered receipt")
			}
		}
	}
	if response := rig.call("/v1/chat/completions", `{"model":"wrong"}`); response.Code != 403 {
		t.Fatal(response.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "http://gateway/v1/models", nil)
	rig.server.proxyInference(httptest.NewRecorder(), request, rig.grant, rig.route)
	if len(rig.records(t)) != 4 || calls.Load() != 2 {
		t.Fatal("model discovery or a denied request became a paid attempt")
	}
}

func TestInferenceAccountingFailsBeforeProviderWhenLedgerUnavailable(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	for _, mode := range []string{"missing", "quota", "closed", "identity"} {
		t.Run(mode, func(t *testing.T) {
			rig := newInferenceReceiptRig(t, upstream)
			switch mode {
			case "missing":
				rig.server.connectorLedger = nil
			case "quota":
				rig.server.connectorLedger = refusingConnectorReceiptLog{err: connectorledger.ErrTenantQuotaExceeded}
			case "closed":
				_ = rig.ledger.Close()
			case "identity":
				rig.grant.RuntimeRef = ""
			}
			for range 2 {
				response := rig.call("/v1/chat/completions", `{"model":"default"}`)
				if response.Code != 503 || !strings.Contains(response.Body.String(), "inference_accounting_unavailable") {
					t.Fatal(response.Body.String())
				}
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("provider was reached without durable accounting")
	}
}

func TestInferenceAttemptSurvivesLostProviderResponseWithoutHiddenRetry(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	response := rig.call("/v1/responses", `{"model":"default","input":"hello"}`)
	if response.Code != 502 || calls.Load() != 1 {
		t.Fatalf("status=%d attempts=%d", response.Code, calls.Load())
	}
	records := rig.records(t)
	if len(records) != 2 || records[1].Receipt.Event.ErrorCode != "outcome_unknown" {
		t.Fatal("lost response was not accounted conservatively")
	}
}

func TestInferencePendingAttemptRecoveryDoesNotConsumeConnectorOrTaskAuthority(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	rig.call("/v1/embeddings", `{"model":"default"}`)
	event := rig.records(t)[0].Receipt.Event
	event.TaskDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := rig.ledger.Begin(event); err != nil {
		t.Fatal(err)
	}
	if err := rig.ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, index, err := openConnectorReceiptLedger(rig.config, rig.private)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(index.spends) != 0 || len(index.tasks) != 0 || len(index.counts) != 0 || len(reopened.Pending()) != 0 {
		t.Fatal("inference polluted connector/task replay authority")
	}
	records := rig.records(t)
	if len(records) != 4 || records[3].Receipt.Event.ErrorCode != "outcome_unknown" {
		t.Fatal("incomplete attempt was discarded")
	}
	summary, err := InspectConnectorReceiptFormat(rig.config)
	if err != nil || summary.FormatVersion != 9 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestInferenceRequiredAccountingBindsPolicyAndConfiguration(t *testing.T) {
	config := Config{Routes: []Route{{RequireAttemptReceipts: true}}}
	if _, err := config.validateAndLoadConnectorReceiptKey(); err == nil {
		t.Fatal("accounting without a ledger accepted")
	}
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	rig := newInferenceReceiptRig(t, upstream)
	if !rig.server.validGrant(rig.grant) {
		t.Fatal("complete grant rejected")
	}
	grant := rig.grant
	grant.RuntimeRef, grant.CapsuleDigest, grant.PolicyDigest = "", "", ""
	if rig.server.validGrant(grant) {
		t.Fatal("unattributed inference grant accepted")
	}
	before := routePolicyDigest(rig.grant, rig.server.routes, nil, nil, nil, 4<<20)
	if before == routePolicyDigest(rig.grant, rig.server.routes, nil, nil, nil, 8<<20) {
		t.Fatal("receipt quota not bound to policy")
	}
	route := rig.route
	route.RequireAttemptReceipts = false
	rig.server.routes[route.ID] = route
	if before == routePolicyDigest(rig.grant, rig.server.routes, nil, nil, nil, 4<<20) {
		t.Fatal("accounting removal did not change route authority")
	}
}
