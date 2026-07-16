package executoruplink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

type v3RoundTripper func(*http.Request) (*http.Response, error)

func (transport v3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestV3ExplicitReportFailureRetriesBeforePollingAndAppliedFalseSettles(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	var polls atomic.Int32
	var localCalls atomic.Int32
	var reports []controlprotocol.ExecutorReportV3
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			assertPollV3(t, r)
			deliveries := make([]json.RawMessage, 0, 1)
			if polls.Add(1) == 1 {
				deliveries = append(deliveries, mustJSON(t, fixture.deliveries[0]))
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Deliveries:      deliveries,
			})
		case "/executor-uplink/report":
			var report controlprotocol.ExecutorReportV3
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports = append(reports, report)
			if len(reports) == 1 {
				http.Error(w, "lost acknowledgement", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: false,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	poller := fixture.poller(t, server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	if err := poller.pollOnce(context.Background()); err == nil {
		t.Fatal("lost first report acknowledgement returned nil")
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if localCalls.Load() != 1 {
		t.Fatalf("local calls=%d, command reexecuted after reclaim", localCalls.Load())
	}
	if polls.Load() != 2 {
		t.Fatalf("polls=%d, retry did not complete before the second poll", polls.Load())
	}
	if len(reports) != 2 || reports[0].DeliveryGeneration != 1 || reports[1].DeliveryGeneration != 1 ||
		reports[0].Status != controlprotocol.ExecutorStatusDone || reports[1].Status != reports[0].Status {
		t.Fatalf("reports=%#v", reports)
	}
	record := fixture.deliveryStore.records[fixture.deliveries[0].DeliveryID]
	if record.SettledGeneration != 1 || record.Phase != deliveryPhaseTerminal {
		t.Fatalf("retained record=%#v", record)
	}
}

func TestV3RetriesTerminalWhenControllerStoresReportButResponseIsLost(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	var polls atomic.Int32
	var reportCalls atomic.Int32
	var localCalls atomic.Int32
	var controllerTerminal atomic.Bool
	reports := make(chan controlprotocol.ExecutorReportV3, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			polls.Add(1)
			assertPollV3(t, r)
			deliveries := make([]json.RawMessage, 0, 1)
			if !controllerTerminal.Load() {
				deliveries = append(deliveries, mustJSON(t, fixture.deliveries[0]))
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Deliveries:      deliveries,
			})
		case "/executor-uplink/report":
			var report controlprotocol.ExecutorReportV3
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
				return
			}
			reports <- report
			call := reportCalls.Add(1)
			controllerTerminal.Store(true)
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Applied:         call == 1,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	baseTransport := server.Client().Transport
	var responseDropped atomic.Bool
	client := &http.Client{Transport: v3RoundTripper(func(request *http.Request) (*http.Response, error) {
		response, err := baseTransport.RoundTrip(request)
		if err != nil || request.URL.Path != "/executor-uplink/report" || !responseDropped.CompareAndSwap(false, true) {
			return response, err
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, io.ErrUnexpectedEOF
	})}
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	})
	config := fixture.config(server, local)
	config.HTTPClient = client
	poller, err := NewPoller(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err == nil {
		t.Fatal("lost terminal response returned nil")
	}
	if !controllerTerminal.Load() {
		t.Fatal("test controller did not store the terminal report")
	}
	if record := fixture.deliveryStore.records[fixture.deliveries[0].DeliveryID]; record.SettledGeneration != 0 {
		t.Fatalf("report was settled without an acknowledgement: %#v", record)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if polls.Load() != 2 || reportCalls.Load() != 2 || localCalls.Load() != 1 {
		t.Fatalf("polls=%d reports=%d local calls=%d", polls.Load(), reportCalls.Load(), localCalls.Load())
	}
	if len(reports) != 2 {
		t.Fatalf("received reports=%d, want 2", len(reports))
	}
	first, second := <-reports, <-reports
	if first != second || first.Status != controlprotocol.ExecutorStatusDone {
		t.Fatalf("retried report changed: first=%#v second=%#v", first, second)
	}
	record := fixture.deliveryStore.records[fixture.deliveries[0].DeliveryID]
	if record.SettledGeneration != 1 || record.Phase != deliveryPhaseTerminal {
		t.Fatalf("retained record=%#v", record)
	}
}

func TestV3InvalidSignedDeliveryIsRejectedWithoutBlockingValidSibling(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	invalidRaw := []byte(`{}`)
	invalid := controlprotocol.ExecutorDeliveryV3{
		DeliveryID: "invalid-delivery", DeliveryGeneration: 1, CommandID: "invalid-command",
		CommandDigest: dsse.Digest(invalidRaw), CommandDSSEBase64: base64.StdEncoding.EncodeToString(invalidRaw),
	}
	var localCalls atomic.Int32
	var reports []controlprotocol.ExecutorReportV3
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Deliveries: []json.RawMessage{
					mustJSON(t, invalid), mustJSON(t, fixture.deliveries[0]),
				},
			})
		case "/executor-uplink/report":
			var report controlprotocol.ExecutorReportV3
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports = append(reports, report)
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: true,
			})
		}
	}))
	defer server.Close()
	poller := fixture.poller(t, server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if localCalls.Load() != 1 || len(reports) != 2 {
		t.Fatalf("local calls=%d reports=%#v", localCalls.Load(), reports)
	}
	if reports[0].Status != controlprotocol.ExecutorStatusRejected || reports[0].ErrorCode != "invalid_signed_command" ||
		reports[1].Status != controlprotocol.ExecutorStatusDone {
		t.Fatalf("reports=%#v", reports)
	}
}

func TestV3RejectsControllerDeliveryAliasesBeforeHandlerEntry(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	canonical := fixture.deliveries[0]
	alias := canonical
	alias.DeliveryID = canonical.DeliveryID + "-alias"
	var polls atomic.Int32
	var localCalls atomic.Int32
	var reports []controlprotocol.ExecutorReportV3
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			delivery := canonical
			if polls.Add(1) > 1 {
				delivery = alias
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Deliveries:      []json.RawMessage{mustJSON(t, delivery)},
			})
		case "/executor-uplink/report":
			var report controlprotocol.ExecutorReportV3
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			reports = append(reports, report)
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: true,
			})
		}
	}))
	defer server.Close()
	poller := fixture.poller(t, server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if localCalls.Load() != 1 {
		t.Fatalf("aliased signed command entered the handler; calls=%d", localCalls.Load())
	}
	if len(reports) != 2 || reports[0].Status != controlprotocol.ExecutorStatusDone ||
		reports[1].Status != controlprotocol.ExecutorStatusRejected ||
		reports[1].ErrorCode != "delivery_identity_mismatch" || reports[1].DeliveryID != alias.DeliveryID {
		t.Fatalf("alias reports=%#v", reports)
	}
}

func TestV3MalformedWrapperDoesNotBlockValidSibling(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	var localCalls atomic.Int32
	var reportCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3,
				Deliveries: []json.RawMessage{
					json.RawMessage(`{"delivery_id":"unroutable","unexpected":true}`),
					mustJSON(t, fixture.deliveries[0]),
				},
			})
		case "/executor-uplink/report":
			reportCalls.Add(1)
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: true,
			})
		}
	}))
	defer server.Close()
	poller := fixture.poller(t, server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	if err := poller.pollOnce(context.Background()); err == nil {
		t.Fatal("malformed wrapper did not produce an aggregate poll error")
	}
	if localCalls.Load() != 1 || reportCalls.Load() != 1 {
		t.Fatalf("local calls=%d report calls=%d", localCalls.Load(), reportCalls.Load())
	}
}

func TestV3ReportFailureDoesNotBlockLaterSibling(t *testing.T) {
	fixture := newV3Fixture(t, 2)
	var localCalls atomic.Int32
	var reportCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			deliveries := make([]json.RawMessage, len(fixture.deliveries))
			for i, delivery := range fixture.deliveries {
				deliveries[i] = mustJSON(t, delivery)
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Deliveries: deliveries,
			})
		case "/executor-uplink/report":
			if reportCalls.Add(1) == 1 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV3{
				ProtocolVersion: controlprotocol.ExecutorProtocolV3, Applied: true,
			})
		}
	}))
	defer server.Close()
	poller := fixture.poller(t, server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		localCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "running"})
	}))
	if err := poller.pollOnce(context.Background()); err == nil {
		t.Fatal("aggregate report failure returned nil")
	}
	if localCalls.Load() != 2 || reportCalls.Load() != 2 {
		t.Fatalf("local calls=%d report calls=%d", localCalls.Load(), reportCalls.Load())
	}
}

func TestV3ProtocolSelectionIsExplicitAndBackwardCompatible(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	base := fixture.config(server, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base.DeliveryState = nil
	base.ProtocolVersion = 0
	if poller, err := NewPoller(base); err != nil || poller.protocolVersion != 2 {
		t.Fatalf("legacy selection poller=%#v err=%v", poller, err)
	}
	base.ProtocolVersion = controlprotocol.ExecutorProtocolV3
	if poller, err := NewPoller(base); err == nil || poller != nil {
		t.Fatal("protocol 3 started without durable delivery state")
	}
	base.ProtocolVersion = 0
	base.DeliveryState = fixture.deliveryStore
	if poller, err := NewPoller(base); err != nil || poller.protocolVersion != controlprotocol.ExecutorProtocolV3 {
		t.Fatalf("v3 selection poller=%#v err=%v", poller, err)
	}
}

type v3Fixture struct {
	now            time.Time
	credentialPath string
	policy         admission.SitePolicy
	state          *StateStore
	deliveryStore  *DeliveryStore
	deliveries     []controlprotocol.ExecutorDeliveryV3
}

func newV3Fixture(t *testing.T, count int) *v3Fixture {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := newStateStore(t, filepath.Join(dir, "state.json"))
	if err := state.advance("tenant-a", "agent-1", position{
		ClaimGeneration: 1, Generation: 1, Sequence: 1, ReportedStatus: "running",
	}); err != nil {
		t.Fatal(err)
	}
	deliveryStore := newDeliveryStore(t, filepath.Join(dir, "deliveries.json"))
	deliveries := make([]controlprotocol.ExecutorDeliveryV3, count)
	for index := range deliveries {
		statement := admission.CommandStatement{
			SchemaVersion: admission.CommandSchemaV2,
			CommandID:     "read-command-" + string(rune('a'+index)), TenantID: "tenant-a",
			NodeID: "node-1", InstanceID: "agent-1",
			RuntimeRef: "uplink:v2:8:tenant-a:6:node-1:agent-1", Kind: "read",
			ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: uint64(index + 2),
			IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
			ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
		}
		signed := signCommand(t, statement, "tenant-command", private)
		deliveryID, err := controlprotocol.ExecutorDeliveryID(statement.TenantID, statement.NodeID, statement.CommandID)
		if err != nil {
			t.Fatal(err)
		}
		deliveries[index] = controlprotocol.ExecutorDeliveryV3{
			DeliveryID: deliveryID, DeliveryGeneration: 1,
			CommandID: statement.CommandID, CommandDigest: dsse.Digest(signed),
			CommandDSSEBase64: base64.StdEncoding.EncodeToString(signed),
		}
	}
	return &v3Fixture{
		now: now, credentialPath: credentialPath, policy: policy, state: state,
		deliveryStore: deliveryStore, deliveries: deliveries,
	}
}

func (f *v3Fixture) config(server *httptest.Server, local http.Handler) Config {
	return Config{
		BaseURL: server.URL, CredentialPath: f.credentialPath, PollInterval: time.Second,
		HTTPClient: server.Client(), Handler: local, LocalToken: "local", State: f.state,
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true,
		CommandPolicy: &f.policy, Now: func() time.Time { return f.now },
		ProtocolVersion: controlprotocol.ExecutorProtocolV3, DeliveryState: f.deliveryStore,
	}
}

func (f *v3Fixture) poller(t *testing.T, server *httptest.Server, local http.Handler) *Poller {
	t.Helper()
	poller, err := NewPoller(f.config(server, local))
	if err != nil {
		t.Fatal(err)
	}
	return poller
}

func assertPollV3(t *testing.T, request *http.Request) {
	t.Helper()
	var poll controlprotocol.ExecutorPollRequestV3
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := dsse.DecodeStrictInto(raw, maxWireBytes, &poll); err != nil ||
		poll.ProtocolVersion != controlprotocol.ExecutorProtocolV3 || poll.NodeID != "node-1" {
		t.Fatalf("poll=%#v raw=%s err=%v", poll, raw, err)
	}
}
