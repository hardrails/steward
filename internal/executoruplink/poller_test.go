package executoruplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/interactionpermit"
	stewarduplink "github.com/hardrails/steward/internal/uplink"
)

func TestPollerSynchronizesAgentInteractionsInBothDirections(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath,
		[]byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	request := uplinkInteractionRequest()
	interaction := gateway.Interaction{
		SchemaVersion: request.SchemaVersion, InteractionID: request.InteractionID,
		IdempotencyKey: request.IdempotencyKey, Source: request.Source,
		TenantID: request.TenantID, NodeID: request.NodeID, InstanceID: request.InstanceID,
		Generation: request.Generation, RuntimeRef: request.RuntimeRef, GrantID: request.GrantID,
		CapsuleDigest: request.CapsuleDigest, PolicyDigest: request.PolicyDigest,
		Kind: request.Kind, Title: request.Title, Prompt: request.Prompt,
		Options: request.Options, AllowText: request.AllowText, TaskID: request.TaskID,
		RunID: request.RunID, ObservedAt: request.ObservedAt, AcceptedAt: request.AcceptedAt,
		ExpiresAt: request.ExpiresAt, RequestDigest: request.RequestDigest, State: "open",
	}
	responseBody := []byte(`{"schema_version":"steward.interaction-response-body.v1","choice":"primary"}`)
	permit := []byte("opaque-signed-permit")
	var gatewayRequestAck, gatewayResponse, controlRequest, controlResponseAck atomic.Int32
	socket := filepath.Join("/tmp", fmt.Sprintf("steward-interactions-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/interactions/outbox":
			values := []gateway.Interaction{interaction}
			if gatewayRequestAck.Load() > 0 {
				values = nil
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"interactions": values})
		case "/v1/interactions/ack":
			gatewayRequestAck.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/interactions/responses":
			gatewayResponse.Add(1)
			resolved := interaction
			resolved.State = "resolved"
			resolved.Response = &gateway.InteractionResponse{
				Body: gateway.InteractionResponseBody{
					SchemaVersion: "steward.interaction-response-body.v1", Choice: "primary",
				},
				KeyID: "tenant-task", PermitDigest: dsse.Digest(permit),
				ResponseDigest: interactionpermit.ResponseDigest(responseBody),
				ResolvedAt:     "2026-07-23T14:02:00Z",
			}
			_ = json.NewEncoder(writer).Encode(resolved)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = gatewayServer.Serve(listener) }()
	t.Cleanup(func() { _ = gatewayServer.Close() })
	gatewayControl, err := gateway.NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}

	controller := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer bearer" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/executor-uplink/interactions":
			var batch controlprotocol.InteractionRequestBatchV1
			if err := json.NewDecoder(request.Body).Decode(&batch); err != nil ||
				batch.Validate() != nil || len(batch.Interactions) != 1 {
				t.Errorf("invalid interaction batch: %+v err=%v", batch, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			controlRequest.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"applied": 1})
		case "/executor-uplink/interactions/responses/poll":
			_ = json.NewEncoder(writer).Encode(controlprotocol.InteractionResponsePollResponseV1{
				SchemaVersion: controlprotocol.InteractionPollSchemaV1,
				Deliveries: []controlprotocol.InteractionResponseDeliveryV1{{
					SchemaVersion:  controlprotocol.InteractionResponseSchemaV1,
					InteractionID:  interaction.InteractionID,
					PermitBase64:   base64.StdEncoding.EncodeToString(permit),
					ResponseBase64: base64.StdEncoding.EncodeToString(responseBody),
					PermitDigest:   dsse.Digest(permit),
				}},
			})
		case "/executor-uplink/interactions/responses/ack":
			var ack controlprotocol.InteractionResponseAckV1
			if err := json.NewDecoder(request.Body).Decode(&ack); err != nil ||
				ack.InteractionID != interaction.InteractionID || ack.PermitDigest != dsse.Digest(permit) {
				t.Errorf("invalid interaction ack: %+v err=%v", ack, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			controlResponseAck.Add(1)
			_ = json.NewEncoder(writer).Encode(map[string]any{"applied": true})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controller.Close()
	poller, err := NewPoller(Config{
		BaseURL: controller.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		HTTPClient: controller.Client(), Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "local", State: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true,
		CommandPolicy: &policy, ProtocolVersion: 2, GatewayControl: gatewayControl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.syncInteractions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gatewayRequestAck.Load() != 1 || gatewayResponse.Load() != 1 ||
		controlRequest.Load() != 1 || controlResponseAck.Load() != 1 {
		t.Fatalf("interaction sync counts gateway_ack=%d gateway_response=%d control_request=%d control_ack=%d",
			gatewayRequestAck.Load(), gatewayResponse.Load(), controlRequest.Load(), controlResponseAck.Load())
	}
}

func TestInteractionSynchronizationRejectsCredentialIdentityRotation(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(
		credentialPath,
		[]byte(`{"version":2,"scope":"node","node_id":"node-2","credential":"rotated"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	poller := &Poller{
		credentialPath: credentialPath,
		expected: &stewarduplink.Credential{
			Version: 2, Scope: "node", NodeID: "node-1", Credential: "original",
		},
		security: stewarduplink.CredentialSecurity{
			SecureExecutor: true, ProtectedTransport: true,
		},
	}
	err := poller.syncInteractions(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rotated uplink credential changed") {
		t.Fatalf("credential identity rotation error = %v", err)
	}
}

func TestInteractionSynchronizationLoopStopsAfterCredentialFailure(t *testing.T) {
	poller := &Poller{
		credentialPath: filepath.Join(t.TempDir(), "missing-credential.json"),
		expected: &stewarduplink.Credential{
			Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer",
		},
		interval: time.Millisecond,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		poller.runInteractions(ctx)
		close(done)
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("interaction synchronization loop did not stop after cancellation")
	}
}

func TestInteractionCourierRejectsInvalidWireResponses(t *testing.T) {
	if _, err := decodeCanonicalInteractionBase64("not-base64"); err == nil {
		t.Fatal("invalid interaction courier base64 was accepted")
	}
	if _, err := decodeCanonicalInteractionBase64("YQ"); err == nil {
		t.Fatal("non-canonical interaction courier base64 was accepted")
	}

	for _, test := range []struct {
		name    string
		handler http.Handler
		want    string
	}{
		{
			name: "upstream rejection",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusForbidden)
				_, _ = writer.Write([]byte(`{"error":"denied","message":"policy denied courier"}`))
			}),
			want: "interaction response poll returned HTTP 403",
		},
		{
			name: "oversized response",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(bytes.Repeat([]byte("x"), maxWireBytes+1))
			}),
			want: "response exceeds",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			poller := &Poller{client: server.Client()}
			_, err := poller.postInteractionJSONResponse(
				context.Background(),
				server.URL,
				"secret",
				map[string]string{"node_id": "node-1"},
				"interaction response poll",
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("courier wire error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestInteractionCourierFailsClosedOnCorruptGatewayOutbox(t *testing.T) {
	socket := filepath.Join("/tmp", fmt.Sprintf("steward-corrupt-interactions-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/interactions/outbox" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"interactions": []gateway.Interaction{{InteractionID: "corrupt"}},
		})
	})}
	go func() { _ = gatewayServer.Serve(listener) }()
	t.Cleanup(func() { _ = gatewayServer.Close() })
	gatewayControl, err := gateway.NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	poller := &Poller{eventGateway: gatewayControl}
	err = poller.publishInteractions(context.Background(), &stewarduplink.Credential{
		Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer",
	})
	if err == nil || !strings.Contains(err.Error(), "gateway interaction outbox is invalid") {
		t.Fatalf("corrupt Gateway outbox error = %v", err)
	}
}

func TestInteractionCourierFailsClosedOnInvalidControllerDeliveries(t *testing.T) {
	for _, test := range []struct {
		name string
		body any
		want string
	}{
		{
			name: "invalid poll projection",
			body: map[string]any{"deliveries": []any{}},
			want: "poll result is invalid",
		},
		{
			name: "invalid courier encoding",
			body: controlprotocol.InteractionResponsePollResponseV1{
				SchemaVersion: controlprotocol.InteractionPollSchemaV1,
				Deliveries: []controlprotocol.InteractionResponseDeliveryV1{{
					SchemaVersion:  controlprotocol.InteractionResponseSchemaV1,
					InteractionID:  "interaction-" + strings.Repeat("a", 64),
					PermitBase64:   "!!!!",
					ResponseBase64: base64.StdEncoding.EncodeToString([]byte("{}")),
					PermitDigest:   "sha256:" + strings.Repeat("b", 64),
				}},
			},
			want: "invalid interaction response delivery",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(test.body)
			}))
			defer server.Close()
			poller := &Poller{
				interactionPollURL: server.URL,
				client:             server.Client(),
			}
			err := poller.deliverInteractionResponses(
				context.Background(),
				&stewarduplink.Credential{
					Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer",
				},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid controller delivery error = %v, want %q", err, test.want)
			}
		})
	}
}

func uplinkInteractionRequest() controlprotocol.InteractionRequestV1 {
	now := time.Date(2026, 7, 23, 14, 0, 0, 0, time.UTC)
	grantID := "grant-" + strings.Repeat("b", 64)
	key := "question-1"
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + key))
	value := controlprotocol.InteractionRequestV1{
		SchemaVersion:  controlprotocol.InteractionRequestSchemaV1,
		InteractionID:  "interaction-" + hex.EncodeToString(sum[:]),
		IdempotencyKey: key, Source: "agent", TenantID: "tenant-a", NodeID: "node-1",
		InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("d", 64),
		Kind:          "decision", Title: "Choose source", Prompt: "Which source should be used?",
		Options: []string{"primary", "secondary"}, AllowText: true,
		ObservedAt: now.Format(time.RFC3339), AcceptedAt: now.Add(time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	value.RequestDigest = controlprotocol.InteractionRequestDigest(value)
	return value
}

func TestPollerPublishesControllerEventsAtLeastOnce(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	grantID := "grant-" + strings.Repeat("d", 64)
	idempotencyKey := "finding-1"
	digest := sha256.Sum256([]byte("steward-instance-event-v1\x00" + grantID + "\x00" + idempotencyKey))
	event := gateway.InstanceEvent{
		SchemaVersion: gateway.InstanceEventSchemaV1,
		EventID:       "event-" + hex.EncodeToString(digest[:]), IdempotencyKey: idempotencyKey,
		Source: "agent", TenantID: "tenant-a", NodeID: "node-1", InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
		Kind: "finding", Code: "source-confirmed", Severity: "info", Summary: "Primary source confirmed.",
		ObservedAt: "2026-07-21T01:00:00Z", AcceptedAt: "2026-07-21T01:00:01Z",
	}
	var acknowledgements atomic.Int32
	// Darwin limits Unix socket addresses to 104 bytes; Go's per-test temporary
	// directory is intentionally descriptive and can exceed that bound.
	socket := filepath.Join("/tmp", fmt.Sprintf("steward-events-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/events":
			events := []gateway.InstanceEvent{event}
			if acknowledgements.Load() > 0 {
				events = nil
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"events": events})
		case "/v1/events/ack":
			acknowledgements.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = gatewayServer.Serve(listener) }()
	t.Cleanup(func() { _ = gatewayServer.Close() })
	gatewayControl, err := gateway.NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	controller := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/executor-uplink/events" || request.Header.Get("Authorization") != "Bearer bearer" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		var batch controlprotocol.InstanceEventBatchRequestV1
		decodeErr := json.NewDecoder(request.Body).Decode(&batch)
		if decodeErr != nil || batch.Validate() != nil || len(batch.Events) != 1 {
			t.Errorf("invalid controller event batch: %+v err=%v", batch, decodeErr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if attempts.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":"unavailable","message":"retry"}`))
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"applied": 1})
	}))
	defer controller.Close()
	poller, err := NewPoller(Config{
		BaseURL: controller.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		HTTPClient: controller.Client(), Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "local", State: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true,
		CommandPolicy: &policy, ProtocolVersion: 2, GatewayControl: gatewayControl,
	})
	if err != nil {
		t.Fatal(err)
	}
	poller.interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		poller.runEvents(ctx)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for acknowledgements.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if attempts.Load() < 2 || acknowledgements.Load() != 1 {
		t.Fatalf("event retry attempts=%d acknowledgements=%d", attempts.Load(), acknowledgements.Load())
	}
}

func TestPollerExecutesAuthenticatedCommandAndReports(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"tenant-a","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reported := make(chan report, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/executor-uplink/poll":
			commandRaw, _ := json.Marshal(command{
				CommandID: "c1", TenantID: "tenant-a", NodeID: "node-1",
				RuntimeRef: "uplink:6:node-1:agent-1", Kind: "provision",
				Payload:         json.RawMessage(`{"profile_id":"p","image":"registry/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":{"memory_bytes":1,"cpu_millis":1,"pids":1},"egress":{}}`),
				ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
			})
			_ = json.NewEncoder(w).Encode(pollResponse{Commands: []json.RawMessage{commandRaw}})
		case "/executor-uplink/report":
			var rep report
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Fatal(err)
			}
			reported <- rep
			_ = json.NewEncoder(w).Encode(reportResponse{Applied: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"runtime_ref":"executor-x","status":"created"}`))
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: local, LocalToken: "local", State: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case rep := <-reported:
		if rep.Status != "done" || rep.ReportedStatus != "stopped" {
			t.Fatalf("report = %#v", rep)
		}
	default:
		t.Fatal("no report received")
	}
}

func TestNewPollerRefusesRemotePlainHTTPByDefault(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	_ = os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"c"}`), 0o600)
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	_, err := NewPoller(Config{
		BaseURL: "http://192.0.2.10", CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), LocalToken: "x", State: store,
	})
	if err == nil {
		t.Fatal("remote plaintext uplink was accepted without acknowledgement")
	}
}

func TestNewPollerRequiresBothNodeScopeSecurityGuards(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	base := Config{
		BaseURL: "https://control.example", CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), LocalToken: "local",
		State: store, CommandPolicy: &policy, SecureNodeID: "node-1",
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.ProtectedTransport = true },
		func(config *Config) { config.SecureExecutor = true },
		func(config *Config) {
			config.SecureExecutor, config.ProtectedTransport, config.BaseURL = true, true, "http://127.0.0.1"
		},
	} {
		candidate := base
		mutate(&candidate)
		if poller, err := NewPoller(candidate); err == nil || poller != nil {
			t.Fatalf("node-scoped poller accepted incomplete guard: %#v", candidate)
		}
	}
	base.SecureExecutor, base.ProtectedTransport = true, true
	if poller, err := NewPoller(base); err != nil || poller == nil {
		t.Fatalf("fully guarded node-scoped poller rejected: %v", err)
	}
	withoutCleanup := policy
	withoutCleanup.SiteCleanupCommandKeys = nil
	base.CommandPolicy = &withoutCleanup
	if poller, err := NewPoller(base); err == nil || poller != nil {
		t.Fatal("node-scoped poller accepted a policy without site cleanup authority")
	}
	lockdown := policy
	lockdown.Tenants = nil
	base.CommandPolicy = &lockdown
	if poller, err := NewPoller(base); err != nil || poller == nil {
		t.Fatalf("node-scoped poller rejected cleanup-only emergency policy: %v", err)
	}
}

func TestPollerPublishesSchedulingIndependentlyWithNodeCredential(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	received := make(chan controlprotocol.ExecutorSchedulingObservationV1, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/executor-uplink/scheduling" || request.Header.Get("Authorization") != "Bearer bearer" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		raw, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		var observation controlprotocol.ExecutorSchedulingObservationV1
		if decodeErr := dsse.DecodeStrictInto(raw, controlprotocol.MaxExecutorSchedulingBytes, &observation); decodeErr != nil {
			t.Error(decodeErr)
			return
		}
		received <- observation
		_ = json.NewEncoder(writer).Encode(map[string]any{"applied": true})
	}))
	defer server.Close()
	observation := controlprotocol.ExecutorSchedulingObservationV1{
		SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
		NodeID:        "node-1", CredentialScope: "node", OS: "linux", Architecture: "amd64",
		Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor,
		Labels:    []controlprotocol.ExecutorSchedulingLabelV1{}, Taints: []string{},
		Policy: controlprotocol.ExecutorSchedulingPolicyV1{
			PerWorkload:     controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128, Workloads: 1},
			Host:            controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 8 << 30, CPUMillis: 8000, PIDs: 2048, Workloads: 32},
			Tenant:          controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2 << 30, CPUMillis: 2000, PIDs: 512, Workloads: 4},
			RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32},
		},
	}
	providerObservation := observation
	var providerCalls atomic.Int32
	var providerFails atomic.Bool
	provider := func(context.Context) (*controlprotocol.ExecutorSchedulingObservationV1, error) {
		if providerFails.Load() {
			return nil, errors.New("Docker inventory unavailable")
		}
		refreshed := providerObservation
		refreshed.CachedImageConfigDigests = []string{fmt.Sprintf("sha256:%064x", providerCalls.Add(1))}
		return &refreshed, nil
	}
	cfg := Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		HTTPClient: server.Client(), Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "local", State: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true,
		CommandPolicy: &policy, ProtocolVersion: 2, Scheduling: &observation,
		SchedulingProvider: provider,
	}
	invalid := observation
	invalid.Architecture = "invalid architecture"
	invalidCfg := cfg
	invalidCfg.Scheduling = &invalid
	if _, err := NewPoller(invalidCfg); err == nil ||
		!strings.Contains(err.Error(), "observation identity is invalid") {
		t.Fatalf("invalid scheduling error = %v", err)
	}
	poller, err := NewPoller(cfg)
	if err != nil {
		t.Fatal(err)
	}
	observation.Architecture = "mutated-after-construction"
	if err := poller.publishScheduling(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case published := <-received:
		if published.NodeID != "node-1" || published.Architecture != "amd64" ||
			len(published.CachedImageConfigDigests) != 1 ||
			published.CachedImageConfigDigests[0] != fmt.Sprintf("sha256:%064x", 1) {
			t.Fatalf("published scheduling observation = %+v", published)
		}
	default:
		t.Fatal("scheduling observation was not published")
	}
	if err := poller.publishScheduling(context.Background()); err != nil {
		t.Fatal(err)
	}
	if published := <-received; published.CachedImageConfigDigests[0] != fmt.Sprintf("sha256:%064x", 2) {
		t.Fatalf("refreshed scheduling observation = %+v", published)
	}
	providerFails.Store(true)
	if err := poller.publishScheduling(context.Background()); err != nil {
		t.Fatal(err)
	}
	if published := <-received; published.CachedImageConfigDigests != nil ||
		published.NodeID != "node-1" || published.Architecture != "amd64" {
		t.Fatalf("failed refresh did not clear stale image locality = %+v", published)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		poller.runScheduling(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduling publisher did not stop after cancellation")
	}
}

func TestPollerRunBacksOffAfterFailureAndStopsWithContext(t *testing.T) {
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	_ = os.WriteFile(credentialPath, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"c"}`), 0o600)
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if polls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"temporarily unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"commands":[]}`))
	}))
	defer server.Close()
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Millisecond,
		Handler:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "x", State: store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { poller.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for polls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Poller.Run did not stop after context cancellation")
	}
	if polls.Load() < 2 {
		t.Fatalf("poll count=%d, want a failed poll and retry", polls.Load())
	}
}

func TestReadBoundedRejectsOversizedResponse(t *testing.T) {
	if _, err := readBounded(strings.NewReader(strings.Repeat("x", 9)), 8); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

func TestTenantScopedV1CommandDecoderDoesNotAcceptV2Fields(t *testing.T) {
	poller := &Poller{}
	credential := &stewarduplink.Credential{Version: 1, TenantID: "tenant-a", NodeID: "node-1", Credential: "bearer"}
	raw := []byte(`{"command_id":"c","tenant_id":"tenant-a","node_id":"node-1","instance_id":"injected","runtime_ref":"uplink:6:node-1:agent-1","kind":"start","payload":{},"claim_generation":1,"instance_generation":1,"command_sequence":1}`)
	if _, err := poller.decodeCommand(raw, credential); err == nil {
		t.Fatal("v1 command decoder accepted a v2-only identity field")
	}
}

func TestNodeScopedPollVerifiesTenantSignedCommandAndAdvertisesProtocol(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	commandPublic, commandPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, commandPublic, []string{"read"})
	runtimeRef, err := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: "signed-read-1",
		TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
		RuntimeRef: runtimeRef, Kind: "read", ClaimGeneration: 1,
		InstanceGeneration: 2, CommandSequence: 3,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
	}
	signed := signCommand(t, statement, "tenant-command", commandPrivate)
	reported := make(chan report, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/executor-uplink/poll":
			var request pollRequest
			raw, _ := io.ReadAll(r.Body)
			if err := dsse.DecodeStrictInto(raw, maxWireBytes, &request); err != nil ||
				request.ProtocolVersion != 2 || request.NodeID != "node-1" || request.CredentialScope != "node" ||
				!slices.Contains(request.Capabilities, controlprotocol.ExecutorCapabilityAuthorizedEffectsV1) ||
				!slices.Contains(request.Capabilities, controlprotocol.ExecutorCapabilityContextLockedEffectsV1) {
				t.Errorf("poll request=%#v raw=%s err=%v", request, raw, err)
			}
			_ = json.NewEncoder(w).Encode(pollResponse{ProtocolVersion: 2, Commands: []json.RawMessage{signed}})
		case "/executor-uplink/report":
			var rep report
			if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
				t.Error(err)
			}
			reported <- rep
			_ = json.NewEncoder(w).Encode(reportResponse{Applied: true})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var localPath string
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localPath = r.Method + " " + r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"runtime_ref": "executor-ref", "status": "running"})
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := store.advance("tenant-a", "agent-1", position{
		ClaimGeneration: 1, Generation: 2, Sequence: 2, ReportedStatus: "running",
	}); err != nil {
		t.Fatal(err)
	}
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		HTTPClient: server.Client(), Handler: local, LocalToken: "local", State: store,
		SecureExecutor: true, ProtectedTransport: true, CommandPolicy: &policy,
		SecureNodeID: "node-1",
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case rep := <-reported:
		if rep.Status != "done" || rep.ReportedStatus != "running" || rep.CommandID != "signed-read-1" {
			t.Fatalf("report = %#v", rep)
		}
	default:
		t.Fatal("no signed command report received")
	}
	if want := "GET /v1/workloads/" + executor.RuntimeRef("tenant-a", "agent-1"); localPath != want {
		t.Fatalf("local path = %q, want %q", localPath, want)
	}
	if got, ok := store.position("tenant-a", "agent-1"); !ok || got.ClaimGeneration != 1 || got.Generation != 2 || got.Sequence != 2 {
		t.Fatalf("durable position = %#v, %v", got, ok)
	}
}

func TestNodeScopedPollRejectsUnsignedWrongScopeAndExpiredCommands(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	runtimeRef, _ := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	base := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: "c", TenantID: "tenant-a",
		NodeID: "node-1", InstanceID: "agent-1", RuntimeRef: runtimeRef, Kind: "read",
		ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
	}
	poller := &Poller{commandPolicy: &policy, now: func() time.Time { return now }}
	nodeCredential := nodeCredentialForTest()
	if _, err := poller.decodeCommand(mustJSON(t, command{
		CommandID: "unsigned", TenantID: "tenant-a", NodeID: "node-1", RuntimeRef: runtimeRef,
		Kind: "read", ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
	}), nodeCredential); err == nil {
		t.Fatal("unsigned node-scoped command was accepted")
	}
	wrongScope := base
	wrongScope.Kind = "destroy"
	if _, err := poller.decodeCommand(signCommand(t, wrongScope, "tenant-command", private), nodeCredential); err == nil {
		t.Fatal("command key escaped its operation scope")
	}
	expired := base
	expired.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	if _, err := poller.decodeCommand(signCommand(t, expired, "tenant-command", private), nodeCredential); err == nil {
		t.Fatal("expired signed command was accepted")
	}
}

func TestNodeScopedDecoderAcceptsOnlyExecutorVerifiedControllerDelegation(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	tenantPublic, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, tenantPublic, []string{"read"})
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1, DelegationID: "deployment-1",
		TenantID: "tenant-a", ControllerKeyID: "controller-1",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"read"}, NodeIDs: []string{"node-1"},
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: "agent-1", LineageID: "lineage-1",
			MinInstanceGeneration: 1, MaxInstanceGeneration: 4,
		}},
		ClaimGeneration: 1,
		IssuedAt:        now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:       now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	delegationPayload, err := admission.MarshalCommandDelegation(delegation)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := dsse.Sign(
		admission.CommandDelegationPayloadType, delegationPayload, "tenant-command", tenantPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := dsse.Marshal(delegationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRef, _ := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: "delegated-read",
		AuthorizationContextDigest: dsse.Digest(delegationRaw),
		DelegationDSSEBase64:       base64.StdEncoding.EncodeToString(delegationRaw),
		TenantID:                   "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
		RuntimeRef: runtimeRef, Kind: "read", ClaimGeneration: 1,
		InstanceGeneration: 2, CommandSequence: 3,
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), Payload: json.RawMessage(`{}`),
	}
	poller := &Poller{commandPolicy: &policy, now: func() time.Time { return now }}
	decoded, err := poller.decodeCommand(
		signCommand(t, statement, "controller-1", controllerPrivate), nodeCredentialForTest(),
	)
	if err != nil || decoded.CommandID != statement.CommandID || !decoded.signed {
		t.Fatalf("delegated command = (%+v, %v)", decoded, err)
	}
	statement.NodeID = "node-2"
	if _, err := poller.decodeCommand(
		signCommand(t, statement, "controller-1", controllerPrivate), nodeCredentialForTest(),
	); err == nil {
		t.Fatal("controller command outside delegated node scope was accepted")
	}
}

func TestExecutorPlacementRevalidationFailsClosed(t *testing.T) {
	assurance := controlprotocol.RuntimeAssuranceV1{
		SchemaVersion: controlprotocol.RuntimeAssuranceSchemaV1,
		Profile:       controlprotocol.RuntimeAssuranceSharedHost, Runtime: "docker",
		Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor, Network: "isolated-bridge",
		StateIsolation: controlprotocol.RuntimeAssuranceStateQuota, CredentialBoundary: "gateway-only",
	}
	assuranceDigest, err := controlprotocol.RuntimeAssuranceDigest(assurance)
	if err != nil {
		t.Fatal(err)
	}
	policy := controlprotocol.ExecutorSchedulingPolicyV1{
		PerWorkload:     controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1, CPUMillis: 1, PIDs: 1, Workloads: 1},
		Host:            controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2, CPUMillis: 2, PIDs: 2, Workloads: 2},
		Tenant:          controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2, CPUMillis: 2, PIDs: 2, Workloads: 2},
		RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
	}
	observation := &controlprotocol.ExecutorSchedulingObservationV1{
		SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
		NodeID:        "node-1", CredentialScope: "node", OS: "linux", Architecture: "amd64",
		Isolation:        controlprotocol.ExecutorSchedulingIsolationGVisor,
		RuntimeAssurance: &assurance, RuntimeAssuranceSHA256: assuranceDigest,
		Labels: []controlprotocol.ExecutorSchedulingLabelV1{{Key: "region", Value: "west"}},
		Taints: []string{"dedicated"}, CachedImageConfigDigests: []string{}, Policy: policy,
	}
	placement := admission.CommandDelegationPlacement{
		RequiredIsolation: "gvisor", RequiredAssurance: controlprotocol.RuntimeAssuranceSharedHost,
		RequiredLabels: []admission.CommandDelegationLabel{{Key: "region", Value: "west"}},
		Tolerations:    []string{"dedicated"},
	}
	if !executorPlacementMatches(observation, placement) {
		t.Fatal("matching signed placement was rejected")
	}
	missing := *observation
	missing.RuntimeAssurance = nil
	missing.RuntimeAssuranceSHA256 = ""
	if executorPlacementMatches(&missing, placement) {
		t.Fatal("missing runtime assurance satisfied signed placement")
	}
	wrongLabel := placement
	wrongLabel.RequiredLabels = []admission.CommandDelegationLabel{{Key: "region", Value: "east"}}
	if executorPlacementMatches(observation, wrongLabel) {
		t.Fatal("wrong label satisfied signed placement")
	}
	untolerated := placement
	untolerated.Tolerations = []string{}
	if executorPlacementMatches(observation, untolerated) {
		t.Fatal("untolerated taint satisfied signed placement")
	}
}

func TestNodeScopedRestartUsesCurrentPolicyAndSiteCleanupAuthority(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	oldTenantPublic, oldTenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPublic, cleanupPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPolicy := commandPolicyFixture(t, oldTenantPublic, []string{"admit", "start", "stop", "destroy", "read", "purge"})
	oldPolicy.SiteCleanupCommandKeys = []admission.CommandKey{{
		KeyID: "site-cleanup", PublicKey: base64.StdEncoding.EncodeToString(cleanupPublic),
		Operations: []string{"stop", "destroy", "purge"},
	}}
	if err := oldPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	runtimeRef, err := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	statement := func(kind string, sequence uint64, payload json.RawMessage) admission.CommandStatement {
		return admission.CommandStatement{
			SchemaVersion: admission.CommandSchemaV2, CommandID: "cleanup-" + kind,
			TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
			RuntimeRef: runtimeRef, Kind: kind, ClaimGeneration: 1,
			InstanceGeneration: 4, CommandSequence: sequence,
			IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
			ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Payload: payload,
		}
	}
	nodeCredential := nodeCredentialForTest()
	beforeRestart := &Poller{commandPolicy: &oldPolicy, now: func() time.Time { return now }}
	if _, err := beforeRestart.decodeCommand(signCommand(t, statement("start", 2, json.RawMessage(`{}`)), "tenant-command", oldTenantPrivate), nodeCredential); err != nil {
		t.Fatalf("old tenant key was not valid before policy replacement: %v", err)
	}

	// Model a restart after the signed policy removes tenant-a completely. The
	// restarted poller must use only current policy, while the site cleanup key
	// remains able to address tenant-a's durable workload identity.
	currentPolicy := oldPolicy
	currentPolicy.PolicyEpoch++
	currentPolicy.Tenants = nil
	if err := currentPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	afterRestart := &Poller{commandPolicy: &currentPolicy, now: func() time.Time { return now }}
	if _, err := afterRestart.decodeCommand(signCommand(t, statement("stop", 2, json.RawMessage(`{}`)), "tenant-command", oldTenantPrivate), nodeCredential); err == nil {
		t.Fatal("removed tenant command key remained trusted after restart")
	}
	if _, err := afterRestart.decodeCommand(signCommand(t, statement("start", 2, json.RawMessage(`{}`)), "site-cleanup", cleanupPrivate), nodeCredential); err == nil {
		t.Fatal("site cleanup key gained start authority")
	}

	var paths []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete || r.URL.Path == "/v1/state/purge" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"runtime_ref": "executor-ref", "status": "created"})
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := store.advance("tenant-a", "agent-1", position{
		ClaimGeneration: 1, Generation: 4, Sequence: 1, ReportedStatus: "running",
	}); err != nil {
		t.Fatal(err)
	}
	dispatch := dispatcher{
		handler: handler, token: "local", nodeID: "node-1", nodeScoped: true, state: store,
	}
	for _, test := range []struct {
		kind     string
		sequence uint64
		payload  json.RawMessage
	}{
		{kind: "stop", sequence: 2, payload: json.RawMessage(`{}`)},
		{kind: "destroy", sequence: 3, payload: json.RawMessage(`{}`)},
		{kind: "purge", sequence: 4, payload: json.RawMessage(`{"lineage_id":"lineage-1"}`)},
	} {
		decoded, err := afterRestart.decodeCommand(
			signCommand(t, statement(test.kind, test.sequence, test.payload), "site-cleanup", cleanupPrivate),
			nodeCredential,
		)
		if err != nil {
			t.Fatalf("decode site cleanup %s: %v", test.kind, err)
		}
		if report := dispatch.execute(context.Background(), decoded); report.Status != "done" {
			t.Fatalf("dispatch site cleanup %s: %#v", test.kind, report)
		}
	}
	if len(paths) != 3 || !strings.Contains(paths[0], "/stop") ||
		!strings.HasPrefix(paths[1], "DELETE /v1/workloads/") || paths[2] != "POST /v1/state/purge" {
		t.Fatalf("cleanup paths = %#v", paths)
	}
}

func commandPolicyFixture(t *testing.T, commandPublic ed25519.PublicKey, operations []string) admission.SitePolicy {
	t.Helper()
	publisherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resources := admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}
	cleanupPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site", PolicyEpoch: 1,
		SiteCleanupCommandKeys: []admission.CommandKey{{
			KeyID: "site-cleanup", PublicKey: base64.StdEncoding.EncodeToString(cleanupPublic),
			Operations: []string{"stop", "destroy", "purge"},
		}},
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:     []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories: []string{"registry.example/agent"}, ResourceCeiling: resources,
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher"}, ResourceCeiling: resources,
			CommandKeys: []admission.CommandKey{{
				KeyID: "tenant-command", PublicKey: base64.StdEncoding.EncodeToString(commandPublic), Operations: operations,
			}},
		}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	return policy
}

func signCommand(t *testing.T, statement admission.CommandStatement, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload := mustJSON(t, statement)
	envelope, err := dsse.Sign(admission.CommandPayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nodeCredentialForTest() *stewarduplink.Credential {
	return &stewarduplink.Credential{Version: 2, Scope: "node", NodeID: "node-1", Credential: "bearer"}
}
