package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

type interactionRig struct {
	server  *Server
	config  Config
	grant   Grant
	private ed25519.PrivateKey
	now     time.Time
}

func newInteractionRig(t *testing.T) *interactionRig {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "gi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := ServiceOperation{
		ServiceID: "hermes-api", ID: "hermes.run", Method: http.MethodPost, Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
		MaxSeconds: 5, MaxPermitSeconds: 300, TaskProtocol: TaskProtocolLifecycleV1,
		StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 5, PollIntervalSeconds: 1,
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"),
		ServiceAddress: "127.0.0.1:0", ServiceTokenFile: filepath.Join(directory, "service.token"),
		StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), ServiceOperations: []ServiceOperation{operation},
		ConnectorReceiptFile:   filepath.Join(directory, "receipts.ndjson"),
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []ConnectorReceiptTenantBudget{{TenantID: "tenant-a", Bytes: 4 << 20}},
		connectorReceiptKey:           receiptPrivate,
	}
	server, err := Open(config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.closeGrantListeners()
		_ = server.audit.Close()
		if server.connectorLedger != nil {
			_ = server.connectorLedger.Close()
		}
	})
	grant := Grant{
		GrantID: GrantID("tenant-a", "agent-a", 1), TenantID: "tenant-a", NodeID: "node-a",
		InstanceID: "agent-a", Generation: 1, RuntimeRef: "executor-" + strings.Repeat("a", 64),
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
		Service:       true, ServiceID: operation.ServiceID, ServiceURL: "http://127.0.0.1:1",
		TaskAuthorities:  []TaskAuthority{{KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(public)}},
		ControllerEvents: true,
	}
	registerTaskGrant(t, server, grant)
	activateConnectorGrant(t, server, grant.GrantID)
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	return &interactionRig{server: server, config: config, grant: grant, private: private, now: now}
}

func interactionControlClient(server *Server) *ControlClient {
	return &ControlClient{client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}}
}

func postInteraction(t *testing.T, socket string, input InteractionInput) *http.Response {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "http://gateway/v1/interactions", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := unixHTTPClient(socket).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func validInteractionInput(now time.Time, key string) InteractionInput {
	return InteractionInput{
		SchemaVersion: interactionRequestSchemaV1, IdempotencyKey: key,
		Kind: "decision", Title: "Publish the research brief?",
		Prompt:  "The draft is complete. Choose whether the agent should prepare a separately authorized publish task.",
		Options: []string{"approve", "deny"}, TaskID: "research-1",
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
}

func signedInteractionResponse(
	t *testing.T,
	rig *interactionRig,
	interaction Interaction,
	body InteractionResponseBody,
) ([]byte, []byte) {
	t.Helper()
	responseRaw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	statement := interactionpermit.Statement{
		SchemaVersion: interactionpermit.SchemaV1,
		NodeID:        interaction.NodeID, TenantID: interaction.TenantID, InstanceID: interaction.InstanceID,
		RuntimeRef: interaction.RuntimeRef, GrantID: interaction.GrantID, Generation: interaction.Generation,
		CapsuleDigest: interaction.CapsuleDigest, PolicyDigest: interaction.PolicyDigest,
		InteractionID: interaction.InteractionID, RequestDigest: interaction.RequestDigest,
		ResponseDigest: interactionpermit.ResponseDigest(responseRaw), ResponseBytes: int64(len(responseRaw)),
		NotBefore: rig.now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: rig.now.Add(time.Hour).Format(time.RFC3339),
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(interactionpermit.PayloadType, payload, "task-approver", rig.private)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return permitRaw, responseRaw
}

func TestInteractionLifecycleDerivesIdentityAndVerifiesResponse(t *testing.T) {
	rig := newInteractionRig(t)
	socket := eventSocketPath(rig.config.GrantRoot, rig.grant.GrantID)
	input := validInteractionInput(rig.now, "publish-decision")
	response := postInteraction(t, socket, input)
	if response.StatusCode != http.StatusAccepted {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(response.Body)
		t.Fatalf("create status=%d body=%s", response.StatusCode, body.String())
	}
	var created Interaction
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if created.TenantID != rig.grant.TenantID || created.NodeID != rig.grant.NodeID ||
		created.InstanceID != rig.grant.InstanceID || created.Generation != rig.grant.Generation ||
		created.GrantID != rig.grant.GrantID || created.RequestDigest == "" ||
		created.State != "open" || created.ControllerAccepted {
		t.Fatalf("created interaction = %+v", created)
	}

	// The same agent key and same content are idempotent.
	response = postInteraction(t, socket, input)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("replay status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	client := interactionControlClient(rig.server)
	outbox, err := client.ListInteractionOutbox(context.Background())
	if err != nil || len(outbox) != 1 || outbox[0].InteractionID != created.InteractionID {
		t.Fatalf("outbox=%+v err=%v", outbox, err)
	}
	if err := client.AckInteractions(context.Background(), []string{created.InteractionID}); err != nil {
		t.Fatal(err)
	}
	outbox, err = client.ListInteractionOutbox(context.Background())
	if err != nil || len(outbox) != 0 {
		t.Fatalf("acknowledged outbox=%+v err=%v", outbox, err)
	}

	body := InteractionResponseBody{SchemaVersion: interactionResponseBodySchemaV1, Choice: "approve"}
	permitRaw, responseRaw := signedInteractionResponse(t, rig, created, body)
	resolved, err := client.ResolveInteraction(context.Background(), created.InteractionID, permitRaw, responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.State != "resolved" || resolved.Response == nil ||
		resolved.Response.Body.Choice != "approve" || resolved.Response.KeyID != "task-approver" {
		t.Fatalf("resolved interaction = %+v", resolved)
	}
	// Exact replay returns the retained resolution rather than spending twice.
	replayed, err := client.ResolveInteraction(context.Background(), created.InteractionID, permitRaw, responseRaw)
	if err != nil || replayed.Response == nil || replayed.Response.PermitDigest != resolved.Response.PermitDigest {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}

	request, _ := http.NewRequest(http.MethodGet,
		"http://gateway/v1/interactions/"+created.InteractionID, nil)
	agentResponse, err := unixHTTPClient(socket).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer agentResponse.Body.Close()
	var visible Interaction
	if agentResponse.StatusCode != http.StatusOK || json.NewDecoder(agentResponse.Body).Decode(&visible) != nil ||
		visible.Response == nil || visible.Response.Body.Choice != "approve" {
		t.Fatalf("agent response status=%d visible=%+v", agentResponse.StatusCode, visible)
	}
}

func TestInteractionRejectsConflictInvalidResponseExpiryAndInactiveGrant(t *testing.T) {
	rig := newInteractionRig(t)
	socket := eventSocketPath(rig.config.GrantRoot, rig.grant.GrantID)
	input := validInteractionInput(rig.now, "decision")
	response := postInteraction(t, socket, input)
	var created Interaction
	_ = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()

	conflict := input
	conflict.Prompt = "different"
	response = postInteraction(t, socket, conflict)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("conflict status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	client := interactionControlClient(rig.server)
	invalidBody := InteractionResponseBody{SchemaVersion: interactionResponseBodySchemaV1, Choice: "not-offered"}
	permitRaw, responseRaw := signedInteractionResponse(t, rig, created, invalidBody)
	if _, err := client.ResolveInteraction(context.Background(), created.InteractionID, permitRaw, responseRaw); err == nil {
		t.Fatal("ResolveInteraction accepted an unoffered choice")
	}

	rig.server.now = func() time.Time { return rig.now.Add(2 * time.Hour) }
	validBody := InteractionResponseBody{SchemaVersion: interactionResponseBodySchemaV1, Choice: "deny"}
	permitRaw, responseRaw = signedInteractionResponse(t, rig, created, validBody)
	if _, err := client.ResolveInteraction(context.Background(), created.InteractionID, permitRaw, responseRaw); err == nil {
		t.Fatal("ResolveInteraction accepted an expired request")
	}

	deactivate := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(deactivate,
		httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil))
	rig.server.now = func() time.Time { return rig.now }
	response = postInteraction(t, socket, validInteractionInput(rig.now, "inactive"))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestInteractionOutboxAndResolutionSurviveRestart(t *testing.T) {
	rig := newInteractionRig(t)
	response := postInteraction(t, eventSocketPath(rig.config.GrantRoot, rig.grant.GrantID),
		validInteractionInput(rig.now, "restart"))
	var created Interaction
	_ = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()
	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()

	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		if reopened.connectorLedger != nil {
			_ = reopened.connectorLedger.Close()
		}
	})
	reopened.now = func() time.Time { return rig.now }
	client := interactionControlClient(reopened)
	outbox, err := client.ListInteractionOutbox(context.Background())
	if err != nil || len(outbox) != 1 || outbox[0].InteractionID != created.InteractionID {
		t.Fatalf("restored outbox=%+v err=%v", outbox, err)
	}
	activate := httptest.NewRecorder()
	reopened.ControlHandler().ServeHTTP(activate,
		httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/activate", nil))
	if activate.Code != http.StatusOK {
		t.Fatalf("reactivate status=%d body=%s", activate.Code, activate.Body.String())
	}
	body := InteractionResponseBody{SchemaVersion: interactionResponseBodySchemaV1, Choice: "deny"}
	permitRaw, responseRaw := signedInteractionResponse(t, rig, created, body)
	resolved, err := client.ResolveInteraction(context.Background(), created.InteractionID, permitRaw, responseRaw)
	if err != nil || resolved.State != "resolved" {
		t.Fatalf("restored resolution=%+v err=%v", resolved, err)
	}
}
