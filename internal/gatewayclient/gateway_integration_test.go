package gatewayclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestClientAgainstGatewayStatusAndTerminalObservation(t *testing.T) {
	const (
		serviceToken = "gateway-integration-secret"
		tenantID     = "tenant-integration"
		instanceID   = "agent-integration"
		taskID       = "task-integration"
		runID        = "run_0123456789abcdef0123456789abcdef"
	)
	terminalRaw := []byte(`{"run_id":"` + runID + `","status":"completed","result":{"changed":true}}`)
	var dispatchCalls atomic.Int64
	var observationCalls atomic.Int64
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodPost:
			dispatchCalls.Add(1)
			if request.RequestURI != "/v1/runs" {
				t.Errorf("dispatch RequestURI=%q", request.RequestURI)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"run_id":"`+runID+`","status":"queued"}`)
		case http.MethodGet:
			observationCalls.Add(1)
			if request.RequestURI != "/v1/runs/"+runID || request.ContentLength != 0 {
				t.Errorf("observation RequestURI=%q content_length=%d", request.RequestURI, request.ContentLength)
			}
			_, _ = w.Write(terminalRaw)
		default:
			t.Errorf("unexpected agent method %q", request.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer agent.Close()

	directory := t.TempDir()
	_, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptKeyPath := filepath.Join(directory, "connector-receipts.private.pem")
	writePrivateKey(t, receiptKeyPath, receiptPrivate)
	taskPublic, taskPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := gateway.ServiceOperation{
		ServiceID: "agent-api", ID: "agent.run", Method: http.MethodPost, Path: "/v1/runs",
		ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
		MaxSeconds: 5, MaxPermitSeconds: 300, TaskProtocol: gateway.TaskProtocolLifecycleV1,
		StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 5, PollIntervalSeconds: 1,
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:12345",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		ServiceOperations:       []gateway.ServiceOperation{operation},
		ConnectorReceiptFile:    filepath.Join(directory, "connector-receipts.ndjson"),
		ConnectorReceiptKeyFile: receiptKeyPath, ConnectorReceiptNodeID: "node-integration/gateway",
		ConnectorReceiptEpoch:         1,
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{TenantID: tenantID, Bytes: 4 << 20}},
	}
	server, err := gateway.Open(config, nil, nil, serviceToken)
	if err != nil {
		t.Fatal(err)
	}
	grant := gateway.Grant{
		GrantID: gateway.GrantID(tenantID, instanceID, 1), TenantID: tenantID, NodeID: "node-integration",
		InstanceID: instanceID, Generation: 1, RuntimeRef: "executor-" + strings.Repeat("a", 64),
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
		Service: true, ServiceID: operation.ServiceID, ServiceURL: agent.URL,
		TaskAuthorities: []gateway.TaskAuthority{{KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(taskPublic)}},
	}
	routePolicyDigest := registerAndActivateGrant(t, server, grant)

	gatewayHTTP := httptest.NewServer(server.ServiceHandler())
	defer gatewayHTTP.Close()
	body := []byte(`{"input":"do real work","session_id":"integration"}`)
	now := time.Now().UTC()
	statement := taskpermit.Statement{
		SchemaVersion: taskpermit.SchemaV1, NodeID: grant.NodeID, TenantID: grant.TenantID,
		InstanceID: grant.InstanceID, RuntimeRef: grant.RuntimeRef, GrantID: grant.GrantID,
		Generation: grant.Generation, CapsuleDigest: grant.CapsuleDigest, PolicyDigest: grant.PolicyDigest,
		RoutePolicyDigest: routePolicyDigest, ServiceID: grant.ServiceID, OperationID: operation.ID,
		OperationPolicyDigest: gateway.ServiceOperationDigest(operation), TaskID: taskID,
		RequestDigest: taskpermit.RequestDigest(body), RequestBytes: int64(len(body)), ContentType: operation.ContentType,
		NotBefore: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339),
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(taskpermit.PayloadType, payload, "task-approver", taskPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rawPermit, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	permitHeader, err := taskpermit.EncodeHeader(rawPermit)
	if err != nil {
		t.Fatal(err)
	}
	dispatchRequest, err := http.NewRequest(http.MethodPost, gatewayHTTP.URL+"/v1/services/"+grant.GrantID+operation.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	dispatchRequest.Header.Set("Authorization", "Bearer "+serviceToken)
	dispatchRequest.Header.Set("Content-Type", operation.ContentType)
	dispatchRequest.Header.Set("X-Steward-Task-Permit", permitHeader)
	dispatchResponse, err := http.DefaultClient.Do(dispatchRequest)
	if err != nil {
		t.Fatal(err)
	}
	dispatchResponse.Body.Close()
	if dispatchResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("dispatch HTTP status=%d", dispatchResponse.StatusCode)
	}

	taskDigest := taskpermit.TaskDigest(tenantID, instanceID, taskID)
	permitDigest := dsse.Digest(rawPermit)
	client, err := gatewayclient.New(gatewayHTTP.URL, serviceToken)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(context.Background(), taskDigest, permitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != gatewayclient.PhaseDispatch || status.State != gatewayclient.StateDispatchAccepted ||
		status.RunID != runID || status.TaskDigest != taskDigest || status.PermitDigest != permitDigest {
		t.Fatalf("dispatch status=%#v", status)
	}
	wrongPermit := "sha256:" + strings.Repeat("d", 64)
	if _, err := client.Status(context.Background(), taskDigest, wrongPermit); !gatewayAPIError(err, http.StatusNotFound, "task_not_found") {
		t.Fatalf("wrong-permit status error=%v", err)
	}
	wrongTask := "sha256:" + strings.Repeat("e", 64)
	if _, err := client.Status(context.Background(), wrongTask, permitDigest); !gatewayAPIError(err, http.StatusNotFound, "task_not_found") {
		t.Fatalf("wrong-task status error=%v", err)
	}

	observed, err := client.Observe(context.Background(), taskDigest, permitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Phase != gatewayclient.PhaseTerminal || observed.State != string(gatewayclient.AgentReportedCompleted) ||
		observed.TaskStatus != gatewayclient.AgentReportedCompleted || observed.ObservedStatus != gatewayclient.ObservedCompleted ||
		observed.RunID != runID || observed.ResponseBytes != int64(len(terminalRaw)) {
		t.Fatalf("terminal observation=%#v", observed)
	}
	decoded, err := base64.StdEncoding.DecodeString(observed.ObservationBase64)
	if err != nil || !bytes.Equal(decoded, terminalRaw) || observed.ResultDigest != dsse.Digest(terminalRaw) {
		t.Fatalf("terminal raw bytes=%q decode_error=%v digest=%q", decoded, err, observed.ResultDigest)
	}
	persisted, err := client.Status(context.Background(), taskDigest, permitDigest)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != string(gatewayclient.AgentReportedCompleted) || persisted.ObservedStatus != "" || persisted.ObservationBase64 != "" ||
		persisted.ResultDigest != observed.ResultDigest || persisted.ResponseBytes != observed.ResponseBytes {
		t.Fatalf("persisted terminal status=%#v", persisted)
	}
	if dispatchCalls.Load() != 1 || observationCalls.Load() != 1 {
		t.Fatalf("agent dispatch_calls=%d observation_calls=%d", dispatchCalls.Load(), observationCalls.Load())
	}
}

func writePrivateKey(t *testing.T, path string, private ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func registerAndActivateGrant(t *testing.T, server *gateway.Server, grant gateway.Grant) string {
	t.Helper()
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	registered := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(registered, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if registered.Code != http.StatusCreated {
		t.Fatalf("register grant status=%d body=%s", registered.Code, registered.Body.String())
	}
	var response struct {
		RoutePolicyDigest string `json:"route_policy_digest"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &response); err != nil || response.RoutePolicyDigest == "" {
		t.Fatalf("register grant response=%s decode_error=%v", registered.Body.String(), err)
	}
	activated := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(activated, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	if activated.Code != http.StatusOK {
		t.Fatalf("activate grant status=%d body=%s", activated.Code, activated.Body.String())
	}
	return response.RoutePolicyDigest
}

func gatewayAPIError(err error, status int, code string) bool {
	apiError, ok := err.(*gatewayclient.APIError)
	return ok && apiError.Status == status && apiError.Code == code
}
