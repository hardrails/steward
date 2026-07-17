package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
)

type connectorRigOptions struct {
	credentialMode    CredentialMode
	allowedCIDRs      []string
	maxConcurrent     int
	maxRequestBytes   int64
	maxResponseBytes  int64
	maxCalls          int
	requirePermit     bool
	actionTenant      string
	authorizedEffects bool
}

type connectorRig struct {
	server    *Server
	config    Config
	grant     Grant
	connector loadedConnector
	actionKey ed25519.PrivateKey
}

type blockingConnectorReceiptLog struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	failed  bool
}

func (log *blockingConnectorReceiptLog) Begin(connectorledger.Event) (connectorledger.Head, error) {
	log.once.Do(func() { close(log.entered) })
	<-log.release
	return connectorledger.Head{}, errors.New("fixture append refused before write")
}

func (log *blockingConnectorReceiptLog) Append(connectorledger.Event) (connectorledger.Head, error) {
	log.once.Do(func() { close(log.entered) })
	<-log.release
	return connectorledger.Head{}, errors.New("fixture append refused before write")
}

func (*blockingConnectorReceiptLog) Finish(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("unexpected fixture finish")
}

func (*blockingConnectorReceiptLog) Dispatch(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("unexpected fixture dispatch")
}

func (log *blockingConnectorReceiptLog) Failed() bool { return log.failed }
func (*blockingConnectorReceiptLog) Close() error     { return nil }

type refusingConnectorReceiptLog struct{ err error }

func (log refusingConnectorReceiptLog) Begin(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, log.err
}
func (log refusingConnectorReceiptLog) Append(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, log.err
}
func (refusingConnectorReceiptLog) Finish(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("unexpected fixture finish")
}
func (refusingConnectorReceiptLog) Dispatch(connectorledger.Event) (connectorledger.Head, error) {
	return connectorledger.Head{}, errors.New("unexpected fixture dispatch")
}
func (refusingConnectorReceiptLog) Failed() bool { return false }
func (refusingConnectorReceiptLog) Close() error { return nil }

func newConnectorRig(t *testing.T, baseURL string, options connectorRigOptions) *connectorRig {
	t.Helper()
	if options.credentialMode == "" {
		options.credentialMode = CredentialModeBearer
	}
	if options.maxConcurrent == 0 {
		options.maxConcurrent = 4
	}
	if options.maxRequestBytes == 0 {
		options.maxRequestBytes = 4096
	}
	if options.maxResponseBytes == 0 {
		options.maxResponseBytes = 8192
	}
	if options.maxCalls == 0 {
		options.maxCalls = 8
	}
	if options.actionTenant == "" {
		options.actionTenant = "tenant-a"
	}
	if options.authorizedEffects && !options.requirePermit {
		t.Fatal("authorized-effects fixture requires an action permit authority")
	}
	directory, err := os.MkdirTemp("/tmp", "gc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	credential := filepath.Join(directory, "connector.token")
	if err := os.WriteFile(credential, []byte("operator-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	connectorConfig := Connector{
		ID: "issues", BaseURL: baseURL, CredentialFile: credential,
		CredentialMode: options.credentialMode, AllowInsecureHTTP: strings.HasPrefix(baseURL, "http://"),
		AllowedCIDRs: options.allowedCIDRs, MaxConcurrent: options.maxConcurrent,
		MaxRequestBytes: options.maxRequestBytes, MaxResponseBytes: options.maxResponseBytes,
		MaxSeconds: 5, MaxCallsPerGrant: options.maxCalls,
		Operations: []ConnectorOperation{
			{ID: "create", Method: http.MethodPost, Path: "/v1/issues"},
			{ID: "read", Method: http.MethodGet, Path: "/v1/issues/current"},
		},
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8092",
		ServiceTokenFile: filepath.Join(directory, "service.token"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
		Connectors:              []Connector{connectorConfig},
		ConnectorReceiptFile:    filepath.Join(directory, "connector-receipts.ndjson"),
		ConnectorReceiptKeyFile: filepath.Join(directory, "connector-receipts.private.pem"),
		ConnectorReceiptNodeID:  "node-test/gateway", ConnectorReceiptEpoch: 1,
		ConnectorReceiptTenantBudgets: []ConnectorReceiptTenantBudget{
			{TenantID: "tenant-a", Bytes: 2 << 20},
			{TenantID: "tenant-b", Bytes: 2 << 20},
		},
	}
	var actionKey ed25519.PrivateKey
	if options.requirePermit {
		actionPublic, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		actionKey = private
		config.ActionPermitNodeID = "node-test"
		config.ActionAuthorities = []ActionAuthority{{KeyID: "approver-a", TenantID: options.actionTenant, PublicKey: base64.StdEncoding.EncodeToString(actionPublic)}}
		config.Connectors[0].ActionAuthorityIDs = []string{"approver-a"}
		config.Connectors[0].MaxActionPermitSeconds = 300
		config.Connectors[0].CredentialEpoch = 1
	}
	_, receiptKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config.connectorReceiptKey = receiptKey
	connectors, err := config.validateAndLoadConnectors()
	if err != nil {
		t.Fatal(err)
	}
	config.loadedConnectors = connectors
	server, err := Open(config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.closeGrantListeners()
		_ = server.audit.Close()
		_ = server.connectorLedger.Close()
	})
	grant := connectorGrant("tenant-a", "agent-a", 1, "issues")
	if options.authorizedEffects {
		grant.NodeID = config.ActionPermitNodeID
		grant.EffectMode = EffectModeAuthorized
		grant.ActionAuthorities = []GrantActionAuthority{{
			KeyID: "approver-a", PublicKey: config.ActionAuthorities[0].PublicKey,
			ConnectorIDs: []string{"issues"},
		}}
	}
	registerConnectorGrant(t, server, grant)
	activateConnectorGrant(t, server, grant.GrantID)
	return &connectorRig{server: server, config: config, grant: grant, connector: connectors["issues"], actionKey: actionKey}
}

func connectorGrant(tenant, instance string, generation uint64, connectors ...string) Grant {
	return Grant{
		GrantID: GrantID(tenant, instance, generation), TenantID: tenant, InstanceID: instance, Generation: generation,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest: "sha256:" + strings.Repeat("c", 64), ConnectorIDs: append([]string(nil), connectors...),
	}
}

func registerConnectorGrant(t *testing.T, server *Server, grant Grant) grantResponse {
	t.Helper()
	raw, _ := json.Marshal(grant)
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	var result grantResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.ConnectorSocket == "" || result.RoutePolicyDigest == "" {
		t.Fatalf("register response=%#v err=%v", result, err)
	}
	return result
}

func activateConnectorGrant(t *testing.T, server *Server, grantID string) {
	t.Helper()
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grantID+"/activate", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", response.Code, response.Body.String())
	}
}

func connectorRequest(method, connectorID, operationID, taskID string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, "/v1/connectors/"+connectorID+"/operations/"+operationID, body)
	if taskID != "" {
		request.Header.Set("X-Steward-Task-ID", taskID)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func invokeConnector(server *Server, grantID string, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.connectorHandler(grantID).ServeHTTP(response, request)
	return response
}

func actionPermitFor(
	t *testing.T,
	rig *connectorRig,
	taskID, operationID string,
	body []byte,
	mutate func(*actionpermit.Statement),
) (string, string) {
	return actionPermitForPayload(t, rig, taskID, operationID, body, "", mutate)
}

func actionPermitForPayload(
	t *testing.T,
	rig *connectorRig,
	taskID, operationID string,
	body []byte,
	payloadType string,
	mutate func(*actionpermit.Statement),
) (string, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	connector := rig.server.connectors["issues"]
	operation, ok := connector.operations[operationID]
	if !ok {
		t.Fatalf("test connector has no operation %q", operationID)
	}
	operationDigest, err := ConnectorOperationPolicyDigest(
		connector.BaseURL, connector.CredentialMode, connector.CredentialEpoch, connector.ID, operation,
	)
	if err != nil {
		t.Fatal(err)
	}
	contentType, err := ConnectorOperationContentType(operation.Method)
	if err != nil {
		t.Fatal(err)
	}
	schemaVersion, effectMode := actionpermit.SchemaV1, ""
	if rig.grant.EffectMode == EffectModeAuthorized {
		schemaVersion, effectMode = actionpermit.SchemaV2, actionpermit.EffectModeAuthorized
	}
	if payloadType == "" {
		if effectMode == actionpermit.EffectModeAuthorized {
			payloadType = actionpermit.PayloadTypeV2
		} else {
			payloadType = actionpermit.PayloadTypeV1
		}
	} else if payloadType == actionpermit.PayloadTypeV1 {
		schemaVersion, effectMode = actionpermit.SchemaV1, ""
	}
	statement := actionpermit.Statement{
		SchemaVersion: schemaVersion, EffectMode: effectMode, NodeID: rig.config.ActionPermitNodeID,
		TenantID: rig.grant.TenantID, InstanceID: rig.grant.InstanceID, Generation: rig.grant.Generation,
		CapsuleDigest: rig.grant.CapsuleDigest, PolicyDigest: rig.grant.PolicyDigest,
		RoutePolicyDigest: rig.server.policyDigests[rig.grant.GrantID], ConnectorID: "issues",
		OperationID: operationID, OperationDigest: operationDigest, TaskID: taskID,
		RequestDigest: actionpermit.RequestDigest(body), RequestBytes: int64(len(body)),
		ContentType: contentType, NotBefore: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(&statement)
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(payloadType, payload, "approver-a", rig.actionKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, err := actionpermit.EncodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return header, dsse.Digest(raw)
}

func TestConnectorRequiresAndSpendsExactSignedActionPermit(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Header.Get(actionPermitHeader) != "" {
			t.Error("action permit reached the upstream")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true,
	})
	body := []byte(`{"title":"bounded"}`)
	taskID := "task-permitted-1"

	missing := invokeConnector(rig.server, rig.grant.GrantID,
		connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body)))
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), `"error":"action_permit_denied"`) || calls.Load() != 0 {
		t.Fatalf("missing permit status=%d body=%s calls=%d", missing.Code, missing.Body.String(), calls.Load())
	}

	validHeader, permitDigest := actionPermitFor(t, rig, taskID, "create", body, nil)
	changed := connectorRequest(http.MethodPost, "issues", "create", taskID, strings.NewReader(`{"title":"changed"}`))
	changed.Header.Set(actionPermitHeader, validHeader)
	changedResponse := invokeConnector(rig.server, rig.grant.GrantID, changed)
	if changedResponse.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("changed body status=%d body=%s calls=%d", changedResponse.Code, changedResponse.Body.String(), calls.Load())
	}

	wrongTenant, _ := actionPermitFor(t, rig, taskID, "create", body, func(statement *actionpermit.Statement) {
		statement.TenantID = "tenant-b"
	})
	foreign := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	foreign.Header.Set(actionPermitHeader, wrongTenant)
	foreignResponse := invokeConnector(rig.server, rig.grant.GrantID, foreign)
	if foreignResponse.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("foreign permit status=%d body=%s calls=%d", foreignResponse.Code, foreignResponse.Body.String(), calls.Load())
	}
	wrongOperationPolicy, _ := actionPermitFor(t, rig, taskID, "create", body, func(statement *actionpermit.Statement) {
		statement.OperationDigest = "sha256:" + strings.Repeat("f", 64)
	})
	wrongOperation := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	wrongOperation.Header.Set(actionPermitHeader, wrongOperationPolicy)
	wrongOperationResponse := invokeConnector(rig.server, rig.grant.GrantID, wrongOperation)
	if wrongOperationResponse.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("wrong operation policy status=%d body=%s calls=%d", wrongOperationResponse.Code, wrongOperationResponse.Body.String(), calls.Load())
	}

	valid := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	valid.Header.Set(actionPermitHeader, validHeader)
	response := invokeConnector(rig.server, rig.grant.GrantID, valid)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("valid permit status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	replay := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	replay.Header.Set(actionPermitHeader, validHeader)
	replayed := invokeConnector(rig.server, rig.grant.GrantID, replay)
	if replayed.Code != http.StatusConflict || !strings.Contains(replayed.Body.String(), `"error":"connector_task_replayed"`) || calls.Load() != 1 {
		t.Fatalf("replay status=%d body=%s calls=%d", replayed.Code, replayed.Body.String(), calls.Load())
	}

	var receipts []connectorledger.Event
	_, err := connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			receipts = append(receipts, record.Receipt.Event)
			return nil
		},
	)
	requestDigest := actionpermit.RequestDigest(body)
	if err != nil || len(receipts) != 2 || receipts[0].PermitDigest != permitDigest ||
		receipts[0].RequestDigest != requestDigest || receipts[1].PermitDigest != permitDigest ||
		receipts[1].RequestDigest != requestDigest || receipts[0].AuthorityKeyID != "approver-a" ||
		receipts[1].AuthorityKeyID != "approver-a" {
		t.Fatalf("receipts=%#v err=%v", receipts, err)
	}
	summary, err := InspectConnectorReceiptFormat(rig.config)
	if err != nil || summary.FormatVersion != 2 {
		t.Fatalf("format summary=%#v err=%v", summary, err)
	}
}

func TestAuthorizedEffectsDenyDowngradeAndRecordOneBoundedDenial(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"changed":true}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true, authorizedEffects: true,
	})
	body := []byte(`{"account":"fixture","operation":"rotate-recovery"}`)
	taskID := "task-authorized-effect"

	for _, attemptedBody := range [][]byte{body, []byte(`{"account":"attacker"}`)} {
		request := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(attemptedBody))
		response := invokeConnector(rig.server, rig.grant.GrantID, request)
		if response.Code != http.StatusForbidden ||
			!strings.Contains(response.Body.String(), `"error":"action_permit_denied"`) || calls.Load() != 0 {
			t.Fatalf("missing permit status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
		}
	}
	// Denial evidence is deliberately one bounded, first-observed sample per
	// grant and error code. A compromised workload can choose that first sample,
	// but cannot grow the durable ledger by probing distinct operations.
	distinctOperation := connectorRequest(http.MethodGet, "issues", "read", "task-distinct-denial", nil)
	if response := invokeConnector(rig.server, rig.grant.GrantID, distinctOperation); response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), `"error":"action_permit_denied"`) || calls.Load() != 0 {
		t.Fatalf("distinct missing permit status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}

	legacy, _ := actionPermitForPayload(
		t, rig, taskID, "create", body, actionpermit.PayloadTypeV1, nil,
	)
	downgrade := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	downgrade.Header.Set(actionPermitHeader, legacy)
	if response := invokeConnector(rig.server, rig.grant.GrantID, downgrade); response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("v1 downgrade status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}

	validHeader, permitDigest := actionPermitFor(t, rig, taskID, "create", body, nil)
	valid := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	valid.Header.Set(actionPermitHeader, validHeader)
	if response := invokeConnector(rig.server, rig.grant.GrantID, valid); response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("authorized effect status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	replay := connectorRequest(http.MethodPost, "issues", "create", taskID, bytes.NewReader(body))
	replay.Header.Set(actionPermitHeader, validHeader)
	if response := invokeConnector(rig.server, rig.grant.GrantID, replay); response.Code != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("replay status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}

	raceTaskID := "task-authorized-race"
	raceHeader, _ := actionPermitFor(t, rig, raceTaskID, "create", body, nil)
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := connectorRequest(http.MethodPost, "issues", "create", raceTaskID, bytes.NewReader(body))
			request.Header.Set(actionPermitHeader, raceHeader)
			statuses <- invokeConnector(rig.server, rig.grant.GrantID, request).Code
		}()
	}
	close(start)
	wait.Wait()
	close(statuses)
	counts := make(map[int]int)
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 || calls.Load() != 2 {
		t.Fatalf("race statuses=%v calls=%d", counts, calls.Load())
	}

	operationDigest, err := ConnectorOperationPolicyDigest(
		rig.connector.BaseURL, rig.connector.CredentialMode, rig.connector.CredentialEpoch,
		rig.connector.ID, rig.connector.operations["create"],
	)
	if err != nil {
		t.Fatal(err)
	}
	var records []connectorledger.Receipt
	_, err = connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			records = append(records, record.Receipt)
			return nil
		},
	)
	if err != nil || len(records) != 5 {
		t.Fatalf("authorized receipts=%#v err=%v", records, err)
	}
	denial, authorization, terminal := records[0], records[1], records[2]
	if denial.SchemaVersion != connectorledger.SchemaV5 || denial.Event.Phase != connectorledger.Deny ||
		denial.Event.ErrorCode != "action_permit_denied" || denial.Event.EffectMode != EffectModeAuthorized ||
		denial.Event.OperationPolicyDigest != operationDigest || denial.Event.AuthorityKeyID != "" || denial.Event.PermitDigest != "" {
		t.Fatalf("denial receipt=%#v", denial)
	}
	for _, record := range []connectorledger.Receipt{authorization, terminal} {
		if record.SchemaVersion != connectorledger.SchemaV5 || record.Event.EffectMode != EffectModeAuthorized ||
			record.Event.OperationPolicyDigest != operationDigest || record.Event.PermitDigest != permitDigest ||
			record.Event.AuthorityKeyID != "approver-a" {
			t.Fatalf("authorized receipt=%#v", record)
		}
	}
	for _, record := range records[3:] {
		if record.SchemaVersion != connectorledger.SchemaV5 || record.Event.EffectMode != EffectModeAuthorized ||
			record.Event.OperationPolicyDigest != operationDigest {
			t.Fatalf("raced authorized receipt=%#v", record)
		}
	}
	summary, err := InspectConnectorReceiptFormat(rig.config)
	if err != nil || summary.FormatVersion != 5 {
		t.Fatalf("format summary=%#v err=%v", summary, err)
	}
	stateRaw, err := os.ReadFile(rig.config.StateFile)
	if err != nil || !bytes.Contains(stateRaw, []byte(`"version":5`)) ||
		!bytes.Contains(stateRaw, []byte(`"effect_mode":"authorized"`)) ||
		!bytes.Contains(stateRaw, []byte(`"action_authorities"`)) {
		t.Fatalf("authorized state=%s err=%v", stateRaw, err)
	}

	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()
	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
	}()
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	afterRestart := connectorRequest(
		http.MethodPost, "issues", "create", "task-denied-after-restart", strings.NewReader(`{"attempt":true}`),
	)
	if response := invokeConnector(reopened, rig.grant.GrantID, afterRestart); response.Code != http.StatusForbidden || calls.Load() != 2 {
		t.Fatalf("post-restart denial status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	var count int
	_, err = connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(connectorledger.VerifiedReceipt) error {
			count++
			return nil
		},
	)
	if err != nil || count != 5 {
		t.Fatalf("post-restart denial records=%d err=%v", count, err)
	}
}

func TestAuthorizedEffectsGrantRejectsAuthorityAndModeSubstitution(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true, authorizedEffects: true,
	})
	baseline := rig.grant
	if !rig.server.validGrant(baseline) {
		t.Fatal("valid authorized-effects grant rejected")
	}
	_, substitutePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	substitutePublic := substitutePrivate.Public().(ed25519.PublicKey)
	baselineDigest := rig.server.routePolicyDigestLocked(baseline)
	substituted := baseline
	substituted.ActionAuthorities = cloneGrantActionAuthorities(baseline.ActionAuthorities)
	substituted.ActionAuthorities[0].PublicKey = base64.StdEncoding.EncodeToString(substitutePublic)
	if baselineDigest == rig.server.routePolicyDigestLocked(substituted) {
		t.Fatal("route-policy digest does not bind the signed action-authority public key")
	}
	tests := []struct {
		name   string
		mutate func(*Grant)
	}{
		{name: "mode removed", mutate: func(grant *Grant) { grant.EffectMode = "" }},
		{name: "standard mode", mutate: func(grant *Grant) { grant.EffectMode = EffectModeStandard }},
		{name: "generic egress", mutate: func(grant *Grant) { grant.EgressRouteIDs = []string{"public-web"} }},
		{name: "node changed", mutate: func(grant *Grant) { grant.NodeID = "other-node" }},
		{name: "connectors removed", mutate: func(grant *Grant) { grant.ConnectorIDs = nil }},
		{name: "authority removed", mutate: func(grant *Grant) { grant.ActionAuthorities = nil }},
		{name: "public key substituted", mutate: func(grant *Grant) {
			grant.ActionAuthorities[0].PublicKey = base64.StdEncoding.EncodeToString(substitutePublic)
		}},
		{name: "connector scope removed", mutate: func(grant *Grant) {
			grant.ActionAuthorities[0].ConnectorIDs = nil
		}},
		{name: "extra signed authority", mutate: func(grant *Grant) {
			grant.ActionAuthorities = append(grant.ActionAuthorities, GrantActionAuthority{
				KeyID: "zz-attacker", PublicKey: base64.StdEncoding.EncodeToString(substitutePublic),
				ConnectorIDs: []string{"issues"},
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := baseline
			candidate.ActionAuthorities = cloneGrantActionAuthorities(baseline.ActionAuthorities)
			test.mutate(&candidate)
			if rig.server.validGrant(candidate) {
				t.Fatal("substituted authorized-effects grant accepted")
			}
		})
	}

	original := rig.server.connectors["issues"]
	changed := original
	changed.ActionAuthorityIDs = append([]string(nil), original.ActionAuthorityIDs...)
	changed.authorities = make(map[string]ed25519.PublicKey, len(original.authorities)+1)
	changed.authorityTenants = make(map[string]string, len(original.authorityTenants)+1)
	for keyID, public := range original.authorities {
		changed.authorities[keyID] = append(ed25519.PublicKey(nil), public...)
		changed.authorityTenants[keyID] = original.authorityTenants[keyID]
	}
	changed.ActionAuthorityIDs = append(changed.ActionAuthorityIDs, "zz-attacker")
	changed.authorities["zz-attacker"] = append(ed25519.PublicKey(nil), substitutePublic...)
	changed.authorityTenants["zz-attacker"] = baseline.TenantID
	rig.server.connectors["issues"] = changed
	if rig.server.validGrant(baseline) {
		t.Fatal("unsigned config added a same-tenant authority to an authorized grant")
	}
	changed.authorityTenants["zz-attacker"] = "tenant-b"
	rig.server.connectors["issues"] = changed
	if rig.server.validGrant(baseline) {
		t.Fatal("unsigned config added a foreign-tenant authority to an authorized grant")
	}
	rig.server.connectors["issues"] = original
}

func TestAuthorizedEffectsDenialFailsClosedWhenEvidenceIsUnavailable(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true, authorizedEffects: true,
	})
	ledger := rig.server.connectorLedger
	rig.server.connectorLedger = refusingConnectorReceiptLog{err: errors.New("fixture evidence unavailable")}
	t.Cleanup(func() { rig.server.connectorLedger = ledger })

	request := connectorRequest(
		http.MethodPost, "issues", "create", "task-evidence-unavailable", strings.NewReader(`{"change":true}`),
	)
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"error":"evidence_unavailable"`) || calls.Load() != 0 {
		t.Fatalf("status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	if len(rig.server.connectorDenials) != 0 {
		t.Fatal("definite denial append failure retained an in-memory denial reservation")
	}
}

func TestConcurrentAuthorizedEffectsDenialsWaitForDurableEvidence(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true, authorizedEffects: true,
	})
	ledger := rig.server.connectorLedger
	blocking := &blockingConnectorReceiptLog{entered: make(chan struct{}), release: make(chan struct{})}
	rig.server.connectorLedger = blocking
	t.Cleanup(func() { rig.server.connectorLedger = ledger })

	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			request := connectorRequest(
				http.MethodPost, "issues", "create", "task-concurrent-denial", strings.NewReader(`{"change":true}`),
			)
			statuses <- invokeConnector(rig.server, rig.grant.GrantID, request).Code
		}()
	}
	<-blocking.entered
	close(blocking.release)
	for range 2 {
		if status := <-statuses; status != http.StatusServiceUnavailable {
			t.Fatalf("concurrent denial status=%d", status)
		}
	}
	if calls.Load() != 0 || len(rig.server.connectorDenials) != 0 || len(rig.server.connectorDenialPending) != 0 {
		t.Fatalf("calls=%d denials=%d pending=%d", calls.Load(), len(rig.server.connectorDenials), len(rig.server.connectorDenialPending))
	}
}

func TestAuthorizedEffectsRetainedGrantRequiresStateFormatFive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true, authorizedEffects: true,
	})
	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()

	raw, err := os.ReadFile(rig.config.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state["version"] = float64(4)
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rig.config.StateFile, raw, 0o600); err != nil {
		t.Fatalf("rewrite state: %v", err)
	}
	if reopened, err := Open(rig.config, nil, nil, "service-token"); err == nil {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
		t.Fatal("authorized-effects authority loaded from pre-v5 Gateway state")
	}
}

func TestConnectorAcceptsBodylessPermitWithExactOutboundMetadata(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodGet || request.Header.Get("Content-Type") != "" || request.ContentLength != 0 {
			t.Errorf("bodyless operation metadata: method=%s content-type=%q length=%d",
				request.Method, request.Header.Get("Content-Type"), request.ContentLength)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true,
	})
	header, _ := actionPermitFor(t, rig, "task-read-permitted", "read", nil, nil)
	request := connectorRequest(http.MethodGet, "issues", "read", "task-read-permitted", nil)
	request.Header.Set(actionPermitHeader, header)
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("bodyless permit status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestConnectorOperationPolicyDigestBindsEveryEffectRouteField(t *testing.T) {
	base := ConnectorOperation{ID: "create", Method: http.MethodPost, Path: "/v1/issues"}
	want, err := ConnectorOperationPolicyDigest("https://api.example.test", CredentialModeBearer, 1, "issues", base)
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		origin      string
		mode        CredentialMode
		epoch       uint64
		connectorID string
		operation   ConnectorOperation
	}{
		{origin: "https://other.example.test", mode: CredentialModeBearer, epoch: 1, connectorID: "issues", operation: base},
		{origin: "https://api.example.test", mode: CredentialModeXAPIKey, epoch: 1, connectorID: "issues", operation: base},
		{origin: "https://api.example.test", mode: CredentialModeBearer, epoch: 2, connectorID: "issues", operation: base},
		{origin: "https://api.example.test", mode: CredentialModeBearer, epoch: 1, connectorID: "other", operation: base},
		{origin: "https://api.example.test", mode: CredentialModeBearer, epoch: 1, connectorID: "issues", operation: ConnectorOperation{ID: "update", Method: http.MethodPost, Path: "/v1/issues"}},
		{origin: "https://api.example.test", mode: CredentialModeBearer, epoch: 1, connectorID: "issues", operation: ConnectorOperation{ID: "create", Method: http.MethodPut, Path: "/v1/issues"}},
		{origin: "https://api.example.test", mode: CredentialModeBearer, epoch: 1, connectorID: "issues", operation: ConnectorOperation{ID: "create", Method: http.MethodPost, Path: "/v2/issues"}},
	}
	for _, variant := range variants {
		got, err := ConnectorOperationPolicyDigest(variant.origin, variant.mode, variant.epoch, variant.connectorID, variant.operation)
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			t.Fatalf("operation policy digest ignored changed route: %#v", variant)
		}
	}
	if _, err := ConnectorOperationPolicyDigest("https://api.example.test/path", CredentialModeBearer, 1, "issues", base); err == nil {
		t.Fatal("operation policy digest accepted a non-origin base URL")
	}
	if _, err := ConnectorOperationPolicyDigest("https://api.example.test", "cookie", 1, "issues", base); err == nil {
		t.Fatal("operation policy digest accepted an unsupported credential mode")
	}
}

func TestConnectorRejectsPermitHeaderWhenPolicyDoesNotRequireIt(t *testing.T) {
	rig := newConnectorRig(t, "https://api.example.test", connectorRigOptions{})
	request := connectorRequest(http.MethodGet, "issues", "read", "task-unconfigured-permit", nil)
	request.Header.Set(actionPermitHeader, "unexpected")
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"error":"action_permit_denied"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectorActionAuthorityCannotCrossTenantBoundary(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true,
	})
	body := []byte(`{"title":"tenant-bound"}`)
	header, _ := actionPermitFor(t, rig, "task-tenant-scope", "create", body, nil)
	connector := rig.server.connectors["issues"]
	connector.authorityTenants["approver-a"] = "tenant-b"
	rig.server.connectors["issues"] = connector
	request := connectorRequest(http.MethodPost, "issues", "create", "task-tenant-scope", bytes.NewReader(body))
	request.Header.Set(actionPermitHeader, header)
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"error":"action_permit_denied"`) || calls.Load() != 0 {
		t.Fatalf("cross-tenant permit status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
}

func TestPermitConnectorGrantRequiresAuthorityForEveryTenantRoute(t *testing.T) {
	rig := newConnectorRig(t, "https://api.example.test", connectorRigOptions{requirePermit: true})
	foreignTenant := connectorGrant("tenant-b", "agent-b", 1, "issues")
	if rig.server.validGrant(foreignTenant) {
		t.Fatal("permit connector grant accepted without an action authority for its tenant")
	}

	foreignConnector := rig.server.connectors["issues"]
	foreignConnector.ID = "foreign"
	foreignConnector.authorityTenants = map[string]string{"approver-a": "tenant-b"}
	rig.server.connectors["foreign"] = foreignConnector
	mixed := connectorGrant("tenant-a", "agent-mixed", 1, "foreign", "issues")
	if rig.server.validGrant(mixed) {
		t.Fatal("mixed connector grant accepted when one permit connector had no tenant authority")
	}
}

func TestConnectorRechecksPermitExpiryAfterDurableSpend(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, requirePermit: true,
	})
	body := []byte(`{"title":"expires-during-spend"}`)
	header, _ := actionPermitFor(t, rig, "task-expiry-fence", "create", body, nil)
	validNow := time.Now().UTC()
	var reads atomic.Int64
	rig.server.now = func() time.Time {
		if reads.Add(1) == 1 {
			return validNow
		}
		return validNow.Add(10 * time.Minute)
	}
	request := connectorRequest(http.MethodPost, "issues", "create", "task-expiry-fence", bytes.NewReader(body))
	request.Header.Set(actionPermitHeader, header)
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("expired-after-spend status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}
	var events []connectorledger.Event
	_, err := connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			events = append(events, record.Receipt.Event)
			return nil
		},
	)
	if err != nil || len(events) != 2 || events[0].Phase != connectorledger.Authorize ||
		events[1].Phase != connectorledger.Terminal || events[1].ErrorCode != "action_permit_expired" {
		t.Fatalf("expiry events=%#v err=%v", events, err)
	}
}

func TestConnectorBrokersExactOperationAndStripsCallerAuthority(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.URL.Path != "/v1/issues" || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "Bearer operator-secret" || request.Header.Get("X-API-Key") != "" ||
			request.Header.Get("Cookie") != "" || request.Header.Get("Proxy-Authorization") != "" ||
			request.Header.Get("X-Smuggled") != "" || request.Header.Get("X-Steward-Task-ID") != "" ||
			request.Header.Get("Content-Type") != "application/json" || string(body) != `{"title":"bounded"}` {
			t.Errorf("unsafe upstream request: method=%s url=%s headers=%v body=%s", request.Method, request.URL, request.Header, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "upstream=secret")
		w.Header().Set("Location", "/hidden")
		w.Header().Set("Authorization", "Bearer reflected-secret")
		w.Header().Set("X-API-Key", "reflected-api-key")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":7}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	request := connectorRequest(http.MethodPost, "issues", "create", "task-create-1", strings.NewReader(`{"title":"bounded"}`))
	request.Header.Set("Authorization", "Bearer agent-secret")
	request.Header.Set("Proxy-Authorization", "Bearer outer-secret")
	request.Header.Set("X-API-Key", "agent-api-key")
	request.Header.Set("Cookie", "agent=secret")
	request.Header.Set("Connection", "X-Smuggled")
	request.Header.Set("X-Smuggled", "must-not-pass")
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusCreated || response.Body.String() != `{"id":7}` || calls.Load() != 1 ||
		response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" ||
		response.Header().Get("Authorization") != "" || response.Header().Get("X-API-Key") != "" {
		t.Fatalf("response status=%d headers=%v body=%q calls=%d", response.Code, response.Header(), response.Body.String(), calls.Load())
	}
	state, err := os.ReadFile(rig.config.StateFile)
	if err != nil || bytes.Contains(state, []byte("operator-secret")) || bytes.Contains(state, []byte("task-create-1")) ||
		bytes.Contains(state, []byte(ConnectorCallDigest("tenant-a", "agent-a", "task-create-1", "issues", "create"))) {
		t.Fatalf("unsafe mutable state=%s err=%v", state, err)
	}
	var receipts []connectorledger.Event
	_, err = connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			receipts = append(receipts, record.Receipt.Event)
			return nil
		},
	)
	if err != nil || len(receipts) != 2 || receipts[0].Phase != connectorledger.Authorize ||
		receipts[1].Phase != connectorledger.Terminal ||
		receipts[0].TaskDigest != ConnectorCallDigest("tenant-a", "agent-a", "task-create-1", "issues", "create") ||
		receipts[0].RoutePolicyDigest == "" || receipts[1].ResponseBytes != int64(len(`{"id":7}`)) {
		t.Fatalf("receipts=%#v err=%v", receipts, err)
	}
}

func TestBlockedConnectorReceiptDoesNotBlockOtherGrantControl(t *testing.T) {
	rig := newConnectorRig(t, "https://api.example.test", connectorRigOptions{})
	other := connectorGrant("tenant-b", "agent-b", 1, "issues")
	registerConnectorGrant(t, rig.server, other)
	activateConnectorGrant(t, rig.server, other.GrantID)
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	blocked := &blockingConnectorReceiptLog{entered: make(chan struct{}), release: make(chan struct{})}
	rig.server.connectorLedger = blocked
	digest := ConnectorCallDigest(rig.grant.TenantID, rig.grant.InstanceID, "blocked-task", "issues", "create")
	receipt := connectorReceiptEvent(
		rig.grant, rig.server.policyDigests[rig.grant.GrantID], "issues", "create", digest, "", "", "", 2,
		"",
	)
	spendDone := make(chan error, 1)
	go func() { spendDone <- rig.server.spendConnectorCall(rig.grant.GrantID, "issues", digest, receipt) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("connector receipt append did not block")
	}

	controlDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		rig.server.ControlHandler().ServeHTTP(
			response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+other.GrantID+"/deactivate", nil),
		)
		controlDone <- response
	}()
	select {
	case response := <-controlDone:
		if response.Code != http.StatusOK {
			t.Fatalf("unrelated deactivation status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		close(blocked.release)
		t.Fatal("blocked receipt append stalled unrelated grant control")
	}
	health := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", health.Code, health.Body.String())
	}

	close(blocked.release)
	if err := <-spendDone; err == nil {
		t.Fatal("fixture connector spend unexpectedly succeeded")
	}
	rig.server.mu.Lock()
	_, retained := rig.server.connectorSpends[digest]
	count := rig.server.connectorCallCounts[rig.grant.GrantID]["issues"]
	rig.server.mu.Unlock()
	if retained || count != 0 {
		t.Fatalf("definite pre-append failure retained reservation=%t count=%d", retained, count)
	}
}

func TestAmbiguousConnectorReceiptFailureRetainsSpend(t *testing.T) {
	rig := newConnectorRig(t, "https://api.example.test", connectorRigOptions{})
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	close(release)
	rig.server.connectorLedger = &blockingConnectorReceiptLog{
		entered: make(chan struct{}), release: release, failed: true,
	}
	digest := ConnectorCallDigest(rig.grant.TenantID, rig.grant.InstanceID, "ambiguous-task", "issues", "create")
	receipt := connectorReceiptEvent(
		rig.grant, rig.server.policyDigests[rig.grant.GrantID], "issues", "create", digest, "", "", "", 2,
		"",
	)
	if err := rig.server.spendConnectorCall(rig.grant.GrantID, "issues", digest, receipt); err == nil {
		t.Fatal("ambiguous fixture append unexpectedly succeeded")
	}
	rig.server.mu.Lock()
	_, retained := rig.server.connectorSpends[digest]
	count := rig.server.connectorCallCounts[rig.grant.GrantID]["issues"]
	rig.server.mu.Unlock()
	if !retained || count != 1 {
		t.Fatalf("ambiguous append retained=%t count=%d", retained, count)
	}
}

func TestConnectorXAPIKeyModeInjectsOnlyFixedHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-API-Key") != "operator-secret" || request.Header.Get("Authorization") != "" {
			t.Errorf("credential headers=%v", request.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		credentialMode: CredentialModeXAPIKey, allowedCIDRs: []string{"127.0.0.0/8"},
	})
	request := connectorRequest(http.MethodGet, "issues", "read", "task-read-1", nil)
	request.Header.Set("Authorization", "Bearer agent")
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectorReceiptSignalSurvivesHTTPFraming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set(connectorReceiptStatusTrailer, "forged")
		w.Header().Set(streamStatusTrailer, "forged")
		w.Header().Set("X-Steward-Forged", "forged")
		if request.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	gatewayServer := httptest.NewServer(rig.server.connectorHandler(rig.grant.GrantID))
	defer gatewayServer.Close()

	post, err := http.NewRequest(http.MethodPost, gatewayServer.URL+"/v1/connectors/issues/operations/create", strings.NewReader(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("X-Steward-Task-ID", "task-no-body")
	response, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent ||
		response.Header.Get(connectorReceiptStatusTrailer) != "recorded" || response.Trailer.Get(connectorReceiptStatusTrailer) != "" ||
		response.Header.Get(streamStatusTrailer) != "" || response.Header.Get("X-Steward-Forged") != "" {
		t.Fatalf("no-body status=%d header=%q trailers=%v read=%v close=%v", response.StatusCode,
			response.Header.Get(connectorReceiptStatusTrailer), response.Trailer, readErr, closeErr)
	}

	get, err := http.NewRequest(http.MethodGet, gatewayServer.URL+"/v1/connectors/issues/operations/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("X-Steward-Task-ID", "task-streamed")
	response, err = http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != `{"ok":true}` ||
		response.Header.Get(connectorReceiptStatusTrailer) != "" || response.Trailer.Get(connectorReceiptStatusTrailer) != "recorded" ||
		response.Header.Get(streamStatusTrailer) != "" || response.Header.Get("X-Steward-Forged") != "" {
		t.Fatalf("stream status=%d header=%q trailers=%v body=%q read=%v close=%v", response.StatusCode,
			response.Header.Get(connectorReceiptStatusTrailer), response.Trailer, body, readErr, closeErr)
	}
}

func TestCredentialRejectingWriterDetectsSplitCredential(t *testing.T) {
	tests := []struct {
		name      string
		chunks    []string
		want      string
		reflected bool
	}{
		{name: "split reflection", chunks: []string{"safe:operator-", "secret:unsafe"}, want: "safe:", reflected: true},
		{name: "near miss", chunks: []string{"safe:operator-secre", "X:done"}, want: "safe:operator-secreX:done"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			filter := credentialRejectingWriter{destination: &output, credential: []byte("operator-secret")}
			var writeErr error
			for _, chunk := range test.chunks {
				if _, writeErr = filter.Write([]byte(chunk)); writeErr != nil {
					break
				}
			}
			if writeErr == nil {
				writeErr = filter.finish()
			}
			if errors.Is(writeErr, errConnectorCredentialReflected) != test.reflected || output.String() != test.want {
				t.Fatalf("output=%q error=%v reflected=%t", output.String(), writeErr, filter.reflected)
			}
		})
	}
}

func TestCredentialRejectingWriterCoalescesTinyWrites(t *testing.T) {
	var output bytes.Buffer
	filter := credentialRejectingWriter{destination: &output, credential: []byte("operator-secret")}
	for range connectorCredentialScanBlockBytes - 1 {
		if _, err := filter.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if output.Len() != 0 {
		t.Fatalf("tiny writes were scanned before the fixed block filled: wrote %d bytes", output.Len())
	}
	for _, value := range []byte("xoperator-secret") {
		if _, err := filter.Write([]byte{value}); err != nil {
			if !errors.Is(err, errConnectorCredentialReflected) {
				t.Fatal(err)
			}
			break
		}
	}
	if err := filter.finish(); !errors.Is(err, errConnectorCredentialReflected) {
		t.Fatalf("finish error = %v", err)
	}
	if !filter.reflected || bytes.Contains(output.Bytes(), []byte("operator-secret")) {
		t.Fatalf("reflected=%t output length=%d", filter.reflected, output.Len())
	}
}

func TestConnectorRejectsReflectedCredentialResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":"prefix","value":"operator-`))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte(`secret","unsafe":true}`))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	gatewayServer := httptest.NewServer(rig.server.connectorHandler(rig.grant.GrantID))
	defer gatewayServer.Close()

	request, err := http.NewRequest(http.MethodGet,
		gatewayServer.URL+"/v1/connectors/issues/operations/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Steward-Task-ID", "task-reflected-credential")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr == nil || closeErr != nil || bytes.Contains(body, []byte("operator-")) ||
		response.Trailer.Get(connectorReceiptStatusTrailer) != "" {
		t.Fatalf("body=%q read=%v close=%v trailers=%v", body, readErr, closeErr, response.Trailer)
	}
	assertConnectorTerminalReceipt(t, rig, "task-reflected-credential", "read", "credential_reflected")
}

func TestConnectorRejectsReflectedCredentialHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "value", header: "X-Upstream-Debug", value: "token=operator-secret"},
		{name: "field name", header: "X-Operator-Secret-Debug", value: "present"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(test.header, test.value)
				_, _ = w.Write([]byte(`{"safe":true}`))
			}))
			defer upstream.Close()
			rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
			taskID := "task-reflected-header-" + strings.ReplaceAll(test.name, " ", "-")
			request := connectorRequest(http.MethodGet, "issues", "read", taskID, nil)
			response := invokeConnector(rig.server, rig.grant.GrantID, request)
			if response.Code != http.StatusBadGateway ||
				!strings.Contains(response.Body.String(), `"error":"credential_reflected"`) ||
				response.Header().Get(test.header) != "" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			assertConnectorTerminalReceipt(t, rig, taskID, "read", "credential_reflected")
		})
	}
}

func TestConnectorReplaySurvivesRestartAndIsScopedToLogicalInstance(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})

	denied := connectorRequest(http.MethodGet, "other", "read", "task-cross", nil)
	if response := invokeConnector(rig.server, rig.grant.GrantID, denied); response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("cross-grant status=%d calls=%d", response.Code, calls.Load())
	}
	first := connectorRequest(http.MethodPost, "issues", "create", "task-durable", strings.NewReader(`{"x":1}`))
	if response := invokeConnector(rig.server, rig.grant.GrantID, first); response.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("first status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
	duplicate := connectorRequest(http.MethodPost, "issues", "create", "task-durable", strings.NewReader(`{"x":2}`))
	if response := invokeConnector(rig.server, rig.grant.GrantID, duplicate); response.Code != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("duplicate status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}

	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()
	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
	}()
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	afterRestart := connectorRequest(http.MethodPost, "issues", "create", "task-durable", strings.NewReader(`{"x":3}`))
	if response := invokeConnector(reopened, rig.grant.GrantID, afterRestart); response.Code != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("restart replay status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}

	secondGrant := connectorGrant("tenant-b", "agent-b", 1, "issues")
	registerConnectorGrant(t, reopened, secondGrant)
	activateConnectorGrant(t, reopened, secondGrant.GrantID)
	otherGrantTask := connectorRequest(http.MethodPost, "issues", "create", "task-durable", strings.NewReader(`{"x":4}`))
	if response := invokeConnector(reopened, secondGrant.GrantID, otherGrantTask); response.Code != http.StatusNoContent || calls.Load() != 2 {
		t.Fatalf("other grant status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}

	controlRequest(t, reopened, http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil, http.StatusOK)
	controlRequest(t, reopened, http.MethodDelete, "/v1/grants/"+rig.grant.GrantID, nil, http.StatusNoContent)
	replacement := connectorGrant("tenant-a", "agent-a", 2, "issues")
	registerConnectorGrant(t, reopened, replacement)
	activateConnectorGrant(t, reopened, replacement.GrantID)
	replacementTask := connectorRequest(http.MethodPost, "issues", "create", "task-durable", strings.NewReader(`{"x":5}`))
	if response := invokeConnector(reopened, replacement.GrantID, replacementTask); response.Code != http.StatusConflict || calls.Load() != 2 {
		t.Fatalf("replacement replay status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
}

func TestConnectorReceiptTombstoneSurvivesUnregisterAndStateDeletion(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	invoke := func(server *Server) int {
		request := connectorRequest(http.MethodPost, "issues", "create", "task-tombstone", strings.NewReader(`{"x":1}`))
		return invokeConnector(server, rig.grant.GrantID, request).Code
	}
	if status := invoke(rig.server); status != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("initial status=%d calls=%d", status, calls.Load())
	}
	controlRequest(t, rig.server, http.MethodDelete, "/v1/grants/"+rig.grant.GrantID, nil, http.StatusNoContent)
	registerConnectorGrant(t, rig.server, rig.grant)
	activateConnectorGrant(t, rig.server, rig.grant.GrantID)
	if status := invoke(rig.server); status != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("post-unregister replay status=%d calls=%d", status, calls.Load())
	}

	rig.server.closeGrantListeners()
	_ = rig.server.audit.Close()
	_ = rig.server.connectorLedger.Close()
	if err := os.Remove(rig.config.StateFile); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(rig.config, nil, nil, "service-token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		reopened.closeGrantListeners()
		_ = reopened.audit.Close()
		_ = reopened.connectorLedger.Close()
	}()
	registerConnectorGrant(t, reopened, rig.grant)
	activateConnectorGrant(t, reopened, rig.grant.GrantID)
	if status := invoke(reopened); status != http.StatusConflict || calls.Load() != 1 {
		t.Fatalf("post-state-deletion replay status=%d calls=%d", status, calls.Load())
	}
}

func TestConnectorRejectsGrantIDDirectoryPrefixAlias(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	prefix := rig.grant.GrantID[:len("grant-")+32]
	suffix := strings.Repeat("f", 32)
	if prefix+suffix == rig.grant.GrantID {
		suffix = strings.Repeat("e", 32)
	}
	alias := connectorGrant("tenant-b", "agent-b", 1, "issues")
	alias.GrantID = prefix + suffix
	raw, _ := json.Marshal(alias)
	response := httptest.NewRecorder()
	rig.server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("prefix alias status=%d body=%s", response.Code, response.Body.String())
	}
	request := connectorRequest(http.MethodGet, "issues", "read", "task-victim-still-bound", nil)
	if response := invokeConnector(rig.server, rig.grant.GrantID, request); response.Code != http.StatusNoContent {
		t.Fatalf("victim listener changed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectorFinalCallBudgetRaceHasOneUpstreamEffect(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, maxCalls: 1, maxConcurrent: 2,
	})
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for _, taskID := range []string{"task-race-a", "task-race-b"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := connectorRequest(http.MethodPost, "issues", "create", taskID, strings.NewReader(`{"x":1}`))
			statuses <- invokeConnector(rig.server, rig.grant.GrantID, request).Code
		}()
	}
	close(start)
	wait.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusNoContent] != 1 || counts[http.StatusTooManyRequests] != 1 || calls.Load() != 1 {
		t.Fatalf("statuses=%v upstream calls=%d", counts, calls.Load())
	}
}

func TestConnectorAttemptBudgetLimitsInvalidWorkAndRecovers(t *testing.T) {
	server := &Server{
		grants: map[string]Grant{
			"grant-a": {GrantID: "grant-a"},
			"grant-b": {GrantID: "grant-b"},
		},
		connectorAttempts: make(map[string]connectorAttemptWindow),
	}
	started := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	for attempt := 0; attempt < maxConnectorAttemptsPerMinute; attempt++ {
		if !server.allowConnectorAttempt("grant-a", started.Add(time.Duration(attempt)*time.Millisecond)) {
			t.Fatalf("attempt %d denied before fixed-window limit", attempt)
		}
	}
	if server.allowConnectorAttempt("grant-a", started.Add(30*time.Second)) {
		t.Fatal("attempt beyond fixed-window limit was accepted")
	}
	if !server.allowConnectorAttempt("grant-b", started.Add(30*time.Second)) {
		t.Fatal("one grant exhausted another grant's attempt budget")
	}
	if server.allowConnectorAttempt("grant-a", started.Add(-time.Second)) {
		t.Fatal("clock rollback restored attempt authority")
	}
	if !server.allowConnectorAttempt("grant-a", started.Add(time.Minute)) {
		t.Fatal("attempt budget did not recover after the fixed window")
	}
	server.mu.Lock()
	delete(server.grants, "grant-a")
	delete(server.connectorAttempts, "grant-a")
	server.mu.Unlock()
	if server.allowConnectorAttempt("grant-a", started.Add(2*time.Minute)) {
		t.Fatal("late request for an unregistered grant was accepted")
	}
	server.mu.Lock()
	_, recreated := server.connectorAttempts["grant-a"]
	server.mu.Unlock()
	if recreated {
		t.Fatal("late request recreated connector limiter state for an unregistered grant")
	}
}

func TestConnectorAttemptProductionClockReadIsSerialized(t *testing.T) {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	server := &Server{grants: map[string]Grant{"grant-a": {GrantID: "grant-a"}}}
	var sampledOutsideLock atomic.Bool
	clock := func() time.Time {
		if server.mu.TryLock() {
			sampledOutsideLock.Store(true)
			server.mu.Unlock()
		}
		return now
	}

	if !server.allowConnectorAttemptWithClock("grant-a", clock) {
		t.Fatal("first connector attempt was denied")
	}
	if sampledOutsideLock.Load() {
		t.Fatal("production connector limiter sampled its clock before taking the state lock")
	}
}

func TestConnectorAuthorizationReceiptFailurePreventsUpstreamEffect(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	response := invokeConnector(rig.server, rig.grant.GrantID,
		connectorRequest(http.MethodPost, "issues", "create", "task-no-receipt", strings.NewReader(`{"title":"blocked"}`)))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"evidence_unavailable"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream received %d calls without durable authorization", calls.Load())
	}
}

func TestConnectorTenantReceiptQuotaFailsBeforeUpstreamEffect(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	rig.server.connectorLedger = refusingConnectorReceiptLog{err: connectorledger.ErrTenantQuotaExceeded}
	response := invokeConnector(rig.server, rig.grant.GrantID,
		connectorRequest(http.MethodPost, "issues", "create", "task-quota", strings.NewReader(`{"title":"blocked"}`)))
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"error":"connector_evidence_quota_exhausted"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream received %d calls without a tenant receipt reservation", calls.Load())
	}
}

func TestConnectorDNSPrivatePolicyAndRedirectsFailClosedAfterSpend(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path == "/v1/issues" {
			http.Redirect(w, request, "/redirect-target", http.StatusFound)
			return
		}
		t.Error("connector followed redirect")
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	dnsOrigin := "http://localhost:" + parsed.Port()
	rig := newConnectorRig(t, dnsOrigin, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}, maxCalls: 3})
	request := connectorRequest(http.MethodPost, "issues", "create", "task-redirect", strings.NewReader(`{"x":1}`))
	response := invokeConnector(rig.server, rig.grant.GrantID, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "redirect_denied") || calls.Load() != 1 {
		t.Fatalf("redirect status=%d body=%s calls=%d", response.Code, response.Body.String(), calls.Load())
	}

	privateRig := newConnectorRig(t, upstream.URL, connectorRigOptions{maxCalls: 2})
	denied := connectorRequest(http.MethodPost, "issues", "create", "task-private", strings.NewReader(`{"x":1}`))
	response = invokeConnector(privateRig.server, privateRig.grant.GrantID, denied)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "address_denied") ||
		privateRig.server.connectorCallCounts[privateRig.grant.GrantID]["issues"] != 1 {
		t.Fatalf("private status=%d body=%s counts=%#v", response.Code, response.Body.String(), privateRig.server.connectorCallCounts)
	}
	replay := connectorRequest(http.MethodPost, "issues", "create", "task-private", strings.NewReader(`{"x":1}`))
	if response = invokeConnector(privateRig.server, privateRig.grant.GrantID, replay); response.Code != http.StatusConflict {
		t.Fatalf("address-denied replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectorResolutionFailuresRecordSignedTerminalReceipts(t *testing.T) {
	originalResolver := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = originalResolver })

	t.Run("resolution failure", func(t *testing.T) {
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("fixture DNS failure")
			},
		}
		rig := newConnectorRig(t, "https://resolution-failure.example", connectorRigOptions{})
		response := invokeConnector(rig.server, rig.grant.GrantID,
			connectorRequest(http.MethodGet, "issues", "read", "task-resolution-failure", nil))
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), `"error":"resolution_failed"`) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		assertConnectorTerminalReceipt(t, rig, "task-resolution-failure", "read", "resolution_failed")
	})

	t.Run("grant revoked during resolution", func(t *testing.T) {
		entered := make(chan struct{})
		var once sync.Once
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				once.Do(func() { close(entered) })
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		rig := newConnectorRig(t, "https://resolution-revocation.example", connectorRigOptions{})
		responseReady := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			responseReady <- invokeConnector(rig.server, rig.grant.GrantID,
				connectorRequest(http.MethodGet, "issues", "read", "task-resolution-revocation", nil))
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("connector did not enter address resolution")
		}

		deactivate := httptest.NewRecorder()
		rig.server.ControlHandler().ServeHTTP(deactivate,
			httptest.NewRequest(http.MethodPost, "/v1/grants/"+rig.grant.GrantID+"/deactivate", nil))
		if deactivate.Code != http.StatusOK {
			t.Fatalf("deactivate status=%d body=%s", deactivate.Code, deactivate.Body.String())
		}
		select {
		case response := <-responseReady:
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"grant_revoked"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		case <-time.After(time.Second):
			t.Fatal("connector did not stop after grant revocation")
		}
		assertConnectorTerminalReceipt(t, rig, "task-resolution-revocation", "read", "grant_revoked")
	})
}

func assertConnectorTerminalReceipt(t *testing.T, rig *connectorRig, taskID, operationID, errorCode string) {
	t.Helper()
	var receipts []connectorledger.Event
	_, err := connectorledger.VerifyRecords(
		rig.config.ConnectorReceiptFile, rig.config.connectorReceiptKey.Public().(ed25519.PublicKey),
		rig.config.ConnectorReceiptNodeID, rig.config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			receipts = append(receipts, record.Receipt.Event)
			return nil
		},
	)
	wantDigest := ConnectorCallDigest(rig.grant.TenantID, rig.grant.InstanceID, taskID, "issues", operationID)
	if err != nil || len(receipts) != 2 || receipts[0].Phase != connectorledger.Authorize ||
		receipts[0].TaskDigest != wantDigest || receipts[1].Phase != connectorledger.Terminal ||
		receipts[1].TaskDigest != wantDigest || receipts[1].Outcome != connectorledger.Failed ||
		receipts[1].ErrorCode != errorCode {
		t.Fatalf("receipts=%#v err=%v", receipts, err)
	}
}

func TestConnectorRequestAndResponseBounds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64))
	}))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{
		allowedCIDRs: []string{"127.0.0.0/8"}, maxRequestBytes: 16, maxResponseBytes: 16,
	})

	tests := []struct {
		name    string
		request *http.Request
		want    int
	}{
		{"missing task", connectorRequest(http.MethodPost, "issues", "create", "", strings.NewReader(`{"x":1}`)), http.StatusBadRequest},
		{"query", connectorRequest(http.MethodPost, "issues", "create", "task-query", strings.NewReader(`{"x":1}`)), http.StatusBadRequest},
		{"wrong method", connectorRequest(http.MethodDelete, "issues", "create", "task-method", nil), http.StatusForbidden},
		{"body on get", connectorRequest(http.MethodGet, "issues", "read", "task-get-body", strings.NewReader(`{}`)), http.StatusBadRequest},
		{"invalid json", connectorRequest(http.MethodPost, "issues", "create", "task-json", strings.NewReader(`{"x":`)), http.StatusBadRequest},
		{"duplicate json", connectorRequest(http.MethodPost, "issues", "create", "task-duplicate-json", strings.NewReader(`{"x":1,"x":2}`)), http.StatusBadRequest},
		{"oversized", connectorRequest(http.MethodPost, "issues", "create", "task-large", strings.NewReader(`{"value":"0123456789"}`)), http.StatusRequestEntityTooLarge},
	}
	tests[1].request.URL.RawQuery = "unsafe=1"
	tests[1].request.RequestURI += "?unsafe=1"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := invokeConnector(rig.server, rig.grant.GrantID, test.request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}

	valid := connectorRequest(http.MethodPost, "issues", "create", "task-response-large", strings.NewReader(`{"x":1}`))
	if response := invokeConnector(rig.server, rig.grant.GrantID, valid); response.Code != http.StatusBadGateway ||
		!strings.Contains(response.Body.String(), "response_too_large") {
		t.Fatalf("response bound status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConnectorGrantEvidenceAndReloadBindings(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	rig := newConnectorRig(t, upstream.URL, connectorRigOptions{allowedCIDRs: []string{"127.0.0.0/8"}})

	for _, mutate := range []func(*Grant){
		func(grant *Grant) { grant.RuntimeRef = "executor-bad" },
		func(grant *Grant) { grant.CapsuleDigest = "sha256:BAD" },
		func(grant *Grant) { grant.PolicyDigest = "" },
		func(grant *Grant) { grant.ConnectorIDs = []string{"issues", "alpha"} },
	} {
		grant := connectorGrant("tenant-b", "bad", 1, "issues")
		mutate(&grant)
		if rig.server.validGrant(grant) {
			t.Fatalf("invalid evidence-bound grant accepted: %#v", grant)
		}
	}
	unbudgeted := connectorGrant("tenant-c", "unbudgeted", 1, "issues")
	if rig.server.validGrant(unbudgeted) {
		t.Fatal("connector grant for an unbudgeted tenant was admitted")
	}

	changedConfig := rig.config
	changedConnectors := make(map[string]loadedConnector, len(rig.config.loadedConnectors))
	for id, connector := range rig.config.loadedConnectors {
		changedConnectors[id] = connector
	}
	changed := changedConnectors["issues"]
	changed.credential = "rotated-secret"
	changedConnectors["issues"] = changed
	changedConfig.loadedConnectors = changedConnectors
	if err := rig.server.Reload(changedConfig, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "retained grant") {
		t.Fatalf("credential-changing reload accepted: %v", err)
	}
	budgetConfig := rig.config
	budgetConfig.ConnectorReceiptTenantBudgets = append([]ConnectorReceiptTenantBudget(nil), rig.config.ConnectorReceiptTenantBudgets...)
	budgetConfig.ConnectorReceiptTenantBudgets[0].Bytes++
	if err := rig.server.Reload(budgetConfig, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "may change only") {
		t.Fatalf("tenant-budget-changing reload accepted: %v", err)
	}
	// A restart cannot overlap the old writer. Closing the live ledger also
	// proves the descriptor lock is released before the retained grant check.
	if err := rig.server.connectorLedger.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(budgetConfig, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "route policy") {
		if opened != nil {
			opened.closeGrantListeners()
			_ = opened.audit.Close()
		}
		t.Fatalf("tenant-budget-changing restart accepted: %v", err)
	}
	if opened, err := Open(changedConfig, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "route policy") {
		if opened != nil {
			opened.closeGrantListeners()
			_ = opened.audit.Close()
		}
		t.Fatalf("credential-changing restart accepted: %v", err)
	}
}
