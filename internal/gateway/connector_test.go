package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
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

	"github.com/hardrails/steward/internal/connectorledger"
)

type connectorRigOptions struct {
	credentialMode   CredentialMode
	allowedCIDRs     []string
	maxConcurrent    int
	maxRequestBytes  int64
	maxResponseBytes int64
	maxCalls         int
}

type connectorRig struct {
	server    *Server
	config    Config
	grant     Grant
	connector loadedConnector
}

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
	directory, err := os.MkdirTemp("/tmp", "gc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	credential := filepath.Join(directory, "connector.token")
	if err := os.WriteFile(credential, []byte("operator-secret\n"), 0o600); err != nil {
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
	registerConnectorGrant(t, server, grant)
	activateConnectorGrant(t, server, grant.GrantID)
	return &connectorRig{server: server, config: config, grant: grant, connector: connectors["issues"]}
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
		bytes.Contains(state, []byte(connectorCallDigest("tenant-a", "agent-a", "task-create-1", "issues", "create"))) {
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
		receipts[0].TaskDigest != connectorCallDigest("tenant-a", "agent-a", "task-create-1", "issues", "create") ||
		receipts[0].RoutePolicyDigest == "" || receipts[1].ResponseBytes != int64(len(`{"id":7}`)) {
		t.Fatalf("receipts=%#v err=%v", receipts, err)
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
		response.Header.Get(connectorReceiptStatusTrailer) != "recorded" || response.Trailer.Get(connectorReceiptStatusTrailer) != "" {
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
		response.Header.Get(connectorReceiptStatusTrailer) != "" || response.Trailer.Get(connectorReceiptStatusTrailer) != "recorded" {
		t.Fatalf("stream status=%d header=%q trailers=%v body=%q read=%v close=%v", response.StatusCode,
			response.Header.Get(connectorReceiptStatusTrailer), response.Trailer, body, readErr, closeErr)
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
	server := &Server{connectorAttempts: make(map[string]connectorAttemptWindow)}
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
	if opened, err := Open(changedConfig, nil, nil, "service-token"); err == nil || !strings.Contains(err.Error(), "route policy") {
		if opened != nil {
			opened.closeGrantListeners()
			_ = opened.audit.Close()
		}
		t.Fatalf("credential-changing restart accepted: %v", err)
	}
}
