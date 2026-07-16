package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/nodeclient"
)

func TestRunActivationRejectsGatewayPreflightBeforeAdvancing(t *testing.T) {
	fixture := newStateMachineActivationFixture(t)
	truncateActivationStateMachineFixture(t, fixture.directory, 0)
	timeNow = func() time.Time { return fixture.now }

	var output bytes.Buffer
	err := runActivation(fixture.runArgumentsWithoutLiveServices(), &output)
	if err == nil || !strings.Contains(err.Error(), "preflight Gateway") {
		t.Fatalf("run error = %v, want Gateway preflight failure", err)
	}
	if output.Len() != 0 {
		t.Fatalf("preflight failure wrote status: %s", output.String())
	}
	chain := loadActivationStateMachineChain(t, fixture.directory)
	if chain.latest().Phase != activation.PhaseNew || len(chain.states) != 1 {
		t.Fatalf("preflight failure advanced state: %#v", chain.states)
	}
}

func TestRunActivationFreshAdmissionResumesToCanaryHandoff(t *testing.T) {
	fixture := newStateMachineActivationFixture(t)
	admitted := readStateMachineAdmission(t, fixture.directory)
	truncateActivationStateMachineFixture(t, fixture.directory, 3)
	removeActivationStateMachineArtifacts(t, fixture.directory,
		activationstore.AdmissionFileName,
		activationstore.ExecutorBeginFileName,
		activationstore.CanaryRequestFileName,
		activationstore.CanaryChallengeFileName,
		activationstore.CanaryTaskFileName,
		activationstore.CanarySubmitFileName,
		activationstore.CanaryStatusFileName,
		activationstore.CanaryResultFileName,
		activationstore.ExecutorCheckpointFileName,
		activationstore.ExecutorDeltaFileName,
		activationstore.ExecutorFinalWitnessFileName,
		activationstore.GatewayTaskReceiptsFileName,
		activationstore.ProofFileName,
	)

	gatewayFixture := newStateMachineGatewayFixture(
		t, fixture.directory,
		http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			t.Errorf("unexpected Gateway call %s %s", request.Method, request.URL.Path)
			http.Error(writer, "unexpected", http.StatusInternalServerError)
		}),
	)
	defer gatewayFixture.server.Close()
	rebindStateMachineGatewayArtifacts(
		t, fixture.directory, gatewayFixture.serviceTrust,
		gatewayFixture.public,
	)

	var nodeCalls atomic.Int32
	nodeTokenPath := filepath.Join(t.TempDir(), "executor.token")
	if err := os.WriteFile(nodeTokenPath, []byte("executor-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nodeServer := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		nodeCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer executor-token" {
			t.Errorf("Executor authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet &&
			request.URL.Path == "/v1/workloads/"+admitted.RuntimeRef:
			writeStateMachineJSONError(
				writer, http.StatusNotFound, "not_found", "workload not found",
			)
		case request.Method == http.MethodPost &&
			request.URL.Path == "/v1/admissions":
			var body struct {
				Activation *struct {
					ActivationID string `json:"activation_id"`
					BeginDigest  string `json:"begin_digest"`
				} `json:"activation"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode admission request: %v", err)
			}
			if body.Activation == nil ||
				body.Activation.ActivationID != "activation-offline-test" ||
				!strings.HasPrefix(body.Activation.BeginDigest, "sha256:") {
				t.Errorf("activation admission identity = %#v", body.Activation)
			}
			state := stateMachineNodeState(admitted, "created")
			state.ActivationID = body.Activation.ActivationID
			state.ActivationBeginDigest = body.Activation.BeginDigest
			writeStateMachineJSON(writer, http.StatusCreated, state)
		case request.Method == http.MethodPost &&
			request.URL.Path == "/v1/workloads/"+admitted.RuntimeRef+"/start":
			writeStateMachineJSON(
				writer, http.StatusOK, stateMachineNodeState(admitted, "running"),
			)
		default:
			t.Errorf("unexpected Executor call %s %s", request.Method, request.URL.Path)
			writeStateMachineJSONError(
				writer, http.StatusNotFound, "not_found", "unexpected request",
			)
		}
	}))
	defer nodeServer.Close()

	timeNow = func() time.Time { return fixture.now.Add(3 * time.Minute) }
	arguments := stateMachineRunArguments(
		fixture,
		nodeServer.URL,
		nodeTokenPath,
		gatewayFixture.configPath,
	)
	var output bytes.Buffer
	if err := runActivation(arguments, &output); err != nil {
		t.Fatal(err)
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.Phase != activation.PhaseCanaryChallengeReady ||
		status.WaitingFor != "canary_task" ||
		status.NextCommand != activationAttachCanaryTaskCommand ||
		!status.Verified {
		t.Fatalf("activation status = %#v", status)
	}
	if nodeCalls.Load() != 3 {
		t.Fatalf("Executor calls = %d, want status, admit, start", nodeCalls.Load())
	}
	chain := loadActivationStateMachineChain(t, fixture.directory)
	wantPhases := []string{
		activation.PhaseImageImported,
		activation.PhaseAdmitted,
		activation.PhaseRunning,
		activation.PhaseCanaryChallengeReady,
	}
	for index, want := range wantPhases {
		if got := chain.states[index+3].Phase; got != want {
			t.Fatalf("state %d phase = %q, want %q", index+3, got, want)
		}
	}
	for _, name := range []string{
		activationstore.AdmissionFileName,
		activationstore.ExecutorBeginFileName,
		activationstore.CanaryRequestFileName,
		activationstore.CanaryChallengeFileName,
	} {
		if _, err := os.Stat(filepath.Join(fixture.directory, name)); err != nil {
			t.Fatalf("activation artifact %q missing: %v", name, err)
		}
	}
}

func TestRunActivationDispatchedCanaryPropagatesAndSticksFailures(
	t *testing.T,
) {
	fixture := newStateMachineActivationFixture(t)
	retainedSubmit := readStateMachineSubmit(t, fixture.directory)
	truncateActivationStateMachineFixture(t, fixture.directory, 6)
	removeActivationStateMachineArtifacts(t, fixture.directory,
		activationstore.CanarySubmitFileName,
		activationstore.CanaryStatusFileName,
		activationstore.CanaryResultFileName,
		activationstore.ExecutorCheckpointFileName,
		activationstore.ExecutorDeltaFileName,
		activationstore.ExecutorFinalWitnessFileName,
		activationstore.GatewayTaskReceiptsFileName,
		activationstore.ProofFileName,
	)

	var mode atomic.Int32
	var submitCalls atomic.Int32
	var statusCalls atomic.Int32
	resultRaw := activationHermesResult(
		t, "activation-offline-test", retainedSubmit.RunID,
	)
	var reboundSubmit activationSubmitRecord
	handler := http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		switch {
		case request.Method == http.MethodPost &&
			strings.HasPrefix(request.URL.Path, "/v1/services/"):
			submitCalls.Add(1)
			raw, err := json.Marshal(struct {
				RunID string `json:"run_id"`
			}{RunID: retainedSubmit.RunID})
			if err != nil {
				t.Error(err)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Steward-Service-Grant", "active")
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set(
				"X-Steward-Task-Receipt",
				string(gatewayclient.TaskReceiptRecorded),
			)
			writer.WriteHeader(http.StatusAccepted)
			if _, err := writer.Write(raw); err != nil {
				t.Errorf("write submit response: %v", err)
			}
		case request.Method == http.MethodGet &&
			strings.HasPrefix(request.URL.Path, "/v1/tasks/"):
			statusCalls.Add(1)
			if mode.Load() == 0 {
				writeStateMachineJSONError(
					writer, http.StatusServiceUnavailable,
					"gateway_unavailable", "temporary Gateway failure",
				)
				return
			}
			writeActivationGatewayResponse(
				t, writer, reboundSubmit,
				activationGatewayTerminalFields(
					resultRaw, "failed", false, retainedSubmit.RunID,
				),
			)
		default:
			t.Errorf("unexpected Gateway call %s %s", request.Method, request.URL.Path)
			writeStateMachineJSONError(
				writer, http.StatusNotFound, "not_found", "unexpected request",
			)
		}
	})
	gatewayFixture := newStateMachineGatewayFixture(
		t, fixture.directory, handler,
	)
	defer gatewayFixture.server.Close()
	rebindStateMachineGatewayArtifacts(
		t, fixture.directory, gatewayFixture.serviceTrust,
		gatewayFixture.public,
	)
	retainedSubmit.ReceiptPublicKeyBase64 = base64.StdEncoding.EncodeToString(
		gatewayFixture.public,
	)
	reboundSubmit = retainedSubmit

	timeNow = func() time.Time { return fixture.now.Add(3 * time.Minute) }
	arguments := stateMachineRunArguments(
		fixture,
		"http://127.0.0.1:1",
		filepath.Join(fixture.directory, "missing-node-token"),
		gatewayFixture.configPath,
	)

	var output bytes.Buffer
	err := runActivation(arguments, &output)
	var apiErr *gatewayclient.APIError
	if !errors.As(err, &apiErr) ||
		apiErr.Code != "gateway_unavailable" {
		t.Fatalf("transport error = %v, want Gateway API error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("retryable Gateway failure wrote terminal status: %s", output.String())
	}
	chain := loadActivationStateMachineChain(t, fixture.directory)
	if chain.latest().Phase != activation.PhaseCanaryDispatched ||
		len(chain.states) != 9 {
		t.Fatalf("retryable failure advanced activation: %#v", chain.states)
	}
	for _, state := range chain.states {
		if state.Phase == activation.PhaseAgentReportedTerminal {
			t.Fatalf("transport failure advanced to agent terminal: %#v", state)
		}
	}
	if submitCalls.Load() != 1 || statusCalls.Load() != 1 {
		t.Fatalf(
			"first run calls: submit=%d status=%d",
			submitCalls.Load(), statusCalls.Load(),
		)
	}

	mode.Store(1)
	output.Reset()
	err = runActivation(arguments, &output)
	var terminal *activationCanaryTerminalError
	if !errors.As(err, &terminal) ||
		terminal.state != string(gatewayclient.AgentReportedFailed) {
		t.Fatalf("terminal error = %v", err)
	}
	status := decodeActivationStatus(t, output.Bytes())
	if status.Phase != activation.PhaseActionRequired ||
		status.WaitingFor != "operator" ||
		!status.Verified {
		t.Fatalf("terminal status = %#v", status)
	}
	chain = loadActivationStateMachineChain(t, fixture.directory)
	if chain.latest().Phase != activation.PhaseActionRequired ||
		chain.latest().ActionRequiredReason != "canary_terminal_failure" {
		t.Fatalf("terminal failure state = %#v", chain.latest())
	}
	for _, state := range chain.states {
		if state.Phase == activation.PhaseAgentReportedTerminal {
			t.Fatalf("failed canary advanced to agent terminal: %#v", state)
		}
	}
	if submitCalls.Load() != 1 || statusCalls.Load() != 2 {
		t.Fatalf(
			"resume calls: submit=%d status=%d",
			submitCalls.Load(), statusCalls.Load(),
		)
	}
}

type stateMachineGatewayFixture struct {
	server       *httptest.Server
	configPath   string
	public       ed25519.PublicKey
	serviceTrust []byte
}

func newStateMachineGatewayFixture(
	t *testing.T,
	workspace string,
	handler http.Handler,
) stateMachineGatewayFixture {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	directory, err := os.MkdirTemp("/tmp", "steward-activation-gateway-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	tokenPath := filepath.Join(directory, "gateway.token")
	if err := os.WriteFile(tokenPath, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "gateway-receipt.private.pem")
	if err := os.WriteFile(
		privatePath,
		pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: privateDER,
		}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "gateway-receipts.ndjson")
	limits := connectorledger.Limits{TenantBudgets: map[string]int64{
		"tenant-a": connectorledger.MinimumLifecycleTenantBytes,
	}}
	log, err := connectorledger.OpenWithLimits(
		receiptPath, private, "node-a/gateway", 1, limits, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var retained serviceTrustInventory
	if err := json.Unmarshal(
		offlineRead(
			t, filepath.Join(workspace, activationstore.ServiceTrustFileName),
		),
		&retained,
	); err != nil {
		t.Fatal(err)
	}
	if len(retained.Services) != 1 ||
		len(retained.Services[0].Operations) != 1 {
		t.Fatalf("retained service trust = %#v", retained)
	}
	gid := os.Getgid()
	if gid == 0 {
		gid = 1
	}
	config := gateway.Config{
		Version:          1,
		ControlSocket:    filepath.Join(directory, "gateway.sock"),
		ServiceAddress:   strings.TrimPrefix(server.URL, "http://"),
		ServiceTokenFile: tokenPath,
		StateFile:        filepath.Join(directory, "gateway-state.json"),
		GrantRoot:        filepath.Join(directory, "grants"),
		ExecutorGID:      gid,
		RelayGID:         gid,
		ServiceOperations: []gateway.ServiceOperation{
			retained.Services[0].Operations[0].gatewayOperation(),
		},
		ConnectorReceiptFile:    receiptPath,
		ConnectorReceiptKeyFile: privatePath,
		ConnectorReceiptNodeID:  "node-a/gateway",
		ConnectorReceiptEpoch:   1,
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{
			TenantID: "tenant-a",
			Bytes:    connectorledger.MinimumLifecycleTenantBytes,
		}},
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var trust bytes.Buffer
	if err := writeServiceTrustInventory(
		&trust, config, "node-a", "tenant-a",
	); err != nil {
		t.Fatal(err)
	}
	return stateMachineGatewayFixture{
		server:       server,
		configPath:   configPath,
		public:       public,
		serviceTrust: trust.Bytes(),
	}
}

func rebindStateMachineGatewayArtifacts(
	t *testing.T,
	directory string,
	serviceTrust []byte,
	receiptPublic ed25519.PublicKey,
) {
	t.Helper()
	serviceTrustPath := filepath.Join(
		directory, activationstore.ServiceTrustFileName,
	)
	if err := os.WriteFile(serviceTrustPath, serviceTrust, 0o600); err != nil {
		t.Fatal(err)
	}
	challengePath := filepath.Join(
		directory, activationstore.CanaryChallengeFileName,
	)
	if raw, err := os.ReadFile(challengePath); err == nil {
		challenge, err := activation.ParseChallengeV1(raw)
		if err != nil {
			t.Fatal(err)
		}
		challenge.ServiceTrustDigest = dsse.Digest(serviceTrust)
		updated, err := activation.MarshalChallengeV1(challenge)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(challengePath, updated, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	submitPath := filepath.Join(
		directory, activationstore.CanarySubmitFileName,
	)
	if raw, err := os.ReadFile(submitPath); err == nil {
		var submit activationSubmitRecord
		if err := json.Unmarshal(raw, &submit); err != nil {
			t.Fatal(err)
		}
		submit.ReceiptPublicKeyBase64 = base64.StdEncoding.EncodeToString(
			receiptPublic,
		)
		updated, err := json.Marshal(submit)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(submitPath, updated, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func stateMachineNodeState(
	admitted permitAdmission,
	status string,
) nodeclient.State {
	authorities := make([]nodeclient.TaskAuthority, len(admitted.TaskAuthorities))
	for index, authority := range admitted.TaskAuthorities {
		authorities[index] = nodeclient.TaskAuthority{
			KeyID: authority.KeyID, PublicKey: authority.PublicKey,
		}
	}
	return nodeclient.State{
		RuntimeRef:        admitted.RuntimeRef,
		Status:            status,
		CapsuleDigest:     admitted.CapsuleDigest,
		PolicyDigest:      admitted.PolicyDigest,
		Generation:        admitted.Generation,
		EvidenceKeyID:     admitted.EvidenceKeyID,
		GrantID:           admitted.GrantID,
		ServicePath:       admitted.ServicePath,
		ServiceID:         admitted.ServiceID,
		TaskAuthorities:   authorities,
		EgressProxy:       admitted.EgressProxy,
		EgressRouteIDs:    append([]string(nil), admitted.EgressRouteIDs...),
		ConnectorURL:      admitted.ConnectorURL,
		ConnectorIDs:      append([]string(nil), admitted.ConnectorIDs...),
		RoutePolicyDigest: admitted.RoutePolicyDigest,
	}
}

func newStateMachineActivationFixture(
	t *testing.T,
) offlineActivationFixture {
	t.Helper()
	previousNow := timeNow
	fixture := newOfflineActivationFixture(t)
	t.Cleanup(func() { timeNow = previousNow })
	return fixture
}

func truncateActivationStateMachineFixture(
	t *testing.T,
	directory string,
	lastSequence uint64,
) {
	t.Helper()
	for sequence := lastSequence + 1; sequence < 12; sequence++ {
		name, err := activationstore.StateCheckpointName(sequence)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func removeActivationStateMachineArtifacts(
	t *testing.T,
	directory string,
	names ...string,
) {
	t.Helper()
	for _, name := range names {
		if err := os.Remove(filepath.Join(directory, name)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func readStateMachineAdmission(
	t *testing.T,
	directory string,
) permitAdmission {
	t.Helper()
	var admitted permitAdmission
	if err := json.Unmarshal(
		offlineRead(
			t, filepath.Join(directory, activationstore.AdmissionFileName),
		),
		&admitted,
	); err != nil {
		t.Fatal(err)
	}
	return admitted
}

func readStateMachineSubmit(
	t *testing.T,
	directory string,
) activationSubmitRecord {
	t.Helper()
	var submit activationSubmitRecord
	if err := json.Unmarshal(
		offlineRead(
			t, filepath.Join(directory, activationstore.CanarySubmitFileName),
		),
		&submit,
	); err != nil {
		t.Fatal(err)
	}
	return submit
}

func loadActivationStateMachineChain(
	t *testing.T,
	directory string,
) activationStateChain {
	t.Helper()
	store, err := activationstore.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, chain, loadErr := loadUnverifiedActivationStateChain(store)
	closeErr := store.Close()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return chain
}

func stateMachineRunArguments(
	fixture offlineActivationFixture,
	nodeURL string,
	nodeTokenPath string,
	gatewayConfigPath string,
) []string {
	arguments := fixture.runArgumentsWithoutLiveServices()
	for index := 0; index+1 < len(arguments); index += 2 {
		switch arguments[index] {
		case "-node-url":
			arguments[index+1] = nodeURL
		case "-node-token-file":
			arguments[index+1] = nodeTokenPath
		case "-gateway-config":
			arguments[index+1] = gatewayConfigPath
		}
	}
	return arguments
}

func writeStateMachineJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(raw)
}

func writeStateMachineJSONError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeStateMachineJSON(writer, status, struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{Error: code, Message: message})
}
