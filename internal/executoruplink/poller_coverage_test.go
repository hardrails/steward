package executoruplink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
)

func TestNewPollerRejectsIncompleteAndInvalidConfiguration(t *testing.T) {
	credentialPath := tenantCredentialFile(t)
	state := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	valid := Config{
		BaseURL: "http://127.0.0.1:8080", CredentialPath: credentialPath,
		PollInterval: time.Second, Handler: handler, LocalToken: "local", State: state,
	}
	for name, mutate := range map[string]func(*Config){
		"zero interval":      func(c *Config) { c.PollInterval = 0 },
		"missing handler":    func(c *Config) { c.Handler = nil },
		"missing token":      func(c *Config) { c.LocalToken = "" },
		"missing state":      func(c *Config) { c.State = nil },
		"relative URL":       func(c *Config) { c.BaseURL = "/control" },
		"unsupported scheme": func(c *Config) { c.BaseURL = "ftp://127.0.0.1/control" },
		"malformed URL":      func(c *Config) { c.BaseURL = "http://%" },
		"missing credential": func(c *Config) { c.CredentialPath = filepath.Join(t.TempDir(), "missing.json") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if poller, err := NewPoller(candidate); err == nil || poller != nil {
				t.Fatalf("NewPoller = %#v, %v; want rejection", poller, err)
			}
		})
	}
	for host, want := range map[string]bool{
		"LOCALHOST": true, "127.0.0.1": true, "::1": true, "192.0.2.1": false, "not-an-ip": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Fatalf("isLoopbackHost(%q)=%v, want %v", host, got, want)
		}
	}
}

func TestNodeScopedPollerRejectsNodeMismatchAndInvalidPolicy(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := Config{
		BaseURL: "https://control.example", CredentialPath: credentialPath, PollInterval: time.Second,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), LocalToken: "local",
		State:          newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
		SecureExecutor: true, ProtectedTransport: true, SecureNodeID: "another-node", CommandPolicy: &policy,
	}
	if poller, err := NewPoller(base); err == nil || poller != nil {
		t.Fatal("node-scoped credential accepted for another Executor node")
	}
	base.SecureNodeID = "node-1"
	invalid := policy
	invalid.PolicyID = ""
	base.CommandPolicy = &invalid
	if poller, err := NewPoller(base); err == nil || poller != nil {
		t.Fatal("invalid signed command policy was accepted")
	}
}

func TestPollOnceRejectsMalformedControlPlaneResponses(t *testing.T) {
	tooMany := make([]json.RawMessage, maxCommandsPerPoll+1)
	for i := range tooMany {
		tooMany[i] = json.RawMessage(`{}`)
	}
	tooManyRaw, err := json.Marshal(pollResponse{Commands: tooMany})
	if err != nil {
		t.Fatal(err)
	}
	for name, response := range map[string]struct {
		status int
		body   string
	}{
		"HTTP rejection":        {status: http.StatusServiceUnavailable, body: `temporarily unavailable`},
		"oversized body":        {status: http.StatusOK, body: strings.Repeat("x", maxWireBytes+1)},
		"malformed JSON":        {status: http.StatusOK, body: `{"commands":[`},
		"missing command array": {status: http.StatusOK, body: `{}`},
		"wrong tenant protocol": {status: http.StatusOK, body: `{"protocol_version":2,"commands":[]}`},
		"too many commands":     {status: http.StatusOK, body: string(tooManyRaw)},
		"malformed command":     {status: http.StatusOK, body: `{"commands":[{"unknown":true}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(response.status)
				_, _ = io.WriteString(w, response.body)
			}))
			defer server.Close()
			poller := newTenantPollerForCoverage(t, server.URL, server.Client())
			if err := poller.pollOnce(context.Background()); err == nil {
				t.Fatal("malformed poll response was accepted")
			}
		})
	}
}

func TestPollOnceRejectsCredentialIdentityRotationAndUnavailableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"commands":[]}`)
	}))
	poller := newTenantPollerForCoverage(t, server.URL, server.Client())
	if err := os.WriteFile(poller.credentialPath, []byte(`{"version":1,"tenant_id":"tenant-b","node_id":"node-1","credential":"rotated"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "rotated") {
		t.Fatalf("identity-changing rotation error = %v", err)
	}

	unavailable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	poller = newTenantPollerForCoverage(t, unavailable.URL, unavailable.Client())
	unavailable.Close()
	if err := poller.pollOnce(context.Background()); err == nil {
		t.Fatal("unavailable poll endpoint returned nil")
	}
}

func TestNodeScopedPollRequiresProtocolTwo(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"read"})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"protocol_version":1,"commands":[]}`)
	}))
	defer server.Close()
	credentialPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credentialPath, []byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	poller, err := NewPoller(Config{
		BaseURL: server.URL, CredentialPath: credentialPath, PollInterval: time.Second,
		HTTPClient: server.Client(), Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "local", State: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true, CommandPolicy: &policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "protocol_version 2") {
		t.Fatalf("protocol mismatch error = %v", err)
	}
}

func TestSendReportRejectsEveryUnacknowledgedResponseShape(t *testing.T) {
	if err := (&Poller{}).sendReport(context.Background(), "credential", report{
		Result: map[string]any{"unsupported": func() {}},
	}); err == nil {
		t.Fatal("unencodable report was accepted")
	}
	if err := (&Poller{}).sendReport(context.Background(), "credential", report{
		Result: map[string]any{"large": strings.Repeat("x", maxWireBytes)},
	}); err == nil {
		t.Fatal("oversized report was accepted")
	}

	for name, response := range map[string]struct {
		status int
		body   string
	}{
		"HTTP rejection": {status: http.StatusConflict, body: "not current"},
		"oversized body": {status: http.StatusOK, body: strings.Repeat("x", maxWireBytes+1)},
		"malformed JSON": {status: http.StatusOK, body: `{`},
		"not applied":    {status: http.StatusOK, body: `{"applied":false}`},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(response.status)
				_, _ = io.WriteString(w, response.body)
			}))
			defer server.Close()
			poller := &Poller{reportURL: server.URL, client: server.Client()}
			if err := poller.sendReport(context.Background(), "credential", report{CommandID: "c"}); err == nil {
				t.Fatal("unacknowledged report returned nil")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"applied":true}`)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&Poller{reportURL: server.URL, client: server.Client()}).sendReport(ctx, "credential", report{}); err == nil {
		t.Fatal("canceled report request returned nil")
	}
}

func TestReadBoundedPropagatesReaderFailure(t *testing.T) {
	if _, err := readBounded(errorReader{}, 8); !errors.Is(err, errCoverageReader) {
		t.Fatalf("readBounded error = %v", err)
	}
}

func TestPollerRunReturnsWhenPollContextIsAlreadyCanceled(t *testing.T) {
	poller := newTenantPollerForCoverage(t, "http://127.0.0.1:1", &http.Client{})
	poller.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		poller.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after a canceled poll")
	}
}

func TestNodeCommandDecoderRejectsMalformedEnvelopeRoutingAndSignature(t *testing.T) {
	trustedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, untrustedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, trustedPublic, []string{"read"})
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	poller := &Poller{commandPolicy: &policy, now: func() time.Time { return now }}
	credential := nodeCredentialForTest()

	validSignature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for name, raw := range map[string][]byte{
		"malformed envelope": []byte(`{}`),
		"wrong payload type": mustJSON(t, dsse.Envelope{
			PayloadType: "application/example", Payload: base64.StdEncoding.EncodeToString([]byte(`{}`)),
			Signatures: []dsse.Signature{{KeyID: "tenant-command", Sig: validSignature}},
		}),
		"invalid payload base64": mustJSON(t, dsse.Envelope{
			PayloadType: admission.CommandPayloadType, Payload: "@@",
			Signatures: []dsse.Signature{{KeyID: "tenant-command", Sig: validSignature}},
		}),
		"invalid routing payload": mustJSON(t, dsse.Envelope{
			PayloadType: admission.CommandPayloadType, Payload: base64.StdEncoding.EncodeToString([]byte(`[]`)),
			Signatures: []dsse.Signature{{KeyID: "tenant-command", Sig: validSignature}},
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if command, err := poller.decodeCommand(raw, credential); err == nil || command.CommandID != "" {
				t.Fatalf("decodeCommand = %#v, %v; want rejection", command, err)
			}
		})
	}

	runtimeRef, err := RuntimeRefV2("tenant-a", "another-node", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2, CommandID: "signed-read",
		TenantID: "tenant-a", NodeID: "another-node", InstanceID: "agent-1", RuntimeRef: runtimeRef,
		Kind: "read", ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Payload: json.RawMessage(`{}`),
	}
	if _, err := poller.decodeCommand(signCommand(t, statement, "tenant-command", untrustedPrivate), credential); err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("untrusted signature error = %v", err)
	}
	_, trustedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy = commandPolicyFixture(t, trustedPrivate.Public().(ed25519.PublicKey), []string{"read"})
	poller.commandPolicy = &policy
	if _, err := poller.decodeCommand(signCommand(t, statement, "tenant-command", trustedPrivate), credential); err == nil || !strings.Contains(err.Error(), "another node") {
		t.Fatalf("wrong-node command error = %v", err)
	}
}

func tenantCredentialFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tenant_id":"tenant-a","node_id":"node-1","credential":"bearer"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTenantPollerForCoverage(t *testing.T, baseURL string, client *http.Client) *Poller {
	t.Helper()
	poller, err := NewPoller(Config{
		BaseURL: baseURL, CredentialPath: tenantCredentialFile(t), PollInterval: time.Second,
		HTTPClient: client, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		LocalToken: "local", State: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return poller
}

var errCoverageReader = errors.New("coverage reader failed")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errCoverageReader }
