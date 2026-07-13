package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestGatewayRouteSetIsValidatedAndAtomic(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid()}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, _ := json.Marshal(config)
	path := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"gateway", "route", "set", "-config", path, "-id", "public-web",
		"-destination", "api.example.com:443", "-destination", "*.example.org:443"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	loaded, _, egress, _, err := gateway.LoadConfig(path)
	if err != nil || len(loaded.EgressRoutes) != 1 || len(egress) != 1 || loaded.EgressAuditFile == "" || !strings.Contains(output.String(), "systemctl reload") {
		t.Fatalf("loaded=%#v egress=%d output=%q err=%v", loaded, len(egress), output.String(), err)
	}
	before, _ := os.ReadFile(path)
	if err := run([]string{"gateway", "route", "set", "-config", path, "-id", "bad", "-destination", "missing-port"}, &output, &output); err == nil {
		t.Fatal("invalid destination accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid update changed gateway config")
	}
	output.Reset()
	if err := run([]string{"gateway", "validate", "-config", path}, &output, &output); err != nil || !strings.Contains(output.String(), "valid") {
		t.Fatalf("validate output=%q err=%v", output.String(), err)
	}
	output.Reset()
	if err := run([]string{"gateway", "route", "list", "-config", path}, &output, &output); err != nil || !strings.Contains(output.String(), "public-web") {
		t.Fatalf("list output=%q err=%v", output.String(), err)
	}
	output.Reset()
	if err := run([]string{"gateway", "route", "set", "-config", path, "-id", "public-web", "-destination", "10.1.2.3:8443", "-allow-cidr", "10.1.0.0/16"}, &output, &output); err != nil || !strings.Contains(output.String(), `"replaced": true`) {
		t.Fatalf("replace output=%q err=%v", output.String(), err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || loaded.EgressRoutes[0].Destinations[0].AllowedCIDRs[0] != "10.1.0.0/16" {
		t.Fatalf("reloaded=%#v err=%v", loaded, err)
	}
}

func TestGatewayCommandRejectsAmbiguousInputs(t *testing.T) {
	var output bytes.Buffer
	for _, arguments := range [][]string{
		{"gateway"}, {"gateway", "unknown"}, {"gateway", "route"}, {"gateway", "route", "remove"},
		{"gateway", "connector"}, {"gateway", "connector", "remove"},
		{"gateway", "route", "set", "-id", "web"}, {"gateway", "route", "set", "-id", "web", "-destination", "missing-port"},
		{"gateway", "connector", "set", "-id", "issues"},
		{"gateway", "validate", "extra"}, {"gateway", "route", "list", "-id", "unexpected"},
		{"gateway", "route", "list", "-max-concurrent", "7"},
	} {
		if err := run(arguments, &output, &output); err == nil {
			t.Fatalf("ambiguous command accepted: %v", arguments)
		}
	}
	var values repeatedFlag
	if err := values.Set(" "); err == nil {
		t.Fatal("empty repeated flag accepted")
	}
	if err := values.Set("value"); err != nil || values.String() != "value" {
		t.Fatalf("values=%v err=%v", values, err)
	}
	unsafe := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(unsafe, []byte(`{}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := writeGatewayConfig(unsafe, gateway.Config{}); err == nil {
		t.Fatal("unsafe config file accepted")
	}
}

func TestGatewayConnectorSetIsValidatedSecretFreeAndAtomic(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgcc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "service.token")
	credential := filepath.Join(directory, "connector.token")
	if err := os.WriteFile(token, []byte("service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("upstream-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(directory, "connector-receipts.private.pem")
	publicKey := filepath.Join(directory, "connector-receipts.public")
	if err := run([]string{"keygen", "-private-out", privateKey, "-public-out", publicKey}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), ConnectorReceiptFile: filepath.Join(directory, "connector-receipts.ndjson"),
		ConnectorReceiptKeyFile: privateKey, ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
	}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	arguments := []string{
		"gateway", "connector", "set", "-config", path, "-id", "issues", "-base-url", "https://api.example.test",
		"-credential-file", credential, "-allow-cidr", "203.0.113.0/24",
		"-operation", "create=POST:/v1/issues", "-operation", "read=GET:/v1/issues/current",
	}
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, _, err := gateway.LoadConfig(path)
	if err != nil || len(loaded.Connectors) != 1 || loaded.Connectors[0].Operations[0].Method != http.MethodPost ||
		strings.Contains(output.String(), "upstream-secret") || !strings.Contains(output.String(), "systemctl reload") {
		t.Fatalf("loaded=%#v output=%q err=%v", loaded.Connectors, output.String(), err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]string(nil), arguments...)
	for index := range bad {
		if bad[index] == "https://api.example.test" {
			bad[index] = "http://api.example.test"
		}
	}
	if err := run(bad, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("plaintext connector origin was accepted without acknowledgement")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid connector update changed gateway config")
	}
	output.Reset()
	if err := run([]string{"gateway", "connector", "list", "-config", path}, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"id": "issues"`) {
		t.Fatalf("list output=%q err=%v", output.String(), err)
	}
	if _, err := parseConnectorOperation("missing-separators"); err == nil {
		t.Fatal("ambiguous connector operation accepted")
	}
	if err := run([]string{"gateway", "connector", "list", "-config", path, "-max-calls-per-grant", "9"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("connector list silently ignored a mutation flag")
	}
	withReceiptOverride := append([]string(nil), arguments...)
	withReceiptOverride = append(withReceiptOverride, "-receipt-epoch", "2")
	if err := run(withReceiptOverride, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("connector set accepted a receipt identity override for an initialized config")
	}

	legacyConfig := config
	legacyConfig.ConnectorReceiptFile = ""
	legacyConfig.ConnectorReceiptKeyFile = ""
	legacyConfig.ConnectorReceiptNodeID = ""
	legacyConfig.ConnectorReceiptEpoch = 0
	legacyRaw, err := json.Marshal(legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(directory, "legacy-gateway.json")
	if err := os.WriteFile(legacyPath, legacyRaw, 0o640); err != nil {
		t.Fatal(err)
	}
	legacyArguments := append([]string(nil), arguments...)
	for index := range legacyArguments {
		if legacyArguments[index] == path {
			legacyArguments[index] = legacyPath
		}
	}
	legacyArguments = append(legacyArguments,
		"-receipt-file", filepath.Join(directory, "legacy-connector-receipts.ndjson"),
		"-receipt-key-file", privateKey, "-receipt-node-id", "node-a/legacy-gateway", "-receipt-epoch", "2")
	if err := run(legacyArguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("add first connector to older config: %v", err)
	}
	upgraded, _, _, _, err := gateway.LoadConfig(legacyPath)
	if err != nil || upgraded.ConnectorReceiptEpoch != 2 || upgraded.ConnectorReceiptNodeID != "node-a/legacy-gateway" {
		t.Fatalf("upgraded receipt identity=%q/%d err=%v", upgraded.ConnectorReceiptNodeID, upgraded.ConnectorReceiptEpoch, err)
	}
}

func TestGatewayRouteSetRejectsRetainedGrantPolicyDrift(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgc-retained-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), EgressAuditFile: filepath.Join(directory, "audit.jsonl"),
		EgressRoutes: []gateway.EgressRoute{{
			ID: "public-web", MaxConcurrent: 1, MaxRequestBytes: 1024, MaxResponseBytes: 1024, MaxTunnelSeconds: 30,
			Destinations: []gateway.EgressDestination{{Host: "api.example.com", Ports: []int{443}}},
		}},
	}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, routes, egressRoutes, serviceToken, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.Open(loaded, routes, egressRoutes, serviceToken)
	if err != nil {
		t.Fatal(err)
	}
	grant := gateway.Grant{
		GrantID: gateway.GrantID("tenant-a", "instance-a", 1), TenantID: "tenant-a", InstanceID: "instance-a", Generation: 1,
		EgressRouteIDs: []string{"public-web"},
	}
	grantRaw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(grantRaw))
	recorder := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	t.Cleanup(func() {
		recorder := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/v1/grants/"+grant.GrantID, nil))
	})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = run([]string{"gateway", "route", "set", "-config", path, "-id", "public-web",
		"-destination", "replacement.example.com:443"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "retained state") {
		t.Fatalf("policy drift err=%v output=%q", err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected retained-policy update changed gateway config")
	}
}
