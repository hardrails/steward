package main

import (
	"bytes"
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

	"github.com/hardrails/steward/internal/gateway"
)

func TestActionTrustInventoryIsFilteredToOneTenant(t *testing.T) {
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		ActionPermitNodeID: "node-a",
		ActionAuthorities: []gateway.ActionAuthority{
			{KeyID: "approver-a", TenantID: "tenant-a", PublicKey: base64.StdEncoding.EncodeToString(publicA)},
			{KeyID: "approver-b", TenantID: "tenant-b", PublicKey: base64.StdEncoding.EncodeToString(publicB)},
		},
		Connectors: []gateway.Connector{
			{ID: "shared", BaseURL: "https://shared.example.test", CredentialMode: gateway.CredentialModeBearer, CredentialEpoch: 1,
				ActionAuthorityIDs: []string{"approver-a", "approver-b"}, MaxActionPermitSeconds: 300,
				Operations: []gateway.ConnectorOperation{{ID: "create", Method: http.MethodPost, Path: "/v1/items"}}},
			{ID: "tenant-b-only", BaseURL: "https://private.example.test", CredentialMode: gateway.CredentialModeXAPIKey, CredentialEpoch: 1,
				ActionAuthorityIDs: []string{"approver-b"}, MaxActionPermitSeconds: 300,
				Operations: []gateway.ConnectorOperation{{ID: "read", Method: http.MethodGet, Path: "/v1/private"}}},
		},
	}
	var output bytes.Buffer
	if err := writeActionTrustInventory(&output, config, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	var inventory actionTrustInventory
	if err := json.Unmarshal(output.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.TenantID != "tenant-a" || len(inventory.Authorities) != 1 ||
		inventory.Authorities[0].KeyID != "approver-a" || len(inventory.Connectors) != 1 ||
		inventory.Connectors[0].ConnectorID != "shared" || len(inventory.Connectors[0].AuthorityKeyIDs) != 1 ||
		inventory.Connectors[0].AuthorityKeyIDs[0] != "approver-a" ||
		inventory.Connectors[0].CredentialMode != gateway.CredentialModeBearer ||
		strings.Contains(output.String(), "tenant-b") || strings.Contains(output.String(), "approver-b") ||
		strings.Contains(output.String(), "private.example.test") {
		t.Fatalf("tenant-filtered inventory=%s", output.String())
	}
	if err := writeActionTrustInventory(&bytes.Buffer{}, config, "tenant-c"); err == nil {
		t.Fatal("action trust export accepted a tenant without an authority")
	}
}

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
		{"gateway", "service"}, {"gateway", "service", "remove"},
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

func TestGatewayServiceSetAndTrustAreValidatedScopedAndAtomic(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sgcs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "service.token")
	if err := os.WriteFile(token, []byte("service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPrivate := filepath.Join(directory, "receipts.private.pem")
	receiptPublic := filepath.Join(directory, "receipts.public")
	if err := run([]string{"keygen", "-private-out", receiptPrivate, "-public-out", receiptPublic}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: token, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
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
	base := []string{
		"gateway", "service", "set", "-config", path, "-service-id", "hermes-api",
		"-operation", "hermes.run=POST:/v1/runs", "-max-seconds", "90", "-max-permit-seconds", "240",
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(base, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "tenant-budget") {
		t.Fatalf("service without tenant budget err=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected service setup changed Gateway config")
	}
	arguments := append(append([]string(nil), base...),
		"-tenant-budget", "tenant-a=1048576", "-receipt-file", filepath.Join(directory, "receipts.ndjson"),
		"-receipt-key-file", receiptPrivate, "-receipt-node-id", "node-a/gateway", "-receipt-epoch", "1")
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, _, err := gateway.LoadConfig(path)
	if err != nil || len(loaded.ServiceOperations) != 1 || loaded.ServiceOperations[0].ID != "hermes.run" ||
		loaded.ServiceOperations[0].ContentType != "application/json" || loaded.ServiceOperations[0].MaxSeconds != 90 ||
		loaded.ServiceOperations[0].MaxPermitSeconds != 240 || len(loaded.ConnectorReceiptTenantBudgets) != 1 ||
		!strings.Contains(output.String(), "systemctl restart") {
		t.Fatalf("loaded=%#v budgets=%#v output=%q err=%v", loaded.ServiceOperations, loaded.ConnectorReceiptTenantBudgets, output.String(), err)
	}

	output.Reset()
	if err := run([]string{"gateway", "service", "trust", "-config", path, "-node-id", "node-a", "-tenant-id", "tenant-a"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var trust serviceTrustInventory
	if err := json.Unmarshal(output.Bytes(), &trust); err != nil {
		t.Fatal(err)
	}
	if len(trust.Services) != 1 || len(trust.Services[0].Operations) != 1 {
		t.Fatalf("service trust=%s", output.String())
	}
	operation := trust.Services[0].Operations[0]
	if trust.SchemaVersion != serviceTrustSchemaV1 || trust.NodeID != "node-a" || trust.TenantID != "tenant-a" ||
		trust.Services[0].ServiceID != "hermes-api" || operation.ServiceID != "hermes-api" ||
		operation.ID != "hermes.run" || operation.Method != http.MethodPost || operation.Path != "/v1/runs" ||
		operation.PolicyDigest != gateway.ServiceOperationDigest(loaded.ServiceOperations[0]) || operation.MaxPermitSeconds != 240 {
		t.Fatalf("service trust=%s", output.String())
	}
	if err := run([]string{"gateway", "service", "trust", "-config", path, "-node-id", "node-a", "-tenant-id", "tenant-b"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("service trust exported for an unbudgeted tenant")
	}
	if err := run([]string{"gateway", "service", "trust", "-config", path, "-tenant-id", "tenant-a"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("service trust exported without a node identity")
	}

	output.Reset()
	if err := run([]string{"gateway", "service", "list", "-config", path}, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"id": "hermes.run"`) {
		t.Fatalf("service list output=%q err=%v", output.String(), err)
	}
	if err := run([]string{"gateway", "service", "list", "-config", path, "-max-seconds", "1"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("service list silently ignored a mutation flag")
	}

	before, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]string{
		append(append([]string(nil), base...), "-operation", "duplicate=POST:/v1/runs"),
		{"gateway", "service", "set", "-config", path, "-service-id", "hermes-api", "-operation", "hermes.run=GET:/v1/runs"},
		{"gateway", "service", "set", "-config", path, "-service-id", "bad service", "-operation", "hermes.run=POST:/v1/runs"},
		append(append([]string(nil), base...), "-tenant-id", "tenant-a"),
		append(append([]string(nil), base...), "-receipt-epoch", "2"),
	} {
		if err := run(invalid, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid service config accepted: %v", invalid)
		}
		unchanged, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(before, unchanged) {
			t.Fatalf("invalid service config changed Gateway config: %v", invalid)
		}
	}

	output.Reset()
	if err := run([]string{"gateway", "service", "set", "-config", path, "-service-id", "hermes-api",
		"-operation", "hermes.run=POST:/v1/runs", "-operation", "hermes.batch=POST:/v1/batch"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || len(loaded.ServiceOperations) != 2 || loaded.ServiceOperations[0].ID != "hermes.batch" ||
		!strings.Contains(output.String(), `"replaced": true`) || !strings.Contains(output.String(), "systemctl reload") {
		t.Fatalf("replaced services=%#v output=%q err=%v", loaded.ServiceOperations, output.String(), err)
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
	connectorArguments := []string{
		"gateway", "connector", "set", "-config", path, "-id", "issues", "-base-url", "https://api.example.test",
		"-credential-file", credential, "-allow-cidr", "203.0.113.0/24",
		"-operation", "create=POST:/v1/issues", "-operation", "read=GET:/v1/issues/current",
	}
	beforeInitialization, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(connectorArguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "tenant-budget") {
		t.Fatalf("first connector without a tenant budget err=%v", err)
	}
	afterInitialization, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeInitialization, afterInitialization) {
		t.Fatal("missing tenant budget changed gateway config")
	}
	arguments := append(append([]string(nil), connectorArguments...), "-tenant-budget", "tenant-a=1048576")
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, _, err := gateway.LoadConfig(path)
	if err != nil || len(loaded.Connectors) != 1 || loaded.Connectors[0].Operations[0].Method != http.MethodPost ||
		loaded.Connectors[0].CredentialEpoch != 0 ||
		len(loaded.ConnectorReceiptTenantBudgets) != 1 || loaded.ConnectorReceiptTenantBudgets[0].TenantID != "tenant-a" ||
		loaded.ConnectorReceiptTenantBudgets[0].Bytes != 1048576 ||
		strings.Contains(output.String(), "upstream-secret") || !strings.Contains(output.String(), "systemctl restart") {
		t.Fatalf("loaded=%#v budgets=%#v output=%q err=%v", loaded.Connectors, loaded.ConnectorReceiptTenantBudgets, output.String(), err)
	}
	legacyCompatible, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacyCompatible, []byte(`"credential_epoch"`)) || bytes.Contains(legacyCompatible, []byte(`"action_authorities"`)) {
		t.Fatalf("non-permit connector serialized permit-only fields: %s", legacyCompatible)
	}
	var preserveOutput bytes.Buffer
	if err := run(connectorArguments, &preserveOutput, &bytes.Buffer{}); err != nil {
		t.Fatalf("replace connector while preserving tenant budgets: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || len(loaded.ConnectorReceiptTenantBudgets) != 1 || loaded.ConnectorReceiptTenantBudgets[0].Bytes != 1048576 ||
		!strings.Contains(preserveOutput.String(), "systemctl reload") {
		t.Fatalf("preserved budgets=%#v err=%v", loaded.ConnectorReceiptTenantBudgets, err)
	}
	permitArguments := append(append([]string(nil), connectorArguments...),
		"-action-authority", "approver-a="+publicKey, "-action-authority-tenant", "approver-a=tenant-a",
		"-action-node-id", "node-a", "-max-action-permit-seconds", "300")
	if err := run(permitArguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("configure action permit: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || loaded.ActionPermitNodeID != "node-a" || len(loaded.ActionAuthorities) != 1 ||
		len(loaded.Connectors[0].ActionAuthorityIDs) != 1 || loaded.Connectors[0].ActionAuthorityIDs[0] != "approver-a" ||
		loaded.ActionAuthorities[0].TenantID != "tenant-a" || loaded.Connectors[0].CredentialEpoch != 1 ||
		loaded.Connectors[0].MaxActionPermitSeconds != 300 {
		t.Fatalf("action permit config=%#v connectors=%#v err=%v", loaded.ActionAuthorities, loaded.Connectors, err)
	}
	if err := run(connectorArguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("replace connector while preserving action permit: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || len(loaded.Connectors[0].ActionAuthorityIDs) != 1 {
		t.Fatalf("preserved action permit connector=%#v err=%v", loaded.Connectors[0], err)
	}
	changePermitLifetime := append(append([]string(nil), connectorArguments...), "-max-action-permit-seconds", "120")
	if err := run(changePermitLifetime, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("change preserved action permit lifetime: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || loaded.Connectors[0].MaxActionPermitSeconds != 120 {
		t.Fatalf("changed action permit lifetime connector=%#v err=%v", loaded.Connectors[0], err)
	}
	var trustOutput bytes.Buffer
	if err := run([]string{"gateway", "connector", "trust", "-config", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "requires -tenant-id") {
		t.Fatalf("tenant-unscoped action trust export error=%v", err)
	}
	if err := run([]string{"gateway", "connector", "trust", "-config", path, "-tenant-id", "tenant-a"}, &trustOutput, &bytes.Buffer{}); err != nil ||
		!strings.Contains(trustOutput.String(), `"schema_version": "steward.action-trust.v1"`) ||
		!strings.Contains(trustOutput.String(), `"node_id": "node-a"`) ||
		!strings.Contains(trustOutput.String(), `"tenant_id": "tenant-a"`) ||
		!strings.Contains(trustOutput.String(), `"public_key_digest": "sha256:`) ||
		!strings.Contains(trustOutput.String(), `"credential_mode": "bearer"`) ||
		!strings.Contains(trustOutput.String(), `"credential_epoch": 1`) ||
		!strings.Contains(trustOutput.String(), `"max_permit_seconds": 120`) ||
		!strings.Contains(trustOutput.String(), `"base_url": "https://api.example.test"`) ||
		!strings.Contains(trustOutput.String(), `"method": "POST"`) ||
		!strings.Contains(trustOutput.String(), `"path": "/v1/issues"`) ||
		!strings.Contains(trustOutput.String(), `"policy_digest": "sha256:`) {
		t.Fatalf("action trust output=%q err=%v", trustOutput.String(), err)
	}
	clearPermit := append(append([]string(nil), connectorArguments...), "-clear-action-permit")
	if err := run(clearPermit, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("clear action permit: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || loaded.ActionPermitNodeID != "" || len(loaded.ActionAuthorities) != 0 ||
		len(loaded.Connectors[0].ActionAuthorityIDs) != 0 || loaded.Connectors[0].CredentialEpoch != 0 {
		t.Fatalf("cleared action permit config=%#v connector=%#v err=%v", loaded.ActionAuthorities, loaded.Connectors[0], err)
	}
	clearedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"credential_epoch", "action_authorities", "action_permit_node_id", "action_authority_ids", "max_action_permit_seconds"} {
		if bytes.Contains(clearedRaw, []byte(`"`+field+`"`)) {
			t.Fatalf("cleared permit config retained legacy-incompatible field %q: %s", field, clearedRaw)
		}
	}
	upsert := append(append([]string(nil), connectorArguments...), "-tenant-budget", "tenant=west=1048576")
	var upsertOutput bytes.Buffer
	if err := run(upsert, &upsertOutput, &bytes.Buffer{}); err != nil {
		t.Fatalf("upsert exact tenant budget: %v", err)
	}
	loaded, _, _, _, err = gateway.LoadConfig(path)
	if err != nil || len(loaded.ConnectorReceiptTenantBudgets) != 2 || loaded.ConnectorReceiptTenantBudgets[0].TenantID != "tenant-a" ||
		loaded.ConnectorReceiptTenantBudgets[1].TenantID != "tenant=west" || !strings.Contains(upsertOutput.String(), "systemctl restart") {
		t.Fatalf("upserted budgets=%#v output=%q err=%v", loaded.ConnectorReceiptTenantBudgets, upsertOutput.String(), err)
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
	for _, invalidBudgets := range [][]string{
		{"-tenant-budget", "tenant-a=1048576", "-tenant-budget", "tenant-a=2097152"},
		{"-tenant-budget", "tenant-a=0"},
		{"-tenant-budget", "tenant-a=not-bytes"},
	} {
		invalid := append(append([]string(nil), connectorArguments...), invalidBudgets...)
		if err := run(invalid, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid tenant budgets accepted: %v", invalidBudgets)
		}
		unchanged, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(after, unchanged) {
			t.Fatalf("invalid tenant budgets changed gateway config: %v", invalidBudgets)
		}
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
