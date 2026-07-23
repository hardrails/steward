package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestAgentServiceConnectorPresetsOwnFiniteContracts(t *testing.T) {
	tests := []struct {
		preset, id, operation string
		concurrent            int
		request, response     int64
		seconds, calls        int
	}{
		{"research-search", "steward-research-search", "search=POST:/v1/search", 8, 64 << 10, 1 << 20, 30, 64},
		{"research-extract", "steward-research-extract", "extract=POST:/v1/extract", 4, 64 << 10, 4 << 20, 60, 64},
		{"browser-search", "steward-browser-search", "search=POST:/v1/search", 4, 64 << 10, 1 << 20, 45, 64},
		{"browser-read", "steward-browser-read", "read=POST:/v1/read", 2, 64 << 10, 1 << 20, 180, 32},
		{"codex-worker", "steward-codex", "run=POST:/v1/run", 2, 64 << 10, 1 << 20, 915, 16},
		{"claude-code-worker", "steward-claude-code", "run=POST:/v1/run", 2, 64 << 10, 1 << 20, 915, 16},
	}
	for _, test := range tests {
		t.Run(test.preset, func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			baseURL := flags.String("base-url", "", "")
			flags.String("id", "", "")
			flags.Var(new(repeatedFlag), "operation", "")
			flags.String("credential-mode", "", "")
			flags.Bool("clear-action-permit", false, "")
			flags.Bool("allow-insecure-http", false, "")
			maxConcurrent := flags.Int("max-concurrent", 4, "")
			maxRequest := flags.Int64("max-request-bytes", 1<<20, "")
			maxResponse := flags.Int64("max-response-bytes", 4<<20, "")
			maxSeconds := flags.Int("max-seconds", 60, "")
			maxCalls := flags.Int("max-calls-per-grant", 16, "")
			if err := flags.Parse([]string{"-base-url", "https://worker.example"}); err != nil {
				t.Fatal(err)
			}
			id, credentialMode := "", ""
			var operations repeatedFlag
			if err := applyGatewayConnectorPreset("set", flags, test.preset, "", &id, baseURL, &credentialMode,
				&operations, maxConcurrent, maxRequest, maxResponse, maxSeconds, maxCalls); err != nil {
				t.Fatal(err)
			}
			if id != test.id || *baseURL != "https://worker.example" || credentialMode != string(gateway.CredentialModeBearer) ||
				len(operations) != 1 || operations[0] != test.operation || *maxConcurrent != test.concurrent ||
				*maxRequest != test.request || *maxResponse != test.response || *maxSeconds != test.seconds || *maxCalls != test.calls {
				t.Fatalf("preset=%s id=%q base=%q mode=%q operations=%v concurrent=%d request=%d response=%d seconds=%d calls=%d",
					test.preset, id, *baseURL, credentialMode, operations, *maxConcurrent, *maxRequest, *maxResponse, *maxSeconds, *maxCalls)
			}
		})
	}
}

func TestAgentServiceConnectorPresetRejectsAmbiguousAuthority(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	baseURL := flags.String("base-url", "", "")
	id := flags.String("id", "", "")
	flags.Var(new(repeatedFlag), "operation", "")
	credentialMode := flags.String("credential-mode", "", "")
	flags.Bool("clear-action-permit", false, "")
	flags.Bool("allow-insecure-http", false, "")
	maxConcurrent := flags.Int("max-concurrent", 4, "")
	maxRequest := flags.Int64("max-request-bytes", 1<<20, "")
	maxResponse := flags.Int64("max-response-bytes", 4<<20, "")
	maxSeconds := flags.Int("max-seconds", 60, "")
	maxCalls := flags.Int("max-calls-per-grant", 16, "")
	if err := flags.Parse([]string{"-base-url", "https://worker.example", "-id", "attacker"}); err != nil {
		t.Fatal(err)
	}
	var operations repeatedFlag
	err := applyGatewayConnectorPreset("set", flags, "codex-worker", "", id, baseURL, credentialMode,
		&operations, maxConcurrent, maxRequest, maxResponse, maxSeconds, maxCalls)
	if err == nil || !strings.Contains(err.Error(), "owns -id") {
		t.Fatalf("ambiguous preset error=%v", err)
	}
}

func TestGitHubIssuesConnectorPresetCreatesProtectedBoundedOperation(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-github-preset-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	serviceToken := filepath.Join(directory, "service.token")
	credential := filepath.Join(directory, "github.token")
	if err := os.WriteFile(serviceToken, []byte("service-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("github-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPrivate := filepath.Join(directory, "receipt.private.pem")
	receiptPublic := filepath.Join(directory, "receipt.public")
	actionPrivate := filepath.Join(directory, "action.private.pem")
	actionPublic := filepath.Join(directory, "action.public")
	for _, pair := range [][2]string{{receiptPrivate, receiptPublic}, {actionPrivate, actionPublic}} {
		if err := keygen([]string{"-private-out", pair[0], "-public-out", pair[1]}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	config := gateway.Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8091",
		ServiceTokenFile: serviceToken, StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(), ConnectorReceiptFile: filepath.Join(directory, "receipts.ndjson"),
		ConnectorReceiptKeyFile: receiptPrivate, ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
	}
	if config.ExecutorGID == 0 {
		config.ExecutorGID, config.RelayGID = 1, 1
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(configPath, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"gateway", "connector", "set", "-config", configPath,
		"-preset", "github-issues", "-repository", "hardrails/steward",
		"-credential-file", credential, "-tenant-budget", "tenant-a=1048576",
		"-action-authority", "tenant-action-1=" + actionPublic,
		"-action-authority-tenant", "tenant-action-1=tenant-a",
		"-action-node-id", "node-a", "-max-action-permit-seconds", "300",
	}
	withoutAuthority := []string{
		"gateway", "connector", "set", "-config", configPath,
		"-preset", "github-issues", "-repository", "hardrails/steward",
		"-credential-file", credential, "-tenant-budget", "tenant-a=1048576",
	}
	if err := run(withoutAuthority, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "action-authority") {
		t.Fatalf("unprotected GitHub preset error=%v", err)
	}
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, _, err := gateway.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Connectors) != 1 {
		t.Fatalf("connectors=%#v", loaded.Connectors)
	}
	connector := loaded.Connectors[0]
	if connector.ID != "github-issues" || connector.BaseURL != "https://api.github.com" ||
		connector.CredentialMode != gateway.CredentialModeBearer || connector.MaxConcurrent != 2 ||
		connector.MaxRequestBytes != 64<<10 || connector.MaxResponseBytes != 1<<20 ||
		connector.MaxSeconds != 30 || connector.MaxCallsPerGrant != 4 ||
		len(connector.Operations) != 1 || connector.Operations[0].ID != "create" ||
		connector.Operations[0].Method != "POST" || connector.Operations[0].Path != "/repos/hardrails/steward/issues" ||
		len(connector.ActionAuthorityIDs) != 1 || connector.ActionAuthorityIDs[0] != "tenant-action-1" {
		t.Fatalf("preset connector=%#v", connector)
	}
	if strings.Contains(output.String(), "github-token") {
		t.Fatalf("preset output leaked credential: %s", output.String())
	}
}

func TestGitHubIssuesConnectorPresetRejectsAmbiguityBeforeMutation(t *testing.T) {
	for _, arguments := range [][]string{
		{"gateway", "connector", "set", "-preset", "github-issues", "-repository", "missing-slash"},
		{"gateway", "connector", "set", "-preset", "github-issues", "-repository", "owner/repo", "-base-url", "https://example.test"},
		{"gateway", "connector", "set", "-preset", "unknown", "-repository", "owner/repo"},
	} {
		err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("ambiguous preset accepted: %v", arguments)
		}
	}
	if validGitHubRepository("-owner/repo") || validGitHubRepository("owner/.hidden") ||
		validGitHubRepository("owner/repo/extra") || !validGitHubRepository("hardrails/steward") {
		t.Fatal("GitHub repository validation is incorrect")
	}
}
