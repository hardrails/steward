package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

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
