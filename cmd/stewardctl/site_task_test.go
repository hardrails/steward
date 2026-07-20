package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestSiteTaskConnectJoinsAuthenticatedTrustAndExternalAuthorityPaths(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	siteDirectory := filepath.Join(directory, "site")
	if err := siteCommand([]string{
		"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	operatorToken := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(operatorToken, []byte("operator-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := contextCommand([]string{
		"set", "production", "-control-url", "http://127.0.0.1:8443", "-token-file", operatorToken,
		"-tenant-id", "tenant-a",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	serviceTrustPath := filepath.Join(directory, "service-trust.json")
	var trust bytes.Buffer
	if err := writeServiceTrustInventory(&trust, gateway.Config{
		ConnectorReceiptNodeID:        "node-a/gateway",
		ConnectorReceiptTenantBudgets: []gateway.ConnectorReceiptTenantBudget{{TenantID: "tenant-a", Bytes: 4 << 20}},
		ServiceOperations: []gateway.ServiceOperation{{
			ServiceID: "hermes-api", ID: "hermes.run", Method: "POST", Path: "/v1/runs",
			ContentType: "application/json", MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20,
			MaxSeconds: 120, MaxPermitSeconds: 300, TaskProtocol: gateway.TaskProtocolLifecycleV1,
			StatusPathPrefix: "/v1/runs/", StatusMaxSeconds: 15, PollIntervalSeconds: 1,
		}},
	}, "node-a", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serviceTrustPath, trust.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	gatewayTokenPath := filepath.Join(directory, "gateway.token")
	if err := os.WriteFile(gatewayTokenPath, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"task", "connect", siteDirectory, "-trust", serviceTrustPath,
		"-gateway-token-file", gatewayTokenPath,
	}
	var output bytes.Buffer
	if err := siteCommand(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "operator-token") || strings.Contains(output.String(), "gateway-token") ||
		!strings.Contains(output.String(), `"context":"production"`) || !strings.Contains(output.String(), `"node_id":"node-a"`) {
		t.Fatalf("task connection output = %s", output.String())
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		t.Fatal(err)
	}
	connected, found := findCLIContext(config, "production")
	if !found || connected.TokenFile != operatorToken || connected.TenantID != "tenant-a" || connected.NodeID != "node-a" ||
		connected.GatewayURL != "http://127.0.0.1:8091" || connected.GatewayTokenFile != gatewayTokenPath ||
		connected.ServiceTrustFile != serviceTrustPath ||
		connected.TaskKeyFile != filepath.Join(siteDirectory, "private", "tenant-task.private.pem") ||
		connected.TaskKeyID != "tenant-task-1" {
		t.Fatalf("task context = %+v", connected)
	}
	if err := siteCommand(arguments, &bytes.Buffer{}); err != nil {
		t.Fatalf("exact task connection retry: %v", err)
	}
}
