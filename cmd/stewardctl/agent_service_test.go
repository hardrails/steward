package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/agentapp"
	"github.com/hardrails/steward/internal/gateway"
)

func TestAgentServiceActivateConfiguresPresetAndExportsRecoverableTrust(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-agent-service-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	bundle := publishedAgentBundle(t, "openclaw", "registry.example/agent@sha256:"+strings.Repeat("a", 64))
	bundleRaw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "agent.bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	serviceToken := filepath.Join(directory, "gateway.token")
	if err := os.WriteFile(serviceToken, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPrivate := filepath.Join(directory, "receipts.private.pem")
	receiptPublic := filepath.Join(directory, "receipts.public")
	if err := keygen([]string{"-private-out", receiptPrivate, "-public-out", receiptPublic}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
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
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(configPath, configRaw, 0o640); err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(directory, "service-trust.json")
	arguments := []string{
		"activate", "-bundle", bundlePath, "-config", configPath,
		"-tenant-id", "tenant-a", "-node-id", "node-a", "-trust-out", trustPath,
	}
	configBefore, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := agentServiceCommand(arguments, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "already contains a different inventory") {
		t.Fatalf("conflicting trust output error = %v", err)
	}
	configAfter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) {
		t.Fatal("failed service activation changed the live Gateway configuration")
	}
	if err := os.Remove(trustPath); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := agentServiceCommand(arguments, &output); err != nil {
		t.Fatal(err)
	}
	var summary agentServiceActivationSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.AgentName != "workspace-auditor" || summary.Runtime != "openclaw" ||
		summary.ServiceID != "openclaw-api" || summary.TenantID != "tenant-a" || summary.NodeID != "node-a" ||
		summary.TrustFile != trustPath || summary.Activation != "systemctl restart steward-gateway.service" || summary.ServiceReplaced {
		t.Fatalf("service activation summary = %+v", summary)
	}
	loaded, _, _, _, err := gateway.LoadConfig(configPath)
	if err != nil || len(loaded.ServiceOperations) != 1 || loaded.ServiceOperations[0].ID != "openclaw.run" ||
		len(loaded.ConnectorReceiptTenantBudgets) != 1 || loaded.ConnectorReceiptTenantBudgets[0].TenantID != "tenant-a" ||
		loaded.ConnectorReceiptTenantBudgets[0].Bytes != 4<<20 {
		t.Fatalf("activated Gateway = %+v, err=%v", loaded, err)
	}
	trustRaw, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	var trust serviceTrustInventory
	if err := json.Unmarshal(trustRaw, &trust); err != nil || trust.NodeID != "node-a" || trust.TenantID != "tenant-a" ||
		len(trust.Services) != 1 || trust.Services[0].ServiceID != "openclaw-api" ||
		len(trust.Services[0].Operations) != 1 || trust.Services[0].Operations[0].ID != "openclaw.run" {
		t.Fatalf("service trust = %+v, err=%v", trust, err)
	}
	output.Reset()
	if err := agentServiceCommand(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || !summary.ServiceReplaced ||
		summary.Activation != "systemctl reload steward-gateway.service" {
		t.Fatalf("service activation retry = %+v, err=%v", summary, err)
	}
	if err := agentServiceCommand([]string{
		"activate", "-bundle", bundlePath, "-config", configPath,
		"-tenant-id", "tenant-a", "-node-id", "node-b", "-trust-out", filepath.Join(directory, "node-b-trust.json"),
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "export agent service trust") {
		t.Fatalf("receipt identity mismatch error = %v", err)
	}
	if err := agentServiceCommand([]string{
		"activate", "-bundle", bundlePath, "-config", configPath,
		"-tenant-id", "tenant-a", "-node-id", "node-a", "-trust-out", string(filepath.Separator),
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "output path is invalid") {
		t.Fatalf("root trust output error = %v", err)
	}
}
