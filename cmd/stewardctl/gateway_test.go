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
		{"gateway", "route", "set", "-id", "web"}, {"gateway", "route", "set", "-id", "web", "-destination", "missing-port"},
		{"gateway", "validate", "extra"}, {"gateway", "route", "list", "-id", "unexpected"},
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
