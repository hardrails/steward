package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestRunInitializesRecoverableControllerWithOwnerOnlyTokenHandoff(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	arguments := []string{"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(stateDirectory, "site-admin.token")
	if strings.TrimSpace(output.String()) != tokenPath {
		t.Fatalf("initialize output=%q want token path %q", output.String(), tokenPath)
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(token, "steward_cp_v1_") || strings.ContainsAny(token, " \t\r\n") {
		t.Fatalf("bootstrap token has unexpected shape: %q", token)
	}
	tokenInfo, err := os.Stat(tokenPath)
	if err != nil || tokenInfo.Mode().Perm() != 0o600 {
		t.Fatalf("admin token info=%v error=%v", tokenInfo, err)
	}
	keyInfo, err := os.Stat(filepath.Join(stateDirectory, "auth.key"))
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("auth key info=%v error=%v", keyInfo, err)
	}
	store, err := controlstore.Open(stateDirectory, controlstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Status()
	store.Close()
	if err != nil || status.Credentials != 1 {
		t.Fatalf("status=%+v error=%v", status, err)
	}
	// If local publication was lost after the durable bootstrap, a new
	// exclusive output path reproduces the same token instead of stranding the
	// store with no usable administrator.
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	recoveredPath := filepath.Join(filepath.Dir(stateDirectory), "recovered-admin.token")
	recoveryArguments := append(append([]string(nil), arguments...), "-admin-token-file", recoveredPath)
	output.Reset()
	if err := run(recoveryArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	recovered, err := os.ReadFile(recoveredPath)
	if err != nil || string(recovered) != string(raw) {
		t.Fatalf("recovered token changed: %q error=%v", recovered, err)
	}
	if err := run(recoveryArguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("existing token output was overwritten: %v", err)
	}
	var checked bytes.Buffer
	if err := run([]string{"-check-config", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}, &checked, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(checked.String()) != "steward-control configuration is valid" {
		t.Fatalf("check output=%q", checked.String())
	}
}

func TestTransportConfigRequiresTLSOutsideLiteralLoopback(t *testing.T) {
	base := options{address: "127.0.0.1:8443"}
	if config, err := transportConfig(base); err != nil || config != nil {
		t.Fatalf("loopback transport=%#v error=%v", config, err)
	}
	for _, address := range []string{"0.0.0.0:8443", ":8443", "localhost:8443", "control.internal:8443"} {
		base.address = address
		if config, err := transportConfig(base); err == nil || config != nil {
			t.Fatalf("remote address %q accepted without TLS", address)
		}
	}
	base.address = "127.0.0.1:8443"
	base.tlsCertFile = "/tmp/cert.pem"
	if _, err := transportConfig(base); err == nil {
		t.Fatal("partial TLS configuration accepted")
	}
}

func TestParseOptionsRejectsUnsafePathsAndCapacity(t *testing.T) {
	for _, arguments := range [][]string{
		{"-state-dir", "relative"},
		{"-state-dir", "/"},
		{"-state-dir", "/tmp/control", "-auth-key-file", "relative"},
		{"-state-dir", "/tmp/control", "-admin-token-file", "relative"},
		{"-state-dir", "/tmp/control", "-auth-key-file", "/tmp/same", "-admin-token-file", "/tmp/same"},
		{"-state-dir", "/tmp/control", "-tls-cert-file", "relative", "-tls-key-file", "/tmp/key"},
		{"-state-dir", "/tmp/control", "-delivery-lease", "0s"},
		{"-state-dir", "/tmp/control", "-delivery-lease", (controlstore.MaxDeliveryLease + time.Second).String()},
		{"-state-dir", "/tmp/control", "-max-poll-deliveries", "129"},
		{"-state-dir", "/tmp/control", "-max-tenants", "0"},
	} {
		if _, err := parseOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe options accepted: %v", arguments)
		}
	}
	if _, err := parseOptions([]string{"-state-dir", "/tmp/control", "-max-nodes", "100", "-max-nodes-per-tenant", "50"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("paired low node limits rejected: %v", err)
	}
}

func TestRunReportsVersionWithoutState(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-version"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "steward-control ") {
		t.Fatalf("version output=%q", output.String())
	}
}
