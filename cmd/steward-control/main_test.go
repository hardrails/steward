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

func TestRunInitializesRecoverableControllerAndPrintsTokenOnce(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "control")
	arguments := []string{"-initialize", "-state-dir", stateDirectory, "-addr", "127.0.0.1:0"}
	var output bytes.Buffer
	if err := run(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(output.String())
	if !strings.HasPrefix(token, "steward_cp_v1_") || strings.ContainsAny(token, " \t\r\n") {
		t.Fatalf("bootstrap token has unexpected shape: %q", token)
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
	if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("repeat initialization error=%v", err)
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
	for _, address := range []string{"0.0.0.0:8443", ":8443", "control.internal:8443"} {
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
		{"-state-dir", "/tmp/control", "-tls-cert-file", "relative", "-tls-key-file", "/tmp/key"},
		{"-state-dir", "/tmp/control", "-delivery-lease", "0s"},
		{"-state-dir", "/tmp/control", "-delivery-lease", (16 * time.Minute).String()},
		{"-state-dir", "/tmp/control", "-max-poll-deliveries", "129"},
		{"-state-dir", "/tmp/control", "-max-tenants", "0"},
	} {
		if _, err := parseOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe options accepted: %v", arguments)
		}
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
