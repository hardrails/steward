package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckConfigValidatesUplinkTLS pins Feature 1's -check-config coverage: a
// malformed TLS configuration fails closed identically on a real boot and under
// -check-config (naming the fix), and a valid TLS configuration validates without
// starting anything.
func TestCheckConfigValidatesUplinkTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	cred := writeValidCredentialFile(t)
	validCA := writeValidCAFile(t)
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("write junk fixture: %v", err)
	}
	missingCA := filepath.Join(t.TempDir(), "no-such-ca.pem")

	// Every case pairs the uplink URL + a valid credential with one broken TLS
	// setting; both the real boot and the dry run must reject it with the marker.
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"unreadable CA file", []string{"-uplink-tls-ca-file", missingCA}, []string{missingCA}},
		{"CA file with no certificate", []string{"-uplink-tls-ca-file", junk}, []string{junk, "no valid PEM certificate"}},
		{"client cert without key", []string{"-uplink-tls-client-cert", validCA}, []string{"no client key"}},
		{"client key without cert", []string{"-uplink-tls-client-key", validCA}, []string{"no client certificate"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := append([]string{"-uplink-url", "http://127.0.0.1:1", "-uplink-credential-file", cred}, tc.args...)
			// Real startup fails closed before binding a port...
			realArgs := append([]string{"-addr", "127.0.0.1:0"}, base...)
			assertFailsWith(t, exec.Command(bin, realArgs...), tc.want...)
			// ...and -check-config fails closed identically.
			checkArgs := append([]string{"-check-config"}, base...)
			assertFailsWith(t, exec.Command(bin, checkArgs...), tc.want...)
		})
	}

	t.Run("a valid custom CA validates cleanly", func(t *testing.T) {
		assertExitsZero(t, exec.Command(bin, "-check-config",
			"-uplink-url", "http://127.0.0.1:1",
			"-uplink-credential-file", cred,
			"-uplink-tls-ca-file", validCA,
		), "configuration valid")
	})
}

// TestUplinkTLSSkipVerifyLogsWarning pins the loud-warning requirement: whenever
// -uplink-tls-skip-verify is set the insecure posture is logged, even under
// -check-config (which otherwise stays quiet), so an operator cannot enable it
// silently.
func TestUplinkTLSSkipVerifyLogsWarning(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	cred := writeValidCredentialFile(t)

	assertExitsZero(t, exec.Command(bin, "-check-config",
		"-uplink-url", "http://127.0.0.1:1",
		"-uplink-credential-file", cred,
		"-uplink-tls-skip-verify",
	), "verification is DISABLED")
}

// TestCheckConfigRejectsOverPermissiveCredential pins Feature 3's -check-config
// coverage: an over-permissive (group/other-readable) credential file is refused
// on both a real boot and the dry run, with an actionable message.
func TestCheckConfigRejectsOverPermissiveCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)

	credPath := filepath.Join(t.TempDir(), "credential.json")
	const body = `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"tok"}`
	if err := os.WriteFile(credPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write credential file: %v", err)
	}
	// World/group readable — exactly the posture the check must refuse.
	if err := os.Chmod(credPath, 0o644); err != nil {
		t.Fatalf("chmod credential file: %v", err)
	}

	base := []string{"-uplink-url", "http://127.0.0.1:1", "-uplink-credential-file", credPath}
	want := []string{credPath, "permission", "chmod 600"}
	realArgs := append([]string{"-addr", "127.0.0.1:0"}, base...)
	assertFailsWith(t, exec.Command(bin, realArgs...), want...)
	checkArgs := append([]string{"-check-config"}, base...)
	assertFailsWith(t, exec.Command(bin, checkArgs...), want...)
}

// TestConfigFileUplinkTLSApplied proves the new uplink_tls_* config-file keys are
// read and applied: a bool key (skip-verify) reaches the runtime and logs its
// warning, and a string key (a bad CA path) reaches — and fails — validation.
func TestConfigFileUplinkTLSApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	cred := writeValidCredentialFile(t)

	t.Run("skip-verify from the file is applied and warns", func(t *testing.T) {
		cfg := writeConfigFile(t, fmt.Sprintf(
			`{"uplink_url":"http://127.0.0.1:1","uplink_credential_file":%q,"uplink_tls_skip_verify":true}`, cred))
		assertExitsZero(t, exec.Command(bin, "-check-config", "-config", cfg), "verification is DISABLED")
	})

	t.Run("a bad CA path from the file is applied and fails validation", func(t *testing.T) {
		badCA := filepath.Join(t.TempDir(), "no-such-ca.pem")
		cfg := writeConfigFile(t, fmt.Sprintf(
			`{"uplink_url":"http://127.0.0.1:1","uplink_credential_file":%q,"uplink_tls_ca_file":%q}`, cred, badCA))
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), badCA)
	})
}

// writeValidCAFile generates a self-signed CA certificate and writes it as a PEM
// bundle to a 0600 temp file, returning its path — a valid -uplink-tls-ca-file
// input that NewHTTPClient accepts.
func writeValidCAFile(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "steward-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}
