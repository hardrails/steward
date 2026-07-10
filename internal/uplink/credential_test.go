package uplink

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredentialValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.json")
	const content = `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"opaque-bearer-token"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cred, err := LoadCredential(path)
	if err != nil {
		t.Fatalf("LoadCredential on a valid file: unexpected err %v", err)
	}
	if cred.TenantID != "acme" {
		t.Errorf("tenant_id = %q, want acme", cred.TenantID)
	}
	if cred.NodeID != "node-7" {
		t.Errorf("node_id = %q, want node-7", cred.NodeID)
	}
	if cred.Credential != "opaque-bearer-token" {
		t.Errorf("credential = %q, want opaque-bearer-token", cred.Credential)
	}
}

func TestLoadCredentialFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"not json", `this is not json`},
		{"truncated json", `{"version":1,"tenant_id":"acme"`},
		{"wrong version", `{"version":999,"tenant_id":"acme","node_id":"node-7","credential":"tok"}`},
		{"zero version", `{"tenant_id":"acme","node_id":"node-7","credential":"tok"}`},
		{"empty tenant_id", `{"version":1,"tenant_id":"","node_id":"node-7","credential":"tok"}`},
		{"missing tenant_id", `{"version":1,"node_id":"node-7","credential":"tok"}`},
		{"empty node_id", `{"version":1,"tenant_id":"acme","node_id":"","credential":"tok"}`},
		{"missing node_id", `{"version":1,"tenant_id":"acme","credential":"tok"}`},
		{"empty credential", `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":""}`},
		{"missing credential", `{"version":1,"tenant_id":"acme","node_id":"node-7"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cred.json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			cred, err := LoadCredential(path)
			if err == nil {
				t.Fatalf("LoadCredential on %s: got nil err, want fail-closed", c.name)
			}
			if cred != nil {
				t.Errorf("LoadCredential on %s: got non-nil credential, want nil on error", c.name)
			}
			// The 3am test: every failure message names the offending path.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the credential file path %q", err, path)
			}
		})
	}
}

func TestLoadCredentialMissingFileFailsClosed(t *testing.T) {
	// Unlike an optional state file, a missing credential file is fatal: the uplink
	// is only loaded when enabled, and it cannot authenticate without one.
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	cred, err := LoadCredential(path)
	if err == nil {
		t.Fatal("LoadCredential on a missing file: got nil err, want fail-closed")
	}
	if cred != nil {
		t.Error("LoadCredential on a missing file: got non-nil credential, want nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the missing file path %q", err, path)
	}
}

func TestLoadCredentialUnreadableFileFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses file permissions; cannot force an unreadable file")
	}
	path := filepath.Join(t.TempDir(), "cred.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tenant_id":"acme","node_id":"n","credential":"t"}`), 0o000); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	cred, err := LoadCredential(path)
	if err == nil {
		t.Fatal("LoadCredential on an unreadable file: got nil err, want fail-closed")
	}
	if cred != nil {
		t.Error("LoadCredential on an unreadable file: got non-nil credential, want nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file path %q", err, path)
	}
}
