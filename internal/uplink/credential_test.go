package uplink

import (
	"os"
	"path/filepath"
	"strconv"
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
		{"unknown field", `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"tok","private_api":"x"}`},
		{"multiple objects", `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"tok"} {}`},
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

func TestLoadCredentialRejectsOversizeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	oversize := filepath.Join(dir, "oversize.json")
	if err := os.WriteFile(oversize, []byte(strings.Repeat("x", maxCredentialBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(oversize); err == nil {
		t.Fatal("oversized credential was accepted")
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"tenant_id":"t","node_id":"n","credential":"c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "credential-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(link); err == nil {
		t.Fatal("credential symlink was accepted")
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

// TestLoadCredentialRejectsOverPermissiveFile pins the fail-closed permission
// check: a credential file readable or writable by group or others (anything
// looser than 0600) is refused with an actionable message naming the path and the
// chmod fix, so a bearer secret can never be quietly loaded from a world- or
// group-exposed file. The check is on the mode bits, so it fires even as root.
func TestLoadCredentialRejectsOverPermissiveFile(t *testing.T) {
	const content = `{"version":1,"tenant_id":"acme","node_id":"node-7","credential":"tok"}`
	// Every mode here exposes at least one group/other read or write bit and must
	// be rejected; the strict modes in the accepted table below must pass.
	rejected := []os.FileMode{0o644, 0o640, 0o604, 0o606, 0o660, 0o666, 0o744, 0o622}
	for _, mode := range rejected {
		t.Run("rejects "+strconv.FormatUint(uint64(mode), 8), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cred.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			// Chmod explicitly so the mode is exact regardless of the process umask.
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod fixture: %v", err)
			}
			cred, err := LoadCredential(path)
			if err == nil {
				t.Fatalf("LoadCredential on a %#o file: got nil err, want fail-closed", mode)
			}
			if cred != nil {
				t.Errorf("LoadCredential on a %#o file: got non-nil credential, want nil", mode)
			}
			// The 3am test: the message names the path and the exact fix.
			msg := err.Error()
			for _, want := range []string{path, "permission", "chmod 600"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
		})
	}

	// The strict modes are accepted: 0600 and stricter carry no group/other bits.
	accepted := []os.FileMode{0o600, 0o400}
	for _, mode := range accepted {
		t.Run("accepts "+strconv.FormatUint(uint64(mode), 8), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cred.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod fixture: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			if _, err := LoadCredential(path); err != nil {
				t.Fatalf("LoadCredential on a %#o file: unexpected err %v", mode, err)
			}
		})
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
