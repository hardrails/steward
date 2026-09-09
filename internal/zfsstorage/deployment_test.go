package zfsstorage

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedStorageRequiresFreshPolicyBeforeConfinedStart(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	unit := read("deploy/systemd/steward-storage-zfs.service")
	for _, line := range []string{
		"AssertSecurity=apparmor",
		"ConditionPathExists=/etc/steward/storage-zfs-worker-token",
		"ExecStartPre=+/usr/sbin/apparmor_parser --replace /opt/steward/current/integration/deploy/config/storage-zfs.apparmor",
		"ExecStart=/usr/bin/aa-exec -p steward-storage-zfs -- /usr/local/bin/steward-storage-zfs -config=/etc/steward/storage-zfs.json",
		"CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN",
		"AmbientCapabilities=CAP_SYS_ADMIN CAP_CHOWN",
		"NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX",
		"User=root", "Group=steward-executor",
		"PrivateTmp=no", "ProtectSystem=no", "ProtectHome=no",
		"ProtectKernelTunables=no", "ProtectKernelModules=no",
		"ProtectControlGroups=no", "ProtectKernelLogs=no", "ProtectClock=no",
	} {
		if !strings.Contains("\n"+unit, "\n"+line+"\n") {
			t.Errorf("missing required unit line %q", line)
		}
	}
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ReadWritePaths=") || strings.HasPrefix(line, "LoadCredential=") ||
			strings.HasPrefix(line, "BindPaths=") || strings.HasPrefix(line, "AppArmorProfile=") {
			t.Errorf("unexpected namespace/pre-parser profile setting: %s", line)
		}
	}
	policy := read("deploy/config/storage-zfs.apparmor")
	for _, rule := range []string{
		"profile steward-storage-zfs {",
		"  /opt/steward/releases/*/steward-storage-zfs mrix,",
		"  /usr/sbin/zfs mrix,",
		"  /etc/steward/storage-zfs-worker-token r,",
		"  mount fstype=zfs -> /var/lib/steward-state/**,",
		"  umount /var/lib/steward-state/**,",
	} {
		if !strings.Contains(policy, rule) {
			t.Errorf("missing policy rule %q", rule)
		}
	}
	for _, forbidden := range []string{"complain", "default_allow", "capability dac_override", "capability mac_admin"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("unsafe policy: %s", forbidden)
		}
	}
	var config map[string]string
	if err := json.Unmarshal([]byte(read("deploy/config/storage-zfs.json.in")), &config); err != nil {
		t.Fatal(err)
	}
	if config["token_file"] != "/etc/steward/storage-zfs-worker-token" {
		t.Fatal("worker requires its own owner-only token copy")
	}
	for _, path := range []string{"scripts/install-node.sh", "scripts/activate-node-release.sh", "scripts/write-release-manifest.sh"} {
		if !strings.Contains(read(path), "\tintegration/deploy/config/storage-zfs.apparmor\n") {
			t.Errorf("profile absent from inventory: %s", path)
		}
	}
	for _, path := range []string{"scripts/build-deb.sh", "scripts/build-rpm.sh"} {
		if !strings.Contains(read(path), "deploy/config/storage-zfs.apparmor") {
			t.Errorf("profile not required by builder: %s", path)
		}
	}
}

func TestStorageUpgradePreflightFailsBeforeServicesStop(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/activate-node-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	start := strings.Index(script, "check_configured_storage() {\n")
	if start < 0 {
		t.Fatal("missing configured storage check")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("missing configured storage function end")
	}
	check := strings.Index(script, "\ncheck_configured_storage /etc/steward/storage-zfs.json\n")
	stop := strings.Index(script, "\n\tservices_stopped=true\n")
	if check < 0 || stop < check {
		t.Fatal("configured storage check must precede service shutdown")
	}
	preflight, err := os.ReadFile("../../scripts/node-preflight.sh")
	if err != nil || !strings.Contains(string(preflight), `"$storage_bin" -check-packaged-config`) {
		t.Fatalf("normal preflight must check packaged prerequisites: %v", err)
	}
	for _, scenario := range []string{"absent", "valid", "invalid", "dangling-config"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			config := filepath.Join(directory, "config")
			if scenario == "dangling-config" {
				if err := os.Symlink(filepath.Join(directory, "missing"), config); err != nil {
					t.Fatal(err)
				}
			} else if scenario != "absent" {
				if err := os.WriteFile(config, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			binary := "#!/usr/bin/env bash\nset -eu\n[[ $1 == -check-packaged-config && $2 == -config && $4 == -client-token-file && $5 == /fixture/executor-token ]]\nprintf 'CHECKED\\n'\n"
			if scenario == "invalid" || scenario == "dangling-config" {
				binary += "exit 37\n"
			}
			if err := os.WriteFile(filepath.Join(directory, "steward-storage-zfs"), []byte(binary), 0o700); err != nil {
				t.Fatal(err)
			}
			fixture := "set -euo pipefail\nrelease_dir=$1\nread_executor_setting() { [[ $1 == EXECUTOR_STATE_BACKEND_TOKEN_FILE ]]; printf '/fixture/executor-token'; }\n" + script[start:start+end+3] + "\ncheck_configured_storage \"$2\"\nprintf 'STOP\\n'\n"
			output, err := exec.Command("bash", "-c", fixture, "storage-preflight-test", directory, config).CombinedOutput()
			shouldStop := scenario == "valid" || scenario == "absent"
			if (err == nil) != shouldStop || strings.Contains(string(output), "STOP") != shouldStop {
				t.Fatalf("output=%s error=%v", output, err)
			}
			if strings.Contains(string(output), "CHECKED") != (scenario != "absent") {
				t.Fatalf("configured backend check not invoked correctly: %s", output)
			}
		})
	}
}
