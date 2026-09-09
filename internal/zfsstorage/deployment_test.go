package zfsstorage

import (
	"encoding/json"
	"os"
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
