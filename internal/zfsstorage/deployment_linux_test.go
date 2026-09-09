package zfsstorage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in host test: create only one random child of an operator-selected ZFS
// dataset and a correspondingly named systemd unit/profile. Existing services,
// pools and application credentials are never selected or replaced.
func TestPackagedStorageServiceConfinement(t *testing.T) {
	parent := os.Getenv("STEWARD_STORAGE_TEST_DATASET_PARENT")
	if parent == "" {
		t.Skip("requires an explicit ZFS parent on an AppArmor/systemd/Docker host")
	}
	if os.Geteuid() != 0 || !validDataset(parent) || len(parent) > 100 {
		t.Fatal("live storage test requires root and a bounded valid parent dataset")
	}
	binary, err := filepath.EvalSymlinks(os.Getenv("STEWARD_STORAGE_TEST_BINARY"))
	if err != nil || !filepath.IsAbs(binary) || strings.ContainsAny(binary, " \t\r\n*?[]{}") {
		t.Fatal("live storage test requires a clean absolute worker binary")
	}
	command := func(args ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		raw, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		return strings.TrimSpace(string(raw)), err
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := command(args...)
		if err != nil {
			t.Fatalf("%s failed: %v: %s", args[0], err, out)
		}
		return out
	}
	if run("zfs", "list", "-H", "-o", "type", parent) != "filesystem" {
		t.Fatal("selected ZFS parent is not a filesystem")
	}
	fixture, err := os.MkdirTemp("/var/lib", "steward-zfs-proof-")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(fixture)
	dataset := parent + "/" + name
	unitPath := "/run/systemd/system/" + name + ".service"
	policyPath := filepath.Join(fixture, "policy")
	configPath := filepath.Join(fixture, "config.json")
	tokenPath := filepath.Join(fixture, "token")
	statePath := filepath.Join(fixture, "state")
	runtimePath := "/run/" + name
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	policy := strings.NewReplacer(
		"profile steward-storage-zfs {", "profile "+name+" {",
		"peer=steward-storage-zfs", "peer="+name,
		"/opt/steward/releases/*/steward-storage-zfs", binary,
		"/etc/steward/storage-zfs.json", configPath,
		"/etc/steward/storage-zfs-worker-token", tokenPath,
		"/run/steward-storage-zfs", runtimePath,
		"/var/lib/steward-state", statePath,
	).Replace(read("deploy/config/storage-zfs.apparmor"))
	unit := strings.NewReplacer(
		"Group=steward-executor", "Group=root",
		"/opt/steward/current/integration/deploy/config/storage-zfs.apparmor", policyPath,
		"-p steward-storage-zfs --", "-p "+name+" --",
		"/usr/local/bin/steward-storage-zfs", binary,
		"/etc/steward/storage-zfs.json", configPath,
		"/etc/steward/storage-zfs-worker-token", tokenPath,
		"RuntimeDirectory=steward-storage-zfs", "RuntimeDirectory="+name,
		"StateDirectory=steward-state", "StateDirectory="+name,
		"Restart=on-failure", "Restart=no",
	).Replace(read("deploy/systemd/steward-storage-zfs.service"))
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	created, installed, loaded := false, false, false
	t.Cleanup(func() {
		if installed {
			if out, err := command("systemctl", "stop", name); err != nil {
				t.Errorf("stop fixture: %v %s", err, out)
				return
			}
			if err := os.Remove(unitPath); err != nil {
				t.Error(err)
			}
			if out, err := command("systemctl", "daemon-reload"); err != nil {
				t.Errorf("reload: %v %s", err, out)
			}
		}
		if loaded {
			if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
				t.Error(err)
				return
			}
			if out, err := command("apparmor_parser", "--remove", policyPath); err != nil {
				t.Errorf("remove fixture profile: %v %s", err, out)
			}
		}
		if created {
			if out, err := command("zfs", "destroy", "-r", dataset); err != nil {
				t.Errorf("remove fixture dataset: %v %s", err, out)
				return
			}
		}
		if err := os.RemoveAll(fixture); err != nil {
			t.Error(err)
		}
	})
	run("zfs", "create", "-o", "canmount=off", "-o", "mountpoint=none", "-o", "quota=67108864", dataset)
	created = true
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	write(tokenPath, hex.EncodeToString(token[:]))
	config, err := json.Marshal(map[string]string{
		"schema": "steward.storage-zfs.config.v1", "socket": runtimePath + "/storage.sock",
		"token_file": tokenPath, "dataset_root": dataset, "mount_root": statePath,
		"docker_socket": "/var/run/docker.sock", "zfs_binary": "/usr/sbin/zfs",
	})
	if err != nil {
		t.Fatal(err)
	}
	write(configPath, string(config))
	write(policyPath, policy)
	file, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	installed = true
	_, err = file.WriteString(unit)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("write fixture unit: %v %v", err, closeErr)
	}
	run("systemd-analyze", "verify", unitPath)
	run("systemctl", "daemon-reload")
	// Mark for cleanup before start: loading can succeed even if the later
	// backend check fails. Removal of a missing profile is harmless to others.
	loaded = true
	run("systemctl", "start", name)
	pid := run("systemctl", "show", name, "-p", "MainPID", "--value")
	current, err := os.ReadFile("/proc/" + pid + "/attr/current")
	if err != nil || strings.TrimSpace(string(current)) != name+" (enforce)" {
		t.Fatalf("worker is not confined: %v %q", err, current)
	}
	hostNS, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	workerNS, err := os.Readlink("/proc/" + pid + "/ns/mnt")
	if err != nil || workerNS != hostNS {
		t.Fatalf("worker hides mounts: %v", err)
	}
	t.Log("packaged startup passed real quotas and runs confined in the host mount namespace")
	run("systemctl", "stop", name)
	assertRefused := func(label string) {
		t.Helper()
		if out, err := command("systemctl", "start", name); err == nil {
			t.Fatalf("%s unexpectedly started: %s", label, out)
		}
		if run("systemctl", "show", name, "-p", "MainPID", "--value") != "0" {
			t.Fatalf("%s left a worker running", label)
		}
		if _, err := os.Stat(runtimePath + "/storage.sock"); !os.IsNotExist(err) {
			t.Fatalf("%s left a socket: %v", label, err)
		}
		t.Log(label + " refused before serving")
	}
	write(policyPath, "not a valid AppArmor policy\n")
	assertRefused("invalid policy despite a previously loaded profile")
	write(policyPath, policy)
	write(unitPath, strings.Replace(unit, "-p "+name+" --", "-p "+name+"-absent --", 1))
	run("systemctl", "daemon-reload")
	assertRefused("missing execution profile")
	write(unitPath, unit)
	run("systemctl", "daemon-reload")
	run("systemctl", "reset-failed", name)
	run("systemctl", "start", name)
	t.Log("restored package policy starts successfully; scoped resources will be removed")
}
