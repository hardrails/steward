package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionAndCheckConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"-version"}, &stdout, &stderr); status != 0 ||
		!strings.HasPrefix(stdout.String(), "steward-storage-zfs ") || stderr.Len() != 0 {
		t.Fatalf("version status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	raw := `{"schema":"steward.storage-zfs.config.v1","socket":"` + filepath.Join(directory, "storage.sock") +
		`","token_file":"` + token + `","dataset_root":"tank/steward","mount_root":"/var/lib/steward-state",` +
		`"docker_socket":"/var/run/docker.sock","zfs_binary":"/usr/sbin/zfs"}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"-check-config", "-config", configPath}, &stdout, &stderr); status != 0 ||
		stdout.String() != "ZFS storage worker configuration valid\n" || stderr.Len() != 0 {
		t.Fatalf("check status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestConfigurationChecksAreMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"-check-config", "-check-backend"}, &stdout, &stderr)
	if status != 2 || !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestCheckConfigRejectsUnknownFieldsAndLooseToken(t *testing.T) {
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	valid := `{"schema":"steward.storage-zfs.config.v1","socket":"` + filepath.Join(directory, "storage.sock") +
		`","token_file":"` + token + `","dataset_root":"tank/steward","mount_root":"/state",` +
		`"docker_socket":"/var/run/docker.sock","zfs_binary":"/usr/sbin/zfs"}`
	if err := os.WriteFile(configPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"-check-config", "-config", configPath}, &stdout, &stderr); status != 2 ||
		!strings.Contains(stderr.String(), "permission policy") {
		t.Fatalf("loose token status=%d stderr=%q", status, stderr.String())
	}
	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(valid, "}") + `,"surprise":true}`
	if err := os.WriteFile(configPath, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if status := run(context.Background(), []string{"-check-config", "-config", configPath}, &stdout, &stderr); status != 2 ||
		!strings.Contains(stderr.String(), "unknown JSON field") {
		t.Fatalf("unknown field status=%d stderr=%q", status, stderr.String())
	}
}

func TestListenUnixRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "storage.sock")
	if err := os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(path); err == nil || !strings.Contains(err.Error(), "non-socket") {
		t.Fatalf("listen error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "sentinel" {
		t.Fatalf("regular file changed: %q, %v", raw, err)
	}
}

func TestNotifySocketWritesBoundedReadiness(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-notify-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := notifySocket(path, "READY=1\nSTATUS=qualified"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	count, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:count]) != "READY=1\nSTATUS=qualified" {
		t.Fatalf("notification=%q err=%v", buffer[:count], err)
	}
	if err := notifySocket("relative.sock", "READY=1"); err == nil {
		t.Fatal("relative notification socket accepted")
	}
	if err := notifySocket("", "READY=1"); err != nil {
		t.Fatalf("empty notification socket error = %v", err)
	}
	for _, state := range []string{"", "READY=1\x00"} {
		if err := notifySocket(path, state); err == nil {
			t.Fatalf("invalid notification state accepted: %q", state)
		}
	}
}

func TestWorkerLocalResourceGuards(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-zfs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	lockPath := filepath.Join(directory, "worker.lock")
	first, err := acquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireLock(lockPath); err == nil {
		t.Fatal("second lifetime lock was acquired")
	}
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(lockPath); err == nil {
		t.Fatal("loose lifetime lock was accepted")
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(directory, "worker.sock")
	listener, err := listenUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err = listenUnix(socketPath)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	_ = listener.Close()
	_ = os.Remove(socketPath)

	worldWritable := filepath.Join(directory, "loose")
	if err := os.Mkdir(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(filepath.Join(worldWritable, "worker.sock")); err == nil {
		t.Fatal("world-writable socket parent was accepted")
	}
	if _, err := listenUnix(filepath.Join(directory, "missing", "worker.sock")); err == nil {
		t.Fatal("missing socket parent was accepted")
	}
}

func TestWorkerConfigurationValidationBranches(t *testing.T) {
	valid := config{
		Schema: configSchema, Socket: "/run/steward/storage.sock", TokenFile: "/etc/steward/token",
		DatasetRoot: "tank/steward", MountRoot: "/var/lib/steward-state",
		DockerSocket: "/var/run/docker.sock", ZFSBinary: "/usr/sbin/zfs",
	}
	for name, mutate := range map[string]func(*config){
		"schema":       func(value *config) { value.Schema = "other" },
		"socket":       func(value *config) { value.Socket = "relative" },
		"token":        func(value *config) { value.TokenFile = "/" },
		"mount":        func(value *config) { value.MountRoot = "/state/../state" },
		"docker":       func(value *config) { value.DockerSocket = "" },
		"socket token": func(value *config) { value.Socket = value.TokenFile },
		"socket docker": func(value *config) {
			value.Socket = value.DockerSocket
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatalf("invalid configuration accepted: %+v", candidate)
			}
		})
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	if _, err := openBackend(valid); err != nil {
		t.Fatalf("open valid backend: %v", err)
	}
	invalidRunner := valid
	invalidRunner.ZFSBinary = "/usr/sbin/zpool"
	if _, err := openBackend(invalidRunner); err == nil {
		t.Fatal("invalid ZFS binary reached backend")
	}
	invalidDocker := valid
	invalidDocker.DockerSocket = "relative"
	if _, err := openBackend(invalidDocker); err == nil {
		t.Fatal("invalid Docker socket reached backend")
	}

	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{"-unknown"}, {"extra"}, {"-config", "/missing/config.json"}} {
		stdout.Reset()
		stderr.Reset()
		if status := run(context.Background(), args, &stdout, &stderr); status != 2 {
			t.Fatalf("args %v status=%d stderr=%q", args, status, stderr.String())
		}
	}
}

func TestLoadConfigTrimsCRLFTokenAndRejectsUnsafePath(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	raw := `{"schema":"steward.storage-zfs.config.v1","socket":"` + filepath.Join(directory, "storage.sock") +
		`","token_file":"` + tokenPath + `","dataset_root":"tank/steward","mount_root":"/state",` +
		`"docker_socket":"/var/run/docker.sock","zfs_binary":"/usr/sbin/zfs"}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	_, token, err := loadConfig(configPath)
	if err != nil || token != "secret" {
		t.Fatalf("load CRLF token = (%q, %v)", token, err)
	}
	for _, path := range []string{"", "relative", "/", filepath.Join(directory, "missing.json")} {
		if _, _, err := loadConfig(path); err == nil {
			t.Fatalf("unsafe configuration path accepted: %q", path)
		}
	}
}

func TestRunFailsCleanlyBeforeServingUnqualifiedBackend(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-worker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("storage-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	raw := `{"schema":"steward.storage-zfs.config.v1","socket":"` + filepath.Join(directory, "storage.sock") +
		`","token_file":"` + tokenPath + `","dataset_root":"tank/steward","mount_root":"/state",` +
		`"docker_socket":"/var/run/docker.sock","zfs_binary":"` + filepath.Join(directory, "zfs") + `"}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"-config", configPath}, &stdout, &stderr); status != 1 ||
		!strings.Contains(stderr.String(), "initialize backend") {
		t.Fatalf("unqualified backend status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(directory, "storage.sock.lock")); err != nil {
		t.Fatalf("lifetime lock was not created: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"-check-config", "-config", configPath}, &stdout, &stderr); status != 2 ||
		!strings.Contains(stderr.String(), "validate token") {
		t.Fatalf("empty token status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestRunFailsClosedWhenBackendConformanceCannotReachDocker(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "steward-conformance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	zfsPath := filepath.Join(directory, "zfs")
	script := `#!/bin/sh
if [ "$1" = "get" ]; then
  for target do :; done
  if [ "$target" = "tank/steward" ]; then
    printf 'type\tfilesystem\n'
    exit 0
  fi
  printf 'dataset does not exist\n' >&2
  exit 1
fi
exit 0
`
	if err := os.WriteFile(zfsPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("storage-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "storage.sock")
	configPath := filepath.Join(directory, "config.json")
	raw := `{"schema":"steward.storage-zfs.config.v1","socket":"` + socketPath +
		`","token_file":"` + tokenPath + `","dataset_root":"tank/steward","mount_root":"/state",` +
		`"docker_socket":"` + filepath.Join(directory, "missing-docker.sock") + `","zfs_binary":"` + zfsPath + `"}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := run(context.Background(), []string{"-check-backend", "-config", configPath}, &stdout, &stderr); status != 1 ||
		!strings.Contains(stderr.String(), "backend conformance failed") {
		t.Fatalf("conformance status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	lock, err := acquireLock(socketPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"-check-backend", "-config", configPath}, &stdout, &stderr); status != 1 ||
		!strings.Contains(stderr.String(), "acquire lifetime lock") {
		t.Fatalf("locked status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}
