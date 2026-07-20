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
}
