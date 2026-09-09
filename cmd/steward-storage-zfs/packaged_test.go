package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func packagedFixture(t *testing.T) (config, fstest.MapFS) {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/config/storage-zfs.json.in")
	if err != nil {
		t.Fatal(err)
	}
	var loaded config
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	return loaded, fstest.MapFS{
		"sys/module/apparmor/parameters/enabled": {Data: []byte("Y\n"), Mode: 0o444},
		"usr/sbin/apparmor_parser":               {Mode: 0o755},
		"usr/bin/aa-exec":                        {Mode: 0o755},
	}
}

func TestPackagedPreflightChecksHostWithoutChangingIt(t *testing.T) {
	for _, scenario := range []string{"valid", "legacy-token", "custom-root", "disabled", "kernel-missing", "parser-missing", "aa-exec-missing", "not-executable", "writable-tool"} {
		t.Run(scenario, func(t *testing.T) {
			loaded, host := packagedFixture(t)
			switch scenario {
			case "legacy-token":
				loaded.TokenFile = "/etc/steward/storage-zfs-token"
			case "custom-root":
				loaded.MountRoot = "/other"
			case "disabled":
				host["sys/module/apparmor/parameters/enabled"].Data = []byte("N\n")
			case "kernel-missing":
				delete(host, "sys/module/apparmor/parameters/enabled")
			case "parser-missing":
				delete(host, "usr/sbin/apparmor_parser")
			case "aa-exec-missing":
				delete(host, "usr/bin/aa-exec")
			case "not-executable":
				host["usr/bin/aa-exec"].Mode = 0o644
			case "writable-tool":
				host["usr/bin/aa-exec"].Mode = 0o777
			}
			err := checkPackagedConfig(loaded, host)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("check error=%v", err)
			}
		})
	}
}

func TestPackagedPreflightCLIRejectsLegacyConfigBeforeOpeningBackend(t *testing.T) {
	loaded, _ := packagedFixture(t)
	directory := t.TempDir()
	loaded.Socket = filepath.Join(directory, "storage.sock")
	loaded.TokenFile = filepath.Join(directory, "old-token")
	if err := os.WriteFile(loaded.TokenFile, []byte("test-private-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"-check-packaged-config", "-config", path}, &stdout, &stderr)
	if status != 2 || !strings.Contains(stderr.String(), "migrate the configuration before activation") || strings.Contains(stderr.String(), "test-private-value") {
		t.Fatalf("status=%d stderr=%s", status, stderr.String())
	}
	if _, err := os.Stat(loaded.Socket + ".lock"); err == nil {
		t.Fatal("preflight unexpectedly created a worker lock")
	}
}

func TestPackagedChecksAreExclusive(t *testing.T) {
	for _, other := range []string{"-check-config", "-check-backend"} {
		var stdout, stderr bytes.Buffer
		if run(context.Background(), []string{"-check-packaged-config", other}, &stdout, &stderr) != 2 || !strings.Contains(stderr.String(), "mutually exclusive") {
			t.Fatalf("accepted simultaneous checks: %s", stderr.String())
		}
	}
}

func TestPackagedTokenCopies(t *testing.T) {
	directory := t.TempDir()
	worker := filepath.Join(directory, "worker")
	client := filepath.Join(directory, "client")
	for _, path := range []string{worker, client} {
		if err := os.WriteFile(path, []byte("test-copy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := checkPackagedToken(worker, "test-copy", client)
	if os.Geteuid() != 0 {
		if err == nil || !strings.Contains(err.Error(), "root-owned") {
			t.Fatalf("untrusted owner accepted: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPackagedToken(worker, "different", client); err == nil || !strings.Contains(err.Error(), "copies differ") {
		t.Fatalf("mismatch error=%v", err)
	}
	if err := checkPackagedToken(worker, "test-copy", worker); err == nil {
		t.Fatal("shared token file accepted")
	}
	if err := os.Chmod(client, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPackagedToken(worker, "test-copy", client); err == nil {
		t.Fatal("loose client token accepted")
	}
}
