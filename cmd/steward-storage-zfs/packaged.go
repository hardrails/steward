package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/securefile"
)

// This checks the stock unit, not arbitrary operator overrides. It never loads
// a policy, takes the worker lock, touches the pool, or changes a credential.
func checkPackagedConfig(loaded config, host fs.FS) error {
	for _, field := range []struct{ name, actual, required string }{
		{"token_file", loaded.TokenFile, "/etc/steward/storage-zfs-worker-token"},
		{"socket", loaded.Socket, "/run/steward-storage-zfs/storage.sock"},
		{"mount_root", loaded.MountRoot, "/var/lib/steward-state"},
		{"docker_socket", loaded.DockerSocket, "/var/run/docker.sock"},
		{"zfs_binary", loaded.ZFSBinary, "/usr/sbin/zfs"},
	} {
		if field.actual != field.required {
			return fmt.Errorf("packaged policy requires %s=%s; migrate the configuration before activation (custom paths require a separately reviewed unit and policy)", field.name, field.required)
		}
	}
	enabled, err := fs.ReadFile(host, "sys/module/apparmor/parameters/enabled")
	if err != nil || strings.TrimSpace(string(enabled)) != "Y" {
		return errors.New("AppArmor must be enabled in the host kernel before activating the packaged storage worker")
	}
	for _, path := range []string{"usr/sbin/apparmor_parser", "usr/bin/aa-exec"} {
		info, err := fs.Stat(host, path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("install AppArmor userspace tools: /%s must be a regular executable not writable by group or others", path)
		}
	}
	return nil
}

func checkPackagedToken(workerPath, workerToken, clientPath string) error {
	info, err := os.Lstat(workerPath)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("worker token copy must be a root-owned regular 0600 file; see the persistent-state upgrade guide")
	}
	if clientPath == "" || !filepath.IsAbs(clientPath) || filepath.Clean(clientPath) != clientPath || clientPath == workerPath {
		return errors.New("provide the distinct Executor owner-only token path with -client-token-file")
	}
	raw, err := securefile.Read(clientPath, maxTokenSize, securefile.OwnerOnly)
	if err != nil {
		return fmt.Errorf("read Executor token copy: %w", err)
	}
	clientToken := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if subtle.ConstantTimeCompare([]byte(workerToken), []byte(clientToken)) != 1 {
		return errors.New("worker and Executor token copies differ; restore identical values before activation, without rotating a live worker's token")
	}
	return nil
}
