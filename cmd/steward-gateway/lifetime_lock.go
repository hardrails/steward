package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/gateway"
)

type gatewayLifetimeLock struct {
	files []*os.File
}

// acquireGatewayLifetimeLock excludes a second Gateway sharing any mutable
// resource, even when an alternate config chooses a different control socket.
// The kernel releases every flock automatically if the process exits.
func acquireGatewayLifetimeLock(config gateway.Config) (*gatewayLifetimeLock, error) {
	paths, err := gatewayMutableLockPaths(config)
	if err != nil {
		return nil, err
	}
	lock := &gatewayLifetimeLock{}
	for _, path := range paths {
		file, err := acquireGatewayResourceLock(path)
		if err != nil {
			_ = lock.Close()
			return nil, err
		}
		lock.files = append(lock.files, file)
	}
	return lock, nil
}

func gatewayMutableLockPaths(config gateway.Config) ([]string, error) {
	resources := []string{config.ControlSocket, config.StateFile, config.GrantRoot}
	if config.EgressAuditFile != "" {
		resources = append(resources, config.EgressAuditFile)
	}
	if config.ConnectorReceiptFile != "" {
		resources = append(resources, config.ConnectorReceiptFile)
	}
	paths := make([]string, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		lockPath := resource + ".steward-gateway.lock"
		if !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath {
			return nil, errors.New("gateway process locks require clean absolute mutable resource paths")
		}
		if lockPathCollides(config, lockPath) {
			return nil, fmt.Errorf("gateway process lock path %q collides with configured Gateway data", lockPath)
		}
		if _, duplicate := seen[lockPath]; duplicate {
			continue
		}
		seen[lockPath] = struct{}{}
		paths = append(paths, lockPath)
	}
	sort.Strings(paths)
	return paths, nil
}

func acquireGatewayResourceLock(lockPath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("create Gateway process lock directory for %q: %w", lockPath, err)
	}
	file, created, err := openGatewayLockFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("open Gateway process lock %q: %w", lockPath, err)
	}
	closeWith := func(lockErr error) (*os.File, error) {
		_ = file.Close()
		return nil, lockErr
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(fmt.Errorf("another Steward Gateway is already running for mutable resource lock %q", lockPath))
		}
		return closeWith(fmt.Errorf("lock Gateway process file %q: %w", lockPath, err))
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return closeWith(fmt.Errorf("protect Gateway process lock %q: %w", lockPath, err))
		}
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return closeWith(fmt.Errorf("inspect Gateway process lock %q: %w", lockPath, err))
	}
	info, err := file.Stat()
	if err != nil {
		return closeWith(fmt.Errorf("inspect Gateway process lock %q: %w", lockPath, err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return closeWith(fmt.Errorf("Gateway process lock %q must be an owner-only regular file owned by the Gateway user", lockPath))
	}
	return file, nil
}

func openGatewayLockFile(path string) (*os.File, bool, error) {
	flags := syscall.O_RDWR | syscall.O_CREAT | syscall.O_EXCL | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	fd, err := syscall.Open(path, flags, 0o600)
	created := err == nil
	if errors.Is(err, syscall.EEXIST) {
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, false, err
	}
	return os.NewFile(uintptr(fd), path), created, nil
}

func lockPathCollides(config gateway.Config, lockPath string) bool {
	paths := []string{
		config.ControlSocket, config.ServiceTokenFile, config.StateFile, config.GrantRoot, config.EgressAuditFile,
		config.ConnectorReceiptFile, config.ConnectorReceiptKeyFile,
	}
	for _, route := range config.Routes {
		paths = append(paths, route.CredentialFile)
	}
	for _, connector := range config.Connectors {
		paths = append(paths, connector.CredentialFile)
	}
	for _, path := range paths {
		if path == lockPath || (path != "" && (strings.HasPrefix(lockPath, path+string(filepath.Separator)) ||
			strings.HasPrefix(path, lockPath+string(filepath.Separator)))) {
			return true
		}
	}
	return false
}

func (lock *gatewayLifetimeLock) Close() error {
	if lock == nil {
		return nil
	}
	var failures []error
	for index := len(lock.files) - 1; index >= 0; index-- {
		if err := lock.files[index].Close(); err != nil {
			failures = append(failures, err)
		}
	}
	lock.files = nil
	return errors.Join(failures...)
}
