package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/gateway"
)

type gatewayLifetimeLock struct {
	file *os.File
}

// acquireGatewayLifetimeLock excludes a second Gateway using the same control
// socket before either process can open mutable state or remove that socket.
// The kernel releases flock automatically if the process exits unexpectedly.
func acquireGatewayLifetimeLock(config gateway.Config) (*gatewayLifetimeLock, error) {
	lockPath := config.ControlSocket + ".lock"
	if !filepath.IsAbs(lockPath) || filepath.Clean(lockPath) != lockPath {
		return nil, errors.New("gateway process lock requires a clean absolute control socket path")
	}
	if lockPathCollides(config, lockPath) {
		return nil, fmt.Errorf("gateway process lock path %q collides with configured Gateway data", lockPath)
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o750); err != nil {
		return nil, fmt.Errorf("create gateway process lock directory: %w", err)
	}

	file, created, err := openGatewayLockFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("open gateway process lock: %w", err)
	}
	closeWith := func(lockErr error) (*gatewayLifetimeLock, error) {
		_ = file.Close()
		return nil, lockErr
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeWith(errors.New("another Steward Gateway is already running for this control socket"))
		}
		return closeWith(fmt.Errorf("lock gateway process file: %w", err))
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return closeWith(fmt.Errorf("protect gateway process lock: %w", err))
		}
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return closeWith(fmt.Errorf("inspect gateway process lock: %w", err))
	}
	info, err := file.Stat()
	if err != nil {
		return closeWith(fmt.Errorf("inspect gateway process lock: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
		return closeWith(errors.New("gateway process lock must be an owner-only regular file owned by the Gateway user"))
	}
	return &gatewayLifetimeLock{file: file}, nil
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
		config.ServiceTokenFile, config.StateFile, config.GrantRoot, config.EgressAuditFile,
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
	if lock == nil || lock.file == nil {
		return nil
	}
	err := lock.file.Close()
	lock.file = nil
	return err
}
