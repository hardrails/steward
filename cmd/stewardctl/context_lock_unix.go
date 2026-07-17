//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockCLIContextConfig(contextPath string) (func() error, error) {
	directory := filepath.Dir(contextPath)
	if err := ensureCLIContextDirectory(directory); err != nil {
		return nil, err
	}
	lockPath := contextPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open CLI context write lock: %w", err)
	}
	fail := func(cause error) (func() error, error) {
		return nil, errors.Join(cause, lockFile.Close())
	}
	openedInfo, err := lockFile.Stat()
	if err != nil {
		return fail(err)
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		return fail(err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return fail(errors.New("CLI context write lock must be an owner-only regular file"))
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fail(fmt.Errorf("lock CLI context file: %w", err))
	}
	return func() error {
		return errors.Join(
			syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN),
			lockFile.Close(),
		)
	}, nil
}
