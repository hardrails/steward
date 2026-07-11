//go:build linux

package main

import (
	"errors"
	"syscall"
)

// extendedACLPresent checks the POSIX access-ACL xattr directly. ENODATA means
// there is no access ACL; ENOTSUP means this filesystem cannot carry one. Any
// other failure is returned so startup fails closed rather than guessing.
func extendedACLPresent(path string) (bool, error) {
	_, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
		return false, nil
	}
	return false, err
}
