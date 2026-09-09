//go:build !linux

package zfsstorage

import "errors"

func (FilesystemMountAccess) MigrateLegacy(string) error {
	return errors.New("qualified state mount access requires Linux")
}

func (FilesystemMountAccess) Prepare(string) error {
	return errors.New("qualified state mount access requires Linux")
}

func (FilesystemMountAccess) Verify(string) error {
	return errors.New("qualified state mount access requires Linux")
}
