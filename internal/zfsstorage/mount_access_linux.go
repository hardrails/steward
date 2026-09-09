package zfsstorage

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const zfsFilesystemMagic = 0x2fc12fc1

func (FilesystemMountAccess) Prepare(path string) error {
	file, err := openZFSRoot(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chown(0, 65532); err != nil {
		return err
	}
	return file.Chmod(0o770)
}

func (FilesystemMountAccess) Verify(path string) error {
	file, err := openZFSRoot(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Uid != 0 || stat.Gid != 65532 || stat.Mode&0o7777 != 0o770 {
		return errors.New("ZFS root must be root-owned with only sandbox group access")
	}
	return nil
}

func openZFSRoot(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("ZFS root requires a clean absolute directory")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(file.Fd()), &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	if stat.Type != zfsFilesystemMagic {
		_ = file.Close()
		return nil, errors.New("state directory is not a mounted ZFS filesystem")
	}
	return file, nil
}
