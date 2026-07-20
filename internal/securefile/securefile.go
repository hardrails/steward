// Package securefile reads small operator-controlled files without following a
// final symlink or trusting a pathname after it has been opened.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"syscall"
)

// Permissions selects the mode-bit policy enforced on every file snapshot.
type Permissions uint8

const (
	// Regular permits any mode on a non-empty bounded regular file.
	Regular Permissions = iota
	// OwnerOnly rejects every group or other permission bit.
	OwnerOnly
	// TrustFile permits group/other reads but rejects their write bits.
	TrustFile
)

// Read returns one stable, bounded snapshot of path. It opens with O_NOFOLLOW
// and O_NONBLOCK, reads through the descriptor with an explicit limit, and
// rejects identity, size, mode, or modification-time changes through the end of
// the read.
func Read(path string, limit int64, permissions Permissions) ([]byte, error) {
	return read(path, limit, permissions, nil)
}

// ReadRoot is Read for a name confined beneath a descriptor-pinned root.
// Root prevents a mutable ancestor or symlink from redirecting the open
// outside the selected directory identity.
func ReadRoot(root *os.Root, name string, limit int64, permissions Permissions) ([]byte, error) {
	return readRootSnapshot(root, name, limit, permissions, 0, false, nil)
}

// ReadRootMode is ReadRoot with an exact permission-mode requirement. The
// mode is checked against the same descriptor-backed snapshot that is read,
// so a pathname replacement cannot separate metadata verification from the
// returned bytes.
func ReadRootMode(root *os.Root, name string, limit int64, mode fs.FileMode) ([]byte, error) {
	if mode&^fs.ModePerm != 0 {
		return nil, errors.New("secure root file read has an invalid mode")
	}
	return readRootSnapshot(root, name, limit, Regular, mode, true, nil)
}

// The hook lets package tests deterministically exercise changes after open.
func read(path string, limit int64, permissions Permissions, afterOpen func(*os.File) error) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 || permissions > TrustFile {
		return nil, errors.New("secure file read has an invalid limit or permission policy")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !validSnapshot(before, limit, permissions) {
		return nil, errors.New("file must be non-empty, bounded, regular, and satisfy its permission policy")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !validSnapshot(opened, limit, permissions) || !sameSnapshot(before, opened) {
		return nil, errors.New("file changed while opening")
	}
	if afterOpen != nil {
		if err := afterOpen(file); err != nil {
			return nil, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat file after reading: %w", err)
	}
	if int64(len(raw)) != opened.Size() ||
		!validSnapshot(after, limit, permissions) ||
		!validSnapshot(current, limit, permissions) ||
		!sameSnapshot(opened, after) || !sameSnapshot(opened, current) {
		return nil, errors.New("file changed while reading")
	}
	return raw, nil
}

func readRoot(
	root *os.Root,
	name string,
	limit int64,
	permissions Permissions,
	afterOpen func(*os.File) error,
) ([]byte, error) {
	return readRootSnapshot(root, name, limit, permissions, 0, false, afterOpen)
}

func readRootSnapshot(
	root *os.Root,
	name string,
	limit int64,
	permissions Permissions,
	exactMode fs.FileMode,
	requireExactMode bool,
	afterOpen func(*os.File) error,
) ([]byte, error) {
	if root == nil || name == "" || limit <= 0 || limit == math.MaxInt64 ||
		permissions > TrustFile {
		return nil, errors.New("secure root file read has an invalid root, name, limit, or permission policy")
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !validRootSnapshot(before, limit, permissions, exactMode, requireExactMode) {
		return nil, errors.New("root file must be non-empty, bounded, regular, and satisfy its permission policy")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !validRootSnapshot(opened, limit, permissions, exactMode, requireExactMode) || !sameSnapshot(before, opened) {
		return nil, errors.New("root file changed while opening")
	}
	if afterOpen != nil {
		if err := afterOpen(file); err != nil {
			return nil, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("stat root file after reading: %w", err)
	}
	if int64(len(raw)) != opened.Size() ||
		!validRootSnapshot(after, limit, permissions, exactMode, requireExactMode) ||
		!validRootSnapshot(current, limit, permissions, exactMode, requireExactMode) ||
		!sameSnapshot(opened, after) || !sameSnapshot(opened, current) {
		return nil, errors.New("root file changed while reading")
	}
	return raw, nil
}

func validRootSnapshot(info os.FileInfo, limit int64, permissions Permissions, exactMode fs.FileMode, requireExactMode bool) bool {
	return validSnapshot(info, limit, permissions) && (!requireExactMode || info.Mode().Perm() == exactMode)
}

func validSnapshot(info os.FileInfo, limit int64, permissions Permissions) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return false
	}
	switch permissions {
	case Regular:
		return true
	case OwnerOnly:
		return info.Mode().Perm()&0o077 == 0
	case TrustFile:
		return info.Mode().Perm()&0o022 == 0
	default:
		return false
	}
}

func sameSnapshot(left, right os.FileInfo) bool {
	return os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}
