// Package securefile reads small operator-controlled files without following a
// final symlink or trusting a pathname after it has been opened.
package securefile

import (
	"errors"
	"io"
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

// The hook lets package tests deterministically exercise changes after open.
func read(path string, limit int64, permissions Permissions, afterOpen func(*os.File) error) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 || permissions > TrustFile {
		return nil, errors.New("secure file read has an invalid limit or permission policy")
	}
	valid := func(info os.FileInfo) bool {
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

	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !valid(before) {
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
	if !valid(opened) || !sameSnapshot(before, opened) {
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
		return nil, errors.New("file changed while reading")
	}
	if int64(len(raw)) != opened.Size() || !valid(after) || !valid(current) ||
		!sameSnapshot(opened, after) || !sameSnapshot(opened, current) {
		return nil, errors.New("file changed while reading")
	}
	return raw, nil
}

func sameSnapshot(left, right os.FileInfo) bool {
	return os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}
