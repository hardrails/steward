//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const darwinAttrCommonExtendedSecurity = 0x00400000

type darwinAttrList struct {
	BitmapCount uint16
	Reserved    uint16
	CommonAttr  uint32
	VolumeAttr  uint32
	DirAttr     uint32
	FileAttr    uint32
	ForkAttr    uint32
}

// extendedACLPresent asks getattrlist(2) for ATTR_CMN_EXTENDED_SECURITY. The
// returned variable-length attribute is empty when no ACL exists and non-empty
// when the file carries an ACL. This raw standard-library syscall keeps the same
// zero-dependency posture as the Linux xattr check.
func extendedACLPresent(path string) (bool, error) {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return false, err
	}
	attrs := darwinAttrList{
		BitmapCount: 5,
		CommonAttr:  darwinAttrCommonExtendedSecurity,
	}
	buf := make([]byte, 64*1024)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETATTRLIST,
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	if errno != 0 {
		return false, fmt.Errorf("getattrlist: %w", errno)
	}
	// The result begins with uint32 total length followed by attrreference_t:
	// int32 data offset, uint32 data length.
	if len(buf) < 12 || binary.LittleEndian.Uint32(buf[:4]) < 12 {
		return false, fmt.Errorf("getattrlist returned a truncated extended-security attribute")
	}
	return binary.LittleEndian.Uint32(buf[8:12]) > 0, nil
}
