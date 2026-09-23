//go:build darwin

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Asking a Darwin device how big it is.
//
// ⛔ SEEKING DOES NOT WORK HERE, AND IT DOES NOT FAIL EITHER. Measured on
// macOS 15 against a real attached device, /dev/disk4 and /dev/rdisk4 alike:
//
//	Seek(0, io.SeekEnd) = 0, err = <nil>
//	ReadAt(512 bytes, offset 0) = 512, err = <nil>
//
// The device reads perfectly and reports a length of zero. The obvious
// portable implementation -- lseek to the end, which Linux does answer -- was
// written here first and returned a plausible wrong answer. A file-backed test
// could never have caught it; attaching a real device caught it immediately.
//
// So: two ioctls. Neither needs cgo.
//
// x/sys/unix v0.48.0 exports neither constant, so they are DERIVED from the
// macro rather than pasted as magic numbers, which is both checkable and
// self-documenting:
//
//	_IOR(g, n, t) = 0x40000000 | (sizeof(t) << 16) | (g << 8) | n
//
// with group 'd' for "disk". DKIOCGETBLOCKSIZE is request 24 returning a
// uint32; DKIOCGETBLOCKCOUNT is request 25 returning a uint64.
const (
	iocOut = 0x40000000

	dkiocGetBlockSize  = iocOut | (4 << 16) | ('d' << 8) | 24 // 0x40046418
	dkiocGetBlockCount = iocOut | (8 << 16) | ('d' << 8) | 25 // 0x40086419
)

// ⛔ The two results are DIFFERENT WIDTHS, and that is why they are not both
// read through one helper. x/sys/unix offers IoctlGetInt, which hands the
// kernel a pointer to a 64-bit int; for the 4-byte block size the kernel
// writes half of it and the other half is whatever the variable held. It
// happens to work on a little-endian machine with a zeroed variable, which is
// the kind of thing that works until it is ported.
func deviceLength(f *os.File) (int64, error) {
	fd := int(f.Fd())

	var blockSize uint32
	if err := ioctlPtr(fd, dkiocGetBlockSize, unsafe.Pointer(&blockSize)); err != nil {
		return 0, fmt.Errorf("asking %s for its block size: %w", f.Name(), err)
	}
	var blockCount uint64
	if err := ioctlPtr(fd, dkiocGetBlockCount, unsafe.Pointer(&blockCount)); err != nil {
		return 0, fmt.Errorf("asking %s for its block count: %w", f.Name(), err)
	}
	if blockSize == 0 || blockCount == 0 {
		return 0, errEmptyDevice
	}
	return int64(blockCount) * int64(blockSize), nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
