package main

import (
	"fmt"
	"io"
)

// alignDevice is the alignment every read to a raw device is rounded to.
//
// Not the device's own sector size, deliberately. 4096 is a multiple of every
// sector size in use (512 and 4096), so a 4096-aligned read of a 4096-multiple
// length satisfies a 512-sector device as well -- which saves a second
// per-platform ioctl for a number that would only ever be one of two values.
const alignDevice = 4096

// alignedReaderAt rounds every read out to whole blocks.
//
// ⛔⛔ A RAW DEVICE REFUSES AN UNALIGNED READ, AND THE DRIVERS ARE FULL OF
// THEM. Measured on macOS against an attached device:
//
//	/dev/disk4  (block)     ReadAt(2 bytes @ 11)  -> 2, ok
//	/dev/rdisk4 (character) ReadAt(2 bytes @ 11)  -> 0, invalid argument
//	                        ReadAt(512 bytes @ 0) -> 512, ok
//
// Reading a 2-byte field at offset 11 is what parsing a FAT BPB IS. So without
// this, /dev/rdisk4 reported `detect: unknown filesystem` -- the EINVAL was
// swallowed by a detector that reads a magic number and, finding no magic,
// says it found no filesystem. The true cause named neither alignment nor the
// device.
//
// That matters beyond one platform: the raw node is the one macOS documents
// for bulk I/O, and O_DIRECT on Linux imposes the same rule. A driver that
// reads structures rather than blocks cannot talk to either without this.
type alignedReaderAt struct {
	r    io.ReaderAt
	size int64
}

// ReadAt satisfies io.ReaderAt with whole-block reads underneath.
//
// The returned length is clamped to the device, which is safe to do without
// rounding: a device's length is always a multiple of its sector size, and the
// aligned start is a multiple of 4096 and therefore of 512 -- so what remains
// to the end is a whole number of sectors.
func (a alignedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off < 0 {
		return 0, fmt.Errorf("device read at negative offset %d", off)
	}
	if off >= a.size {
		return 0, io.EOF
	}

	start := off - off%alignDevice
	end := off + int64(len(p))
	if rem := end % alignDevice; rem != 0 {
		end += alignDevice - rem
	}
	if end > a.size {
		end = a.size
	}

	buf := make([]byte, end-start)
	n, err := a.r.ReadAt(buf, start)
	if n == 0 && err != nil {
		return 0, err
	}
	// What the caller asked for, within what actually arrived.
	from := off - start
	if from >= int64(n) {
		return 0, io.EOF
	}
	copied := copy(p, buf[from:n])
	if copied < len(p) {
		return copied, io.EOF
	}
	return copied, nil
}
