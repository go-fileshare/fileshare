//go:build linux

package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// deviceLength asks a Linux device how big it is.
//
// BLKGETSIZE64 returns the size of the medium in bytes and is the answer the
// kernel keeps; lseek to the end returns the same number on Linux, but only on
// Linux -- on Darwin it returns 0 with no error, which is why this is a
// per-platform file rather than one seek shared by both.
//
// The seek is kept as a fallback for the nodes BLKGETSIZE64 does not serve:
// a device-mapper target or a loop device answers the ioctl, but a character
// device that is not a disk at all will not, and a file bind-mounted over a
// device node is a regular file wearing the wrong name.
func deviceLength(f *os.File) (int64, error) {
	if size, err := unix.IoctlGetUint32(int(f.Fd()), unix.BLKGETSIZE64); err == nil && size > 0 {
		return int64(size), nil
	}
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("asking %s how big it is: %w", f.Name(), err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("putting the cursor of %s back: %w", f.Name(), err)
	}
	if end <= 0 {
		return 0, errEmptyDevice
	}
	return end, nil
}
