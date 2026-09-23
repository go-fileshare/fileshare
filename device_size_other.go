//go:build !linux && !darwin

package main

import (
	"fmt"
	"io"
	"os"
)

// deviceLength on every other platform seeks to the end.
//
// ⚠ Stated as what it is: the BSDs answer a seek on a disk node, and Windows
// needs IOCTL_DISK_GET_LENGTH_INFO on a \\.\PhysicalDriveN handle, which this
// does not do. A platform where the seek returns 0 gets errEmptyDevice, which
// says the device reported no length -- true, and better than a size invented
// to keep the call site tidy. Darwin was exactly this case, and it is why it
// has a file of its own.
func deviceLength(f *os.File) (int64, error) {
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
