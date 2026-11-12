// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// loopStatusMatches asks the kernel's own record of /dev/loopN: loop(4),
// LOOP_GET_STATUS64 returns loop_info64 with lo_device and lo_inode, the device
// and inode of the backing file, with no path in it. The node is root:disk 0660
// on most systems, so this works only for a process that may open it; where it
// may not (EACCES) the answer is "no", and the sysfs path stays the one source.
// lo_device is huge_encode_dev(st_dev), which is also what stat(2) reports on
// Linux (cp_new_stat), so the two compare as they are.
func loopStatusMatches(fi os.FileInfo, dev string) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	f, err := os.Open(dev)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := unix.IoctlLoopGetStatus64(int(f.Fd()))
	if err != nil {
		return false
	}
	return info.Inode == uint64(st.Ino) && info.Device == uint64(st.Dev)
}
