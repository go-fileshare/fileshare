// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"os"
)

// platformMountedBy reads the loop devices from /sys/block and names the mount
// from /proc/self/mountinfo; see mountcheck_loop.go. A system with no
// /sys/block (a container without sysfs) is an error, not "not mounted".
func platformMountedBy(_ context.Context, fi os.FileInfo) (string, error) {
	return loopHolder(fi, "/sys/block", "/proc/self/mountinfo")
}
