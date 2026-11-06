// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package main

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// evictFromCache cannot be done on macOS without root (`sudo purge`).
func evictFromCache(string) bool { return false }

// loadAverage1 is the 1-minute load average (sysctl vm.loadavg: three
// uint32 fixed-point values, padding, then the int64 scale), and whether it
// could be read.
func loadAverage1() (float64, bool) {
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(b) < 24 {
		return 0, false
	}
	scale := binary.NativeEndian.Uint64(b[16:24])
	if scale == 0 {
		return 0, false
	}
	return float64(binary.NativeEndian.Uint32(b[0:4])) / float64(scale), true
}
