// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// evictFromCache drops the file's clean pages from the page cache
// (posix_fadvise(POSIX_FADV_DONTNEED), which needs no privilege) and reports
// whether it could.
func evictFromCache(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// Dirty pages are not dropped: flush them first.
	if err := f.Sync(); err != nil {
		return false
	}
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED) == nil
}

// loadAverage1 is the 1-minute load average, and whether it could be read.
func loadAverage1() (float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}
