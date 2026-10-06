// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// The two ways a host filesystem says it is full: a full disk, and an NTFS
// quota. A protocol library looks for the POSIX errnos, which Go defines on
// Windows too and which no Windows call returns.
var (
	errNoSpace error = windows.ERROR_DISK_FULL
	errQuota   error = windows.ERROR_DISK_QUOTA_EXCEEDED

	noSpaceErrno error = syscall.ENOSPC
	quotaErrno   error = syscall.EDQUOT
)
