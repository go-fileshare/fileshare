// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix && !windows

package main

import "syscall"

// No quota to speak of: only a full disk.
var (
	errNoSpace error = syscall.ENOSPC
	errQuota   error = syscall.ENOSPC

	noSpaceErrno error = syscall.ENOSPC
	quotaErrno   error = syscall.ENOSPC
)
