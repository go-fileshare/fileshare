// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import "syscall"

// The two ways a host filesystem says it is full, and the errnos a protocol
// library looks for: here they are the same.
var (
	errNoSpace error = syscall.ENOSPC
	errQuota   error = syscall.EDQUOT

	noSpaceErrno error = syscall.ENOSPC
	quotaErrno   error = syscall.EDQUOT
)
