// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import "syscall"

// The two ways a host filesystem says it is full.
var (
	errNoSpace error = syscall.ENOSPC
	errQuota   error = syscall.EDQUOT
)
