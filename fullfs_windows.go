// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import "golang.org/x/sys/windows"

// The two ways a host filesystem says it is full: a full disk, and an NTFS
// quota.
var (
	errNoSpace error = windows.ERROR_DISK_FULL
	errQuota   error = windows.ERROR_DISK_QUOTA_EXCEEDED
)
