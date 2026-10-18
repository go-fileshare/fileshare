// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !linux

package launch

import "syscall"

// platformAttr: nothing beyond Credential and Setsid here. These systems have
// no parent-death signal in Go's SysProcAttr: a worker outlives a launcher
// that dies, until its front closes the socket.
func platformAttr(*syscall.SysProcAttr) {}

// hardenWorker: no PR_SET_NO_NEW_PRIVS outside Linux.
func hardenWorker() error { return nil }
