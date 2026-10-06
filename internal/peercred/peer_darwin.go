// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package peercred

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerOf reads LOCAL_PEERCRED, the BSD form of SO_PEERCRED: the effective
// credentials the peer had at connect(2). It is here so the tests of the
// servers built on this package run on a Mac too; the provisioner itself is
// Linux only.
func peerOf(c *net.UnixConn) (uid, gid uint32, pid int32, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *unix.Xucred
	pid = -1
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if p, perr := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); perr == nil {
			pid = int32(p)
		}
	}); err != nil {
		return 0, 0, 0, err
	}
	if serr != nil {
		return 0, 0, 0, serr
	}
	if cred.Ngroups < 1 {
		return 0, 0, 0, errors.New("LOCAL_PEERCRED reported no group")
	}
	return cred.Uid, cred.Groups[0], pid, nil
}
