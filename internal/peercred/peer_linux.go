// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package peercred

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerOf reads SO_PEERCRED: the credentials the kernel recorded for the peer
// when it called connect(2) (or socketpair(2)), unix(7).
func peerOf(c *net.UnixConn) (uid, gid uint32, pid int32, err error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *unix.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, 0, err
	}
	if serr != nil {
		return 0, 0, 0, serr
	}
	return cred.Uid, cred.Gid, cred.Pid, nil
}
