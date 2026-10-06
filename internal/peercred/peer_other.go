// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package peercred

import (
	"errors"
	"net"
)

// peerOf has nothing to ask on this system, and refuses rather than guess:
// credentials that cannot name the peer must not let it in.
func peerOf(*net.UnixConn) (uid, gid uint32, pid int32, err error) {
	return 0, 0, 0, errors.New("this system does not report a unix socket's peer")
}
