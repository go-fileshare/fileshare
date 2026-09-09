// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"net"
	"os/exec"
)

// Windows has no ExtraFiles: os/exec says so plainly, and there is no portable
// way to hand a socket to a child here. So on Windows the parent's listener is
// closed and the CHILD binds the same address.
//
// What is lost is only the privileged-port half of the idea -- a child that
// needs a low port must be able to bind it itself. The isolation that matters
// is untouched: the child still opens only the images it was given.
func passListener(cmd *exec.Cmd, ln net.Listener) error {
	return ln.Close()
}

func inheritedListener(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
