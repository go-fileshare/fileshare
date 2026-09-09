// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

// The parent binds, the child inherits.
//
// This is what lets a child serve a PRIVILEGED port without being privileged:
// the parent binds 445 (as root, or with a capability) and the child gets the
// listener as file descriptor 3, having never needed the privilege itself. It
// also means a child that dies cannot take the port with it -- the parent still
// holds it, and the address is not left in TIME_WAIT for the next start.
func passListener(cmd *exec.Cmd, ln net.Listener) error {
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("the listener is a %T, not a TCP one", ln)
	}
	f, err := tcp.File()
	if err != nil {
		return err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	cmd.Env = append(os.Environ(), "FILESHARE_LISTENER=3")
	return nil
}

// inheritedListener picks up what the parent bound, or binds for itself when
// nobody handed it anything -- which is what happens if a person runs
// `serve-one` by hand.
func inheritedListener(addr string) (net.Listener, error) {
	if os.Getenv("FILESHARE_LISTENER") == "" {
		return net.Listen("tcp", addr)
	}
	f := os.NewFile(3, "listener")
	if f == nil {
		return nil, fmt.Errorf("the parent said it passed a listener and there is none")
	}
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("taking the listener the parent passed: %w", err)
	}
	f.Close() // FileListener dups it
	return ln, nil
}
