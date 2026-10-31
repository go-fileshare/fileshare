// SPDX-License-Identifier: BSD-3-Clause

//go:build !wasip1

package main

import "net"

// listenTCP binds a TCP listener. On wasip1 the standard library cannot
// (listen_wasip1.go): a WebAssembly container listens through its engine's
// sockets.
func listenTCP(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
