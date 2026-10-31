// SPDX-License-Identifier: BSD-3-Clause

//go:build wasip1

package main

import (
	"net"

	"github.com/stealthrocket/net/wasip1"
)

// listenTCP binds a TCP listener through the engine's sockets: Go's net
// package has no listen on wasip1, and a WebAssembly container engine (such
// as go-wasmcontainers, in a browser tab) serves the WasmEdge socket
// extension that stealthrocket/net calls.
func listenTCP(addr string) (net.Listener, error) { return wasip1.Listen("tcp", addr) }
