// SPDX-License-Identifier: BSD-3-Clause

//go:build wasip1

package main

import "context"

// notifyContext is only cancellable on wasip1: no signal reaches a WebAssembly
// guest, and subscribing to one costs everything. With no threads, Go's runtime
// waits for a signal by yielding in a loop (runtime/sigqueue.go signal_recv,
// notetsleepg), so after signal.Notify one goroutine is always runnable and the
// scheduler seldom reaches the network poller: a listener accepted nothing,
// measured in the go-wasmcontainers engine, until the loop happened to yield
// to it. The container ends when its engine stops it.
func notifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
