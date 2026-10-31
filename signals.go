// SPDX-License-Identifier: BSD-3-Clause

//go:build !wasip1

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// notifyContext is cancelled on SIGINT or SIGTERM (signals_wasip1.go says why
// wasip1 is different).
func notifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
