// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// hangups is a channel that receives when the process gets SIGHUP -- the
// signal a daemon is sent to read its world again -- until stop is closed.
func hangups(stop <-chan struct{}) <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	out := make(chan struct{}, 1)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-stop:
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}
