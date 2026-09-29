// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

// hangups never receives where there is no SIGHUP; the interval and the admin
// API's ReloadDirectory still reload.
func hangups(<-chan struct{}) <-chan struct{} { return nil }
