// SPDX-License-Identifier: BSD-3-Clause

//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import "os"

// lockImage is a no-op where there is no flock: a writable HFS+ image is not
// protected against a second writer here (see hfsplus_lock_flock.go).
func lockImage(*os.File) error { return nil }

func unlockImage(*os.File) {}
