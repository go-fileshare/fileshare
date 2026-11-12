// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockImage takes an exclusive advisory lock on the image, without waiting: a
// writable HFS+ volume is the whole image in memory, flushed whole by every
// change, so a second writer (another fileshare, anything else that takes the
// lock) would have its changes overwritten by the next flush. It is advisory:
// it keeps out processes that ask for the lock too, not a macOS mount. The lock
// goes when the file is closed.
func lockImage(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

func unlockImage(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
