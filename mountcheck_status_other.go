// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import "os"

// loopStatusMatches has nothing to ask off Linux; the loop code runs here only
// under test, against a fake sysfs.
func loopStatusMatches(os.FileInfo, string) bool { return false }
