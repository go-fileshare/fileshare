// SPDX-License-Identifier: BSD-3-Clause

//go:build nosftp

package main

// Without SFTP there is nowhere an opkssh login could arrive.
const haveOpenPubkey = false

func knownMaxAge(string) bool { return true }
