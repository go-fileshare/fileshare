// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import "io/fs"

// keytabOwnerOK: on Windows the file's ACL is the operator's, and readKeytab
// does not call this.
func keytabOwnerOK(fs.FileInfo) error { return nil }
