//go:build !unix

package main

import "io/fs"

// deviceGroup has no answer off unix (Windows, wasip1). On Windows, access to
// a physical drive is decided by an ACL and by membership of Administrators,
// not by a group on an inode; wasip1 has no device nodes at all.
// Returning false makes the caller fall back to the generic sentence rather
// than invent a group name that would send somebody looking for one.
func deviceGroup(fs.FileInfo) (string, bool) { return "", false }
