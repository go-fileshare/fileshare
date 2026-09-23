//go:build windows

package main

import "io/fs"

// deviceGroup has no answer on Windows: access to a physical drive is decided
// by an ACL and by membership of Administrators, not by a group on an inode.
// Returning false makes the caller fall back to the generic sentence rather
// than invent a group name that would send somebody looking for one.
func deviceGroup(fs.FileInfo) (string, bool) { return "", false }
