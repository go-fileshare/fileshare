// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// keytabOwnerOK accepts a keytab owned by root or by the account this server
// runs as: any other owner can rewrite the mode, or the keys.
func keytabOwnerOK(fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("its owner cannot be read")
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("it belongs to uid %d, neither root nor this server (uid %d)", uid, os.Geteuid())
	}
	return nil
}
