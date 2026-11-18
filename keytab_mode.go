// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"runtime"
)

// checkKeytabMode refuses a keytab that anybody but its owner and its group
// could read, or that its group could change. A keytab holds the service's
// long-term keys -- with both nfs/ and cifs/ in one file, the right to be
// this server for both -- so a copy read by another account forges tickets
// to it for every person of the realm.
//
// Group-READ stays allowed: the usual layout is root:<service group> 0640,
// the same as every other secret a systemd unit reads through its group.
//
// Windows has no mode bits worth reading; its ACLs are the operator's (the
// README says where to put the file), so nothing is checked there.
func checkKeytabMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("kerberos keytab %s: %w", path, err)
	}
	if m := fi.Mode().Perm(); m&0o027 != 0 {
		return fmt.Errorf("kerberos keytab %s is mode %v: it must not be readable or writable by others, nor writable by its group (chmod 0640 or 0600)", path, m)
	}
	return nil
}
