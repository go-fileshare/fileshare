//go:build unix

package main

import (
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
)

// deviceGroup is the name of the group that owns a device node.
//
// It exists so a refusal can say "join the disk group" rather than "permission
// denied", which is the difference between a person solving the problem and a
// person reaching for sudo. The group is read from the node itself rather than
// guessed per platform, because it is `disk` on most Linux distributions,
// `operator` on macOS, and neither on some.
//
// A numeric id that resolves to no name is still useful, so it is returned as
// digits rather than dropped: a reader can put it into `getent group`.
func deviceGroup(fi fs.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	gid := strconv.FormatUint(uint64(st.Gid), 10)
	if g, err := user.LookupGroupId(gid); err == nil && g.Name != "" {
		return g.Name, true
	}
	return gid, true
}
