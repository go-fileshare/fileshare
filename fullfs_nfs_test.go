// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"testing"
)

// NFS: a full share is NFS3ERR_NOSPC (28), whichever errno. NFS3ERR_DQUOT
// (69) would say "quota" more exactly, and go-filesystems/nfs maps nothing
// to it: a client shows both as "no space left", and the share's size IS
// its quota.
func TestAFullShareOverNFS(t *testing.T) {
	if protocolByName("nfs") == nil {
		t.Skip("built without nfs")
	}
	for _, e := range fullErrnos {
		t.Run(e.name, func(t *testing.T) {
			serveFull(t, e.errno())
			r := start(t, fullDirShare(t)+"serve \"nfs\" { addr = \"127.0.0.1:0\" }\n")
			fh := nfsMount(t, r.addrs["nfs"], "/full")
			// MKDIR3args: the directory, the name, a sattr3 that sets nothing.
			args := append(append(xdrOpaque(fh), xdrOpaque([]byte("d"))...), xdrU32(0, 0, 0, 0, 0, 0)...)
			res := nfsRPC(t, r.addrs["nfs"], 100003, 3, 9, args)
			st := getBE32(res)
			t.Logf("MKDIR: nfsstat3 %d", st)
			if st != 28 {
				t.Errorf("MKDIR on a full share: nfsstat3 %d, want 28 (NFS3ERR_NOSPC)", st)
			}
		})
	}
}
