// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"testing"
)

// NFS: a full share answers by errno (go-filesystems/nfs reads it through
// the rewrite, which unwraps to it): NFS3ERR_NOSPC (28) for no space,
// NFS3ERR_DQUOT (69) for a quota -- RFC 1813 §2.6, and what Linux's knfsd
// sends (fs/nfsd/vfs.c, nfserrno).
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
			if st != e.nfs {
				t.Errorf("MKDIR on a full share: nfsstat3 %d, want %d (RFC 1813 §2.6)", st, e.nfs)
			}
		})
	}
}
