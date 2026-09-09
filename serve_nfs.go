// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"net"

	"github.com/go-filesystems/nfs"
)

// NFS is the protocol that can express NOTHING about who is asking, and the
// whole of this program's honesty is in what that means here.
//
// A share that names who may use it never reaches this function: see
// protocol.exports. What is left is shares that are for everyone, and the only
// question remaining is whether they are writable -- which is a property of the
// share, not of a person.
//
// Each share is exported at /name, so `mount host:/photos` is the same name a
// person types everywhere else.
func serveNFS(s *server, p *protocol, ln net.Listener) error {
	srv, err := nfs.New()
	if err != nil {
		return err
	}
	served, _ := p.exports(s.shares)
	for _, sh := range served {
		opts := []nfs.ExportOption{
			// The size is known because the image was opened to find it, and
			// `df` on a mount that reports zero free bytes makes a client
			// refuse writes it could have done.
			nfs.WithCapacity(sh.size, sh.size),
		}
		if sh.anyoneWrites() {
			opts = append(opts, nfs.ReadWrite())
		}
		if err := srv.Export("/"+sh.name, sh.fsys, opts...); err != nil {
			return err
		}
	}
	return srv.Serve(ln)
}
