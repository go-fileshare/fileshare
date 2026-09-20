// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"fmt"
	"net"

	"github.com/go-authn/krb5"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/rpcgss"
)

// NFS, and what it can say about who is asking.
//
// Without a kerberos block it can say NOTHING: AUTH_UNIX is a claim the client
// makes about itself and the wire cannot disagree. A share that names who may
// use it never reaches this function then -- see protocol.exports -- and what
// is left is shares that are for everyone, where the only question is whether
// they are writable.
//
// WITH one, sec=krb5 carries a principal that a ticket proves, and a restricted
// share can be served at last. Each export then asks, on every operation, what
// this caller may do.
//
// Each share is exported at /name, so `mount host:/photos` is the same name a
// person types everywhere else.
func serveNFS(s *server, p *protocol, ln net.Listener) error {
	srv, err := nfs.New()
	if err != nil {
		return err
	}
	k := s.cfg.Kerberos
	if k != nil {
		acceptor, err := krb5.Load(k.Keytab)
		if err != nil {
			return fmt.Errorf("kerberos keytab %s: %w", k.Keytab, err)
		}
		if err := srv.SetAuthenticator(rpcgss.New(acceptor)); err != nil {
			return err
		}
	}

	served, _ := p.exports(s.cfg, s.shares)
	for _, sh := range served {
		opts := []nfs.ExportOption{
			// The size is known because the image was opened to find it, and
			// `df` on a mount that reports zero free bytes makes a client
			// refuse writes it could have done.
			nfs.WithCapacity(sh.size, sh.size),
		}
		switch {
		case sh.anyoneWrites():
			opts = append(opts, nfs.ReadWrite())
		case k != nil && sh.restricted() && !sh.readOnly:
			// ⛔ The export has to be writable for the PREDICATE to have
			// anything to decide. Leaving it read-only because the share is
			// restricted would refuse the named writers too, silently, and
			// the share would look served while nobody could write it.
			opts = append(opts, nfs.ReadWrite())
		}
		if k != nil && sh.restricted() {
			opts = append(opts, nfs.AllowPrincipal(principalGate(k, sh)))
		}
		if err := srv.Export("/"+sh.name, sh.fsys, opts...); err != nil {
			return err
		}
	}
	return srv.Serve(ln)
}

// principalGate turns a share's list of names into the question NFS asks.
//
// ⛔ The realm is compared, not just the name before the @. alice@EXAMPLE.ORG
// and alice@PARTNER.ORG are different people, and a server that matched on the
// short name would hand one realm's files to another realm's alice.
//
// An empty principal -- an AUTH_UNIX caller, or anyone at all if the keytab
// were missing -- maps to no user and is refused by both answers. That is the
// safe direction: a misconfiguration serves nothing rather than everything.
func principalGate(k *kerberosBlock, sh *share) func(string) (bool, bool) {
	return func(principal string) (read, write bool) {
		user := k.userOf(principal)
		if user == "" {
			return false, false
		}
		return sh.mayUse(user), sh.mayUse(user) && !sh.readOnlyFor(user)
	}
}
