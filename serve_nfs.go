// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/go-authn/krb5"
	"github.com/go-filesystems/nfs"
	"github.com/go-filesystems/nfs/rpc"
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
	s.nfsKeyOnce.Do(func() { s.nfsKey, s.nfsKeyErr = nfs.NewHandleKey() })
	if s.nfsKeyErr != nil {
		return s.nfsKeyErr
	}
	if err := srv.SetHandleKey(s.nfsKey); err != nil {
		return err
	}
	k := s.cfg.Kerberos
	if k != nil {
		s.nfsOnce.Do(func() {
			a, err := krb5.Load(k.Keytab)
			if err != nil {
				s.nfsErr = fmt.Errorf("kerberos keytab %s: %w", k.Keytab, err)
				return
			}
			s.nfsState = a
		})
		if s.nfsErr != nil {
			return s.nfsErr
		}
		acceptor := s.nfsState.(*krb5.Acceptor)
		if err := srv.SetAuthenticator(rpcgss.New(acceptor)); err != nil {
			return err
		}
	}

	if c := s.tlsConfigs["nfs"]; c != nil {
		// Offered, not required: go-filesystems/nfs answers the AUTH_TLS
		// probe and upgrades, and still serves a client that never asks. A
		// client certificate, when client_ca_file asks for one, proves the
		// machine -- which is why a restricted share still needs kerberos.
		if err := srv.SetTLS(c); err != nil {
			return err
		}
	}

	certIdentity := s.nfsCRL != nil
	if certIdentity {
		// The name is read once per connection, from the certificate
		// crypto/tls verified against client_ca_file; nfs_identity.go says
		// what it means and what it cannot.
		if err := srv.SetCertificatePrincipal(func(chain []*x509.Certificate) (string, bool) {
			p, err := nfs.OtherNamePrincipal(chain[0])
			return p, err == nil
		}); err != nil {
			return err
		}
	}

	served, _ := p.exports(s.cfg, s.currentShares())
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
		case (k != nil || certIdentity) && sh.restricted() && !sh.readOnly:
			// ⛔ The export has to be writable for the PREDICATE to have
			// anything to decide. Leaving it read-only because the share is
			// restricted would refuse the named writers too, silently, and
			// the share would look served while nobody could write it.
			opts = append(opts, nfs.ReadWrite())
		}
		switch {
		case certIdentity && sh.restricted():
			// Over TLS or not at all: the identity is in the certificate,
			// and a call in the clear carries none -- and would carry the
			// share's contents in the clear besides.
			opts = append(opts, nfs.RequireTLS(), nfs.AllowCall(s.certificateGate(k, sh)))
		case k != nil && sh.restricted():
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
		return sh.mayUse(local(user)), sh.mayUse(local(user)) && !sh.readOnlyFor(local(user))
	}
}

// certificateGate is what a share naming people asks of every NFS call when
// identities come from certificates -- on EVERY call, because NFSv3 has no
// session to decide once for: a file handle outlives any mount.
//
// In order: a Kerberos principal, when there is one, is asked as it always
// was; otherwise the connection's certificate -- not revoked (the CRL, failing
// closed), naming somebody, somebody this server admits the way it admits a
// token -- and then the share's own lists, with the groups the certificate
// carries.
func (s *server) certificateGate(k *kerberosBlock, sh *share) func(*rpc.Call) (bool, bool) {
	kerberos := func(string) (bool, bool) { return false, false }
	if k != nil {
		kerberos = principalGate(k, sh)
	}
	return func(c *rpc.Call) (read, write bool) {
		if c.Cred.Flavor == rpcsecGSS {
			return kerberos(c.Principal)
		}
		if c.TLS == nil || len(c.TLS.PeerCertificates) == 0 || c.Principal == "" {
			return false, false
		}
		leaf := c.TLS.PeerCertificates[0]
		// ⛔ Checked at every call, not only at the handshake: an NFS
		// connection lives for days, a certificate for hours -- and once it
		// expires the provider drops it from its CRL, so a revoked one
		// would come back (found by the security review).
		if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return false, false
		}
		list, err := s.nfsCRL.get()
		if err != nil {
			return false, false
		}
		crl := list.(crlList)
		// The CRL speaks for the CA that signed it and for no other: a
		// certificate from another CA of client_ca_file is not in it,
		// revoked or not.
		if !bytes.Equal(leaf.RawIssuer, crl.issuer) || crl.revoked(leaf.SerialNumber) {
			return false, false
		}
		p := principal{name: c.Principal, federated: true, groups: groupsOfCert(leaf)}
		if s.admitFederated(p) != nil || s.federatedRevoked(p.name, "", "", leaf.NotBefore) != nil {
			return false, false
		}
		return sh.mayUse(p), sh.mayUse(p) && !sh.readOnlyFor(p)
	}
}

// rpcsecGSS is RPCSEC_GSS's credential flavour (RFC 2203).
const rpcsecGSS = 6
