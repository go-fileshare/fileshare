// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/go-authn/directory"
)

// A protocol is one way to reach a share, and what it can honestly promise.
//
// The field that matters is authenticates. Everything else in this program
// follows from it: a share that names who may use it can only be served by a
// protocol that can tell people apart, and a protocol that cannot is refused
// the share rather than handed it to whoever connects.
type protocol struct {
	name string

	// authenticates: can this protocol prove who is asking?
	//
	//   SMB     NTLMv2, and the password never crosses the wire.
	//   WebDAV  HTTP Basic (and TLS underneath, which is the caller's).
	//   NFSv3   Not on its own: AUTH_UNIX is a claim the wire cannot check.
	//           With a kerberos block it can, and canAuthenticate is where
	//           that deployment-dependent answer is given.
	authenticates bool

	// why is what a refusal says. It is written here, once, rather than
	// composed at the point of refusal, so the reason a person reads is the
	// reason the code acts on.
	why string

	// serve runs until the listener is closed.
	serve func(*server, *protocol, net.Listener) error

	// defaultPort is what a person gets when they do not say. They are the
	// registered ones, and a person who does not care should still land where
	// a client looks.
	defaultPort int
}

// The protocols COMPILED INTO this binary, in the order they registered.
//
// Each lives in its own file behind a build tag, and registers itself here.
// `go build -tags nonfs` leaves NFS out entirely: not disabled at runtime,
// absent -- no listener, no code, no dependency.
//
// The alternative was subprocess plugins, and it was measured rather than
// argued: hashicorp/go-plugin brings gRPC and protobuf, which cost 13.2 MB on
// their own -- more than this entire binary with all three protocols and every
// driver in it (13.1 MB). A plugin host would be twice the size before loading
// anything, and each plugin would carry gRPC again. Plugins buy other things --
// protocols nobody here wrote, crash isolation -- but not the thing they would
// have been for.
var protocols []*protocol

// known is every protocol this program has a name for, whether or not it was
// compiled in. A configuration that names one which was left out deserves to
// be told THAT, rather than "there is no such protocol".
var known = []string{"smb", "webdav", "nfs", "sftp", "s3"}

func register(p *protocol) {
	protocols = append(protocols, p)
	slices.SortFunc(protocols, func(a, b *protocol) int { return strings.Compare(a.name, b.name) })
}

func protocolByName(name string) *protocol {
	for _, p := range protocols {
		if p.name == name {
			return p
		}
	}
	return nil
}

func protocolNames() string {
	names := make([]string, 0, len(protocols))
	for _, p := range protocols {
		names = append(names, p.name)
	}
	return list(names)
}

// missing says whether a name is a protocol this program knows but this
// BINARY does not have -- the difference between a typo and a build tag.
func missing(name string) bool {
	return protocolByName(name) == nil && slices.Contains(known, name)
}

// exports reports what this protocol will actually serve, and what it will
// not.
//
// A share that names who may use it is NOT exported over a protocol that
// cannot tell them apart. This is the whole point of the program: a
// configuration that says "photos belongs to alice" and a protocol that would
// hand photos to whoever connects cannot both be honoured, and quietly
// widening access is the worse of the two failures.
// canAuthenticate reports whether this protocol can tell people apart in THIS
// deployment.
//
// For every protocol but NFS the answer is a property of the protocol and
// nothing else. NFS is the exception: it cannot, until a keytab turns
// RPCSEC_GSS on, and then it can -- which is why the question takes a
// configuration rather than being a field.
func (p *protocol) canAuthenticate(c *config) bool {
	if p.authenticates {
		return true
	}
	return p.name == "nfs" && c != nil && c.Kerberos != nil
}

func (p *protocol) exports(c *config, shares []*share) (served, refused []*share) {
	for _, s := range shares {
		if len(s.protocols) > 0 && !slices.Contains(s.protocols, p.name) {
			// Not refused, just not for this one: the share said which
			// protocols carry it, and this is not among them.
			continue
		}
		if !p.canAuthenticate(c) && s.restricted() {
			refused = append(refused, s)
			continue
		}
		served = append(served, s)
	}
	return served, refused
}

// refusal is what a person reads when a share is not exported.
func (p *protocol) refusal(s *share) string {
	return fmt.Sprintf("%s is not served over %s: it is restricted to %s, and %s",
		s.name, p.name, s.who(), p.why)
}

// canServeUser answers whether a protocol can authenticate THIS person, given
// what their directory holds for them.
//
// It is a function rather than a switch inside the `check` renderer because it
// is the answer `check` prints AND the reason a mount fails later: the two
// must be the same rule, and a rule stated in one place cannot drift from
// itself. It also makes the distinctions testable without building a
// configuration that can reach every credential shape -- an NT hash arrives
// from SQL or LDAP and cannot be written in an HCL user block at all.
func canServeUser(name string, who *directory.Identity, cfg *config) bool {
	switch name {
	case "smb":
		// NTLMv2 needs the password or its MD4, and nothing else will do.
		return who.Can(directory.NTHash)
	case "webdav":
		return who.Can(directory.Verifier) || who.Can(directory.Password)
	case "sftp":
		// A trusted authority makes everybody able to present a certificate,
		// whatever this directory holds for them.
		return who.Can(directory.PublicKeys) || (cfg != nil && cfg.TrustedUserCAFile != "")
	case "s3":
		// ⛔ NEARLY the same answer as SMB, and the difference matters. SigV4
		// proves possession of the secret by computing an HMAC from it, so
		// this server needs the secret -- the password itself. A source that
		// can only CHECK a password answers WebDAV and cannot answer S3,
		// exactly as it cannot answer NTLMv2.
		//
		// But NOT directory.NTHash: that is the MD4 SMB can work from, and an
		// HMAC cannot be computed from it. An identity holding only an NT hash
		// serves SMB and not S3, so the two columns are neighbours rather than
		// copies -- which is the kind of thing `check` exists to print.
		return who.Can(directory.Password)
	}
	return false
}
