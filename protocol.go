// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
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
	//   NFSv3   No. AUTH_UNIX is a claim the wire cannot check.
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

var protocols = []*protocol{
	{
		name:          "smb",
		authenticates: true,
		serve:         serveSMB,
		defaultPort:   445,
	},
	{
		name:          "webdav",
		authenticates: true,
		serve:         serveWebDAV,
		defaultPort:   8080,
	},
	{
		name:          "nfs",
		authenticates: false,
		why: "NFSv3 has no authentication at all: AUTH_UNIX is a claim the client makes " +
			"about itself and the wire cannot disagree with it",
		serve:       serveNFS,
		defaultPort: 2049,
	},
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

// exports reports what this protocol will actually serve, and what it will
// not.
//
// A share that names who may use it is NOT exported over a protocol that
// cannot tell them apart. This is the whole point of the program: a
// configuration that says "photos belongs to alice" and a protocol that would
// hand photos to whoever connects cannot both be honoured, and quietly
// widening access is the worse of the two failures.
func (p *protocol) exports(shares []*share) (served, refused []*share) {
	for _, s := range shares {
		if !p.authenticates && s.restricted() {
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
