// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/go-filesystems/sftp"
	"github.com/go-filesystems/sftp/sshd"
	"golang.org/x/crypto/ssh"
)

// SFTP is the protocol every client already has -- `sftp` ships with OpenSSH,
// the Finder and GNOME mount it, every editor speaks it -- and the one whose
// shape fits this program least: a person logs in and lands in ONE filesystem,
// not in a list of shares.
//
// So the shares become the top-level directories of a tree built for the
// person who just authenticated (see unionfs.go), and the daemon is told to
// build it per connection. That hook exists because this program needed it:
// go-filesystems/sftp v0.2.0 added Config.ServerFor and Config.Password.
func serveSFTP(s *server, p *protocol, ln net.Listener) error {
	hostKey, err := s.hostKey()
	if err != nil {
		return err
	}
	cas, err := s.trustedUserCAs()
	if err != nil {
		return err
	}
	served, _ := p.exports(s.shares)
	d, err := sshd.New(nil, sshd.Config{
		HostKeys:       []ssh.Signer{hostKey},
		TrustedUserCAs: cas,
		// A key proves who is asking without this server ever holding the
		// secret, and a certificate says it with an expiry date on it. There
		// is deliberately NO password here: an SSH client that prompts for one
		// is an SSH client doing the thing keys exist to avoid, and the
		// passwords in this configuration are for the protocols that have
		// nothing better.
		PublicKeyFor: func(user string, key ssh.PublicKey) bool {
			for _, k := range s.keys[user] {
				if string(k.Marshal()) == string(key.Marshal()) {
					return true
				}
			}
			return false
		},
		ServerFor: func(user string) (*sftp.Server, error) {
			tree := unionFor(served, user)
			if len(tree.entries) == 0 {
				// Nothing here for them. Refusing says so; an empty directory
				// would look like a server that lost their files.
				return nil, fmt.Errorf("no shares for %q", user)
			}
			// ReadWrite, because the TREE decides: an sftp.Server that is
			// read-only refuses every write for everybody, and what this
			// program promises is per share and per person. unionFS refuses
			// the writes that must be refused, before a driver sees them.
			return sftp.New(tree, sftp.ReadWrite())
		},
	})
	if err != nil {
		return err
	}
	go func() {
		<-s.stopping
		d.Close()
	}()
	return d.Serve(ln)
}

// trustedUserCAs reads the authorities whose certificates are accepted.
func (s *server) trustedUserCAs() ([]ssh.PublicKey, error) {
	if s.trustedCAFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(s.trustedCAFile)
	if err != nil {
		return nil, fmt.Errorf("the trusted user CA file: %w", err)
	}
	cas, err := sshd.ParseAuthorizedKeys(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.trustedCAFile, err)
	}
	if len(cas) == 0 {
		return nil, fmt.Errorf("%s holds no keys", s.trustedCAFile)
	}
	return cas, nil
}

// hostKey is the identity clients pin.
//
// A generated one changes on every restart, and every client that has seen the
// server before then reports a changed host key -- which is the client doing
// its job, and a warning a person learns to click past. So the file is the
// normal case and the generated key says out loud that it is not.
func (s *server) hostKey() (ssh.Signer, error) {
	if s.hostKeyFile == "" {
		fmt.Fprintln(s.out, "sftp: no host_key_file, so this server's identity changes at every start:")
		fmt.Fprintln(s.out, "      every client that has seen it before will warn about a changed key")
		return sshd.GenerateHostKey()
	}
	pem, err := os.ReadFile(s.hostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("the sftp host key: %w", err)
	}
	return sshd.ParseHostKey(pem)
}
