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
	s.sftpOnce.Do(func() {
		id := &sftpIdentity{}
		if id.hostKey, s.sftpErr = s.hostKey(); s.sftpErr != nil {
			return
		}
		if id.cas, s.sftpErr = s.trustedUserCAs(); s.sftpErr != nil {
			return
		}
		if id.fed, s.sftpErr = newFederatedSFTP(s.cfg.OIDC, s.sshKRL, s.federatedRevoked); s.sftpErr != nil {
			return
		}
		s.sftpState = id
	})
	if s.sftpErr != nil {
		return s.sftpErr
	}
	id := s.sftpState.(*sftpIdentity)
	hostKey, cas, fed := id.hostKey, id.cas, id.fed
	served, _ := p.exports(s.cfg, s.currentShares())
	var certificateFor func(string, *ssh.Certificate) (*ssh.Permissions, error)
	if fed != nil {
		certificateFor = fed.certificate
	}
	// With ssh_domains, every certificate is decided by certificateFor,
	// where its domain grant is read (domaingrant.go); without, nothing
	// changes: the local authorities are sshd's, as they always were.
	trusted := cas
	if len(s.cfg.SSHDomains) > 0 {
		certificateFor = s.grantedCertificateFor(cas, fed)
		trusted = nil
	}
	// One daemon per connection, so that what is decided at login reaches
	// the connection it was decided on: the handshake deadline is lifted
	// there, and nowhere else can tell which connection just logged in.
	// sshd.New only assembles an ssh.ServerConfig; it is cheap.
	configFor := func(c *sshConn) sshd.Config {
		return sshd.Config{
			CertificateFor: certificateFor,
			HostKeys:       []ssh.Signer{hostKey},
			TrustedUserCAs: trusted,
			// A key proves who is asking without this server ever holding the
			// secret, and a certificate says it with an expiry date on it. There
			// is deliberately NO password here: an SSH client that prompts for one
			// is an SSH client doing the thing keys exist to avoid, and the
			// passwords in this configuration are for the protocols that have
			// nothing better.
			PublicKeyFor: func(user string, key ssh.PublicKey) bool {
				for _, k := range s.keysFor(user) {
					if string(k.Marshal()) == string(key.Marshal()) {
						return true
					}
				}
				return false
			},
			ServerForLogin: func(user string, perms *ssh.Permissions) (*sftp.Server, error) {
				c.loggedIn()
				who := principalOf(user, perms)
				who.localName = who.federated && s.localNames()
				if who.federated {
					if err := s.admitFederated(who); err != nil {
						return nil, fmt.Errorf("%s: the provider vouches for them %v", user, err)
					}
					// Said once per login: which groups the provider says this person
					// is in is the first thing asked when a share does not appear.
					fmt.Fprintf(s.out, "sftp: %s, vouched for by the provider, in groups %v\n", user, who.groups)
				}
				tree := unionFor(served, who)
				tree.revoked = fed.sessionRevoked(user, perms, func(why error) {
					// Refusing each operation is not enough: the client is
					// told, and the connection is not kept for a session
					// that will never be served again.
					fmt.Fprintf(s.out, "sftp: %s: %v; connection closed\n", user, why)
					c.Close()
				})
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
		}
	}
	// Refused here, once, rather than at every connection.
	if _, err := sshd.New(nil, configFor(nil)); err != nil {
		return err
	}
	return serveSSH(ln, s.stopping, s.preAuthTimeout, func(c *sshConn) error {
		d, err := sshd.New(nil, configFor(c))
		if err != nil {
			return err
		}
		return d.HandleConn(c)
	})
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

// sftpIdentity is what SFTP reads once and keeps across generations.
type sftpIdentity struct {
	hostKey ssh.Signer
	cas     []ssh.PublicKey
	fed     *federatedSFTP
}
