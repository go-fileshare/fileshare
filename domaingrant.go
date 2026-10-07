// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/go-authn/sshcert"
	"golang.org/x/crypto/ssh"
)

// The domain grant: which hosts a certificate is meant for.
//
// The EuroHPC Federation Platform's SSH CA (GÉANT / MyAccessID) signs one
// certificate that every site of the federation trusts, and says in the
// ssh-domain-grant@core.aai.geant.org extension which hosting entity's hosts
// it was issued for; go-authn/bridge writes the same extension for the
// clients configured with ssh_domain_grants. sshd itself ignores the
// extension, so a site that does not read it accepts a certificate meant for
// somebody else's machines. With ssh_domains, this server reads it -- with
// go-authn/sshcert, which parses and matches it exactly as specified -- and
// refuses a certificate whose grant names none of this host's names.
//
// ⛔ Fail-closed. A certificate with NO grant is refused unless
// ssh_accept_ungranted says otherwise: GÉANT's own ssh-cert-authorize lets
// such a certificate through ("might be valid for non-domain-based auth"),
// and on a host that trusts a second authority -- its own for staff, a test
// one, the federation's staging CA -- that second authority's certificates
// carry no grant, and the filter filters nothing. A grant that is present and
// does not parse is refused whatever ssh_accept_ungranted says: an authority
// that wrote one meant to restrict the certificate, and reading it as absent
// would undo exactly that.
//
// The grant is read on the certificates an AUTHORITY signed: the local ones
// (trusted_user_ca_file) and the provider's (oidc.ssh_ca_file). An opkssh
// certificate is signed by the user's own key, so a grant in it would be the
// user's word about themselves; its audience is the ID token's client ID
// (opkssh_client_id), and ssh_domains does not apply to it.

// grantedCertificateFor is sshd's CertificateFor when ssh_domains is set.
//
// sshd hands certificates from Config.TrustedUserCAs to x/crypto's
// CertChecker and never to a callback, so with ssh_domains the local
// authorities are not given to it as such: every certificate comes here,
// after sshd has checked what can be checked without trusting the signer
// (a user certificate, its signature by the key it names, its validity
// window, this user among its principals, no critical option but
// source-address, which sshd enforces), and the signer is looked up here
// instead.
func (s *server) grantedCertificateFor(cas []ssh.PublicKey, fed *federatedSFTP) func(string, *ssh.Certificate) (*ssh.Permissions, error) {
	local := make(map[string]bool, len(cas))
	for _, ca := range cas {
		local[string(ca.Marshal())] = true
	}
	return func(user string, cert *ssh.Certificate) (*ssh.Permissions, error) {
		signer := string(cert.SignatureKey.Marshal())
		switch {
		case local[signer]:
			if err := s.domainGrant(user, cert); err != nil {
				return nil, err
			}
			// What CertChecker.Authenticate returns for a trusted
			// authority's certificate: its critical options -- of which
			// x/crypto then enforces source-address -- and its extensions.
			//
			// source-address is the only critical option sshd lets reach
			// CertificateFor, and sshd itself puts the certificate's value
			// into what this returns (go-filesystems/sftp#19), so it is
			// enforced whatever is written here; this says the same thing.
			return &ssh.Permissions{
				CriticalOptions: maps.Clone(cert.CriticalOptions),
				Extensions:      maps.Clone(cert.Extensions),
			}, nil
		case fed != nil && fed.ca != nil && signer == string(fed.ca.Marshal()):
			if err := s.domainGrant(user, cert); err != nil {
				return nil, err
			}
		}
		if fed != nil {
			return fed.certificate(user, cert)
		}
		return nil, errors.New("a certificate no trusted authority signed")
	}
}

// domainGrant decides whether a certificate is meant for this host, says
// why when it is not, and counts the decision.
func (s *server) domainGrant(user string, cert *ssh.Certificate) error {
	g := &s.stats.grants
	domains := s.cfg.SSHDomains
	patterns, present, err := sshcert.DomainGrant(cert)
	var why error
	switch {
	case err != nil:
		g.malformed.Add(1)
		why = fmt.Errorf("its domain grant does not parse, and is refused whatever ssh_accept_ungranted says: %w", err)
	case !present && s.cfg.SSHAcceptUngranted:
		g.ungranted.Add(1)
		fmt.Fprintf(s.out, "sftp: %s: %s has no domain grant; accepted, as ssh_accept_ungranted says\n", logName(user), describeCert(cert))
		return nil
	case !present:
		g.absent.Add(1)
		why = fmt.Errorf("it has no domain grant (%s), and ssh_domains requires one", sshcert.DomainGrantExtension)
	default:
		for _, d := range domains {
			if sshcert.Grants(patterns, d) {
				g.granted.Add(1)
				return nil
			}
		}
		g.notGranted.Add(1)
		why = fmt.Errorf("its domain grant [%s] names none of this host's names [%s]",
			strings.Join(patterns, " "), strings.Join(domains, " "))
	}
	fmt.Fprintf(s.out, "sftp: %s: %s refused: %v\n", logName(user), describeCert(cert), why)
	return why
}

// describeCert is how a log line names a certificate: its serial and key ID,
// what an issuer looks it up by.
func describeCert(cert *ssh.Certificate) string {
	return fmt.Sprintf("certificate %d (%q)", cert.Serial, cert.KeyId)
}

// logName is a user name as a log line can hold it. These lines are written
// before the client has proved anything -- the name is whatever it sent --
// so one that would break the line, or forge another, is quoted.
func logName(user string) string {
	if q := strconv.Quote(user); q[1:len(q)-1] != user {
		return q
	}
	return user
}
