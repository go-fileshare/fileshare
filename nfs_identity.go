// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

// NFS, with the caller's identity taken from their client certificate.
//
//	serve "nfs" {
//	  tls            = true
//	  client_ca_file = "/etc/fileshare/bridge-x509-ca.pem"
//	  identity       = "certificate"
//	  crl_url        = "https://bridge.example.org/x509/crl"
//	}
//
// go-authn/bridge issues a short-lived X.509 certificate after an identity
// provider login, naming the person the way FreeBSD's rpc.tlsservd -u reads
// it -- the SubjectAltName otherName 1.3.6.1.4.1.2238.1.1.1, a UTF8String
// user@domain, which draft-cel-nfsv4-rpc-tls-othername describes and has no
// IANA number for yet -- and their groups in an extension. Every NFS call on
// a share that names people then asks, on that connection's certificate: is
// it revoked (the CRL, failing closed), who is it, is that somebody this
// server admits, and may they use this share.
//
// ⛔ What it cannot promise, and why RFC 9289 alone refuses to: the server
// sees a CONNECTION's certificate. A Linux client attaches one to a mount
// (tlshd, the keyring serial on the mount line), so EVERY user of that mount
// acts as the person the certificate names. On a workstation one person uses,
// that is exactly them; on a machine several people log into, it is whoever
// mounted. Kerberos (sec=krb5) is the answer there, and this is not.

// groupTag is how go-authn/bridge writes a person's groups into their
// certificate: one SubjectAltName URI each, a tag URI (RFC 4151: no
// registration, made for exactly this) tag:go-authn.github.io,2026:group:<the
// group, url.PathEscape'd -- an IA5String is ASCII>, beside the one identity
// otherName. Not urn:x-...: RFC 8141 took the experimental URN namespaces
// away, and a strict parser refuses one. FreeBSD's rpc.tlsservd reads the
// first identity otherName and skips every other SAN entry.
//
// ⛔ Not an extension of its own. One was designed, under a UUID-derived arc
// (2.25.<128-bit number>), and MEASURED: Go's x509.ParseCertificate refuses
// the whole certificate -- "malformed extension OID field" -- because an
// asn1.ObjectIdentifier arc is an int. Every Go TLS server would have turned
// the certificate away. A URI SAN needs no OID, and every parser reads it.
const groupTag = "go-authn.github.io,2026:group:"

// crlList is an X.509 CRL, as a revocation list: signed by the client CA,
// and trusted until its NextUpdate at most.
type crlList struct {
	// issuer is the subject of the CA that signed it, raw.
	issuer  []byte
	serials map[string]bool
	number  *big.Int
	this    time.Time
	next    time.Time
}

func (c crlList) describe() string {
	return fmt.Sprintf("CRL number %v, %d revoked, next update %s", c.number, len(c.serials), c.next.UTC().Format(time.RFC3339))
}
func (c crlList) expires() time.Time { return c.next }

func (c crlList) older(than revoked) bool {
	o, ok := than.(crlList)
	if !ok || c.number == nil || o.number == nil {
		return false
	}
	// A lower number, or the same number issued earlier: RFC 5280 5.2.3
	// gives two CRLs with different thisUpdate different numbers, but
	// go-authn/bridge before v0.10.1 did not.
	cmp := c.number.Cmp(o.number)
	return cmp < 0 || cmp == 0 && c.this.Before(o.this)
}

func (c crlList) revoked(serial *big.Int) bool { return c.serials[serial.String()] }

// crlParser reads a CRL, PEM or DER, and refuses one no CA of cas signed: a
// CRL anybody could have written revokes whatever they like, and -- worse --
// un-revokes it.
func crlParser(cas []*x509.Certificate) func([]byte) (revoked, error) {
	return func(b []byte) (revoked, error) {
		if blk, _ := pem.Decode(b); blk != nil {
			b = blk.Bytes
		}
		rl, err := x509.ParseRevocationList(b)
		if err != nil {
			return nil, err
		}
		signed := false
		var issuer []byte
		for _, ca := range cas {
			if rl.CheckSignatureFrom(ca) == nil {
				signed, issuer = true, ca.RawSubject
				break
			}
		}
		if !signed {
			return nil, fmt.Errorf("the CRL is signed by none of the client CAs")
		}
		// ⛔ A CRL whose critical extensions are not all understood is not
		// understood: a delta CRL read as complete forgets every earlier
		// revocation, and a scoped one (issuingDistributionPoint) covers
		// less than it seems. Go's parser accepts both; this does not.
		for _, e := range rl.Extensions {
			switch {
			case e.Id.Equal(oidDeltaCRLIndicator):
				return nil, fmt.Errorf("a delta CRL: this server reads complete CRLs only")
			case e.Critical && !e.Id.Equal(oidCRLNumber) && !e.Id.Equal(oidAuthorityKeyID):
				return nil, fmt.Errorf("the CRL has a critical extension %v this server does not handle", e.Id)
			}
		}
		for _, entry := range rl.RevokedCertificateEntries {
			for _, e := range entry.Extensions {
				if e.Critical {
					// certificateIssuer (an indirect CRL) and its kind.
					return nil, fmt.Errorf("a revoked entry has a critical extension %v this server does not handle", e.Id)
				}
			}
		}
		out := crlList{issuer: issuer, serials: map[string]bool{}, number: rl.Number, this: rl.ThisUpdate, next: rl.NextUpdate}
		for _, e := range rl.RevokedCertificateEntries {
			out.serials[e.SerialNumber.String()] = true
		}
		return out, nil
	}
}

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidCRLNumber         = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidAuthorityKeyID    = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// readCerts is every certificate in a PEM file.
func readCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return out, nil
}

// openNFSCRL makes the CRL list of an nfs serve block that asks for
// certificate identity, or nil.
func openNFSCRL(b *serveBlock, out io.Writer) (*revocationList, error) {
	if b == nil || b.Identity != "certificate" {
		return nil, nil
	}
	cas, err := readCerts(b.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("nfs: client_ca_file: %w", err)
	}
	refresh, maxAge, err := listTiming("crl", b.CRLRefresh, b.CRLMaxAge)
	if err != nil {
		return nil, fmt.Errorf("nfs: %w", err)
	}
	l, err := newRevocationList("x509_crl", b.CRLURL, b.CRLFile, b.CRLCAFile, refresh, maxAge, crlParser(cas), out)
	if err != nil {
		return nil, err
	}
	l.stateFile = b.CRLStateFile
	if l.stateFile == "" && b.CRLURL != "" {
		fmt.Fprintf(out, "nfs: no crl_state_file, so a restart forgets which CRL is newer: "+
			"an older one, still signed and current, would be taken after it\n")
	}
	l.restore()
	return l, nil
}

// groupsOfCert is the groups go-authn/bridge put in a certificate, or none.
func groupsOfCert(c *x509.Certificate) []string {
	var out []string
	for _, u := range c.URIs {
		if u.Scheme != "tag" {
			continue
		}
		rest, ok := strings.CutPrefix(u.Opaque, groupTag)
		if !ok || rest == "" {
			continue
		}
		g, err := url.PathUnescape(rest)
		if err != nil {
			continue
		}
		out = append(out, g)
	}
	return out
}

// checkIdentity refuses what identity = "certificate" cannot mean.
func (b serveBlock) checkIdentity() error {
	certKeys := b.CRLURL != "" || b.CRLFile != "" || b.CRLCAFile != "" || b.CRLRefresh != "" || b.CRLMaxAge != ""
	switch {
	case b.Identity == "" && certKeys:
		return fmt.Errorf("%s: a CRL is for identity = \"certificate\"", b.Protocol)
	case b.Identity == "":
		return nil
	case b.Identity != "certificate":
		return fmt.Errorf("%s: identity = %q: the one there is is \"certificate\"", b.Protocol, b.Identity)
	case b.Protocol != "nfs":
		return fmt.Errorf("%s: identity is for nfs", b.Protocol)
	case !b.TLS || b.ClientCAFile == "":
		return fmt.Errorf("nfs: identity = \"certificate\" needs tls = true and client_ca_file: the identity is in the certificate the client presents")
	case b.CRLURL == "" && b.CRLFile == "":
		return fmt.Errorf("nfs: identity = \"certificate\" needs crl_url or crl_file: a person's certificate nothing can revoke outlives their removal by its whole lifetime")
	}
	if err := checkListSource("crl", b.CRLURL, b.CRLFile); err != nil {
		return fmt.Errorf("nfs: %w", err)
	}
	_, _, err := listTiming("crl", b.CRLRefresh, b.CRLMaxAge)
	return err
}
