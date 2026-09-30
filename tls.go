// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/go-authn/servercert"
)

// TLS, for the protocols that speak it:
//
//	tls {
//	  cert_file = "/etc/fileshare/tls/fullchain.pem"
//	  key_file  = "/etc/fileshare/tls/key.pem"
//	}
//
//	serve "webdav" {
//	  addr = "0.0.0.0:443"
//	  tls  = true
//	}
//	serve "nfs" {
//	  tls            = true
//	  client_ca_file = "/etc/fileshare/tls/clients.pem"
//	}
//
// or a certificate from an ACME CA -- Let's Encrypt by default, or one that
// knows who you are through external account binding, as GÉANT TCS does:
//
//	tls {
//	  acme {
//	    directory_url     = "https://acme-v02.harica.gr/acme/<uuid>/directory"   # the Server URL cm.harica.gr shows
//	    domains           = ["files.example.org"]
//	    cache_dir         = "/var/lib/fileshare/acme"
//	    eab_key_id        = "..."
//	    eab_hmac_key_file = "/etc/fileshare/tls/eab.key"
//	  }
//	}
//
// The certificate is go-authn/servercert's: files reloaded when they change,
// or autocert. What decides which ACME setups can work at all is how the CA
// checks the name, and it is said here once:
//
//	tls-alpn-01  the CA connects to port 443 (RFC 8737), so a TLS protocol
//	             must be served on 443 for it to answer
//	http-01      the CA connects to port 80 (RFC 8555 §8.3): http_challenge
//	             names a listener for it
//	none         a CA whose account has the domain PRE-VALIDATED asks for
//	             no challenge at all -- HARICA's enterprise accounts for GÉANT
//	             TCS -- and then a server nobody outside can reach still gets
//	             its certificate
//
// ⛔ SMB and SFTP do not take `tls`: SMB 3 encrypts with its own keys, SFTP is
// SSH. NFS over TLS is RFC 9289, and it authenticates the MACHINE: a client
// certificate says which host is talking, not which person -- so a share that
// names who may use it is still refused over NFS without a kerberos block.
type tlsBlock struct {
	CertFile string     `hcl:"cert_file,optional"`
	KeyFile  string     `hcl:"key_file,optional"`
	ACME     *acmeBlock `hcl:"acme,block"`
}

type acmeBlock struct {
	DirectoryURL   string   `hcl:"directory_url,optional"`
	Email          string   `hcl:"email,optional"`
	Domains        []string `hcl:"domains"`
	CacheDir       string   `hcl:"cache_dir"`
	EABKeyID       string   `hcl:"eab_key_id,optional"`
	EABHMACKeyFile string   `hcl:"eab_hmac_key_file,optional"`
	// HTTPChallenge is where to answer http-01, which the CA asks on port
	// 80: "0.0.0.0:80", or the address a port 80 is forwarded to.
	HTTPChallenge string `hcl:"http_challenge,optional"`
}

// tlsProtocols are the ones that can be served over TLS here.
var tlsProtocols = []string{"webdav", "s3", "nfs"}

func (t *tlsBlock) servercert() servercert.Config {
	c := servercert.Config{CertFile: t.CertFile, KeyFile: t.KeyFile}
	if a := t.ACME; a != nil {
		c.ACME = &servercert.ACME{DirectoryURL: a.DirectoryURL, Email: a.Email, Domains: a.Domains,
			CacheDir: a.CacheDir, EABKeyID: a.EABKeyID, EABHMACKeyFile: a.EABHMACKeyFile,
			HTTPChallenge: a.HTTPChallenge != ""}
	}
	return c
}

// checkTLS refuses what TLS cannot mean here, and -- the reason this exists
// -- a password crossing a network in the clear.
func (c *config) checkTLS() error {
	var usesTLS bool
	for _, b := range c.Serves {
		switch {
		case b.TLS && !slices.Contains(tlsProtocols, b.Protocol):
			return fmt.Errorf("%s does not take tls: SMB 3 encrypts with its own keys and SFTP is SSH", b.Protocol)
		case b.TLS && c.TLS == nil:
			return fmt.Errorf("%s says tls, and there is no tls block to say where the certificate comes from", b.Protocol)
		case b.ClientCAFile != "" && b.Protocol != "nfs":
			return fmt.Errorf("%s: client_ca_file is for nfs, whose clients present a certificate", b.Protocol)
		case b.ClientCAFile != "" && !b.TLS:
			return fmt.Errorf("nfs: client_ca_file without tls = true would check nothing")
		case b.Plaintext && b.Protocol != "webdav":
			return fmt.Errorf("%s: plaintext is for webdav, the protocol that sends a password", b.Protocol)
		case b.Plaintext && b.TLS:
			return fmt.Errorf("webdav says tls and plaintext: one or the other")
		}
		if b.TLS {
			usesTLS = true
		}
		if err := b.checkIdentity(); err != nil {
			return err
		}
		if b.Protocol == "webdav" && !b.TLS && !b.Plaintext && c.hasCredentials() && !loopback(b.Addr) {
			// ⛔ HTTP Basic is the password, base64'd, on every request, and a
			// bearer token is as good as one. Refused rather than warned:
			// a warning scrolls by, and the password does not come back.
			return fmt.Errorf("webdav on %s would carry passwords in the clear: serve it with tls = true, "+
				"or -- when TLS is terminated in front of it, by a proxy -- say plaintext = true", b.Addr)
		}
	}
	if c.TLS == nil {
		return nil
	}
	if !usesTLS {
		return fmt.Errorf("there is a tls block and no serve block says tls = true: nothing would use it")
	}
	if err := c.TLS.servercert().Check(); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if a := c.TLS.ACME; a != nil && a.HTTPChallenge != "" {
		if _, _, err := net.SplitHostPort(a.HTTPChallenge); err != nil {
			return fmt.Errorf("tls: http_challenge %q is not an address to listen on: %w", a.HTTPChallenge, err)
		}
	}
	return nil
}

// hasCredentials reports whether anybody here authenticates with something
// that must not travel in the clear.
func (c *config) hasCredentials() bool {
	return len(c.Users) > 0 || len(c.Directories) > 0 || c.OIDC != nil
}

// loopback reports whether an address only this machine can reach.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serveBlockFor is the serve block of a protocol.
func (c *config) serveBlockFor(name string) *serveBlock {
	for i := range c.Serves {
		if c.Serves[i].Protocol == name {
			return &c.Serves[i]
		}
	}
	return nil
}

// tlsFor is the TLS configuration a protocol's connections are served with,
// or nil when it is served in the clear.
func (s *server) tlsFor(proto string) (*tls.Config, error) {
	b := s.cfg.serveBlockFor(proto)
	if b == nil || !b.TLS || s.certs == nil {
		return nil, nil
	}
	cfg := s.certs.TLSConfig()
	if proto != "nfs" {
		// ⛔ APPENDED, and it has to be there. With ACME, NextProtos holds
		// "acme-tls/1", and a Go server refuses a client whose ALPN list
		// shares nothing with its own: every browser and WebDAV client
		// offers http/1.1, and would be turned away at the handshake. Not
		// h2 -- net/http speaks HTTP/2 over TLS it set up itself, not over
		// a listener handed to it, and offering it would be a lie.
		cfg.NextProtos = append(cfg.NextProtos, "http/1.1")
		return cfg, nil
	}
	// RFC 9289 §5.2: RPC-with-TLS is identified by ALPN "sunrpc". The ACME
	// protocol, when there is one, stays: tls-alpn-01 is answered on any
	// listener the CA reaches.
	cfg.NextProtos = append(cfg.NextProtos, "sunrpc")
	if b.ClientCAFile != "" {
		pem, err := os.ReadFile(b.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("nfs: client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("nfs: %s holds no PEM certificate", b.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// describeTLS says where the certificate comes from, for `check`.
func (t *tlsBlock) describe() string {
	if t.ACME != nil {
		ca := t.ACME.DirectoryURL
		if ca == "" {
			ca = "Let's Encrypt"
		}
		return fmt.Sprintf("ACME from %s for %s", ca, strings.Join(t.ACME.Domains, ", "))
	}
	return "the files " + t.CertFile + " and " + t.KeyFile
}
