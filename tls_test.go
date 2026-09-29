// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/servercert"
)

// pki is a CA, a server certificate for localhost and 127.0.0.1, and a client
// certificate, written as PEM files the way a site would have them.
type pki struct {
	caFile, certFile, keyFile, clientCert, clientKey string
	pool                                             *x509.CertPool
	client                                           tls.Certificate
}

func newPKI(t *testing.T, dir string) *pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, server bool) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			tmpl.DNSNames = []string{"localhost"}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	pemOf := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }
	keyPEM := func(k *ecdsa.PrivateKey) []byte {
		b, _ := x509.MarshalPKCS8PrivateKey(k)
		return pemOf("PRIVATE KEY", b)
	}
	p := &pki{pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.caFile = write(t, dir, "ca.pem", string(pemOf("CERTIFICATE", caDER)))
	sDER, sKey := issue(2, "localhost", x509.ExtKeyUsageServerAuth, true)
	p.certFile = write(t, dir, "server.pem", string(pemOf("CERTIFICATE", sDER)))
	p.keyFile = write(t, dir, "server.key", string(keyPEM(sKey)))
	cDER, cKey := issue(3, "workstation-7", x509.ExtKeyUsageClientAuth, false)
	p.clientCert = write(t, dir, "client.pem", string(pemOf("CERTIFICATE", cDER)))
	p.clientKey = write(t, dir, "client.key", string(keyPEM(cKey)))
	p.client, err = tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// What tls, plaintext and client_ca_file may not say, each beside the
// configuration that differs by that one thing and loads.
func TestTLSConfigRefusals(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	p := newPKI(t, dir)
	img := image(t, dir, "d.img", nil)
	tlsBlock := fmt.Sprintf("tls {\n  cert_file = %q\n  key_file = %q\n}\n", hclPath(p.certFile), hclPath(p.keyFile))
	withUsers := func(serves string) string {
		return strings.Replace(configFor(t, dir, fmt.Sprintf("share \"d\" {\n  image = %q\n}\n", hclPath(img))),
			serveBlocks(), serves, 1)
	}
	noUsers := fmt.Sprintf("share \"d\" {\n  image = %q\n}\n", hclPath(img))
	cases := []struct{ name, body, want string }{
		{"webdav on a public address, with passwords", withUsers(`serve "webdav" { addr = "0.0.0.0:8080" }`), "in the clear"},
		{"... served over TLS", withUsers(tlsBlock + "serve \"webdav\" {\n  addr = \"0.0.0.0:8443\"\n  tls = true\n}"), ""},
		{"... said plaintext on purpose", withUsers("serve \"webdav\" {\n  addr = \"0.0.0.0:8080\"\n  plaintext = true\n}"), ""},
		{"... on loopback", withUsers(`serve "webdav" { addr = "127.0.0.1:8080" }`), ""},
		{"... with nobody to authenticate", noUsers + `serve "webdav" { addr = "0.0.0.0:8080" }`, ""},
		{"tls on smb", withUsers(tlsBlock + `serve "smb" { tls = true }`), "does not take tls"},
		{"tls without a tls block", withUsers(`serve "webdav" { tls = true }`), "no tls block"},
		{"a tls block nothing uses", withUsers(tlsBlock + `serve "webdav" {}`), "nothing would use it"},
		{"client_ca_file on webdav", withUsers(tlsBlock + fmt.Sprintf("serve \"webdav\" {\n  tls = true\n  client_ca_file = %q\n}", hclPath(p.caFile))), "for nfs"},
		{"client_ca_file without tls", noUsers + tlsBlock + fmt.Sprintf("serve \"webdav\" { tls = true }\nserve \"nfs\" { client_ca_file = %q }", hclPath(p.caFile)), "check nothing"},
		{"plaintext on s3", withUsers(`serve "s3" { plaintext = true }`), "for webdav"},
		{"plaintext and tls", withUsers(tlsBlock + "serve \"webdav\" {\n  tls = true\n  plaintext = true\n}"), "one or the other"},
		{"files and acme", withUsers(fmt.Sprintf("tls {\n  cert_file = %q\n  key_file = %q\n  acme {\n    domains = [\"x.example\"]\n    cache_dir = \"/var/lib/x\"\n  }\n}\n", hclPath(p.certFile), hclPath(p.keyFile)) + `serve "webdav" { tls = true }`), "tls:"},
		{"an http_challenge that is no address", withUsers("tls {\n  acme {\n    domains = [\"x.example\"]\n    cache_dir = \"/var/lib/x\"\n    http_challenge = \"eighty\"\n  }\n}\n" + `serve "webdav" { tls = true }`), "http_challenge"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !anyAuthenticates() && strings.Contains(c.body, "user ") {
				t.Skip("a binary with no authenticating protocol")
			}
			if protocolByName("webdav") == nil && strings.Contains(c.body, `"webdav"`) ||
				protocolByName("s3") == nil && strings.Contains(c.body, `"s3"`) ||
				protocolByName("nfs") == nil && strings.Contains(c.body, `"nfs"`) ||
				protocolByName("smb") == nil && strings.Contains(c.body, `"smb"`) {
				t.Skip("built without a protocol this case names")
			}
			_, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", c.body)})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("loaded; want a refusal saying %q", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}

// runServer serves a configuration through run -- generations and all -- and
// returns the address each protocol was bound to.
func runServer(t *testing.T, body string) (*server, map[string]string) {
	t.Helper()
	cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := open(cfg, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		<-done
		srv.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for !srv.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	addrs := map[string]string{}
	srv.runMu.Lock()
	for _, f := range srv.feeds {
		addrs[f.proto] = f.ln.Addr().String()
	}
	srv.runMu.Unlock()
	return srv, addrs
}

// The NFS half of RFC 9289, asked the way a Linux client asks: the AUTH_TLS
// probe in the clear, STARTTLS back, a handshake with ALPN "sunrpc", and then
// an RPC inside. With client_ca_file, a client without a certificate from that
// authority does not get past the handshake.
func TestNFSOverTLS(t *testing.T) {
	if protocolByName("nfs") == nil {
		t.Skip("built without nfs")
	}
	dir := t.TempDir()
	p := newPKI(t, dir)
	img := image(t, dir, "d.img", nil)
	srv, addrs := runServer(t, fmt.Sprintf(`share "d" { image = %q }
tls {
  cert_file = %q
  key_file  = %q
}
serve "nfs" {
  addr           = "127.0.0.1:0"
  tls            = true
  client_ca_file = %q
}
`, hclPath(img), hclPath(p.certFile), hclPath(p.keyFile), hclPath(p.caFile)))

	dial := func(cert *tls.Certificate) error {
		c, err := net.Dial("tcp", addrs["nfs"])
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		// The probe: NFSv3 NULL with an AUTH_TLS credential and an empty
		// AUTH_NONE verifier (RFC 9289 §4.1).
		if err := rpcCall(c, 1, 7); err != nil {
			return err
		}
		verf, stat, err := rpcReply(c)
		if err != nil {
			return err
		}
		if string(verf) != "STARTTLS" || stat != 0 {
			return fmt.Errorf("probe answered %q, status %d", verf, stat)
		}
		cfg := &tls.Config{RootCAs: p.pool, ServerName: "localhost", NextProtos: []string{"sunrpc"}}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		tc := tls.Client(c, cfg)
		if err := tc.Handshake(); err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		if got := tc.ConnectionState().NegotiatedProtocol; got != "sunrpc" {
			return fmt.Errorf("ALPN %q, want sunrpc", got)
		}
		// Inside the tunnel, an ordinary NULL call with AUTH_NONE.
		if err := rpcCall(tc, 2, 0); err != nil {
			return err
		}
		if _, stat, err := rpcReply(tc); err != nil || stat != 0 {
			return fmt.Errorf("NULL inside TLS: status %d, %v", stat, err)
		}
		return nil
	}
	if err := dial(&p.client); err != nil {
		t.Fatalf("a client with a certificate from the CA: %v", err)
	}
	if err := dial(nil); err == nil {
		t.Fatal("a client with no certificate got through, and client_ca_file asks for one")
	}
	if srv.tlsConfigs["nfs"].ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("client_ca_file did not make a certificate required")
	}
}

// rpcCall sends an NFSv3 NULL call with the given credential flavour, record
// marked as RPC over TCP is (RFC 5531 §11).
func rpcCall(c net.Conn, xid uint32, flavor uint32) error {
	words := []uint32{xid, 0, 2, 100003, 3, 0, flavor, 0, 0, 0}
	b := make([]byte, 4+4*len(words))
	be32(b, 0x80000000|uint32(4*len(words)))
	for i, w := range words {
		be32(b[4+4*i:], w)
	}
	_, err := c.Write(b)
	return err
}

// rpcReply reads one accepted reply, and returns its verifier body and
// accept status.
func rpcReply(c net.Conn) ([]byte, uint32, error) {
	var mark [4]byte
	if _, err := ioReadFull(c, mark[:]); err != nil {
		return nil, 0, err
	}
	n := int(getBE32(mark[:]) &^ 0x80000000)
	body := make([]byte, n)
	if _, err := ioReadFull(c, body); err != nil {
		return nil, 0, err
	}
	if n < 24 || getBE32(body[4:]) != 1 || getBE32(body[8:]) != 0 {
		return nil, 0, fmt.Errorf("not an accepted reply: % x", body)
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if off+4 > n {
		return nil, 0, fmt.Errorf("short reply: % x", body)
	}
	return body[20 : 20+vlen], getBE32(body[off:]), nil
}

func be32(b []byte, v uint32) { b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v) }
func getBE32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// With ACME the certificate's configuration names acme-tls/1, and a Go server
// refuses a client whose ALPN list shares nothing with its own -- so each
// protocol's own name must be there beside it, or every HTTPS and NFS client
// is refused at the handshake. Asked of the configuration, since a handshake
// would ask a real CA for a certificate.
func TestALPNUnderACMEKeepsEachProtocolsOwn(t *testing.T) {
	// Not the TempDir itself: servercert refuses a cache others can read,
	// which is right -- it holds private keys -- and a new one is made 0700.
	cache := filepath.Join(t.TempDir(), "acme")
	cfg := &config{
		TLS: &tlsBlock{ACME: &acmeBlock{Domains: []string{"files.example.org"}, CacheDir: cache}},
		Serves: []serveBlock{
			{Protocol: "webdav", TLS: true},
			{Protocol: "s3", TLS: true},
			{Protocol: "nfs", TLS: true},
		},
	}
	certs, err := servercert.New(cfg.TLS.servercert())
	if err != nil {
		t.Fatal(err)
	}
	defer certs.Close()
	s := &server{cfg: cfg, certs: certs}
	for proto, want := range map[string]string{"webdav": "http/1.1", "s3": "http/1.1", "nfs": "sunrpc"} {
		c, err := s.tlsFor(proto)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(c.NextProtos, "acme-tls/1") || !slices.Contains(c.NextProtos, want) {
			t.Errorf("%s: NextProtos %v, want acme-tls/1 and %s", proto, c.NextProtos, want)
		}
	}
}
