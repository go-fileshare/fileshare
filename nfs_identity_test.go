// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// bridgeCA issues what go-authn/bridge issues: client certificates naming a
// person in the FreeBSD otherName, their groups as tag:go-authn.github.io URIs,
// and a CRL.
type bridgeCA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	caFile  string
	crlFile string
	number  int64
	serial  int64
}

func newBridgeCA(t *testing.T, dir string) *bridgeCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bridge x509 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &bridgeCA{cert: cert, key: key, serial: 100,
		caFile:  write(t, dir, "bridge-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
		crlFile: filepath.Join(dir, "bridge.crl")}
	ca.publish(t)
	return ca
}

// sanWith is a SubjectAltName extension holding one FreeBSD identity
// otherName per name given, and one group URI per group -- built by hand,
// because crypto/x509 has no field for an otherName.
func sanWith(t *testing.T, names []string, groups []string) pkix.Extension {
	t.Helper()
	var entries []asn1.RawValue
	for _, n := range names {
		utf8, _ := asn1.MarshalWithParams(n, "utf8")
		value, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8})
		oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2238, 1, 1, 1})
		entries = append(entries, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: append(oid, value...)})
	}
	for _, g := range groups {
		u := "tag:" + groupTag + url.PathEscape(g)
		entries = append(entries, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)})
	}
	der, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: der}
}

// issue is a client certificate naming names (one, normally) with groups.
func (ca *bridgeCA) issue(t *testing.T, names []string, groups []string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca.serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial), Subject: pkix.Name{CommonName: "someone"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{sanWith(t, names, groups)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the certificate bridge would issue does not parse in Go: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// publish writes the CRL, revoking the serials given.
func (ca *bridgeCA) publish(t *testing.T, revoked ...*big.Int) {
	t.Helper()
	ca.number++
	var entries []x509.RevocationListEntry
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(ca.number),
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca.crlFile, der, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mount asks MOUNT MNT for an export, over TLS with cert (nil: none), and
// then GETATTR on the handle it gave: 0 when both succeed, otherwise the first
// refusal -- 13 is both MNT3ERR_ACCES and NFS3ERR_ACCES.
func mount(t *testing.T, addr string, pool *x509.CertPool, cert *tls.Certificate, export string, overTLS bool) (uint32, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var conn net.Conn = c
	if overTLS {
		if err := rpcCall(c, 1, 7); err != nil {
			return 0, err
		}
		if verf, stat, err := rpcReply(c); err != nil || string(verf) != "STARTTLS" || stat != 0 {
			return 0, fmt.Errorf("probe: %q %d %v", verf, stat, err)
		}
		cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", NextProtos: []string{"sunrpc"}}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		tc := tls.Client(c, cfg)
		if err := tc.Handshake(); err != nil {
			return 0, fmt.Errorf("handshake: %w", err)
		}
		conn = tc
	}
	// MOUNT v3 (100005), procedure MNT (1), AUTH_NONE, dirpath argument.
	words := []uint32{2, 0, 2, 100005, 3, 1, 0, 0, 0, 0}
	path := []byte(export)
	pad := (4 - len(path)%4) % 4
	n := 4*len(words) + 4 + len(path) + pad
	b := make([]byte, 4, 4+n)
	be32(b, 0x80000000|uint32(n))
	for _, w := range words {
		var x [4]byte
		be32(x[:], w)
		b = append(b, x[:]...)
	}
	var l [4]byte
	be32(l[:], uint32(len(path)))
	b = append(append(append(b, l[:]...), path...), make([]byte, pad)...)
	if _, err := conn.Write(b); err != nil {
		return 0, err
	}
	var mark [4]byte
	if _, err := ioReadFull(conn, mark[:]); err != nil {
		return 0, err
	}
	body := make([]byte, int(getBE32(mark[:])&^0x80000000))
	if _, err := ioReadFull(conn, body); err != nil {
		return 0, err
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if getBE32(body[off:]) != 0 {
		return 0, fmt.Errorf("accept status %d", getBE32(body[off:]))
	}
	status := getBE32(body[off+4:])
	if status != 0 {
		return status, nil
	}
	// Mounted: now an NFS operation on the handle, which is where the gate
	// must hold whatever MOUNT said -- a handle outlives any mount.
	hlen := int(getBE32(body[off+8:]))
	handle := body[off+12 : off+12+hlen]
	return getattr(conn, handle)
}

// getattr sends NFSv3 GETATTR on a handle and returns its nfsstat3: 0 is
// NFS3_OK, 13 NFS3ERR_ACCES.
func getattr(conn net.Conn, handle []byte) (uint32, error) {
	words := []uint32{3, 0, 2, 100003, 3, 1, 0, 0, 0, 0}
	pad := (4 - len(handle)%4) % 4
	n := 4*len(words) + 4 + len(handle) + pad
	b := make([]byte, 4, 4+n)
	be32(b, 0x80000000|uint32(n))
	for _, w := range words {
		var x [4]byte
		be32(x[:], w)
		b = append(b, x[:]...)
	}
	var l [4]byte
	be32(l[:], uint32(len(handle)))
	b = append(append(append(b, l[:]...), handle...), make([]byte, pad)...)
	if _, err := conn.Write(b); err != nil {
		return 0, err
	}
	var mark [4]byte
	if _, err := ioReadFull(conn, mark[:]); err != nil {
		return 0, err
	}
	body := make([]byte, int(getBE32(mark[:])&^0x80000000))
	if _, err := ioReadFull(conn, body); err != nil {
		return 0, err
	}
	vlen := int(getBE32(body[16:]))
	off := 20 + (vlen+3)&^3
	if getBE32(body[off:]) != 0 {
		return 0, fmt.Errorf("accept status %d", getBE32(body[off:]))
	}
	return getBE32(body[off+4:]), nil
}

// A share naming people, served over NFS with nothing but certificates:
// alice's opens it, bob's does not, no certificate does not get past the
// handshake, a call in the clear is refused, and once alice's certificate is
// in the CRL -- or the CRL is too old to trust -- hers does not either.
func TestNFSIdentityFromCertificates(t *testing.T) {
	dir := t.TempDir()
	server := newPKI(t, dir) // the server's own certificate
	ca := newBridgeCA(t, dir)
	img := image(t, dir, "d.img", map[string]string{"/x.txt": "x"})
	open := image(t, dir, "o.img", nil)
	pw := write(t, dir, "pw", "unused\n")
	srv, addrs := runServer(t, fmt.Sprintf(`
user "alice@univ-a.fr" { password_file = %q }
user "bob@univ-a.fr"   { password_file = %q }
share "t" {
  image = %q
  allow = ["alice@univ-a.fr"]
}
share "open" { image = %q }
tls {
  cert_file = %q
  key_file  = %q
}
serve "nfs" {
  addr           = "127.0.0.1:0"
  tls            = true
  client_ca_file = %q
  identity       = "certificate"
  crl_file       = %q
  crl_refresh    = "1s"
}
`, hclPath(pw), hclPath(pw), hclPath(img), hclPath(open), hclPath(server.certFile), hclPath(server.keyFile),
		hclPath(ca.caFile), hclPath(ca.crlFile)))
	addr := addrs["nfs"]
	alice, aliceLeaf := ca.issue(t, []string{"alice@univ-a.fr"}, []string{"engineers", "urn:geant:univ.fr:group:x#login.example.org"})
	bob, _ := ca.issue(t, []string{"bob@univ-a.fr"}, nil)
	twice, _ := ca.issue(t, []string{"alice@univ-a.fr", "bob@univ-a.fr"}, nil)

	if got := groupsOfCert(aliceLeaf); !slices.Equal(got, []string{"engineers", "urn:geant:univ.fr:group:x#login.example.org"}) {
		t.Fatalf("groups read back: %v", got)
	}
	// NFS names the share restricted, and serves it: identities exist here.
	if served, _ := protocolByName("nfs").exports(srv.cfg, srv.currentShares()); len(served) != 2 {
		t.Fatalf("nfs serves %v", names(served))
	}

	check := func(what string, cert *tls.Certificate, export string, overTLS bool, want uint32) {
		t.Helper()
		got, err := mount(t, addr, server.pool, cert, export, overTLS)
		if err != nil {
			if want == 0 {
				t.Fatalf("%s: %v", what, err)
			}
			return // refused at the handshake: fine for a refusal
		}
		if got != want {
			t.Fatalf("%s: mount status %d, want %d", what, got, want)
		}
	}
	check("alice's certificate, her share", &alice, "/t", true, 0)
	check("bob's certificate, alice's share", &bob, "/t", true, 13)
	check("two identities in one certificate", &twice, "/t", true, 13)
	check("no certificate", nil, "/t", true, 13)
	check("alice, in the clear", nil, "/t", false, 13)
	check("the open share, in the clear", nil, "/open", false, 0)

	// Revoked: the next call is refused.
	ca.publish(t, aliceLeaf.SerialNumber)
	if _, err := srv.nfsCRL.fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	check("alice, revoked", &alice, "/t", true, 13)

	// Unrevoked but stale: refused too -- the CRL fails closed.
	ca.publish(t)
	if _, err := srv.nfsCRL.fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	check("alice, reinstated", &alice, "/t", true, 0)
	srv.nfsCRL.mu.Lock()
	srv.nfsCRL.now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	srv.nfsCRL.mu.Unlock()
	check("alice, with a CRL past max_age", &alice, "/t", true, 13)
}

// A CRL no client CA signed is refused, and the last good one kept.
func TestACRLMustBeSignedByTheClientCA(t *testing.T) {
	dir := t.TempDir()
	ca := newBridgeCA(t, dir)
	other := newBridgeCA(t, t.TempDir())
	parse := crlParser([]*x509.Certificate{ca.cert})
	good, _ := os.ReadFile(ca.crlFile)
	if _, err := parse(good); err != nil {
		t.Fatalf("the CA's own CRL: %v", err)
	}
	forged, _ := os.ReadFile(other.crlFile)
	if _, err := parse(forged); err == nil {
		t.Fatal("a CRL signed by another CA was accepted")
	}
}
