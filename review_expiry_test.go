// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs && !nosftp && !nowebdav

package main

// Written by the adversarial review of the revocation paths; kept as the
// regression tests of its fixes (see review_revocation_test.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-filesystems/nfs/rpc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"
)

// F9 (NFS): the certificate gate never looks at NotAfter. A TLS connection
// opened while the certificate was valid keeps being served after it
// expires; and bridge drops a revoked certificate from its CRL once it has
// expired (certstore.revoked: now.Before(NotAfter)), so a revoked
// certificate on a live connection is ADMITTED again after expiry.
func TestFoundNFSGateIgnoresExpiry(t *testing.T) {
	dir := t.TempDir()
	server := newPKI(t, dir)
	ca := newBridgeCA(t, dir)
	img := image(t, dir, "d.img", map[string]string{"/x.txt": "x"})
	pw := write(t, dir, "pw", "unused\n")
	srv, _ := runServer(t, fmt.Sprintf(`
user "alice@univ-a.fr" { password_file = %q }
share "t" {
  image = %q
  allow = ["alice@univ-a.fr"]
}
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
}
`, hclPath(pw), hclPath(img), hclPath(server.certFile), hclPath(server.keyFile), hclPath(ca.caFile), hclPath(ca.crlFile)))
	// A certificate that WAS valid when the connection was made, expired now.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "alice"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute),
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{sanWith(t, []string{"alice@univ-a.fr"}, nil)}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	leaf, _ := x509.ParseCertificate(der)
	var sh *share
	for _, s := range srv.currentShares() {
		if s.name == "t" {
			sh = s
		}
	}
	gate := srv.certificateGate(nil, sh)
	call := &rpc.Call{Cred: rpc.Auth{Flavor: rpc.AuthUnix}, Principal: "alice@univ-a.fr",
		TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}

	ca.publish(t, leaf.SerialNumber) // revoked while valid
	if _, err := srv.nfsCRL.fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r, _ := gate(call); r {
		t.Fatal("control: a revoked certificate was admitted")
	}
	ca.publish(t) // it expired: bridge's next CRL no longer lists it
	if _, err := srv.nfsCRL.fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r, w := gate(call); r {
		t.Errorf("FAIL-OPEN: an EXPIRED (NotAfter %s), formerly revoked certificate on a live connection is admitted: read=%v write=%v",
			leaf.NotAfter.Format(time.RFC3339), r, w)
	}
}

// F9 (SFTP): the same for an open SSH session -- sessionRevoked asks the
// KRL, never ValidBefore; bridge's KRL drops expired certificates.
func TestFoundSFTPSessionIgnoresExpiry(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caKey, _ := ssh.NewPublicKey(caPub)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	uk, _ := ssh.NewPublicKey(userPub)
	cert := &ssh.Certificate{Key: uk, Serial: 7, CertType: ssh.UserCert, KeyId: "alice",
		ValidPrincipals: []string{"alice@univ-a.fr"},
		ValidAfter:      uint64(time.Now().Add(-2 * time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(-time.Minute).Unix())} // expired
	cert.SignCert(rand.Reader, caSigner)

	var mu sync.Mutex
	body := func(revoke bool) []byte {
		b := krl.NewBuilder(1, "")
		if revoke {
			b.RevokeSerial(caKey, 7)
		}
		out, _ := b.Marshal(time.Now())
		return out
	}
	cur := body(true)
	l, _ := newRevocationList("ssh_krl", "", t.TempDir()+"/k", "", time.Minute, time.Hour, parseKRL, io.Discard)
	l.parse = func(b []byte) (revoked, error) { return parseKRL(b) }
	l.file = ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Write(cur)
	}))
	defer srv.Close()
	l.url, l.client = srv.URL, srv.Client()
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := &federatedSFTP{ca: caKey, krl: l, revoked: func(string, string, string, time.Time) error { return nil }}
	perms := marked(nil)
	perms.Extensions[certMark] = b64(cert.Marshal())
	perms.Extensions[issuedMark] = fmt.Sprint(cert.ValidAfter)
	gone := f.sessionRevoked("alice@univ-a.fr", perms, nil)
	if gone() == nil {
		t.Fatal("control: revoked session still served")
	}
	mu.Lock()
	cur = body(false)
	mu.Unlock()
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := gone(); err == nil {
		t.Errorf("FAIL-OPEN: a session on an EXPIRED (ValidBefore %s), formerly revoked certificate is served again",
			time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
	}
}

// F2b: a SET signed by a key the transmitter has just rotated in and
// published is refused for up to a minute after the last JWKS fetch --
// including the forced fetch every (re)start of a session makes.
func TestFoundRotatedKeyRefusedWithinAMinute(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var mu sync.Mutex
	serving := k1
	jw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &serving.PublicKey, KeyID: "k", Algorithm: "ES256"}}})
	}))
	defer jw.Close()
	r := &ssfReceiver{client: jw.Client(), jwks: jw.URL, out: io.Discard}
	if err := r.refreshKeys(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	serving = k2 // rotated and PUBLISHED
	mu.Unlock()
	s := signSET(t, k2, "k", map[string]any{"iss": "x"})
	if _, err := r.Verify(s); err != nil {
		t.Errorf("a SET signed by the transmitter's current, published key was refused (and, via setErrs, dropped by bridge): %v", err)
	}
}

func b64(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = enc
	return base64Std(b)
}

func base64Std(b []byte) string { return b64enc.EncodeToString(b) }

var b64enc = base64.StdEncoding

// What latches and what does not: a revocation latches for the session's
// life and ends it once; a list that is not known to be current refuses, and
// lets the session resume once it is.
func TestASessionRevocationLatchesAndAnUnknownListDoesNot(t *testing.T) {
	answer := errRevocationUnknown
	f := &federatedSFTP{revoked: func(string, string, string, time.Time) error { return answer }}
	perms := marked(nil)
	perms.Extensions[issuedMark] = fmt.Sprint(time.Now().Add(-time.Minute).Unix())
	var ended []error
	gone := f.sessionRevoked("alice@univ-a.fr", perms, func(err error) { ended = append(ended, err) })
	if gone() == nil {
		t.Fatal("refused while the list is unknown: want an error")
	}
	answer = nil
	if err := gone(); err != nil || len(ended) != 0 {
		t.Fatalf("the list current again: err = %v, ended %d times; want served, never ended", err, len(ended))
	}
	answer = fmt.Errorf("alice's sessions were revoked")
	if gone() == nil {
		t.Fatal("a revocation was not seen")
	}
	answer = nil // pruned, or the provider changed its mind
	if err := gone(); err == nil {
		t.Error("a revoked session was served again once the revocation was gone")
	}
	if len(ended) != 1 {
		t.Errorf("ended called %d times, want once", len(ended))
	}
}
