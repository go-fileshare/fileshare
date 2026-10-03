// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// krlIssuer serves a KRL and its signature the way go-authn/bridge v0.10.0
// does: an ETag of the content, If-None-Match, and If-Match on the
// signature answered 412 when the list was issued again.
type krlIssuer struct {
	mu       sync.Mutex
	raw, sig []byte
	noSig    bool
	between  func() // run once the list is sent, before its signature
}

func (is *krlIssuer) set(raw, sig []byte) {
	is.mu.Lock()
	is.raw, is.sig = raw, sig
	is.mu.Unlock()
}

func (is *krlIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	is.mu.Lock()
	raw, sig, noSig, between := is.raw, is.sig, is.noSig, is.between
	is.mu.Unlock()
	h := sha256.Sum256(raw)
	tag := `"` + hex.EncodeToString(h[:16]) + `"`
	if strings.HasSuffix(r.URL.Path, ".sig") {
		if noSig {
			http.NotFound(w, r)
			return
		}
		if m := r.Header.Get("If-Match"); m != "" && m != tag {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Write(sig)
		return
	}
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(raw)
	if between != nil {
		is.mu.Lock()
		is.between = nil
		is.mu.Unlock()
		between()
	}
}

type testSSHCA struct{ signer ssh.Signer }

func newTestSSHCA(t *testing.T) testSSHCA {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return testSSHCA{s}
}

// issue is a KRL of version v revoking serials, issued at at, expiring
// valid later (none when zero), signed in namespace ns.
func (c testSSHCA) issue(t *testing.T, v uint64, at time.Time, valid time.Duration, ns string, serials ...uint64) ([]byte, []byte) {
	t.Helper()
	b := krl.NewBuilder(v, "test")
	for _, s := range serials {
		b.RevokeSerial(c.signer.PublicKey(), s)
	}
	if valid != 0 {
		b.SetExpires(at.Add(valid))
	}
	raw, err := b.Marshal(at)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sshsig.Sign(strings.NewReader(string(raw)), c.signer, sshsig.HashSHA512, ns)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sshsig.Armor(s)
}

func (c testSSHCA) cert(t *testing.T, serial uint64) *ssh.Certificate {
	t.Helper()
	upub, _, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := ssh.NewPublicKey(upub)
	cert := &ssh.Certificate{Key: u, Serial: serial, CertType: ssh.UserCert, KeyId: "u",
		ValidPrincipals: []string{"u"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		t.Fatal(err)
	}
	return cert
}

// signedKRLList opens the list an oidc block names, against an issuer.
func signedKRLList(t *testing.T, srv *httptest.Server, ca testSSHCA) *revocationList {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pub")
	os.WriteFile(caFile, ssh.MarshalAuthorizedKey(ca.signer.PublicKey()), 0o644)
	tlsCA := filepath.Join(dir, "tls.pem")
	os.WriteFile(tlsCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	l, err := openSSHKRL(&oidcBlock{SSHCAFile: caFile, SSHKRLURL: srv.URL + "/ssh/krl", SSHKRLCAFile: tlsCA}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestASignedKRLIsVerified(t *testing.T) {
	ca := newTestSSHCA(t)
	now := time.Now()
	is := &krlIssuer{}
	is.set(ca.issue(t, 1, now, time.Hour, revocation.Namespace, 7))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	l := signedKRLList(t, srv, ca)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatalf("control: a list signed by the CA is refused: %v", err)
	}
	cur, err := l.get()
	if err != nil {
		t.Fatal(err)
	}
	if !cur.(sshKRL).k.IsRevoked(ca.cert(t, 7)) || cur.(sshKRL).k.IsRevoked(ca.cert(t, 8)) {
		t.Error("the list does not revoke what it says")
	}

	// Everything a mirror, a cache, or a compromised server may serve:
	// refused, the good copy kept.
	other := newTestSSHCA(t)
	emptyByOther, otherSig := other.issue(t, 2, now, time.Hour, revocation.Namespace)
	empty, _ := ca.issue(t, 2, now, time.Hour, revocation.Namespace)
	wrongNS, wrongNSSig := ca.issue(t, 2, now, time.Hour, "file")
	noExpiry, noExpirySig := ca.issue(t, 2, now, 0, revocation.Namespace)
	for name, c := range map[string][2][]byte{
		"an empty list signed by another CA": {emptyByOther, otherSig},
		"an empty list, another's signature": {empty, otherSig},
		"a signature in another namespace":   {wrongNS, wrongNSSig},
		"a list that never expires":          {noExpiry, noExpirySig},
	} {
		is.set(c[0], c[1])
		if _, err := l.fetch(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		cur, err := l.get()
		if err != nil || !cur.(sshKRL).k.IsRevoked(ca.cert(t, 7)) {
			t.Errorf("%s: the good copy was not kept (%v)", name, err)
		}
	}
}

// go-authn/bridge before v0.10.0 serves no signature: refused, so the
// provider's certificates are refused until it does.
func TestAnUnsignedKRLFromAURLIsRefused(t *testing.T) {
	ca := newTestSSHCA(t)
	is := &krlIssuer{noSig: true}
	is.set(ca.issue(t, 1, time.Now(), time.Hour, revocation.Namespace))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	l := signedKRLList(t, srv, ca)
	_, err := l.fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
		t.Errorf("no signature: %v", err)
	}
	if _, err := l.get(); !errors.Is(err, errRevocationUnknown) {
		t.Errorf("never verified, yet usable: %v", err)
	}
}

// The list's own expiry ends it, however recently a 304 confirmed it.
func TestAKRLPastItsExpiryIsNotCurrent(t *testing.T) {
	ca := newTestSSHCA(t)
	start := time.Now()
	is := &krlIssuer{}
	is.set(ca.issue(t, 1, start, time.Hour, revocation.Namespace))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	l := signedKRLList(t, srv, ca)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	at := start.Add(61 * time.Minute)
	l.now = func() time.Time { return at }
	if _, err := l.fetch(context.Background()); err != nil { // a 304
		t.Fatal(err)
	}
	if _, err := l.get(); !errors.Is(err, errRevocationUnknown) {
		t.Errorf("a KRL past its expiry, confirmed by a 304 a moment ago: %v", err)
	}
	// Issued again, it is current again.
	is.set(ca.issue(t, 1, at, time.Hour, revocation.Namespace))
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.get(); err != nil {
		t.Errorf("re-issued: %v", err)
	}
}

// A list issued again between the list and its signature: 412, and the
// pair is fetched again at once.
func TestAReissueBetweenListAndSignatureIsRetried(t *testing.T) {
	ca := newTestSSHCA(t)
	now := time.Now()
	is := &krlIssuer{}
	is.set(ca.issue(t, 1, now, time.Hour, revocation.Namespace))
	next, nextSig := ca.issue(t, 2, now, time.Hour, revocation.Namespace, 9)
	is.between = func() { is.set(next, nextSig) }
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	l := signedKRLList(t, srv, ca)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatalf("a re-issue in between: %v", err)
	}
	cur, _ := l.get()
	if cur == nil || cur.(sshKRL).k.Version != 2 {
		t.Errorf("held %v, want version 2", cur)
	}
}

// A KRL placed by hand is trusted as the filesystem is: no signature asked.
func TestAKRLFileNeedsNoSignature(t *testing.T) {
	ca := newTestSSHCA(t)
	raw, _ := ca.issue(t, 1, time.Now(), 0, revocation.Namespace, 3)
	p := filepath.Join(t.TempDir(), "revoked.krl")
	os.WriteFile(p, raw, 0o644)
	l, err := openSSHKRL(&oidcBlock{SSHKRLFile: p}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatalf("an unsigned KRL file: %v", err)
	}
	if _, err := l.get(); err != nil {
		t.Errorf("a KRL file with no expiry: %v", err)
	}
}

func TestKRLURLNeedsTheCA(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "d.img", nil)
	ca := filepath.Join(dir, "ca.pub")
	os.WriteFile(ca, ssh.MarshalAuthorizedKey(newTestSSHCA(t).signer.PublicKey()), 0o644)
	body := func(caLine string) string {
		return fmt.Sprintf(`name = "TESTFS"
oidc {
  issuer      = "https://idp.example.org"
  audience    = "fileshare"
  ssh_krl_url = "https://idp.example.org/ssh/krl"
  %s
}
share "d" {
  image = %q
  allow = ["oidc:groups:x"]
}
serve "sftp" { addr = "127.0.0.1:0" }
`, caLine, hclPath(img))
	}
	_, err := loadConfig([]string{write(t, dir, "no-ca.hcl", body(""))})
	if err == nil || !strings.Contains(err.Error(), "ssh_krl_url needs ssh_ca_file") {
		t.Errorf("ssh_krl_url without ssh_ca_file: %v", err)
	}
	if _, err := loadConfig([]string{write(t, dir, "ca.hcl", body(fmt.Sprintf("ssh_ca_file = %q", hclPath(ca))))}); err != nil {
		t.Errorf("control: with ssh_ca_file: %v", err)
	}
	if _, err := openSSHKRL(&oidcBlock{SSHKRLURL: "https://idp/ssh/krl"}, io.Discard); err == nil {
		t.Error("openSSHKRL without a CA: no error")
	}
}
