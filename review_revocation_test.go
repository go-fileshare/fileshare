// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

// The tests in this file were written by an adversarial review of the
// revocation paths, each proving a fail-open it found; they stay as the
// regression tests of the fixes. A "FAIL-OPEN" in a failure names the
// defect come back.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	fsftp "github.com/go-filesystems/sftp"
	"github.com/go-jose/go-jose/v4"
	psftp "github.com/pkg/sftp"
)

// signSET signs claims as a SET with the given key and kid.
func signSET(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

func startReceiver(t *testing.T, tr *transmitter, dir string) (*ssfReceiver, context.CancelFunc) {
	t.Helper()
	caFile := write(t, dir, "tr-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tr.Certificate().Raw})))
	tokenFile := write(t, dir, "ssf.token", "stream-secret\n")
	b := &ssfBlock{Transmitter: tr.URL, Audience: "https://files.example.org", TokenFile: tokenFile,
		StateFile: filepath.Join(dir, "state", "revocations.json"), CAFile: caFile, MaxAge: "1m"}
	os.MkdirAll(filepath.Join(dir, "state"), 0o755)
	r, err := newSSFReceiver(b, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for r.store.age() < 0 {
		if time.Now().After(deadline) {
			t.Fatal("never heard")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return r, cancel
}

func revocationClaims(tr *transmitter, jti, account string, at time.Time) map[string]any {
	return map[string]any{
		"iss": tr.URL, "aud": "https://files.example.org", "iat": time.Now().Unix(), "jti": jti,
		"sub_id": map[string]any{"format": "account", "uri": "acct:" + account},
		"events": map[string]any{eventSessionRevoked: map[string]any{"event_timestamp": at.Unix()}},
	}
}

// F4: a SET with no iat and no event_timestamp revokes "since 1970": the
// entry is pruned on the spot, the event is acknowledged, nothing is
// revoked.
func TestFoundSETWithoutTimesRevokesNothing(t *testing.T) {
	payload := `{"iss":"https://b","aud":"https://f","jti":"x",
	 "sub_id":{"format":"account","uri":"acct:alice@univ.fr"},
	 "events":{"` + eventSessionRevoked + `":{}}}`
	keys, at, err := parseRevocation([]byte(payload), "https://b", "https://f")
	t.Logf("keys=%v at=%v err=%v", keys, at.UTC(), err)
	st, _ := openRevocationStore(filepath.Join(t.TempDir(), "s.json"), 192*time.Hour, time.Hour)
	st.heardFrom()
	if err == nil {
		if err := st.revoke(keys, at); err != nil {
			t.Fatal(err)
		}
	}
	if err == nil && st.check("alice@univ.fr", "", "", time.Now().Add(-time.Hour)) == nil {
		t.Errorf("a session-revoked SET without iat was accepted (acked) and revoked nothing (entries=%d)", st.count())
	}
}

// F4b: NumericDate may be fractional (RFC 7519 §2): the SET is refused as
// permanent -- acknowledged and dropped.
func TestFoundFractionalIatRefused(t *testing.T) {
	payload := `{"iss":"https://b","aud":"https://f","iat":1790000000.5,"jti":"x",
	 "sub_id":{"format":"account","uri":"acct:alice@univ.fr"},
	 "events":{"` + eventSessionRevoked + `":{"event_timestamp":1790000000}}}`
	_, _, err := parseRevocation([]byte(payload), "https://b", "https://f")
	if err != nil {
		t.Errorf("a SET with a fractional iat is refused (and would be acked as permanent): %v", err)
	}
}

// helpers for CRL tests
func mkCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func mkCRL(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey, num int64, serials []int64, ext []pkix.Extension) []byte {
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(num),
		ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: entries,
		ExtraExtensions: ext}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// F5: a delta CRL (critical deltaCRLIndicator) and a CRL with an unknown
// critical extension are both accepted as a COMPLETE list.
func TestFoundCRLCriticalExtensionsIgnored(t *testing.T) {
	ca, key := mkCA(t, "ca")
	parse := crlParser([]*x509.Certificate{ca})
	base, _ := asn1.Marshal(big.NewInt(1))
	delta := mkCRL(t, ca, key, 2, nil, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: base}})
	if _, err := parse(delta); err == nil {
		t.Error("a delta CRL (deltaCRLIndicator, critical) was accepted as the complete list")
	}
	unknown := mkCRL(t, ca, key, 3, nil, []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}})
	if _, err := parse(unknown); err == nil {
		t.Error("a CRL with an unknown critical extension was accepted")
	}
}

// F6: an older CRL (lower CRL number) replaces a newer one: a rollback
// un-revokes.
func TestFoundCRLRollbackAccepted(t *testing.T) {
	ca, key := mkCA(t, "ca")
	l, _ := newRevocationList("x509_crl", "", filepath.Join(t.TempDir(), "crl"), "", time.Minute, time.Hour, crlParser([]*x509.Certificate{ca}), io.Discard)
	os.WriteFile(l.file, mkCRL(t, ca, key, 5, []int64{42}, nil), 0o644)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(l.file, mkCRL(t, ca, key, 4, nil, nil), 0o644)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Logf("older CRL refused: %v", err)
		return
	}
	cur, _ := l.get()
	if !cur.(crlList).revoked(big.NewInt(42)) {
		t.Errorf("CRL number 4 replaced number 5: serial 42 un-revoked")
	}
}

// F7: the list client follows an https -> http redirect.
func TestFoundListFollowsRedirectToCleartext(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("v-from-http")) }))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/krl", http.StatusFound)
	}))
	defer tlsSrv.Close()
	l, _ := newRevocationList("test", tlsSrv.URL, "", "", time.Minute, time.Hour, parseListOf, io.Discard)
	l.client = tlsSrv.Client()
	if _, err := l.fetch(context.Background()); err == nil {
		cur, _ := l.get()
		t.Errorf("a list fetched over cleartext http after a redirect was accepted: %q", cur.describe())
	}
}

// F8: a share whose driver has no Opener cannot be read over SFTP through
// the union: OpenFile answers ErrInvalid and go-filesystems/sftp, seeing
// the union IS an Opener, fails the open instead of falling back.
type plainShare struct{ m *memShare }

func (p plainShare) Close() error                                    { return nil }
func (p plainShare) ReadFile(s string) ([]byte, error)               { return p.m.ReadFile(s) }
func (p plainShare) ListDir(s string) ([]filesystem.DirEntry, error) { return p.m.ListDir(s) }
func (p plainShare) Stat(s string) (filesystem.Stat, error)          { return p.m.Stat(s) }
func (p plainShare) WriteFile(s string, b []byte, m os.FileMode) error {
	return p.m.WriteFile(s, b, m)
}
func (p plainShare) ReadLink(s string) (string, error)   { return p.m.ReadLink(s) }
func (p plainShare) MkDir(s string, m os.FileMode) error { return nil }
func (p plainShare) DeleteFile(s string) error           { return p.m.DeleteFile(s) }
func (p plainShare) DeleteDir(s string) error            { return nil }
func (p plainShare) Rename(a, b string) error            { return p.m.Rename(a, b) }

func TestFoundSFTPNonOpenerShareUnreadable(t *testing.T) {
	m := &memShare{files: map[string][]byte{"/a.txt": []byte("hello")}}
	u := &unionFS{entries: []unionEntry{{name: "s", fsys: plainShare{m}}}}
	srv, err := fsftp.New(u, fsftp.ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	go srv.Serve(c1)
	cl, err := psftp.NewClientPipe(c2, c2)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	f, err := cl.Open("/s/a.txt")
	if err != nil {
		t.Errorf("open of a file on a non-Opener share fails over SFTP: %v", err)
		return
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "hello" {
		t.Errorf("read: %q %v", b, err)
	}
	_ = strings.TrimSpace
}

// F1: a list that arrives broken leaves the last good copy and its tag
// alone. Its own tag is not remembered -- sent back, it would have the
// server answer 304 and keep a stale copy "fresh" for ever -- so every later
// fetch fails while the list stays broken, and max_age then refuses.
func TestFoundBrokenListAgesOut(t *testing.T) {
	var body atomic.Value
	body.Store("v1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := body.Load().(string)
		if r.Header.Get("If-None-Match") == `"`+b+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"`+b+`"`)
		w.Write([]byte(b))
	}))
	defer srv.Close()
	now := time.Unix(1_000_000, 0)
	l, err := newRevocationList("test", srv.URL, "", "", time.Minute, time.Hour, parseListOf, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	l.client = srv.Client()
	l.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := l.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	body.Store("broken-v2")
	for i := 0; i < 5; i++ {
		if _, err := l.fetch(ctx); err == nil {
			t.Fatalf("FAIL-OPEN: fetch %d of a broken list succeeded", i)
		}
		now = now.Add(50 * time.Minute)
	}
	if l.etag != `"v1"` {
		t.Errorf("the tag kept is %q, want the last good copy's", l.etag)
	}
	if got, err := l.get(); err == nil {
		t.Errorf("FAIL-OPEN: stale copy %q served 250m after it was last good (max_age 1h)", got.describe())
	}
}

// F2: a SET that does not verify (a key rotated in that the JWKS does not
// show yet) is neither acknowledged NOR reported: reported, a transmitter
// that drops on setErrs (go-authn/bridge did) loses it. The poll round fails
// instead, so the receiver is not "heard from" and fails closed at max_age,
// and the SET is delivered again once the key is published.
func TestFoundUnverifiableSETStaysQueued(t *testing.T) {
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	r, cancel := startReceiver(t, tr, dir)
	defer cancel()
	rotated, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := signSET(t, rotated, "t2", revocationClaims(tr, "j-rot", "alice@univ.fr", time.Now().Add(-time.Minute)))
	tr.mu.Lock()
	tr.queue["j-rot"] = s
	polled := tr.polled
	tr.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		tr.mu.Lock()
		n := tr.polled
		tr.mu.Unlock()
		if n >= polled+3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not polled")
		}
		time.Sleep(20 * time.Millisecond)
	}
	tr.mu.Lock()
	_, reported := tr.setErrs["j-rot"]
	_, still := tr.queue["j-rot"]
	tr.mu.Unlock()
	if reported || !still {
		t.Errorf("FAIL-OPEN: an unverifiable SET was reported (%v) or taken off the queue (queued: %v)", reported, still)
	}
	if age := r.store.age(); age < 0.5 {
		t.Errorf("FAIL-OPEN: the receiver counts itself heard from %.1fs ago while it cannot read what it is sent", age)
	}
	// The key is published: the SET lands.
	tr.mu.Lock()
	tr.keys = append(tr.keys, jose.JSONWebKey{Key: &rotated.PublicKey, KeyID: "t2", Algorithm: "ES256", Use: "sig"})
	tr.mu.Unlock()
	r.mu.Lock()
	r.triedKids = nil
	r.mu.Unlock()
	// The next poll after a failed round waits out a backoff of up to
	// max_age/4 (15 s here).
	deadline = time.Now().Add(40 * time.Second)
	for r.store.check("alice@univ.fr", "", "", time.Now().Add(-time.Hour)) == nil {
		if time.Now().After(deadline) {
			t.Fatal("FAIL-OPEN: the SET never landed once its key was published")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// F3: a revocation that cannot be written down is not acknowledged and not
// reported: it stays queued at the transmitter, and lands -- in the state
// file too -- once the disk takes writes again.
func TestFoundUnwritableStateKeepsTheSETQueued(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permissions")
	}
	if runtime.GOOS == "windows" {
		t.Skip("a directory's mode does not stop a write on Windows")
	}
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	r, cancel := startReceiver(t, tr, dir)
	defer cancel()
	stateDir := filepath.Join(dir, "state")
	os.Chmod(stateDir, 0o500) // a full disk, a read-only remount
	defer os.Chmod(stateDir, 0o755)
	s := signSET(t, tr.key, "t1", revocationClaims(tr, "j-io", "alice@univ.fr", time.Now().Add(-time.Minute)))
	tr.mu.Lock()
	tr.queue["j-io"] = s
	polled := tr.polled
	tr.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		tr.mu.Lock()
		n := tr.polled
		tr.mu.Unlock()
		if n >= polled+3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not polled")
		}
		time.Sleep(20 * time.Millisecond)
	}
	tr.mu.Lock()
	_, reported := tr.setErrs["j-io"]
	_, still := tr.queue["j-io"]
	tr.mu.Unlock()
	if reported || !still {
		t.Errorf("FAIL-OPEN: a revocation not written down was reported (%v) or taken off the queue (queued: %v)", reported, still)
	}
	os.Chmod(stateDir, 0o755)
	deadline = time.Now().Add(40 * time.Second)
	for {
		tr.mu.Lock()
		_, still = tr.queue["j-io"]
		tr.mu.Unlock()
		if !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the SET was never acknowledged once the disk took writes")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	_ = r
	st, err := openRevocationStore(filepath.Join(stateDir, "revocations.json"), 192*time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st.heardFrom()
	if err := st.check("alice@univ.fr", "", "", time.Now().Add(-time.Hour)); err == nil {
		t.Errorf("FAIL-OPEN after restart: the acknowledged revocation is not in the state file")
	}
}

// F11: an HS256 SET never verifies, whatever key set the receiver holds: a
// symmetric key taken from a public JWKS would let whoever reads it sign.
func TestFoundHMACKeyIsNeverUsed(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	r := &ssfReceiver{keys: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: secret, KeyID: "h", Algorithm: "HS256"}}},
		client: &http.Client{Timeout: time.Second}, jwks: "https://127.0.0.1:1/jwks", out: io.Discard}
	r.last = time.Now()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret},
		(&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "h"))
	obj, _ := signer.Sign([]byte(`{"iss":"x"}`))
	s, _ := obj.CompactSerialize()
	if _, err := r.Verify(s); err == nil {
		t.Errorf("FAIL-OPEN: an HMAC-signed SET was accepted against a symmetric key")
	}
}

// A stream the transmitter has paused or disabled answers polls with
// nothing: the receiver would count itself heard from and never be told.
// Its status, asked at session start, stops the session instead; and an
// enabled one starts as before.
func TestFoundDisabledStreamIsNotHeardFrom(t *testing.T) {
	for _, c := range []struct {
		status string
		heard  bool
	}{{"disabled", false}, {"paused", false}, {"enabled", true}} {
		t.Run(c.status, func(t *testing.T) {
			dir := t.TempDir()
			tr := newTransmitter(t, "stream-secret")
			tr.status = c.status
			r, cancel := receiverFor(t, tr, dir)
			defer cancel()
			if heard := waitHeard(r, 3*time.Second); heard != c.heard {
				t.Errorf("FAIL-OPEN: a stream %s at the transmitter: heard from = %v", c.status, heard)
			}
		})
	}
}

// Every endpoint the transmitter names is reached over https: the rule on
// `transmitter` is worth nothing if the keys it points to are not.
func TestFoundCleartextDiscoveredEndpointIsRefused(t *testing.T) {
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	// A plaintext server that really serves the transmitter's keys: so
	// what refuses it is the rule, not a failed fetch.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &tr.key.PublicKey, KeyID: "t1", Algorithm: "ES256", Use: "sig"}}})
	}))
	defer plain.Close()
	tr.jwksURI = plain.URL + "/jwks"
	r, cancel := receiverFor(t, tr, dir)
	defer cancel()
	if waitHeard(r, 3*time.Second) {
		t.Errorf("FAIL-OPEN: a transmitter publishing its keys at %s was heard from", tr.jwksURI)
	}
}

// receiverFor starts a receiver on tr without waiting to hear from it.
func receiverFor(t *testing.T, tr *transmitter, dir string) (*ssfReceiver, context.CancelFunc) {
	t.Helper()
	caFile := write(t, dir, "tr-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tr.Certificate().Raw})))
	tokenFile := write(t, dir, "ssf.token", "stream-secret\n")
	b := &ssfBlock{Transmitter: tr.URL, Audience: "https://files.example.org", TokenFile: tokenFile,
		StateFile: filepath.Join(dir, "state", "revocations.json"), CAFile: caFile, MaxAge: "1m"}
	os.MkdirAll(filepath.Join(dir, "state"), 0o755)
	r, err := newSSFReceiver(b, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)
	return r, cancel
}

func waitHeard(r *ssfReceiver, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if r.store.age() >= 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
