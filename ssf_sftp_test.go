// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp && !noopenpubkey && !nowebdav

package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// OpenPubkey certificates are in no revocation list -- nothing issued them
// but the person's own key -- so a shared signals revocation is the only way
// to take one back: refused at login, and the session it opened, open file
// included, stops being served. What the provider issues after is theirs.
func TestSharedSignalsRevokeAnOpenPubkeySession(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	caFile := write(t, dir, "tr-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tr.Certificate().Raw})))
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "aaaa"})
	r := start(t, fmt.Sprintf(`
oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
}
ssf {
  transmitter = %q
  audience    = "https://files.example.org"
  client_id          = "fileshare"
  client_secret_file = %q
  state_file  = %q
  ca_file     = %q
}
share "photos" {
  image = %q
  allow = ["oidc:user:trevor@univ-example.fr"]
}
serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, tr.URL, hclPath(write(t, dir, "secret", "client-secret\n")), hclPath(filepath.Join(dir, "rev.json")),
		hclPath(caFile), hclPath(photos)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.srv.ssf.run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for r.srv.revocations.age() < 0 {
		if time.Now().After(deadline) {
			t.Fatal("the transmitter was never heard from")
		}
		time.Sleep(20 * time.Millisecond)
	}

	op := &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", iat: time.Now().Add(-10 * time.Minute)}
	_, signer := opksshCert(t, keygen, dir, "early", op)
	cl, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("before the revocation: %v", err)
	}
	defer done()
	f, err := cl.Open("/photos/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 2)
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("reading before the revocation: %v", err)
	}

	tr.revoke(t, "j1", "https://files.example.org", "trevor@univ-example.fr", p.URL, "s-trevor@univ-example.fr",
		time.Now().Add(-5*time.Minute))
	for !slices.Contains(func() []string { tr.mu.Lock(); defer tr.mu.Unlock(); return slices.Clone(tr.acked) }(), "j1") {
		if time.Now().After(deadline.Add(10 * time.Second)) {
			t.Fatal("the revocation was never acknowledged")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := cl.ReadDir("/"); err == nil {
		t.Error("the open session still lists after the revocation")
	}
	if _, err := f.Read(buf); err == nil {
		t.Error("the open file is still read after the revocation")
	}
	if _, _, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(signer)); err == nil {
		t.Error("the certificate issued before the revocation logged in")
	}
	// Issued since: the person, re-enabled, is not locked out.
	op.iat = time.Now()
	_, fresh := opksshCert(t, keygen, dir, "fresh", op)
	cl2, done2, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(fresh))
	if err != nil {
		t.Fatalf("a certificate issued after the revocation: %v", err)
	}
	defer done2()
	if _, err := cl2.ReadDir("/photos"); err != nil {
		t.Errorf("the new session: %v", err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.issued == 0 {
		t.Error("no access token was ever asked for with the client credentials")
	}
}
