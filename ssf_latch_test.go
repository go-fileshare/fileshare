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

// A session the shared signals revoked stays revoked, and its connection is
// closed. The revocation itself is forgotten after `retain`; the session used
// to ask again, find nothing, and be served again -- the audit read the share
// on the same SFTP connection 200 hours (of the store's clock) later. The
// control is that the revocation really was pruned.
func TestARevokedSessionStaysRevokedAndIsClosed(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	caFile := write(t, dir, "tr-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tr.Certificate().Raw})))
	r := start(t, fmt.Sprintf(`
oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
}
ssf {
  transmitter        = %q
  audience           = "https://files.example.org"
  client_id          = "fileshare"
  client_secret_file = %q
  state_file         = %q
  ca_file            = %q
}
share "photos" {
  image = %q
  allow = ["oidc:user:trevor@univ-example.fr"]
}
serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, tr.URL, hclPath(write(t, dir, "secret", "client-secret\n")), hclPath(filepath.Join(dir, "rev.json")),
		hclPath(caFile), hclPath(image(t, dir, "photos.img", map[string]string{"/a.txt": "secret"}))))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.srv.ssf.run(ctx)
	deadline := time.Now().Add(20 * time.Second)
	for r.srv.revocations.age() < 0 {
		if time.Now().After(deadline) {
			t.Fatal("the transmitter was never heard from")
		}
		time.Sleep(20 * time.Millisecond)
	}

	op := &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", iat: time.Now().Add(-10 * time.Minute)}
	_, cert := opksshCert(t, keygen, dir, "trevor", op)
	cl, done, err := sftpAs(t, r.addrs["sftp"], op.user, ssh.PublicKeys(cert))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if _, err := cl.ReadDir("/photos"); err != nil {
		t.Fatalf("CONTROL: before the revocation the session could not read: %v", err)
	}

	tr.revoke(t, "j1", "https://files.example.org", op.user, p.URL, "s-"+op.user, time.Now().Add(-5*time.Minute))
	for !slices.Contains(func() []string { tr.mu.Lock(); defer tr.mu.Unlock(); return slices.Clone(tr.acked) }(), "j1") {
		if time.Now().After(deadline.Add(10 * time.Second)) {
			t.Fatal("the revocation was never acknowledged")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := cl.Open("/photos/a.txt"); err == nil {
		t.Fatal("the session was not cut by the revocation")
	}
	// The connection itself goes: the client's next request finds it closed.
	closed := make(chan error, 1)
	go func() { _, err := cl.Getwd(); closed <- err }()
	select {
	case err := <-closed:
		if err == nil {
			t.Error("the revoked session's connection still answers")
		}
	case <-time.After(5 * time.Second):
		t.Error("the revoked session's connection neither answers nor closes")
	}

	// 200 h later, by the store's clock, another revocation prunes trevor's.
	st := r.srv.revocations
	later := time.Now().Add(200 * time.Hour)
	st.mu.Lock()
	st.now = func() time.Time { return later }
	st.mu.Unlock()
	st.heardFrom()
	if err := st.revoke([]string{accountKey("someone-else@univ-example.fr")}, later); err != nil {
		t.Fatal(err)
	}
	if err := st.check(op.user, "", "", op.iat); err != nil {
		t.Fatalf("CONTROL: trevor's revocation was not pruned: %v", err)
	}
	if f, err := cl.Open("/photos/a.txt"); err == nil {
		f.Close()
		t.Error("the revoked session is served again once its revocation was pruned")
	}
}
