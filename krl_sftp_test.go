// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A provider certificate revoked in the KRL: refused at login, and -- the
// part SSH itself cannot do -- a session it already opened, and a file that
// session already has open, stop being served. The KRLs are written by
// OpenSSH's ssh-keygen -k, the implementation sshd's RevokedKeys reads.
func TestAKRLRevokesProviderCertificatesAndTheirSessions(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "aaaa"})
	caKey, _, _ := keyFiles(t, dir, "bridge-ca")
	krlFile := filepath.Join(dir, "bridge.krl")
	// writeKRL has ssh-keygen revoke the serials given, of that CA.
	writeKRL := func(serials ...uint64) {
		t.Helper()
		spec := ""
		for _, s := range serials {
			spec += fmt.Sprintf("serial: %d\n", s)
		}
		specFile := write(t, dir, "krl.spec", spec)
		if out, err := exec.Command(keygen, "-k", "-f", krlFile, "-s", caKey+".pub", specFile).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -k: %v\n%s", err, out)
		}
	}
	writeKRL()
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
oidc {
  issuer       = %q
  audience     = "fileshare"
  ssh_ca_file  = %q
  ssh_krl_file = %q
}
share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}
serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(caKey+".pub"), hclPath(krlFile), hclPath(photos), photosGroup))
	krl := r.srv.sshKRL
	if krl == nil {
		t.Fatal("the KRL was not opened")
	}
	if _, err := krl.fetch(t.Context()); err != nil {
		t.Fatal(err)
	}

	issue := func(name string, serial uint64) ssh.Signer {
		t.Helper()
		key, signer, _ := keyFiles(t, dir, name)
		out, err := exec.Command(keygen, "-q", "-s", caKey, "-I", name, "-z", fmt.Sprint(serial), "-V", "-5m:+1h",
			"-n", name+"@univ-example.fr", "-O", "extension:groups@go-authn.org="+photosGroup, key+".pub").CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return certSigner(t, key+"-cert.pub", signer)
	}
	trevor := issue("trevor", 7)
	ursula := issue("ursula", 8)

	cl, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(trevor))
	if err != nil {
		t.Fatalf("before any revocation: %v", err)
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

	// Serial 7 revoked, as bridge publishes it.
	writeKRL(7)
	if changed, err := krl.fetch(t.Context()); err != nil || !changed {
		t.Fatalf("the new KRL: %v %v", changed, err)
	}
	if _, err := cl.ReadDir("/"); err == nil {
		t.Error("a session opened before the revocation still lists")
	}
	if _, err := f.Read(buf); err != io.EOF && err == nil {
		t.Error("a file opened before the revocation is still read")
	}
	if _, _, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(trevor)); err == nil {
		t.Error("a revoked certificate logged in")
	}
	// The control: a certificate the KRL does not name.
	cl2, done2, err := sftpAs(t, r.addrs["sftp"], "ursula@univ-example.fr", ssh.PublicKeys(ursula))
	if err != nil {
		t.Fatalf("a certificate the KRL does not name: %v", err)
	}
	if _, err := cl2.ReadDir("/photos"); err != nil {
		t.Errorf("ursula's session: %v", err)
	}

	// ⛔ A KRL too old to trust revokes everything it governs -- the open
	// session included.
	krl.mu.Lock()
	krl.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	krl.mu.Unlock()
	if _, err := cl2.ReadDir("/photos"); err == nil {
		t.Error("a session was still served with a KRL past max_age")
	}
	done2()
	if _, _, err := sftpAs(t, r.addrs["sftp"], "ursula@univ-example.fr", ssh.PublicKeys(ursula)); err == nil {
		t.Error("a provider certificate logged in with a KRL past max_age")
	}
}
