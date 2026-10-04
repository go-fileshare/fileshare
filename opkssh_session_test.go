// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp && !noopenpubkey

package main

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// An opkssh session ends when its PK Token is older than opkssh_max_age, as a
// new login would, and not when the certificate says: the person signs that
// certificate with their own key and may make it valid for ever. The audit
// opened a session 8 s before max_age with a "forever" certificate and still
// read the share 10 s later. Here the token has 2 s left at login; the control
// is the same session reading inside them.
func TestAnOpksshSessionEndsAtMaxAgeWhateverTheCertificateSays(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
  opkssh_max_age   = "12h"
}
share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}
serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(image(t, dir, "photos.img", map[string]string{"/a.txt": "secret"})), photosGroup))

	// iat is whole seconds; the session must end at iat + 12h.
	iat := time.Unix(time.Now().Add(-12*time.Hour+2*time.Second).Unix(), 0)
	ends := iat.Add(12 * time.Hour)
	op := &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}, iat: iat}
	key, signer, priv := keyFiles(t, dir, "trevor")
	if out, err := exec.Command(keygen, "-q", "-s", key, "-I", op.user, "-V", "-5m:forever",
		"-O", "extension:openpubkey-pkt="+pktFor(t, priv, op), key+".pub").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	cl, done, err := sftpAs(t, r.addrs["sftp"], op.user, ssh.PublicKeys(certSigner(t, key+"-cert.pub", signer)))
	if err != nil {
		t.Fatalf("login inside max_age: %v", err)
	}
	defer done()
	if time.Now().Before(ends) {
		if _, err := cl.ReadDir("/photos"); err != nil {
			t.Fatalf("CONTROL: inside max_age the session could not read: %v", err)
		}
	}
	time.Sleep(time.Until(ends) + 1100*time.Millisecond)
	if f, err := cl.Open("/photos/a.txt"); err == nil {
		f.Close()
		t.Errorf("the session still reads %v after its PK Token passed opkssh_max_age", time.Since(ends).Round(time.Millisecond))
	}
}
