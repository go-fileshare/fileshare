// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// What a KRL can name, beyond the serial TestAKRLRevokesProviderCertificatesAndTheirSessions
// revokes by: the key ID, the certified key (by its public key and by its
// SHA-256 fingerprint) and the authority's own key. Each is written by
// OpenSSH's ssh-keygen -k, the implementation sshd's RevokedKeys reads, and
// each has its control: a spec of the same kind that names somebody else
// leaves the certificate working.
func TestAKRLRevokesByKeyIDByCertifiedKeyAndByAuthority(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "aaaa"})
	caKey, _, _ := keyFiles(t, dir, "bridge-ca")
	otherCA, _, _ := keyFiles(t, dir, "other-ca")
	krlFile := filepath.Join(dir, "bridge.krl")
	writeKRL := func(ca, spec string) {
		t.Helper()
		specFile := write(t, dir, "krl.spec", spec)
		if out, err := exec.Command(keygen, "-k", "-f", krlFile, "-s", ca+".pub", specFile).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -k: %v\n%s", err, out)
		}
	}
	writeKRL(caKey, "")
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

	issue := func(name string, serial uint64) (keyFile string, signer ssh.Signer) {
		t.Helper()
		key, s, _ := keyFiles(t, dir, name)
		out, err := exec.Command(keygen, "-q", "-s", caKey, "-I", name, "-z", fmt.Sprint(serial), "-V", "-5m:+1h",
			"-n", name+"@univ-example.fr", "-O", "extension:groups@go-authn.org="+photosGroup, key+".pub").CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return key, certSigner(t, key+"-cert.pub", s)
	}
	pubLine := func(file string) string {
		t.Helper()
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	fingerprint := func(file string) string {
		t.Helper()
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubLine(file)))
		if err != nil {
			t.Fatal(err)
		}
		return ssh.FingerprintSHA256(pk)
	}
	loggedIn := func(user string, s ssh.Signer) bool {
		t.Helper()
		_, done, err := sftpAs(t, r.addrs["sftp"], user+"@univ-example.fr", ssh.PublicKeys(s))
		if err == nil {
			done()
		}
		return err == nil
	}
	reload := func(ca, spec string) {
		t.Helper()
		writeKRL(ca, spec)
		if _, err := krl.fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	n := 0
	for _, tc := range []struct {
		name string
		// spec returns the KRL spec naming the certificate (target) or a
		// stranger (decoy), given the target's key file.
		spec func(target bool, name, keyFile string, strangerKey string) (ca, spec string)
	}{
		{"key id", func(target bool, name, _ string, _ string) (string, string) {
			if target {
				return caKey, "id: " + name + "\n"
			}
			return caKey, "id: somebody-else\n"
		}},
		{"certified key", func(target bool, _, keyFile string, stranger string) (string, string) {
			if target {
				return caKey, "key: " + pubLine(keyFile+".pub") + "\n"
			}
			return caKey, "key: " + pubLine(stranger+".pub") + "\n"
		}},
		{"certified key by fingerprint", func(target bool, _, keyFile string, stranger string) (string, string) {
			if target {
				return caKey, "hash: " + fingerprint(keyFile+".pub") + "\n"
			}
			return caKey, "hash: " + fingerprint(stranger+".pub") + "\n"
		}},
		{"the authority's key", func(target bool, _, _ string, stranger string) (string, string) {
			if target {
				return caKey, "key: " + pubLine(caKey+".pub") + "\n"
			}
			return caKey, "key: " + pubLine(otherCA+".pub") + "\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n++
			name := fmt.Sprintf("user%d", n)
			keyFile, s := issue(name, uint64(100+n))
			stranger, _, _ := keyFiles(t, dir, fmt.Sprintf("stranger%d", n))

			reload(tc.spec(false, name, keyFile, stranger))
			if !loggedIn(name, s) {
				t.Fatalf("control: a KRL naming somebody else (%s) refused %s", tc.name, name)
			}
			reload(tc.spec(true, name, keyFile, stranger))
			if loggedIn(name, s) {
				t.Errorf("a certificate revoked by %s logged in", tc.name)
			}
			// And back: a KRL that no longer names it lets it in again, so the
			// refusal above was the revocation and nothing else.
			reload(caKey, "")
			if !loggedIn(name, s) {
				t.Errorf("an empty KRL still refuses a certificate (%s)", tc.name)
			}
		})
	}
}

// A certificate outside its validity is refused whichever side of it, and the
// same authority's certificate inside it is the control. A certificate from an
// authority nobody trusts, on the path the provider's certificates take, is
// refused too -- with no ssh_domains configured, so no domain grant could have
// let it in.
func TestACertificateOutsideItsValidityOrFromNoTrustedAuthorityIsRefused(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	caKey, _, _ := keyFiles(t, dir, "bridge-ca")
	rogueCA, _, _ := keyFiles(t, dir, "rogue-ca")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

oidc {
  issuer      = %q
  audience    = "fileshare"
  ssh_ca_file = %q
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(caKey+".pub"), hclPath(photos), photosGroup))

	issue := func(ca, name, validity string) ssh.Signer {
		t.Helper()
		key, s, _ := keyFiles(t, dir, name)
		out, err := exec.Command(keygen, "-q", "-s", ca, "-I", name, "-V", validity,
			"-n", name+"@univ-example.fr", "-O", "extension:groups@go-authn.org="+photosGroup, key+".pub").CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return certSigner(t, key+"-cert.pub", s)
	}
	loggedIn := func(user string, s ssh.Signer) bool {
		t.Helper()
		cl, done, err := sftpAs(t, r.addrs["sftp"], user+"@univ-example.fr", ssh.PublicKeys(s))
		if err != nil {
			return false
		}
		defer done()
		_, err = cl.ReadDir("/photos")
		return err == nil
	}

	if !loggedIn("valid", issue(caKey, "valid", "-5m:+1h")) {
		t.Fatal("control: a valid provider certificate was refused")
	}
	for _, tc := range []struct{ name, validity string }{
		{"expired", "-2h:-1h"},
		{"not yet valid", "+1h:+2h"},
	} {
		if loggedIn(tc.name, issue(caKey, strings.ReplaceAll(tc.name, " ", "-"), tc.validity)) {
			t.Errorf("a %s certificate logged in", tc.name)
		}
	}
	if loggedIn("rogue", issue(rogueCA, "rogue", "-5m:+1h")) {
		t.Error("a certificate from an authority nobody trusts logged in")
	}
}
