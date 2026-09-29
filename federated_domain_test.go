//go:build !nosftp && !nowebdav

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Which institutions may come in at all (oidc.domains), and a share for one
// institution's people (oidc:domain:), over SFTP with the provider's
// certificates and over WebDAV with its tokens.
func TestFederatedDomains(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	lab := image(t, dir, "lab.img", map[string]string{"/l.txt": "l"})
	caKey, _, _ := keyFiles(t, dir, "bridge-ca")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

oidc {
  issuer      = %q
  audience    = "fileshare"
  ssh_ca_file = %q
  domains     = ["univ-example.fr", "Partner.EDU"]
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}
share "lab" {
  image = %q
  allow = ["oidc:domain:partner.edu"]
}

serve "sftp"   { addr = "127.0.0.1:0" }
serve "webdav" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(caKey+".pub"), hclPath(photos), photosGroup, hclPath(lab)))

	issue := func(name, principal string, groups ...string) ssh.Signer {
		t.Helper()
		key, signer, _ := keyFiles(t, dir, name)
		args := []string{"-q", "-s", caKey, "-I", name, "-V", "-5m:+1h", "-n", principal}
		if len(groups) > 0 {
			args = append(args, "-O", "extension:groups@go-authn.org="+strings.Join(groups, "\n"))
		}
		if out, err := exec.Command(keygen, append(args, key+".pub")...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return certSigner(t, key+"-cert.pub", signer)
	}
	sees := func(user string, s ssh.Signer) (string, error) {
		t.Helper()
		cl, done, err := sftpAs(t, r.addrs["sftp"], user, ssh.PublicKeys(s))
		if err != nil {
			return "", err
		}
		defer done()
		es, _ := cl.ReadDir("/")
		var n []string
		for _, e := range es {
			n = append(n, e.Name())
		}
		return strings.Join(n, ","), nil
	}

	// In an admitted domain and the photos group: photos.
	if got, err := sees("trevor@univ-example.fr", issue("trevor", "trevor@univ-example.fr", photosGroup)); err != nil || got != "photos" {
		t.Errorf("trevor: %q %v", got, err)
	}
	// ⛔ In the photos group, from a domain not admitted: refused outright.
	if _, err := sees("eve@elsewhere.fr", issue("eve", "eve@elsewhere.fr", photosGroup)); err == nil {
		t.Error("somebody from a domain not admitted got in")
	}
	// The partner's people reach the lab by their domain alone, whatever the
	// case of the configuration.
	if got, err := sees("pat@partner.edu", issue("pat", "pat@partner.edu")); err != nil || got != "lab" {
		t.Errorf("pat: %q %v", got, err)
	}
	// ⛔ "evilpartner.edu" ends with the right letters, and is not it.
	if _, err := sees("x@evilpartner.edu", issue("x", "x@evilpartner.edu", photosGroup)); err == nil {
		t.Error("a domain that merely ends with an admitted one got in")
	}

	// The same rules over WebDAV, with tokens.
	if _, err := webdavGetToken(r, federatedToken(t, p, "eve@elsewhere.fr", photosGroup), "/photos/a.txt"); err == nil {
		t.Error("a token from a domain not admitted was accepted over WebDAV")
	}
	if got, err := webdavGetToken(r, federatedToken(t, p, "pat@partner.edu"), "/lab/l.txt"); err != nil || string(got) != "l" {
		t.Errorf("pat over WebDAV: %v", err)
	}
	if _, err := webdavGetToken(r, federatedToken(t, p, "trevor@univ-example.fr", photosGroup), "/lab/l.txt"); err == nil {
		t.Error("oidc:domain admitted somebody from another domain")
	}
	// The log says who came in and in which groups.
	if !strings.Contains(r.out.String(), "trevor@univ-example.fr, vouched for by the provider, in groups ["+photosGroup+"]") {
		t.Errorf("the log does not say trevor's groups:\n%s", r.out.String())
	}
}
