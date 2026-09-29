//go:build !nosftp

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// People the provider vouches for, over SFTP. The certificates are made by
// OpenSSH's own ssh-keygen; the OpenPubkey token by the openpubkey client;
// the opkssh login is OpenSSH's sftp.

func needOpenSSH(t *testing.T) (keygen, sftpBin string) {
	t.Helper()
	k, err1 := exec.LookPath("ssh-keygen")
	s, err2 := exec.LookPath("sftp")
	if err1 != nil || err2 != nil {
		if os.Getenv("FILESHARE_REQUIRE_JUDGE") != "" {
			t.Fatal("OpenSSH's ssh-keygen and sftp are required here")
		}
		t.Skip("OpenSSH is not installed")
	}
	return k, s
}

// keyFiles writes an Ed25519 key as OpenSSH reads it.
func keyFiles(t *testing.T, dir, name string) (string, ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	os.WriteFile(p, pem.EncodeToMemory(blk), 0o600)
	s, _ := ssh.NewSignerFromKey(priv)
	os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(s.PublicKey()), 0o644)
	return p, s, priv
}

// certSigner reads a certificate ssh-keygen wrote, as a client presents it.
func certSigner(t *testing.T, certFile string, key ssh.Signer) ssh.Signer {
	t.Helper()
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(pk.(*ssh.Certificate), key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSFTPForPeopleTheProviderCertified(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	openImg := image(t, dir, "open.img", map[string]string{"/o.txt": "o"})
	staff := image(t, dir, "staff.img", map[string]string{"/s.txt": "s"})
	caKey, _, _ := keyFiles(t, dir, "bridge-ca")
	localCA, _, _ := keyFiles(t, dir, "local-ca")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
trusted_user_ca_file = %q

user "alice" {}

oidc {
  issuer      = %q
  audience    = "fileshare"
  ssh_ca_file = %q
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}
share "staff" {
  image = %q
  allow = ["alice"]
}
share "open" { image = %q }

serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(localCA+".pub"), p.URL, hclPath(caKey+".pub"), hclPath(photos), photosGroup, hclPath(staff), hclPath(openImg)))

	// issue has ssh-keygen sign a certificate with ca.
	issue := func(ca, name, principal string, opts ...string) ssh.Signer {
		t.Helper()
		key, signer, _ := keyFiles(t, dir, name)
		args := []string{"-q", "-s", ca, "-I", name, "-V", "-5m:+1h"}
		if principal != "" {
			args = append(args, "-n", principal)
		}
		args = append(args, opts...)
		if out, err := exec.Command(keygen, append(args, key+".pub")...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return certSigner(t, key+"-cert.pub", signer)
	}

	trevor := issue(caKey, "trevor", "trevor@univ-example.fr", "-O", "extension:groups@go-authn.org="+photosGroup)
	cl, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(trevor))
	if err != nil {
		t.Fatalf("a provider certificate in the photos group: %v", err)
	}
	entries, _ := cl.ReadDir("/")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "photos,open" {
		t.Errorf("trevor sees %v, want photos and the open share", names)
	}
	done()

	// ⛔ Certified by the provider, and no rule names him: a stranger.
	mallory := issue(caKey, "mallory", "mallory@univ-example.fr", "-O", "extension:groups@go-authn.org=urn:other")
	if _, _, err := sftpAs(t, r.addrs["sftp"], "mallory@univ-example.fr", ssh.PublicKeys(mallory)); err == nil {
		t.Error("a provider certificate no rule names was let in")
	}

	// ⛔ A LOCAL authority's certificate claiming the provider's groups, and
	// even the mark this server sets for itself: read as a local account.
	forged := issue(localCA, "forged", "alice", "-O", "extension:groups@go-authn.org="+photosGroup,
		"-O", "extension:federated@go-fileshare=1", "-O", "extension:groups@go-fileshare="+photosGroup)
	cl, done, err = sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(forged))
	if err != nil {
		t.Fatalf("alice with a local certificate: %v", err)
	}
	entries, _ = cl.ReadDir("/")
	for _, e := range entries {
		if e.Name() == "photos" {
			t.Error("a local certificate's claimed groups were believed")
		}
	}
	done()

	// ⛔ A provider certificate with no principal is valid for ANYBODY
	// (PROTOCOL.certkeys): refused, not read as whoever logs in with it.
	anybody := issue(caKey, "anybody", "", "-O", "extension:groups@go-authn.org="+photosGroup)
	if _, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(anybody)); err == nil {
		done()
		t.Error("a provider certificate with no principal was accepted")
	}

	// A provider certificate for somebody else is not a way in as trevor.
	if _, _, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(mallory)); err == nil {
		t.Error("mallory's certificate logged in as trevor")
	}
}
