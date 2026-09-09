//go:build !nosftp

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTP, judged by a client this project did not write: github.com/pkg/sftp,
// the one every Go program that speaks SFTP uses. The protocol itself is
// judged upstream by OpenSSH's own `sftp` binary; what is tested here is what
// this program adds — who gets in, and what tree they land in.

// keyPair makes a key and the authorized_keys line for it.
func keyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
}

func sftpAs(t *testing.T, addr, user string, auth ssh.AuthMethod) (*sftp.Client, func(), error) {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, func() {}, err
	}
	cl, err := sftp.NewClient(c)
	if err != nil {
		c.Close()
		return nil, func() {}, err
	}
	return cl, func() { cl.Close(); c.Close() }, nil
}

// A key belongs to one person, and a password is not a way in at all: an SSH
// client that prompts for one is doing the thing keys exist to avoid.
func TestSFTPAuthenticatesByKey(t *testing.T) {
	needUsers(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	aliceKey, alicePub := keyPair(t)
	bobKey, bobPub := keyPair(t)
	strangerKey, _ := keyPair(t)

	r := start(t, fmt.Sprintf(`
name = "TESTFS"

user "alice" { authorized_keys = [%q] }
user "bob"   { authorized_keys = [%q] }

share "photos" {
  image = %q
}

serve "sftp" { addr = "127.0.0.1:0" }
`, alicePub, bobPub, hclPath(img)))

	if _, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(aliceKey)); err != nil {
		t.Errorf("alice with her own key: %v", err)
	} else {
		done()
	}
	// The one that matters: a key that IS authorised, offered as somebody else.
	if _, _, err := sftpAs(t, r.addrs["sftp"], "bob", ssh.PublicKeys(aliceKey)); err == nil {
		t.Error("alice's key logged bob in")
	}
	if _, _, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(strangerKey)); err == nil {
		t.Error("a key nobody listed was accepted")
	}
	if _, _, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.Password("hunter2")); err == nil {
		t.Error("SFTP accepted a password")
	}
	_ = bobKey
}

// The shares are the top-level directories, and the tree is built for the
// person who authenticated.
func TestSFTPGivesEachPersonTheirOwnTree(t *testing.T) {
	needUsers(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	alices := image(t, dir, "alices.img", map[string]string{"/secret.txt": "mine"})
	aliceKey, alicePub := keyPair(t)
	bobKey, bobPub := keyPair(t)

	r := start(t, fmt.Sprintf(`
name = "TESTFS"

user "alice" { authorized_keys = [%q] }
user "bob"   { authorized_keys = [%q] }

share "photos" {
  image   = %q
  allow   = ["alice", "bob"]
  writers = ["alice"]
}

share "alices" {
  image = %q
  allow = ["alice"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, alicePub, bobPub, hclPath(photos), hclPath(alices)))

	// What each person sees at the root.
	for _, tc := range []struct {
		user string
		key  ssh.Signer
		want string
	}{
		{"alice", aliceKey, "alices,photos"},
		{"bob", bobKey, "photos"},
	} {
		cl, done, err := sftpAs(t, r.addrs["sftp"], tc.user, ssh.PublicKeys(tc.key))
		if err != nil {
			t.Fatalf("%s: %v", tc.user, err)
		}
		entries, err := cl.ReadDir("/")
		if err != nil {
			done()
			t.Fatalf("%s listing the root: %v", tc.user, err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
			if !e.IsDir() {
				t.Errorf("%s: %q at the root is not a directory", tc.user, e.Name())
			}
		}
		sort.Strings(names)
		if got := strings.Join(names, ","); got != tc.want {
			t.Errorf("%s sees %q, want %q", tc.user, got, tc.want)
		}
		done()
	}

	// Reading, through the tree.
	alice, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(aliceKey))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f, err := alice.Open("/photos/greeting.txt")
	if err != nil {
		t.Fatalf("opening through the tree: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	f.Close()
	if string(buf[:n]) != "hello" {
		t.Errorf("read %q", buf[:n])
	}

	// Alice writes where she may.
	w, err := alice.Create("/photos/fromalice.txt")
	if err != nil {
		t.Fatalf("alice creating a file she may write: %v", err)
	}
	if _, err := w.Write([]byte("mine")); err != nil {
		t.Errorf("alice writing: %v", err)
	}
	w.Close()

	// Bob may read that share and not write it, and the refusal comes from
	// this program rather than from a driver that would have allowed it.
	bob, doneBob, err := sftpAs(t, r.addrs["sftp"], "bob", ssh.PublicKeys(bobKey))
	if err != nil {
		t.Fatal(err)
	}
	defer doneBob()
	if _, err := bob.Open("/photos/greeting.txt"); err != nil {
		t.Errorf("bob reading a share he may read: %v", err)
	}
	if f, err := bob.Create("/photos/frombob.txt"); err == nil {
		f.Close()
		t.Error("bob wrote to a share he may only read")
	}
	// And the share he may not use is not a directory he can see.
	if _, err := bob.ReadDir("/alices"); err == nil {
		t.Error("bob listed a share he may not use")
	}
	// Nor can anybody write at the root: the shares are the configuration's.
	if f, err := alice.Create("/newshare.txt"); err == nil {
		f.Close()
		t.Error("a file was created at the root of the tree")
	}
}

// A certificate is a key with an expiry date and a name on it, signed by an
// authority this server trusts — so access is issued and expires elsewhere.
func TestSFTPAcceptsACertificate(t *testing.T) {
	needUsers(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	caSigner, caPub := keyPair(t)
	userKey, _ := keyPair(t)
	_, alicePub := keyPair(t) // alice has a key of her own as well

	caFile := write(t, dir, "ca.pub", caPub+"\n")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
trusted_user_ca_file = %q

user "alice" { authorized_keys = [%q] }

share "photos" {
  image = %q
  allow = ["alice"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(caFile), alicePub, hclPath(img)))

	sign := func(principal string, valid time.Duration) ssh.Signer {
		t.Helper()
		cert := &ssh.Certificate{
			Key:             userKey.PublicKey(),
			CertType:        ssh.UserCert,
			KeyId:           "issued elsewhere",
			ValidPrincipals: []string{principal},
			ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(valid).Unix()),
		}
		if err := cert.SignCert(rand.Reader, caSigner); err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewCertSigner(cert, userKey)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	cl, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(sign("alice", time.Hour)))
	if err != nil {
		t.Fatalf("a certificate naming alice: %v", err)
	}
	if _, err := cl.ReadDir("/photos"); err != nil {
		t.Errorf("listing with a certificate: %v", err)
	}
	done()

	// Expired, and naming somebody else: both refused, and neither is a
	// question this program answers itself -- the certificate says so.
	if _, _, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(sign("alice", -time.Minute))); err == nil {
		t.Error("an expired certificate was accepted")
	}
	if _, _, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(sign("mallory", time.Hour))); err == nil {
		t.Error("a certificate naming somebody else logged alice in")
	}
}
