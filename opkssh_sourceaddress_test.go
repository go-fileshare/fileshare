//go:build !nosftp && !noopenpubkey

package main

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

// opkServerOn serves one share to an OpenID provider's group, with opkssh
// logins accepted, on listen.
func opkServerOn(t *testing.T, p *idp, listen string) *running {
	t.Helper()
	photos := image(t, t.TempDir(), "photos.img", map[string]string{"/a.txt": "a"})
	return start(t, fmt.Sprintf(`
name = "TESTFS"

oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}

serve "sftp" { addr = %q }
`, p.URL, hclPath(photos), photosGroup, listen))
}

// An opkssh certificate is signed by the user's own key, so it reaches
// fileshare through sshd's CertificateFor -- the path on which
// go-filesystems/sftp v0.5.1 accepts and enforces source-address. ssh-keygen
// pins it here with its own -O source-address, the way `opkssh login` would
// be asked to; the logins go through the server's real SFTP listener.
func TestOpksshCertificateSourceAddress(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	op := &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}}
	v4 := opkServerOn(t, p, "127.0.0.1:0")
	n := 0
	login := func(t *testing.T, r *running, pin, from string) error {
		t.Helper()
		n++
		var opts []string
		if pin != "" {
			opts = append(opts, "source-address="+pin)
		}
		_, signer := opksshCert(t, keygen, dir, fmt.Sprintf("trevor-%d", n), op, opts...)
		if pin != "" {
			if got := signer.PublicKey().(*ssh.Certificate).CriticalOptions["source-address"]; got != pin {
				t.Fatalf("ssh-keygen's certificate carries source-address %q, not %q", got, pin)
			}
		}
		return logsInFrom(t, from, r.addrs["sftp"], op.user, signer)
	}
	check := func(t *testing.T, r *running, cases []pinCase) {
		t.Helper()
		for _, tc := range cases {
			if err := login(t, r, tc.pin, tc.from); (err == nil) != tc.admit {
				t.Errorf("opkssh, pinned to %q, from %s: admitted = %v (%v), want %v", tc.pin, tc.from, err == nil, err, tc.admit)
			}
		}
	}

	t.Run("from 127.0.0.1", func(t *testing.T) {
		check(t, v4, []pinCase{
			{pin: "", from: "127.0.0.1", admit: true}, // the witness
			{pin: "127.0.0.1/32", from: "127.0.0.1", admit: true},
			{pin: "192.0.2.1/32", from: "127.0.0.1", admit: false},
			{pin: "192.0.2.1/32,127.0.0.1/32", from: "127.0.0.1", admit: true},
		})
	})
	t.Run("from 127.0.0.2", func(t *testing.T) {
		needSecondIPv4Loopback(t)
		check(t, v4, []pinCase{
			{pin: "", from: "127.0.0.2", admit: true}, // the witness
			{pin: "127.0.0.1/32", from: "127.0.0.2", admit: false},
			{pin: "127.0.0.0/8", from: "127.0.0.2", admit: true},
		})
	})
	t.Run("from ::1", func(t *testing.T) {
		needAddress(t, "::1", "the host has no IPv6 loopback")
		v6 := opkServerOn(t, p, "[::1]:0")
		check(t, v6, []pinCase{
			{pin: "", from: "::1", admit: true}, // the witness
			{pin: "::1/128", from: "::1", admit: true},
			{pin: "127.0.0.1/32", from: "::1", admit: false},
		})
		check(t, v4, []pinCase{
			{pin: "::1/128", from: "127.0.0.1", admit: false},
		})
	})
}
