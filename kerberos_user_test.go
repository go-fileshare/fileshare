// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"strings"
	"testing"
)

// A person who has a ticket and nothing else is a user: their credential is the
// KDC's word, issued elsewhere, so there is nothing to write down here -- the
// way a certificate from trusted_user_ca_file already is. Found when an SMB
// server for people with a passkey and no password could not be configured.
func TestAKerberosOnlyUserNeedsNoCredentialHere(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	open := image(t, dir, "open.img", nil)
	body := fmt.Sprintf("user \"alice@example.org\" {}\nshare \"open\" { image = %q }\n", hclPath(open)) + kerberosOnlyServe

	// With nothing to take its place a credential-less user is still refused.
	_, err := loadConfig([]string{write(t, dir, "none.hcl", body)})
	if err == nil || !strings.Contains(err.Error(), "no way to authenticate") {
		t.Errorf("a user with no credential and no kerberos block: %v", err)
	}

	kt, _ := ktFile(t, dir, "cifs/fs.example.org")
	withKrb := fmt.Sprintf("kerberos {\n realm = %q\n keytab = %q\n}\n", smbRealm, hclPath(kt)) + body
	if _, err := loadConfig([]string{write(t, dir, "krb.hcl", withKrb)}); err != nil {
		t.Errorf("a user with no credential and a kerberos block: %v", err)
	}
}

// ⛔ A person's name in the KDC may hold an @: authn-bridge names a local account
// login@scope, and the principal is then login@scope@REALM. The realm is the
// part after the LAST @ (a realm is a DNS name and holds none).
func TestAPrincipalWhoseNameHoldsAnAt(t *testing.T) {
	k := &kerberosBlock{Realm: "EXAMPLE.ORG"}
	for _, tc := range []struct {
		principal, want string
	}{
		{"alice@mesocentre.test@EXAMPLE.ORG", "alice@mesocentre.test"},
		{"alice@mesocentre.test@PARTNER.ORG", ""},
		// The realm is not smuggled in through the name.
		{"alice@EXAMPLE.ORG@PARTNER.ORG", ""},
		{"alice@PARTNER.ORG@EXAMPLE.ORG", "alice@PARTNER.ORG"},
		{"@@EXAMPLE.ORG", ""},
		{"alice@", ""},
	} {
		if got := k.userOf(tc.principal); got != tc.want {
			t.Errorf("userOf(%q) = %q, want %q", tc.principal, got, tc.want)
		}
	}
}

// The whole of it over SMB: a user declared with no credential, whose name holds
// an @, mounts with a ticket, with signing required.
func TestSMBKerberosLogsInAScopedNameWithNoCredential(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	kt, ring := ktFile(t, dir, "cifs/fs.example.org")
	private := image(t, dir, "private.img", map[string]string{"/hello.txt": "for a passkey"})
	r := start(t, fmt.Sprintf(`
user "alice@mesocentre.test" {}

kerberos {
  realm  = %q
  keytab = %q
}

share "private" {
  image = %q
  allow = ["alice@mesocentre.test"]
}

%s
`, smbRealm, hclPath(kt), hclPath(private), kerberosOnlyServe))

	fs := mountKrb(t, r, krbInitiator(t, ring, "alice@mesocentre.test", smbRealm, "cifs/fs.example.org"), "private")
	if fs == nil {
		t.Fatal("alice@mesocentre.test, with a ticket, was refused her share")
	}
	if got, err := fs.ReadFile("hello.txt"); err != nil || string(got) != "for a passkey" {
		t.Fatalf("reading: %q, %v", got, err)
	}
	// Nothing was written down here that a password could be checked against.
	if tryMountSMB(t, r, "alice@mesocentre.test", "", "private") != nil {
		t.Error("an empty password logged the credential-less user in")
	}
	if mountKrb(t, r, krbInitiator(t, ring, "mallory@mesocentre.test", smbRealm, "cifs/fs.example.org"), "private") != nil {
		t.Error("a scoped name this server does not know was let in")
	}
}
