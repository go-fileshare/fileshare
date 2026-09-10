//go:build !nosmb

package main

import (
	"fmt"
	"strings"
	"testing"
)

// A group is a name for several people, and every rule takes it.
//
// The point is not the expansion -- that is go-authn/directory's, and tested
// there -- but that the SERVER expands it in both places a person is named:
// who may connect, and who may write. A group honoured in one and not the
// other is the shape of an access defect nobody notices until somebody writes
// where they should not.
func TestAGroupStandsForItsMembersEverywhere(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	// An unrestricted share as well, because NFS cannot authenticate and
	// refuses a configuration where it would carry nothing at all.
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	r := start(t, people(t, dir)+fmt.Sprintf(`
group "staff"  { members = ["alice", "bob"] }
group "owners" { members = ["alice"] }

share "photos" {
  image   = %q
  allow   = ["@staff"]
  writers = ["@owners"]
}

share "open" { image = %q }
`, hclPath(img), hclPath(open))+serveBlocks())

	// bob is in staff and not in owners: he reads and does not write.
	bs := mountSMB(t, r, "bob", "swordfish", "photos")
	if got, err := bs.ReadFile("greeting.txt"); err != nil || string(got) != "hello" {
		t.Errorf("bob is in @staff and read %q, %v", got, err)
	}
	if err := bs.WriteFile("frombob.txt", []byte("nope"), 0o644); err == nil {
		t.Error("bob wrote to a share only @owners may write")
	}

	// alice is in both.
	as := mountSMB(t, r, "alice", "hunter2", "photos")
	if err := as.WriteFile("fromalice.txt", []byte("mine"), 0o644); err != nil {
		t.Errorf("alice is in @owners and could not write: %v", err)
	}

	// carol is in neither, and the share is not hers to see.
	cs := tryMountSMB(t, r, "carol", "correct horse", "photos")
	if cs == nil {
		return
	}
	if _, err := cs.ReadFile("greeting.txt"); err == nil {
		t.Error("carol is in no group named by the share and read it anyway")
	}
}

// A group that names somebody the directories have never heard of is a
// configuration error, not an empty set: it is nearly always a typo, and a
// server that starts anyway serves a share to fewer people than its author
// believes -- or, with the mistake in `writers`, to more.
func TestAGroupNamingAStrangerIsRefused(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := people(t, dir) + fmt.Sprintf(`
group "staff" { members = ["alice", "trevor"] }

share "photos" {
  image = %q
  allow = ["@staff"]
}

share "open" { image = %q }
`, hclPath(img), hclPath(open)) + serveBlocks()
	path := write(t, dir, "c.hcl", body)
	out, err := execute(t, "check", path)
	if err == nil {
		t.Fatalf("check accepted a group naming somebody nobody knows:\n%s", out)
	}
	if !strings.Contains(err.Error(), "trevor") {
		t.Errorf("the refusal does not name trevor: %v", err)
	}
}

// The report says, per person, which protocols their credentials can answer.
func TestCheckSaysWhoCanUseWhat(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	body := people(t, dir) + fmt.Sprintf(`
share "photos" { image = %q }
`, hclPath(img)) + serveBlocks()
	path := write(t, dir, "c.hcl", body)
	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	for _, want := range []string{
		"USER", "AUTHENTICATES WITH", "SMB",
		"alice", "bob", "carol",
		"a password from", // and the file it was read from
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password")
	}
}

// A `users` block described wrongly is refused before anything connects: an
// unreachable directory and a mistyped one produce the same symptom -- a
// server that will not start -- and only one of them is fixed by looking at
// the network.
func TestUsersBlocksThatCannotBeWhatTheySay(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{
			"a kind nobody has",
			`users "kerberos" { driver = "sqlite" }`,
			"there is no \"kerberos\" directory here",
		},
		{
			"ldap fields in a sql block",
			`users "sql" {
			   driver   = "sqlite"
			   dsn_file = "/d"
			   url      = "ldap://h"
			   bind_dn  = "cn=r"
			 }`,
			"belongs to an ldap block",
		},
		{
			"sql fields in an ldap block",
			`users "ldap" {
			   url     = "ldap://h"
			   base_dn = "dc=x"
			   driver  = "sqlite"
			 }`,
			"belongs to a sql block",
		},
		{
			// The one that matters: a URL is printed by this program, by the
			// LDAP package's errors, and by whatever collects the output.
			"a bind password in the url",
			`users "ldap" {
			   url     = "ldap://cn=reader:hunter2@h"
			   base_dn = "dc=x"
			 }`,
			"credentials in its url",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			body := tc.block + fmt.Sprintf("\nshare \"s\" { image = %q }\n", "/i") + serveBlocks()
			_, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Error("the refusal printed the password it was refusing")
			}
		})
	}
}
