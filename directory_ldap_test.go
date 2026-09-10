//go:build !noldap && !nosmb && !nowebdav

package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldaptest"
)

// People out of LDAP, and the honest half of what that costs.
//
// The fixture is somebody else's LDAP SERVER (glauth/ldap), not a fake built
// from my reading of the protocol: a fake could only confirm that reading.
//
// What this measures is the thing a site discovers otherwise at a mount: a
// directory that publishes sambaNTPassword can serve SMB, and one that only
// answers a bind cannot -- NTLMv2 needs the password or its MD4, and a client
// never sends either. The server says so in `check` and then behaves that way.
func TestPeopleFromLDAPAndWhatEachCanUse(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	// The directory is go-authn/directory/ldaptest -- glauth/ldap underneath,
	// an independent implementation, read in its own CI by OpenLDAP's client.
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			// dora has what a Samba-aware directory publishes.
			"dora": {Password: "hunter2", NTHash: hex.EncodeToString(directory.NTHashOf("hunter2"))},
			// eli has only what LDAP holds by default: a password nobody can
			// read, which is exactly why SMB cannot serve him.
			"eli": {Password: "swordfish"},
		},
		Groups: map[string][]string{"engineers": {"dora", "eli"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pw := write(t, dir, "bind.pw", d.ReaderPassword+"\n")
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
users "ldap" {
  url                = %q
  base_dn            = %q
  group_base_dn      = %q
  bind_dn            = %q
  bind_password_file = %q
}

share "photos" {
  image = %q
  allow = ["@engineers"]
}

share "open" { image = %q }
`, d.URL, d.PeopleDN, d.GroupsDN, d.ReaderDN, hclPath(pw), hclPath(img), hclPath(open)) + serveBlocks()

	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	// The matrix, per person: dora yes everywhere, eli not over SMB.
	for _, want := range []string{"dora", "eli", d.URL, "a password check"} {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	// dora's NT hash is what SMB needs; eli has only a bind, and the table
	// must say so rather than leaving him to find out at a mount.
	if row := line(out, "dora"); !strings.Contains(row, "an NT hash") {
		t.Errorf("dora's sambaNTPassword did not reach the report: %q", row)
	}
	if row := line(out, "eli"); strings.Count(row, "yes") != 1 {
		t.Errorf("eli can be checked by a bind and nothing else, so exactly one protocol should say yes: %q", row)
	}

	r := start(t, body)
	// dora: her NT hash came out of the directory, so NTLMv2 can be answered.
	fs := mountSMB(t, r, "dora", "hunter2", "photos")
	if got, err := fs.ReadFile("greeting.txt"); err != nil || string(got) != "hello" {
		t.Errorf("dora read %q, %v", got, err)
	}
	// eli: the same share, the same group, and SMB cannot serve him -- said
	// by `check` beforehand, and true here.
	if es := tryMountSMB(t, r, "eli", "swordfish", "photos"); es != nil {
		t.Error("eli mounted over SMB, and LDAP published nothing NTLMv2 can use")
	}
	// And the protocol that CAN check him by a bind lets him in.
	if _, err := webdavGet(r, "eli", "swordfish", "/photos/greeting.txt"); err != nil {
		t.Errorf("eli could not use webdav, which needs only a password check: %v", err)
	}
	// A bind that fails is a refusal, not a way in.
	if _, err := webdavGet(r, "eli", "wrong", "/photos/greeting.txt"); err == nil {
		t.Error("a wrong password was accepted")
	}
	// ⛔ And the empty password, which this directory answers with SUCCESS
	// exactly as a real one does: the refusal has to happen before the bind.
	if _, err := webdavGet(r, "eli", "", "/photos/greeting.txt"); err == nil {
		t.Error("eli was let in with an empty password (the unauthenticated bind)")
	}
	// The passwords really were checked against the DIRECTORY, rather than
	// against something this program held.
	if d.Binds() == 0 {
		t.Error("no bind reached the directory")
	}
}

// line is the first line of out containing s, with its columns intact.
func line(out, s string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, s) {
			return l
		}
	}
	return ""
}
