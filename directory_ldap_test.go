//go:build !noldap && !nosmb && !nowebdav

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// Named for what it is here: an LDAP server to test against, not the
	// package that talks to one.
	ldapd "github.com/glauth/ldap"
	"github.com/go-authn/directory"
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
	url := serveLDAP(t, &ldapFixture{
		// dora has what a Samba-aware directory publishes.
		people: map[string]ldapPerson{
			"dora": {
				dn:       "uid=dora,ou=people,dc=example,dc=org",
				password: "hunter2",
				ntHash:   hex.EncodeToString(directory.NTHashOf("hunter2")),
			},
			// eli has only what LDAP holds by default: a password nobody can
			// read, which is exactly why SMB cannot serve him.
			"eli": {dn: "uid=eli,ou=people,dc=example,dc=org", password: "swordfish"},
		},
		groups: map[string][]string{"engineers": {"dora", "eli"}},
	})
	pw := write(t, dir, "bind.pw", "let me read\n")
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
users "ldap" {
  url                = %q
  base_dn            = "ou=people,dc=example,dc=org"
  group_base_dn      = "ou=groups,dc=example,dc=org"
  bind_dn            = "cn=reader,dc=example,dc=org"
  bind_password_file = %q
}

share "photos" {
  image = %q
  allow = ["@engineers"]
}

share "open" { image = %q }
`, url, hclPath(pw), hclPath(img), hclPath(open)) + serveBlocks()

	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	// The matrix, per person: dora yes everywhere, eli not over SMB.
	for _, want := range []string{"dora", "eli", url, "a password check"} {
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

type ldapPerson struct {
	dn       string
	password string
	ntHash   string
	sshKeys  []string
}

type ldapFixture struct {
	people map[string]ldapPerson
	groups map[string][]string
}

func (f *ldapFixture) Bind(bindDN, password string, _ net.Conn) (ldapd.LDAPResultCode, error) {
	if bindDN == "cn=reader,dc=example,dc=org" && password == "let me read" {
		return ldapd.LDAPResultSuccess, nil
	}
	for _, p := range f.people {
		if p.dn == bindDN && p.password != "" && password == p.password {
			return ldapd.LDAPResultSuccess, nil
		}
	}
	// An empty password binds SUCCESSFULLY in a real directory -- the
	// unauthenticated bind -- and so it does here, so that a server relying on
	// a bind has something real to refuse.
	if password == "" {
		return ldapd.LDAPResultSuccess, nil
	}
	return ldapd.LDAPResultInvalidCredentials, nil
}

func (f *ldapFixture) Search(_ string, req ldapd.SearchRequest, _ net.Conn) (ldapd.ServerSearchResult, error) {
	var entries []*ldapd.Entry
	switch {
	case strings.Contains(req.Filter, "posixAccount"):
		for uid, p := range f.people {
			attrs := []*ldapd.EntryAttribute{{Name: "uid", Values: []string{uid}}}
			if p.ntHash != "" {
				attrs = append(attrs, &ldapd.EntryAttribute{Name: "sambaNTPassword", Values: []string{p.ntHash}})
			}
			if len(p.sshKeys) > 0 {
				attrs = append(attrs, &ldapd.EntryAttribute{Name: "sshPublicKey", Values: p.sshKeys})
			}
			entries = append(entries, &ldapd.Entry{DN: p.dn, Attributes: attrs})
		}
	case strings.Contains(req.Filter, "posixGroup"):
		for name, members := range f.groups {
			if !strings.Contains(req.Filter, "cn="+name+")") {
				continue
			}
			entries = append(entries, &ldapd.Entry{
				DN:         "cn=" + name + ",ou=groups,dc=example,dc=org",
				Attributes: []*ldapd.EntryAttribute{{Name: "memberUid", Values: members}},
			})
		}
	}
	return ldapd.ServerSearchResult{Entries: entries, ResultCode: ldapd.LDAPResultSuccess}, nil
}

func serveLDAP(t *testing.T, f *ldapFixture) string {
	t.Helper()
	s := ldapd.NewServer()
	s.BindFunc("", f)
	s.SearchFunc("", f)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	// Bind first, announce second: the address a client dials is the one the
	// listener got, not the one asked for.
	addr := ln.Addr().String()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing is listening on %s", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return "ldap://" + addr
}
