// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// The premise this program was built on: NFSv3 cannot tell people apart, so a
// share naming who may use it is refused rather than handed to whoever
// connects. A kerberos block changes the premise, and these tests are about
// the exact point where it does.

func TestNFSRefusesARestrictedShareWithoutAKeytab(t *testing.T) {
	p := protocolByName("nfs")
	if p == nil {
		t.Skip("built without NFS")
	}
	sh := &share{name: "private", allow: []string{"alice"}}

	served, refused := p.exports(&config{}, []*share{sh})
	if len(served) != 0 || len(refused) != 1 {
		t.Fatalf("without a keytab: served %d, refused %d", len(served), len(refused))
	}
	// And the refusal says why, in words somebody can act on.
	if why := p.refusal(sh); why == "" {
		t.Error("the refusal said nothing")
	}
}

func TestNFSCarriesARestrictedShareWithOne(t *testing.T) {
	p := protocolByName("nfs")
	if p == nil {
		t.Skip("built without NFS")
	}
	sh := &share{name: "private", allow: []string{"alice"}}
	cfg := &config{Kerberos: &kerberosBlock{Realm: "EXAMPLE.ORG", Keytab: "/etc/krb5.keytab"}}

	served, refused := p.exports(cfg, []*share{sh})
	if len(served) != 1 || len(refused) != 0 {
		t.Fatalf("with a keytab: served %d, refused %d", len(served), len(refused))
	}
}

// ⛔ The realm is half the name. Two realms can each have an alice, and a
// server matching on the short name would hand one realm's files to the other
// realm's person.
func TestAPrincipalFromAnotherRealmIsNobody(t *testing.T) {
	k := &kerberosBlock{Realm: "EXAMPLE.ORG"}
	for _, tc := range []struct {
		principal, want string
	}{
		{"alice@EXAMPLE.ORG", "alice"},
		{"alice@PARTNER.ORG", ""},
		{"alice", ""},
		{"@EXAMPLE.ORG", ""},
		{"", ""},
		{"alice@example.org", ""}, // a realm is case-sensitive on the wire
	} {
		if got := k.userOf(tc.principal); got != tc.want {
			t.Errorf("userOf(%q) = %q, want %q", tc.principal, got, tc.want)
		}
	}
}

func TestTheGateAnswersBothQuestions(t *testing.T) {
	k := &kerberosBlock{Realm: "EXAMPLE.ORG"}
	sh := &share{name: "team", allow: []string{"alice", "bob"}, writers: []string{"alice"}}
	gate := principalGate(k, sh)

	for _, tc := range []struct {
		principal   string
		read, write bool
	}{
		{"alice@EXAMPLE.ORG", true, true},
		{"bob@EXAMPLE.ORG", true, false}, // on the list, not a writer
		{"mallory@EXAMPLE.ORG", false, false},
		{"alice@PARTNER.ORG", false, false}, // the other realm's alice
		// ⛔ An AUTH_UNIX caller has no principal at all. Both answers must be
		// no: this is the direction a misconfiguration has to fail in.
		{"", false, false},
	} {
		r, w := gate(tc.principal)
		if r != tc.read || w != tc.write {
			t.Errorf("%q: read=%v write=%v, want read=%v write=%v",
				tc.principal, r, w, tc.read, tc.write)
		}
	}
}

func TestAReadOnlyShareRefusesEverybodysWrites(t *testing.T) {
	// readOnly is a property of the IMAGE. No principal overrides it, not even
	// one named as a writer.
	k := &kerberosBlock{Realm: "EXAMPLE.ORG"}
	sh := &share{name: "archive", readOnly: true, allow: []string{"alice"}, writers: []string{"alice"}}
	r, w := principalGate(k, sh)("alice@EXAMPLE.ORG")
	if !r {
		t.Error("alice cannot read a share she is allowed on")
	}
	if w {
		t.Error("a read-only share accepted a write")
	}
}

// ⛔ A keytab that cannot be read STOPS the server. Serving on regardless
// would hand a share marked "alice only" to whoever connects, because without
// an authenticator every caller is the same anonymous one.
func TestAnUnreadableKeytabStopsTheNFSServer(t *testing.T) {
	p := protocolByName("nfs")
	if p == nil {
		t.Skip("built without NFS")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s := &server{cfg: &config{Kerberos: &kerberosBlock{
		Realm:  "EXAMPLE.ORG",
		Keytab: filepath.Join(t.TempDir(), "absent.keytab"),
	}}}
	err = serveNFS(s, p, ln)
	if err == nil {
		t.Fatal("the server started without the keytab it was told to use")
	}
	if !strings.Contains(err.Error(), "keytab") {
		t.Errorf("err = %v, want something naming the keytab", err)
	}
}

// And a readable one is accepted, so the refusal above is about the file
// rather than about Kerberos being configured at all.
func TestAReadableKeytabIsAccepted(t *testing.T) {
	p := protocolByName("nfs")
	if p == nil {
		t.Skip("built without NFS")
	}
	dir := t.TempDir()
	kt := keytab.New()
	if err := kt.AddEntry("nfs/localhost", "EXAMPLE.ORG", "a key nobody types",
		time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "krb5.keytab")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: &config{Kerberos: &kerberosBlock{Realm: "EXAMPLE.ORG", Keytab: path}}}
	done := make(chan error, 1)
	go func() { done <- serveNFS(s, p, ln) }()
	// Serve blocks; closing the listener is how it ends. What is being
	// checked is that it got past the keytab and the exports at all.
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case err := <-done:
		if err != nil && strings.Contains(err.Error(), "keytab") {
			t.Errorf("a readable keytab was refused: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("serveNFS did not return after the listener closed")
	}
}
