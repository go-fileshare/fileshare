//go:build !nosmb

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/go-authn/directory"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	krbcreds "github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// SMB with Kerberos, from the kerberos block NFS already reads.
//
// The judge is go-smb2's Krb5Initiator: a client this project did not write,
// building a real AP-REQ and reading the AP-REP. There is no KDC; the tickets are
// minted here under the keytab the server loads, which is all a KDC contributes
// to what the SERVER does. (go-filesystems/smb proves the protocol, signing in
// every dialect; these prove what this program decides: who is let in, and as
// whom.)

const smbRealm = "EXAMPLE.ORG"

// ktFile writes a keytab holding one entry per principal and returns its path
// with the keytab, for minting tickets.
func ktFile(t *testing.T, dir string, spns ...string) (string, *keytab.Keytab) {
	t.Helper()
	kt := keytab.New()
	for _, spn := range spns {
		if err := kt.AddEntry(spn, smbRealm, "secret-of-"+spn, time.Now(), 1, 18); err != nil {
			t.Fatal(err)
		}
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "krb5.keytab")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, kt
}

// krbInitiator is a client holding one ticket: who, from realm, for spn, minted
// under kt.
func krbInitiator(t *testing.T, kt *keytab.Keytab, who, realm, spn string) *smb2.Krb5Initiator {
	t.Helper()
	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, who)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)
	tkt, key, err := messages.NewTicket(cname, realm, sname, smbRealm, types.NewKrbFlags(), kt, 18, 1, start, start, end, end)
	if err != nil {
		t.Fatal(err)
	}
	other := keytab.New()
	if err := other.AddEntry("krbtgt/"+realm, realm, "tgs", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	tgt, tgtKey, err := messages.NewTicket(cname, realm, types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm),
		realm, types.NewKrbFlags(), other, 18, 1, start, start, end, end)
	if err != nil {
		t.Fatal(err)
	}
	cc := &krbcreds.CCache{Version: 4}
	cc.DefaultPrincipal.Realm, cc.DefaultPrincipal.PrincipalName = realm, cname
	for _, e := range []struct {
		tk  messages.Ticket
		key types.EncryptionKey
		rlm string
	}{{tgt, tgtKey, realm}, {tkt, key, smbRealm}} {
		b, err := e.tk.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		c := &krbcreds.Credential{Key: e.key, AuthTime: start, StartTime: start, EndTime: end, RenewTill: end, Ticket: b}
		c.Client.Realm, c.Client.PrincipalName = realm, cname
		c.Server.Realm, c.Server.PrincipalName = e.rlm, e.tk.SName
		cc.Credentials = append(cc.Credentials, c)
	}
	cfg, err := krbconfig.NewFromString("[libdefaults]\n default_realm = " + realm + "\n")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.NewFromCCache(cc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &smb2.Krb5Initiator{Client: cl, TargetSPN: spn}
}

// mountKrb mounts share as in, or returns nil when the server refused anywhere
// along the way.
func mountKrb(t *testing.T, r *running, in smb2.Initiator, share string) *smb2.Share {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	d := &smb2.Dialer{Initiator: in, Negotiator: smb2.Negotiator{RequireMessageSigning: true}}
	s, err := d.Dial(ctx, r.addrs["smb"])
	if err != nil {
		cancel()
		return nil
	}
	fs, err := s.Mount(share)
	if err != nil {
		s.Logoff()
		cancel()
		return nil
	}
	t.Cleanup(func() { fs.Umount(); s.Logoff(); cancel() })
	return fs
}

// said waits for the server to have written want: the protocols announce from
// their own goroutines, and a listener that is bound is not yet one that has
// said what it will do.
func said(t *testing.T, r *running, want string) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(r.out.String(), want) {
			return
		}
	}
	t.Errorf("the server did not say %q:\n%s", want, r.out.String())
}

// smbKrbConfig is a server with a private share (alice only), an open one, the
// three people of people(), and the kerberos block over the keytab at kt.
func smbKrbConfig(t *testing.T, dir, kt, serve string) string {
	t.Helper()
	private := image(t, dir, "private.img", map[string]string{"/hello.txt": "hello from a ticket"})
	open := image(t, dir, "open.img", map[string]string{"/open.txt": "for everyone"})
	return people(t, dir) + fmt.Sprintf(`
kerberos {
  realm  = %q
  keytab = %q
}

share "private" {
  image = %q
  allow = ["alice"]
}

share "open" { image = %q }

%s
`, smbRealm, hclPath(kt), hclPath(private), hclPath(open), serve)
}

const bothServe = `serve "smb" { addr = "127.0.0.1:0" }`
const kerberosOnlyServe = `serve "smb" {
  addr = "127.0.0.1:0"
  ntlm = false
}`

// A ticket for cifs/<host> logs a known person in, as that person: the share
// that names alice lets alice in and works, with signing required. NTLM goes on
// working beside it.
func TestSMBKerberosLogsAKnownPersonIn(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	kt, ring := ktFile(t, dir, "cifs/fs.example.org", "nfs/fs.example.org")
	r := start(t, smbKrbConfig(t, dir, kt, bothServe))
	said(t, r, "smb: Kerberos for EXAMPLE.ORG (cifs/fs.example.org)")

	fs := mountKrb(t, r, krbInitiator(t, ring, "alice", smbRealm, "cifs/fs.example.org"), "private")
	if fs == nil {
		t.Fatal("alice, with a ticket, was refused her own share")
	}
	got, err := fs.ReadFile("hello.txt")
	if err != nil || string(got) != "hello from a ticket" {
		t.Fatalf("reading: %q, %v", got, err)
	}
	if err := fs.WriteFile("from-alice.txt", []byte("signed"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Beside it, the password still works.
	if mountSMB(t, r, "alice", "hunter2", "private") == nil {
		t.Fatal("NTLM stopped working when Kerberos was added")
	}
}

// The ticket proves who somebody is to the KDC, and the share decides what
// they may do: bob is a known person and is let in, to the share that is open
// and not to the one that names alice -- exactly as with a password.
func TestSMBKerberosHonoursTheSharesAccessLists(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	kt, ring := ktFile(t, dir, "cifs/fs.example.org")
	r := start(t, smbKrbConfig(t, dir, kt, bothServe))

	if mountKrb(t, r, krbInitiator(t, ring, "bob", smbRealm, "cifs/fs.example.org"), "open") == nil {
		t.Error("bob, with a ticket, could not mount the share that is open to everyone")
	}
	if mountKrb(t, r, krbInitiator(t, ring, "bob", smbRealm, "cifs/fs.example.org"), "private") != nil {
		t.Error("bob, with a ticket, mounted a share that names only alice")
	}
}

// ⛔ Unknown is not allowed. Each of these has a perfectly good ticket for this
// server's own key, and is refused anyway.
func TestSMBKerberosRefusesWhoeverItShould(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	kt, ring := ktFile(t, dir, "cifs/fs.example.org", "nfs/fs.example.org")
	r := start(t, smbKrbConfig(t, dir, kt, bothServe))

	for _, tc := range []struct {
		name, who, realm, spn string
	}{
		// The KDC knows her; this configuration does not. A share open to everyone
		// who authenticates must not be open to everybody the realm holds, which NTLM
		// never allowed (it checks the name against the people it has).
		{"a principal of the realm this server does not know", "mallory", smbRealm, "cifs/fs.example.org"},
		// Another realm's alice is not ours: the realm is half the name.
		{"another realm's alice", "alice", "PARTNER.ORG", "cifs/fs.example.org"},
		// A ticket for the NFS service, which the same keytab can decrypt, is not
		// a ticket for SMB.
		{"a ticket for nfs", "alice", smbRealm, "nfs/fs.example.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if fs := mountKrb(t, r, krbInitiator(t, ring, tc.who, tc.realm, tc.spn), "open"); fs != nil {
				t.Errorf("%s was let in", tc.name)
			}
		})
	}
}

// ntlm = false: the server offers Kerberos alone, and a password does nothing.
func TestSMBKerberosOnly(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	kt, ring := ktFile(t, dir, "cifs/fs.example.org")
	r := start(t, smbKrbConfig(t, dir, kt, kerberosOnlyServe))

	if tryMountSMB(t, r, "alice", "hunter2", "open") != nil {
		t.Error("a password worked on a server with ntlm = false")
	}
	if mountKrb(t, r, krbInitiator(t, ring, "alice", smbRealm, "cifs/fs.example.org"), "private") == nil {
		t.Error("a ticket did not work on a Kerberos-only server")
	}
}

// ⛔ Refused at load, not at the first client: ntlm = false with nothing to take
// NTLM's place is a server nobody can log in to; and ntlm is an SMB word.
func TestSMBNTLMOffIsRefusedAtLoadWithoutKerberos(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	open := image(t, dir, "open.img", nil)
	body := people(t, dir) + fmt.Sprintf("share \"open\" { image = %q }\n", hclPath(open))
	path := write(t, dir, "a.hcl", body+kerberosOnlyServe)
	_, err := loadConfig([]string{path})
	if err == nil || !strings.Contains(err.Error(), "ntlm = false") || !strings.Contains(err.Error(), "no kerberos block") {
		t.Errorf("ntlm = false without a kerberos block: %v", err)
	}

	path = write(t, dir, "b.hcl", body+"serve \"webdav\" {\n addr = \"127.0.0.1:0\"\n ntlm = false\n}\n")
	if _, err := loadConfig([]string{path}); err == nil || !strings.Contains(err.Error(), "for SMB") {
		t.Errorf("ntlm on webdav: %v", err)
	}
}

// A keytab with no cifs/ principal leaves SMB as it was, and says so; with
// ntlm = false it stops the server, which could otherwise be logged in to by
// nobody. A keytab that cannot be read stops it either way.
func TestSMBKerberosAndAKeytabWithoutCifs(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	nfsOnly, _ := ktFile(t, dir, "nfs/fs.example.org")

	r := start(t, smbKrbConfig(t, dir, nfsOnly, bothServe))
	said(t, r, "holds no cifs/<host>@EXAMPLE.ORG principal, so SMB stays NTLM-only")
	if mountSMB(t, r, "alice", "hunter2", "private") == nil {
		t.Error("SMB stopped working for a deployment that never asked for Kerberos over it")
	}

	for name, tc := range map[string]struct{ keytab, serve, want string }{
		"ntlm off, no cifs key": {nfsOnly, kerberosOnlyServe, "holds no cifs/<host>@EXAMPLE.ORG principal"},
		"no such keytab":        {filepath.Join(dir, "absent.keytab"), bothServe, "kerberos keytab"},
	} {
		t.Run(name, func(t *testing.T) {
			cfgText := smbKrbConfig(t, t.TempDir(), tc.keytab, tc.serve)
			cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", cfgText)})
			if err != nil {
				t.Fatal(err)
			}
			srv, err := open(cfg, &safeBuffer{})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			err = serveSMB(srv, protocolByName("smb"), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("serving: %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// cifsPrincipals reads the realm's cifs/<host> entries and nothing else.
func TestCifsPrincipalsAreTheRealmsCifsEntries(t *testing.T) {
	kt := keytab.New()
	for _, e := range []struct{ spn, realm string }{
		{"cifs/b.example.org", smbRealm}, {"cifs/a.example.org", smbRealm}, {"cifs/a.example.org", smbRealm},
		{"nfs/a.example.org", smbRealm}, {"cifs/x.partner.org", "PARTNER.ORG"}, {"cifs", smbRealm},
	} {
		if err := kt.AddEntry(e.spn, e.realm, "x", time.Now(), 1, 18); err != nil {
			t.Fatal(err)
		}
	}
	got := cifsPrincipals(kt, smbRealm)
	if strings.Join(got, ",") != "cifs/a.example.org,cifs/b.example.org" {
		t.Errorf("got %v", got)
	}
}

// With a kerberos block a person whose directory can only verify a password (no
// password, no NT hash: a bind, say) can still be served over SMB, because a
// ticket needs nothing the directory holds; without one they cannot.
func TestSMBCanServeAPersonWithoutAnNTKeyWhenKerberosIsOn(t *testing.T) {
	bind := directory.NewIdentity("eli", directory.WithVerifier(func(string) error { return nil }))
	if canServeUser("smb", bind, nil) || canServeUser("smb", bind, &config{}) {
		t.Error("a verifier-only person can use SMB with no kerberos block")
	}
	if !canServeUser("smb", bind, &config{Kerberos: &kerberosBlock{Realm: smbRealm}}) {
		t.Error("a verifier-only person cannot use SMB though a kerberos block lets a ticket stand in")
	}
}
