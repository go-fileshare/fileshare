//go:build !nosmb

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// forgedAPReq builds a complete GSS Kerberos token for cifs/localhost: a
// ticket issued to tName@tRealm, sealed with the service key of srealm, and an
// authenticator, sealed with the ticket's session key, naming aName@aRealm.
// The client controls the authenticator, never the ticket.
func forgedAPReq(t *testing.T, kt *keytab.Keytab, srealm, tName, tRealm, aName, aRealm string, cusec int) []byte {
	t.Helper()
	now := time.Now().UTC()
	sname := types.PrincipalName{NameType: 2, NameString: []string{"cifs", "localhost"}}
	tkt, sk, err := messages.NewTicket(types.PrincipalName{NameType: 1, NameString: []string{tName}}, tRealm,
		sname, srealm, asn1.BitString{Bytes: []byte{0, 0, 0, 0}, BitLength: 32}, kt, 18, 1,
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := types.NewAuthenticator(aRealm, types.PrincipalName{NameType: 1, NameString: []string{aName}})
	if err != nil {
		t.Fatal(err)
	}
	auth.Cusec = cusec // gokrb5 keeps a process-wide replay cache
	req, err := messages.NewAPReq(tkt, sk, auth)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x01, 0x00), b...), 0)
}

// The person an SMB session belongs to is the one the KDC sealed in the
// ticket. A partner realm's alice holding a genuine cross-realm ticket for
// cifs/ must not become OUR alice by writing our realm in her authenticator
// (gokrb5 v8.4.4 compares the authenticator's name with the ticket's, not its
// realm, and builds its credentials from the authenticator).
func TestSMBIdentityComesFromTheTicketNotTheAuthenticator(t *testing.T) {
	dir := t.TempDir()
	path, kt := ktFile(t, dir, "cifs/localhost")
	// A key for the same service name in ANOTHER realm, in the same keytab: it
	// must not let another realm's ticket in.
	if err := kt.AddEntry("cifs/localhost", "PARTNER.ORG", "partner-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := newSMBAcceptor(&kerberosBlock{Realm: smbRealm, Keytab: path}, func(u string) bool { return u == "alice" })
	if err != nil || a == nil {
		t.Fatalf("acceptor: %v %v", a, err)
	}
	for i, tc := range []struct {
		name                    string
		sRealm, tName, tRealm   string
		aName, aRealm           string
		wantUser, wantPrincipal string // "" = refused
		wantErr                 string
	}{
		{"the control: our alice", smbRealm, "alice", smbRealm, "alice", smbRealm, "alice", "alice@" + smbRealm, ""},
		{"a partner's alice claiming our realm", smbRealm, "alice", "PARTNER.ORG", "alice", smbRealm, "", "", "another client"},
		{"a partner's alice, honest", smbRealm, "alice", "PARTNER.ORG", "alice", "PARTNER.ORG", "", "", "is not in realm"},
		{"another name", smbRealm, "alice", smbRealm, "bob", smbRealm, "", "", "rejected"},
		{"a ticket for the partner realm's cifs key", "PARTNER.ORG", "alice", smbRealm, "alice", smbRealm, "", "", "for realm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := a.Accept(forgedAPReq(t, kt, tc.sRealm, tc.tName, tc.tRealm, tc.aName, tc.aRealm, 2000+i))
			if tc.wantUser == "" {
				if err == nil {
					t.Fatalf("ACCEPTED as %s (%s)", got.User, got.Principal)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("refused for another reason: %v (want %q)", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got.User != tc.wantUser || got.Principal != tc.wantPrincipal {
				t.Errorf("got %q / %q, want %q / %q", got.User, got.Principal, tc.wantUser, tc.wantPrincipal)
			}
		})
	}
}

// A keytab another account can read hands it this server's identity for
// every person of the realm. Group-read stays allowed (root:<group> 0640).
func TestAKeytabOthersCanReadIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	dir := t.TempDir()
	path, _ := ktFile(t, dir, "cifs/localhost")
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true}, {0o640, true}, {0o400, true}, {0o440, true}, // controls
		{0o644, false}, {0o604, false}, {0o660, false}, {0o602, false}, {0o666, false},
	} {
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		a, err := newSMBAcceptor(&kerberosBlock{Realm: smbRealm, Keytab: path}, func(string) bool { return true })
		if tc.ok && (err != nil || a == nil) {
			t.Errorf("mode %v refused: %v", tc.mode, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("mode %v accepted", tc.mode)
		}
		if err := checkKeytabMode(filepath.Clean(path)); (err == nil) != tc.ok {
			t.Errorf("checkKeytabMode(%v) = %v", tc.mode, err)
		}
	}
}
