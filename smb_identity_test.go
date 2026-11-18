//go:build !nosmb

package main

import (
	"strings"
	"testing"
	"time"
)

// The person an SMB session belongs to is the one the KDC sealed in the
// ticket. A partner realm's alice holding a genuine cross-realm ticket for
// cifs/ must not become OUR alice by writing our realm in her authenticator.
// gokrb5 v8.4.4 compares the authenticator's name with the ticket's, not its
// realm, and builds its credentials from the authenticator (gokrb5#577).
func TestSMBIdentityComesFromTheTicketNotTheAuthenticator(t *testing.T) {
	dir := t.TempDir()
	_, kt := ktFile(t, dir, "cifs/localhost")
	// A key for the same service name in ANOTHER realm, in the same keytab: it
	// must not let another realm's ticket in.
	if err := kt.AddEntry("cifs/localhost", "PARTNER.ORG", "partner-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	path := writeKeytab(t, dir, "both.keytab", kt, 0o600)
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
			got, _, err := a.Accept(forgedAPReqFor(t, kt, "cifs", tc.sRealm, tc.tName, tc.tRealm, tc.aName, tc.aRealm, 2000+i))
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
