//go:build !nonfs

package main

import (
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// NFS sec=krb5 goes through the acceptor serveNFS installs (go-authn/krb5).
// Its identity must be the ticket's too: a partner realm's alice claiming our
// realm in her authenticator is refused, and principalGate then sees the
// ticket's realm. This holds from go-authn/krb5 v0.3.4 (gokrb5#577); with
// v0.3.3 the forged case is accepted as alice@EXAMPLE.ORG.
func TestNFSIdentityComesFromTheTicketNotTheAuthenticator(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("nfs/localhost", "EXAMPLE.ORG", "nfs-key", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	path := writeKeytab(t, t.TempDir(), "nfs.keytab", kt, 0o600)
	read, err := readKeytab(path)
	if err != nil {
		t.Fatal(err)
	}
	a := newNFSAcceptor(read)
	for i, tc := range []struct {
		name          string
		tRealm        string
		aRealm        string
		wantPrincipal string // "" = refused
	}{
		{"the control: our alice", "EXAMPLE.ORG", "EXAMPLE.ORG", "alice@EXAMPLE.ORG"},
		{"the control: a partner's alice, honest", "PARTNER.ORG", "PARTNER.ORG", "alice@PARTNER.ORG"},
		{"a partner's alice claiming our realm", "PARTNER.ORG", "EXAMPLE.ORG", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, err := a.Accept(forgedAPReqFor(t, kt, "nfs", "EXAMPLE.ORG", "alice", tc.tRealm, "alice", tc.aRealm, 3000+i))
			if tc.wantPrincipal == "" {
				if err == nil {
					t.Fatalf("ACCEPTED as %s", ctx.Principal())
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if ctx.Principal() != tc.wantPrincipal {
				t.Errorf("principal %q, want %q", ctx.Principal(), tc.wantPrincipal)
			}
			// And the gate the export applies: only OUR realm's alice is a user.
			k := &kerberosBlock{Realm: "EXAMPLE.ORG"}
			if got, want := k.userOf(ctx.Principal()) == "alice", tc.tRealm == "EXAMPLE.ORG"; got != want {
				t.Errorf("userOf(%s) maps to alice = %v, want %v", ctx.Principal(), got, want)
			}
		})
	}
}
