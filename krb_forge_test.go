package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// forgedAPReqFor builds a complete GSS Kerberos token for <service>/localhost:
// a ticket issued to tName@tRealm, sealed with the service key of srealm, and
// an authenticator, sealed with the ticket's session key, naming
// aName@aRealm. The client controls the authenticator, never the ticket.
func forgedAPReqFor(t *testing.T, kt *keytab.Keytab, service, srealm, tName, tRealm, aName, aRealm string, cusec int) []byte {
	t.Helper()
	now := time.Now().UTC()
	sname := types.PrincipalName{NameType: 2, NameString: []string{service, "localhost"}}
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

// writeKeytab writes kt at dir/name with mode and returns the path.
func writeKeytab(t *testing.T, dir, name string, kt *keytab.Keytab, mode os.FileMode) string {
	t.Helper()
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// A keytab another account can read hands it this server's identity for
// every person of the realm. Group-read stays allowed (root:<group> 0640).
// readKeytab is the one reader both SMB and NFS go through.
func TestAKeytabOthersCanReadIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	kt := keytab.New()
	if err := kt.AddEntry("cifs/localhost", "EXAMPLE.ORG", "k", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o600, true}, {0o640, true}, {0o400, true}, {0o440, true}, // controls
		{0o644, false}, {0o604, false}, {0o660, false}, {0o602, false}, {0o666, false},
	} {
		p := writeKeytab(t, dir, "kt-"+tc.mode.String(), kt, tc.mode)
		if _, err := readKeytab(p); (err == nil) != tc.ok {
			t.Errorf("mode %v: err = %v, want ok=%v", tc.mode, err, tc.ok)
		}
	}
	// Not a regular file, and an empty one: refused too.
	if _, err := readKeytab(dir); err == nil {
		t.Error("a directory was read as a keytab")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeytab(empty); err == nil {
		t.Error("an empty keytab was accepted")
	}
}
