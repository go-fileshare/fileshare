//go:build !nosftp && !noopenpubkey

package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/discover"
	opkjose "github.com/openpubkey/openpubkey/jose"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"golang.org/x/crypto/ssh"
)

// testOP is an OpenID provider for the openpubkey client: it signs, with the
// test identity provider's key, an ID token whose nonce commits to the
// client's key -- which is what go-authn/bridge does for real.
type testOP struct {
	p        *idp
	clientID string
	user     string
	groups   []string
	// iat is when the ID token says it was issued; zero is now.
	iat time.Time
	// email and emailVerified, when email is set, go into the ID token;
	// emailVerified nil leaves email_verified out.
	email         string
	emailVerified any
}

func (o *testOP) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	nonce, err := cic.Hash()
	if err != nil {
		return nil, err
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: o.p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if !o.iat.IsZero() {
		now = o.iat
	}
	claims := map[string]any{
		"iss": o.p.URL, "aud": o.clientID, "sub": "s-" + o.user, "nonce": string(nonce),
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"preferred_username": o.user, "groups": o.groups,
	}
	if o.email != "" {
		claims["email"] = o.email
		if o.emailVerified != nil {
			claims["email_verified"] = o.emailVerified
		}
	}
	idt, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		return nil, err
	}
	return &simpleoidc.Tokens{IDToken: []byte(idt)}, nil
}

func (o *testOP) PublicKeyByKeyId(context.Context, string) (*discover.PublicKeyRecord, error) {
	return &discover.PublicKeyRecord{PublicKey: &o.p.key.PublicKey, Alg: "RS256", Issuer: o.p.URL}, nil
}
func (o *testOP) PublicKeyByToken(context.Context, []byte) (*discover.PublicKeyRecord, error) {
	return o.PublicKeyByKeyId(context.Background(), "")
}
func (o *testOP) Issuer() string { return o.p.URL }
func (o *testOP) VerifyIDToken(context.Context, []byte, *clientinstance.Claims) error {
	return nil
}

// opksshCert is what `opkssh login` writes: a certificate signed by the
// user's own key, carrying the PK Token -- made here by ssh-keygen.
func opksshCert(t *testing.T, keygen, dir, name string, op *testOP) (string, ssh.Signer) {
	t.Helper()
	key, signer, priv := keyFiles(t, dir, name)
	if out, err := exec.Command(keygen, "-q", "-s", key, "-I", op.user, "-V", "-5m:+1h",
		"-O", "extension:openpubkey-pkt="+pktFor(t, priv, op), key+".pub").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return key, certSigner(t, key+"-cert.pub", signer)
}

func TestSFTPForOpenPubkey(t *testing.T) {
	needUsers(t)
	keygen, sftpBin := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(photos), photosGroup))

	// OpenSSH's sftp, with the certificate opkssh would have written.
	key, _ := opksshCert(t, keygen, dir, "trevor", &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}})
	host, port, _ := strings.Cut(r.addrs["sftp"], ":")
	// A deadline: a client waiting on a server that never answers is a
	// test that hangs the lane, not one that fails.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sftpBin, "-b", "-", "-P", port, "-o", "ConnectTimeout=10", "-i", key, "-o", "CertificateFile="+key+"-cert.pub",
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes", "trevor@univ-example.fr@"+host)
	cmd.Stdin = strings.NewReader("ls /photos\n")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "a.txt") {
		t.Fatalf("OpenSSH sftp with an opkssh certificate: %v\n%s", err, out)
	}

	// ⛔ The refusals, with the x/crypto client.
	for name, c := range map[string]struct {
		op   *testOP
		user string
	}{
		"a token for another client ID":   {&testOP{p: p, clientID: "fileshare", user: "trevor@univ-example.fr", groups: []string{photosGroup}}, "trevor@univ-example.fr"},
		"logging in as somebody else":     {&testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}}, "alice@univ-example.fr"},
		"a token nobody's rule names":     {&testOP{p: p, clientID: "opkssh", user: "mallory@univ-example.fr", groups: []string{"urn:other"}}, "mallory@univ-example.fr"},
		"a token another provider signed": {&testOP{p: newIDP(t), clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}}, "trevor@univ-example.fr"},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "a token another provider signed" {
				// Its iss is the real provider's, its signature is not.
				c.op.p = &idp{Server: p.Server, key: c.op.p.key}
			}
			_, signer := opksshCert(t, keygen, dir, strings.ReplaceAll(name, " ", "-"), c.op)
			if _, done, err := sftpAs(t, r.addrs["sftp"], c.user, ssh.PublicKeys(signer)); err == nil {
				done()
				t.Fatal("admitted")
			}
		})
	}

	// ⛔ A certificate whose key is not the one the token commits to: the
	// PK Token lifted from trevor's certificate into another key's.
	_, trevorSigner := opksshCert(t, keygen, dir, "trevor2", &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}})
	stolen := trevorSigner.PublicKey().(*ssh.Certificate).Extensions["openpubkey-pkt"]
	thief, thiefSigner, _ := keyFiles(t, dir, "thief")
	if out, err := exec.Command(keygen, "-q", "-s", thief, "-I", "x", "-V", "-5m:+1h",
		"-O", "extension:openpubkey-pkt="+stolen, thief+".pub").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(certSigner(t, thief+"-cert.pub", thiefSigner))); err == nil {
		done()
		t.Error("a PK Token lifted into another key's certificate logged in")
	}

	// And trevor's own key and token, in a certificate ANOTHER key signed:
	// not the shape opkssh makes, and refused as such.
	tk, tSigner, tPriv := keyFiles(t, dir, "trevor3")
	other, _, _ := keyFiles(t, dir, "other-signer")
	pkt := pktFor(t, tPriv, &testOP{p: p, clientID: "opkssh", user: "trevor@univ-example.fr", groups: []string{photosGroup}})
	if out, err := exec.Command(keygen, "-q", "-s", other, "-I", "x", "-V", "-5m:+1h",
		"-O", "extension:openpubkey-pkt="+pkt, tk+".pub").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, done, err := sftpAs(t, r.addrs["sftp"], "trevor@univ-example.fr", ssh.PublicKeys(certSigner(t, tk+"-cert.pub", tSigner))); err == nil {
		done()
		t.Error("an OpenPubkey certificate another key signed was accepted")
	}
}

// pktFor is a compact PK Token committing to priv's public key.
func pktFor(t *testing.T, priv ed25519.PrivateKey, op *testOP) string {
	t.Helper()
	c, err := client.New(op, client.WithSigner(crypto.Signer(priv), opkjose.EdDSA))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := c.Auth(context.Background())
	if err != nil {
		t.Fatalf("the openpubkey client: %v", err)
	}
	compact, err := pkt.Compact()
	if err != nil {
		t.Fatal(err)
	}
	return string(compact)
}

// With username_claim = "email", an opkssh login is refused unless the
// provider verified the email (OpenID Connect Core 5.1): unverified, it is
// what the person typed. The control is the same login, verified.
func TestAnOpksshLoginByAnUnverifiedEmailIsRefused(t *testing.T) {
	needUsers(t)
	keygen, _ := needOpenSSH(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

oidc {
  issuer           = %q
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
  username_claim   = "email"
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(photos), photosGroup))
	for i, c := range []struct {
		verified any
		ok       bool
	}{{true, true}, {false, false}, {nil, false}} {
		op := &testOP{p: p, clientID: "opkssh", user: "x", groups: []string{photosGroup},
			email: "eve@univ-example.fr", emailVerified: c.verified}
		_, signer := opksshCert(t, keygen, dir, fmt.Sprintf("eve%d", i), op)
		_, done, err := sftpAs(t, r.addrs["sftp"], "eve@univ-example.fr", ssh.PublicKeys(signer))
		if err == nil {
			done()
		}
		if (err == nil) != c.ok {
			t.Errorf("email_verified %v: logged in = %v, want %v (%v)", c.verified, err == nil, c.ok, err)
		}
	}
}
