//go:build !nosftp

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/sshcert"
	"github.com/go-net-health/endpoint"
	"golang.org/x/crypto/ssh"
)

// ssh_domains: a certificate is accepted only where its domain grant says it
// may be used. The certificates are signed here, with go-authn/sshcert
// writing the grant, and by OpenSSH's ssh-keygen; the logins go through the
// server's real SFTP listener, with x/crypto's client and OpenSSH's sftp.

// noGrant stands for a certificate without the extension.
const noGrant = "\x00none"

// grantCert signs a certificate for principal with ca. grant is the raw
// value of the extension -- the JSON array, which x/crypto wraps in an SSH
// string as the specification asks -- or noGrant.
func grantCert(t *testing.T, ca ssh.Signer, principal, grant string, extra map[string]string) ssh.Signer {
	t.Helper()
	userKey, _ := keyPair(t)
	cert := &ssh.Certificate{
		Key:             userKey.PublicKey(),
		Serial:          42,
		CertType:        ssh.UserCert,
		KeyId:           "grant " + grant,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	for k, v := range extra {
		cert.Extensions[k] = v
	}
	if grant != noGrant {
		cert.Extensions[sshcert.DomainGrantExtension] = grant
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, userKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// granted encodes patterns the way an issuer does, with go-authn/sshcert.
func granted(t *testing.T, patterns ...string) string {
	t.Helper()
	v, err := sshcert.EncodeDomainGrant(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// scrape is the server's /metrics body, from its collector.
func scrape(t *testing.T, s *server) string {
	t.Helper()
	var w endpoint.Writer
	s.collect(&w)
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// logsIn reports whether user gets in with signer and can list /photos.
func logsIn(t *testing.T, addr, user string, signer ssh.Signer) error {
	t.Helper()
	cl, done, err := sftpAs(t, addr, user, ssh.PublicKeys(signer))
	if err != nil {
		return err
	}
	defer done()
	_, err = cl.ReadDir("/photos")
	return err
}

// grantServer serves one share to alice, whose certificates come from a
// local authority, with extra configuration above the user block.
func grantServer(t *testing.T, extra string) (*running, ssh.Signer, ssh.Signer) {
	t.Helper()
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	ca, caPub := keyPair(t)
	aliceKey, alicePub := keyPair(t)
	caFile := write(t, dir, "ca.pub", caPub+"\n")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
trusted_user_ca_file = %q
%s

user "alice" { authorized_keys = [%q] }

share "photos" {
  image = %q
  allow = ["alice"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(caFile), extra, alicePub, hclPath(img)))
	return r, ca, aliceKey
}

func TestSFTPDomainGrant(t *testing.T) {
	needUsers(t)
	r, ca, aliceKey := grantServer(t, `ssh_domains = ["files.example.org", "sftp.Example.NET"]`)
	addr := r.addrs["sftp"]

	for _, tc := range []struct {
		name  string
		grant string
		admit bool
		why   string // what the log must say, for a refusal
	}{
		{"granted this host", granted(t, "files.example.org"), true, ""},
		{"granted this host among others", granted(t, "login.example.eu", "files.example.org"), true, ""},
		{"granted the SECOND configured name", granted(t, "sftp.example.net"), true, ""},
		{"granted in another case", granted(t, "FILES.example.ORG"), true, ""},
		{"a wildcard for one label", granted(t, "*.example.org"), true, ""},
		{"a wildcard inside a label", granted(t, "f*s.example.org"), true, ""},
		{"a wildcard for the second name", granted(t, "sftp.*.net"), true, ""},
		{"granted another host", granted(t, "login.example.org"), false, "names none of this host's names"},
		{"a wildcard spans ONE label, not two", granted(t, "*.org"), false, "names none"},
		{"a wildcard one label too deep", granted(t, "*.files.example.org"), false, "names none"},
		{"a wildcard is one or more characters", granted(t, "file*.example.org"), true, ""},
		{"a wildcard is never zero characters", granted(t, "files-*.example.org"), false, "names none"},
		{"an empty grant names no host", "[]", false, "names none"},
		{"no grant at all", noGrant, false, "has no domain grant"},
		{"a grant that is not JSON", "files.example.org", false, "does not parse"},
		{"a grant that is null", "null", false, "does not parse"},
		{"a grant that is not compact", `["files.example.org", "x.org"]`, false, "does not parse"},
		{"a grant with a bad pattern", `["files.example.*"]`, false, "does not parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.out.String())
			err := logsIn(t, addr, "alice", grantCert(t, ca, "alice", tc.grant, nil))
			if (err == nil) != tc.admit {
				t.Fatalf("admitted = %v (%v), want %v", err == nil, err, tc.admit)
			}
			logged := r.out.String()[before:]
			if !tc.admit && (!strings.Contains(logged, "sftp: alice: certificate 42") ||
				!strings.Contains(logged, "refused: ") || !strings.Contains(logged, tc.why)) {
				t.Errorf("the refusal was not logged as %q:\n%s", tc.why, logged)
			}
		})
	}

	// What sshd checked before still holds on this path: the grant is one
	// more condition, not a replacement for the others.
	if err := logsIn(t, addr, "bob", grantCert(t, ca, "alice", granted(t, "files.example.org"), nil)); err == nil {
		t.Error("a granted certificate naming alice logged in as bob")
	}
	stranger, _ := keyPair(t)
	if err := logsIn(t, addr, "alice", grantCert(t, stranger, "alice", granted(t, "files.example.org"), nil)); err == nil {
		t.Error("a granted certificate from an authority nobody trusts was accepted")
	}
	// A key is not a certificate, and carries no grant to read.
	if err := logsIn(t, addr, "alice", aliceKey); err != nil {
		t.Errorf("alice's own key, with ssh_domains set: %v", err)
	}

	m := scrape(t, r.srv)
	for _, want := range []string{
		`fileshare_sftp_domain_grant_total{result="granted"}`,
		`fileshare_sftp_domain_grant_total{result="refused_not_granted"}`,
		`fileshare_sftp_domain_grant_total{result="refused_absent"} 1`,
		`fileshare_sftp_domain_grant_total{result="refused_malformed"} 4`,
		`fileshare_sftp_domain_grant_total{result="accepted_ungranted"} 0`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("/metrics has no %s:\n%s", want, m)
		}
	}
}

// ssh_accept_ungranted: for a server that also trusts an authority that
// never writes a grant. It lets in what has none, and nothing else.
func TestSFTPDomainGrantOptOut(t *testing.T) {
	needUsers(t)
	r, ca, _ := grantServer(t, "ssh_domains = [\"files.example.org\"]\nssh_accept_ungranted = true")
	addr := r.addrs["sftp"]

	if err := logsIn(t, addr, "alice", grantCert(t, ca, "alice", noGrant, nil)); err != nil {
		t.Errorf("no grant, with ssh_accept_ungranted: %v", err)
	}
	if !strings.Contains(r.out.String(), "has no domain grant; accepted, as ssh_accept_ungranted says") {
		t.Errorf("accepting an ungranted certificate was not logged:\n%s", r.out)
	}
	if err := logsIn(t, addr, "alice", grantCert(t, ca, "alice", granted(t, "files.example.org"), nil)); err != nil {
		t.Errorf("granted this host: %v", err)
	}
	// ⛔ A grant that names somebody else's hosts is still a refusal...
	if err := logsIn(t, addr, "alice", grantCert(t, ca, "alice", granted(t, "login.example.org"), nil)); err == nil {
		t.Error("a certificate granted another host was let in by ssh_accept_ungranted")
	}
	// ⛔ ...and so is one that does not parse, ALWAYS: the authority meant
	// to restrict it, and reading it as absent would undo that.
	for _, bad := range []string{"null", "{}", "files.example.org", `["files.example.org",]`} {
		if err := logsIn(t, addr, "alice", grantCert(t, ca, "alice", bad, nil)); err == nil {
			t.Errorf("a malformed grant %s was let in by ssh_accept_ungranted", bad)
		}
	}
	m := scrape(t, r.srv)
	for _, want := range []string{
		`fileshare_sftp_domain_grant_total{result="accepted_ungranted"} 1`,
		`fileshare_sftp_domain_grant_total{result="refused_malformed"} 4`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("/metrics has no %s:\n%s", want, m)
		}
	}
}

// ⛔ Without ssh_domains NOTHING changes: a deployment that has not asked for
// the grant must not start refusing certificates because they carry one --
// not even one it could not parse.
func TestSFTPWithoutSSHDomainsReadsNoGrant(t *testing.T) {
	needUsers(t)
	r, ca, _ := grantServer(t, "")
	for _, grant := range []string{noGrant, granted(t, "login.example.org"), "null", "not json"} {
		if err := logsIn(t, r.addrs["sftp"], "alice", grantCert(t, ca, "alice", grant, nil)); err != nil {
			t.Errorf("grant %q, without ssh_domains: %v", grant, err)
		}
	}
	if strings.Contains(r.out.String(), "domain grant") {
		t.Errorf("a server without ssh_domains spoke of domain grants:\n%s", r.out)
	}
	if m := scrape(t, r.srv); strings.Contains(m, "fileshare_sftp_domain_grant_total") {
		t.Errorf("a server without ssh_domains exposes grant metrics:\n%s", m)
	}
}

// The provider's certificates (oidc.ssh_ca_file, go-authn/bridge's ssh_ca)
// are read the same way: bridge writes the grant for clients configured
// with ssh_domain_grants.
func TestSFTPDomainGrantOnTheProvidersCertificates(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	bridgeCA, bridgePub := keyPair(t)
	caFile := write(t, dir, "bridge-ca.pub", bridgePub+"\n")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
ssh_domains = ["files.example.org"]

oidc {
  issuer      = %q
  audience    = "fileshare"
  ssh_ca_file = %q
}

share "photos" {
  image = %q
  allow = ["oidc:groups:%s"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, p.URL, hclPath(caFile), hclPath(photos), photosGroup))
	groups := map[string]string{bridgeGroups: photosGroup}
	trevor := "trevor@univ-example.fr"
	if err := logsIn(t, r.addrs["sftp"], trevor, grantCert(t, bridgeCA, trevor, granted(t, "*.example.org"), groups)); err != nil {
		t.Errorf("a provider certificate granted this host: %v", err)
	}
	for name, grant := range map[string]string{
		"no grant":            noGrant,
		"another host":        granted(t, "login.example.org"),
		"a grant that is bad": "[1]",
	} {
		if err := logsIn(t, r.addrs["sftp"], trevor, grantCert(t, bridgeCA, trevor, grant, groups)); err == nil {
			t.Errorf("a provider certificate with %s was let in", name)
		}
	}
}

func TestSSHDomainsConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"a pattern for a name", `trusted_user_ca_file = "/ca.pub"
			ssh_domains = ["*.example.org"]`, "is a pattern"},
		{"not a host name", `trusted_user_ca_file = "/ca.pub"
			ssh_domains = ["files..example.org"]`, "is not a host name"},
		{"a trailing dot", `trusted_user_ca_file = "/ca.pub"
			ssh_domains = ["files.example.org."]`, "is not a host name"},
		{"the same name twice", `trusted_user_ca_file = "/ca.pub"
			ssh_domains = ["files.example.org", "FILES.example.org"]`, "listed twice"},
		{"no authority to read a grant from", `ssh_domains = ["files.example.org"]`, "no certificate authority is trusted"},
		{"an opt-out of nothing", `trusted_user_ca_file = "/ca.pub"
			ssh_accept_ungranted = true`, "means nothing without ssh_domains"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := write(t, t.TempDir(), "c.hcl", tc.body+`
share "s" { image = "/i" }
serve "sftp" {}
`)
			_, err := loadConfig([]string{p})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
	// And the two that are meant: by the local authority, and by the provider's.
	for _, body := range []string{
		`trusted_user_ca_file = "/ca.pub"
		 ssh_domains = ["files.example.org", "sftp.example.net"]
		 ssh_accept_ungranted = true`,
		`ssh_domains = ["files.example.org"]
		 oidc {
		   issuer      = "https://idp.example.org"
		   audience    = "fileshare"
		   ssh_ca_file = "/bridge-ca.pub"
		 }`,
	} {
		p := write(t, t.TempDir(), "c.hcl", body+`
share "s" { image = "/i" }
serve "sftp" {}
`)
		if _, err := loadConfig([]string{p}); err != nil {
			t.Errorf("%s:\n%v", body, err)
		}
	}
}

// The judges: certificates OpenSSH's ssh-keygen signed, its grant written by
// -O extension:..., and OpenSSH's own sftp logging in with them.
func TestSFTPDomainGrantWithOpenSSH(t *testing.T) {
	needUsers(t)
	keygen, sftpBin := needOpenSSH(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	ca, _, _ := keyFiles(t, dir, "ca")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
trusted_user_ca_file = %q
ssh_domains = ["files.example.org"]

user "alice" {}

share "photos" {
  image = %q
  allow = ["alice"]
}

serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(ca+".pub"), hclPath(img)))

	// issue has ssh-keygen sign alice's certificate, with the grant if any.
	issue := func(name string, grant string) (key string, signer ssh.Signer) {
		t.Helper()
		key, s, _ := keyFiles(t, dir, name)
		args := []string{"-q", "-s", ca, "-I", name, "-n", "alice", "-V", "-5m:+1h"}
		if grant != noGrant {
			args = append(args, "-O", "extension:"+sshcert.DomainGrantExtension+"="+grant)
		}
		if out, err := exec.Command(keygen, append(args, key+".pub")...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
		return key, certSigner(t, key+"-cert.pub", s)
	}
	// sftp runs OpenSSH's client with a certificate.
	sftp := func(key string) (string, error) {
		t.Helper()
		host, port, _ := strings.Cut(r.addrs["sftp"], ":")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, sftpBin, "-b", "-", "-P", port, "-o", "ConnectTimeout=10",
			"-i", key, "-o", "CertificateFile="+key+"-cert.pub", "-o", "IdentitiesOnly=yes",
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes", "alice@"+host)
		cmd.Stdin = strings.NewReader("ls /photos\n")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	key, signer := issue("granted", `["*.example.org"]`)
	// The certificate ssh-keygen wrote is read as the grant it was given.
	if p, present, err := sshcert.DomainGrant(signer.PublicKey().(*ssh.Certificate)); err != nil || !present ||
		len(p) != 1 || p[0] != "*.example.org" {
		t.Fatalf("ssh-keygen's grant reads as %v %v %v", p, present, err)
	}
	if out, err := sftp(key); err != nil || !strings.Contains(out, "greeting.txt") {
		t.Errorf("OpenSSH sftp, granted *.example.org: %v\n%s", err, out)
	}
	key, _ = issue("elsewhere", `["files.example.com"]`)
	if out, err := sftp(key); err == nil {
		t.Errorf("OpenSSH sftp, granted another host, got in:\n%s", out)
	}
	key, _ = issue("ungranted", noGrant)
	if out, err := sftp(key); err == nil {
		t.Errorf("OpenSSH sftp, with no grant, got in:\n%s", out)
	}
	// x/crypto's client, for the malformed one: the refusal is the server's.
	_, bad := issue("malformed", `[files.example.org]`)
	if err := logsIn(t, r.addrs["sftp"], "alice", bad); err == nil {
		t.Error("a malformed grant ssh-keygen wrote was accepted")
	}
	logs := r.out.String()
	for _, want := range []string{
		`("elsewhere") refused: its domain grant [files.example.com] names none of this host's names [files.example.org]`,
		`("ungranted") refused: it has no domain grant`,
		`("malformed") refused: its domain grant does not parse`,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("the log has no %q:\n%s", want, logs)
		}
	}
}
