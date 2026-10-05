//go:build !nowebdav

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A token, over the one protocol that can carry one.
//
// ⛔ The point of the test is the pair: WebDAV lets a token in, and a person
// who exists only as a token cannot use SMB or SFTP -- not because this
// program refuses them there, but because those protocols have nowhere to put
// an Authorization header. `check` says it, and this shows it.
func TestATokenOpensWebDAVAndNothingElse(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := people(t, dir) + fmt.Sprintf(`
oidc {
  issuer   = %q
  audience = "fileshare"
}

share "photos" {
  image   = %q
  allow   = ["alice", "bob"]
  writers = ["bob"]
}

share "open" { image = %q }
`, p.URL, hclPath(img), hclPath(open)) + serveBlocks()
	r := start(t, body)

	// alice is named in this file AND in the token: both halves agree.
	token := p.sign(t, map[string]any{
		"iss": p.URL, "sub": "u-1", "aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "alice",
	})
	if got, err := webdavGetToken(r, token, "/photos/greeting.txt"); err != nil || string(got) != "hello" {
		t.Errorf("a token was refused over webdav: %v (%q)", err, got)
	}

	// ⛔ A token this server cannot check is not a way in: another issuer,
	// another audience, and one that expired.
	other := newIDP(t)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"another issuer", other.sign(t, map[string]any{
			"iss": other.URL, "sub": "u-1", "aud": "fileshare",
			"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "alice",
		})},
		{"another audience", p.sign(t, map[string]any{
			"iss": p.URL, "sub": "u-1", "aud": "somebody-else",
			"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "alice",
		})},
		{"expired", p.sign(t, map[string]any{
			"iss": p.URL, "sub": "u-1", "aud": "fileshare",
			"exp": time.Now().Add(-time.Hour).Unix(), "preferred_username": "alice",
		})},
		{"not a token", "not-a-token"},
	} {
		if _, err := webdavGetToken(r, tc.token, "/photos/greeting.txt"); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}

	// ⛔ A valid token for somebody this server has never heard of. The
	// provider vouches for them; that is not the same as this server having a
	// share for them, and the safe reading of "I do not know you" is not
	// "you are allowed".
	stranger := p.sign(t, map[string]any{
		"iss": p.URL, "sub": "u-2", "aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "trevor",
	})
	if _, err := webdavGetToken(r, stranger, "/open/b.txt"); err == nil {
		t.Error("a valid token for somebody no source here knows was accepted")
	}

	// The share's own rules still decide: alice may read this one and bob is
	// the only writer, token or no token. A token says WHO somebody is; it
	// does not say what they may do here.
	if err := webdavPutToken(r, token, "/photos/new.txt", "mine"); err == nil {
		t.Error("a token got past the share's write rules")
	}

	// And the challenge says what this server accepts: both, here.
	res, err := http.Get("http://" + r.addrs["webdav"] + "/photos/greeting.txt")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	challenges := strings.Join(res.Header.Values("WWW-Authenticate"), " | ")
	if !strings.Contains(challenges, "Bearer") || !strings.Contains(challenges, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want both a Bearer and a Basic challenge", challenges)
	}
}

// trust_all is the other shape: the provider IS the directory, and it is
// spelled out because it is the difference between "these people" and
// "everybody that provider has".
func TestTrustAllAcceptsAnybodyTheProviderVouchesFor(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
oidc {
  issuer    = %q
  audience  = "fileshare"
  trust_all = true
}

share "open" { image = %q }
`, p.URL, hclPath(img)) + serveBlocks()
	r := start(t, body)

	token := p.sign(t, map[string]any{
		"iss": p.URL, "sub": "u-2", "aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "trevor",
	})
	if got, err := webdavGetToken(r, token, "/open/b.txt"); err != nil || string(got) != "b" {
		t.Errorf("trust_all refused somebody the provider vouched for: %v (%q)", err, got)
	}
	// A forged token is still a forged token.
	other := newIDP(t)
	forged := other.sign(t, map[string]any{
		"iss": p.URL, "sub": "u-2", "aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "trevor",
	})
	if _, err := webdavGetToken(r, forged, "/open/b.txt"); err == nil {
		t.Error("trust_all accepted a token the provider did not sign")
	}
}

// A configuration naming a provider with nowhere to carry a token does not do
// what it says, and is refused rather than started.
func TestOIDCWithoutWebDAVIsRefused(t *testing.T) {
	needUsers(t)
	var withoutWebdav *protocol
	for _, pr := range protocols {
		if pr.name != "webdav" && pr.authenticates {
			withoutWebdav = pr
			break
		}
	}
	if withoutWebdav == nil {
		t.Skip("this binary has no authenticating protocol other than webdav")
	}
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
oidc {
  issuer   = "https://login.example.test"
  audience = "fileshare"
}

share "open" { image = %q }

serve %q {}
`, hclPath(img), withoutWebdav.name)
	_, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err == nil || !strings.Contains(err.Error(), "neither webdav nor a federated sftp") {
		t.Errorf("error = %v", err)
	}
	// SFTP carries the provider's word too, once the oidc block says how:
	// its SSH CA, or opkssh.
	if protocolByName("sftp") != nil {
		ca := write(t, dir, "ca.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGzsRUMGgSpTy1SW6sfnPvRbiB5W8kL7LZ7mnxHgYgJv ca\n")
		sftpOnly := fmt.Sprintf(`
oidc {
  issuer      = "https://login.example.test"
  audience    = "fileshare"
  ssh_ca_file = %q
}

share "open" { image = %q }

serve "sftp" {}
`, hclPath(ca), hclPath(img))
		if _, err := loadConfig([]string{write(t, dir, "sftp.hcl", sftpOnly)}); err != nil {
			t.Errorf("an oidc block for sftp alone was refused: %v", err)
		}
	}
	// And a block that cannot verify anything is refused too.
	for _, missing := range []string{"issuer", "audience"} {
		body := fmt.Sprintf(`
oidc {
  %s = "x"
}

share "open" { image = %q }
`, map[string]string{"issuer": "audience", "audience": "issuer"}[missing], hclPath(img)) + serveBlocks()
		if _, err := loadConfig([]string{write(t, dir, missing+".hcl", body)}); err == nil {
			t.Errorf("an oidc block with no %s was accepted", missing)
		}
	}
}

// check says which protocols a token can be carried by, which is one.
func TestCheckSaysWhereATokenWorks(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := people(t, dir) + fmt.Sprintf(`
oidc {
  issuer   = %q
  audience = "fileshare"
}

share "open" { image = %q }
`, p.URL, hclPath(img)) + serveBlocks()
	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	contains := []string{
		"accepted over webdav and nowhere else",
		"must also be named here",
		p.URL,
	}
	for _, want := range contains {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	// With no domains, a provider's bare name is matched against this file's
	// names, and check says so; with domains it cannot be, and check is quiet.
	if !strings.Contains(out, "no domains: a token or provider certificate") {
		t.Errorf("check did not warn that a provider name reaches a local account:\n%s", out)
	}
	scoped := strings.Replace(body, `audience = "fileshare"`, `audience = "fileshare"
  domains  = ["univ-example.fr"]`, 1)
	out, err = execute(t, "check", write(t, dir, "d.hcl", scoped))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if strings.Contains(out, "no domains:") {
		t.Errorf("check warned about domains when they are set:\n%s", out)
	}
}

// sign mints a token with pyjwt: an implementation nobody in this repository
// wrote, so a token that is accepted here is one a provider could really send.
func (p *idp) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	python := needPyJWT(t)
	pem := privatePEM(t, p.key)
	in, err := json.Marshal(map[string]any{"key": pem, "claims": claims})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `
import sys, json, jwt
r = json.load(sys.stdin)
print(jwt.encode(r["claims"], r["key"], algorithm="RS256", headers={"kid": "k1"}))
`)
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("pyjwt: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("pyjwt: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func needPyJWT(t *testing.T) string {
	t.Helper()
	for _, python := range []string{"python3", "python"} {
		p, err := exec.LookPath(python)
		if err != nil {
			continue
		}
		if err := exec.Command(p, "-c", "import jwt, cryptography").Run(); err == nil {
			return p
		}
	}
	if os.Getenv("FILESHARE_REQUIRE_JUDGE") != "" {
		t.Fatal("FILESHARE_REQUIRE_JUDGE is set and there is no python with pyjwt: the tokens here are " +
			"signed by an independent implementation, and this lane exists to run against it")
	}
	t.Skip("no python with pyjwt here: the tokens are signed by an independent implementation")
	return ""
}

func webdavGetToken(r *running, token, path string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return body, nil
}

func webdavPutToken(r *running, token, path, body string) error {
	req, _ := http.NewRequest(http.MethodPut, "http://"+r.addrs["webdav"]+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return nil
}
