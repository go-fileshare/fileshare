//go:build !nowebdav

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// People a federation vouches for, named by what the provider says about
// them rather than by an account here. The tokens are signed by go-jose,
// which nobody in this repository wrote; go-authn/oidc verifies them.

func (p *idp) joseSign(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func federatedToken(t *testing.T, p *idp, user string, groups ...string) string {
	return p.joseSign(t, map[string]any{
		"iss": p.URL, "sub": "s-" + user, "aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(), "preferred_username": user, "groups": groups,
	})
}

const photosGroup = "urn:mace:univ-example.fr:fileshare:photos"

func TestSharesNamedByTheProvider(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	staff := image(t, dir, "staff.img", map[string]string{"/s.txt": "s"})
	open := image(t, dir, "open.img", map[string]string{"/o.txt": "o"})
	fed := image(t, dir, "fed.img", map[string]string{"/f.txt": "f"})
	shares := fmt.Sprintf(`
oidc {
  issuer   = %q
  audience = "fileshare"
}

share "photos" {
  image   = %q
  allow   = ["oidc:groups:%s", "oidc:user:bob@univ-example.fr", "alice"]
  writers = ["oidc:groups:%s"]
}

share "staff" {
  image = %q
  allow = ["alice"]
}

share "open" { image = %q }

share "fed" {
  image = %q
  allow = ["oidc:user:bob"]
}
`, p.URL, hclPath(photos), photosGroup, photosGroup, hclPath(staff), hclPath(open), hclPath(fed))
	r := start(t, onlyProtocol(t, dir, "webdav", shares))

	// trevor exists nowhere here. The provider says he is in the photos
	// group, and that is what the share asks.
	trevor := federatedToken(t, p, "trevor@univ-example.fr", photosGroup)
	if got, err := webdavGetToken(r, trevor, "/photos/a.txt"); err != nil || string(got) != "a" {
		t.Fatalf("a member of the provider's group was refused: %v", err)
	}
	if err := webdavPutToken(r, trevor, "/photos/new.txt", "mine"); err != nil {
		t.Errorf("a member of the writers group could not write: %v", err)
	}
	// ... and nothing else: staff names alice alone.
	if _, err := webdavGetToken(r, trevor, "/staff/s.txt"); err == nil {
		t.Error("a federated member of one share's group reached another share")
	}

	// bob is named one by one, and is not in the writers group.
	bob := federatedToken(t, p, "bob@univ-example.fr")
	if _, err := webdavGetToken(r, bob, "/photos/a.txt"); err != nil {
		t.Errorf("oidc:user did not admit its user: %v", err)
	}
	if err := webdavPutToken(r, bob, "/photos/bob.txt", "x"); err == nil {
		t.Error("a reader named by oidc:user wrote")
	}

	// ⛔ Somebody the provider vouches for and no rule names: refused, as a
	// token for a stranger always was.
	mallory := federatedToken(t, p, "mallory@univ-example.fr", "urn:mace:univ-example.fr:other")
	if _, err := webdavGetToken(r, mallory, "/photos/a.txt"); err == nil {
		t.Error("a token outside every rule was accepted")
	}
	// ... not even where anyone who authenticates may go: she did not, as
	// far as this server is concerned.
	if _, err := webdavGetToken(r, mallory, "/open/o.txt"); err == nil {
		t.Error("a stranger to every rule reached a share open to anyone authenticated")
	}
	// trevor did: a rule here names him.
	if _, err := webdavGetToken(r, trevor, "/open/o.txt"); err != nil {
		t.Errorf("somebody a rule names is not authenticated for the open share: %v", err)
	}
	// ⛔ The LOCAL bob, with his password, is not the provider's bob that
	// oidc:user:bob names.
	req0, _ := http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+"/fed/f.txt", nil)
	req0.SetBasicAuth("bob", "swordfish")
	if res, err := http.DefaultClient.Do(req0); err == nil && res.StatusCode == http.StatusOK {
		t.Error("a local account matched a rule about the provider's user of the same name")
	}
	if _, err := webdavGetToken(r, federatedToken(t, p, "bob"), "/fed/f.txt"); err != nil {
		t.Errorf("the provider's bob was refused: %v", err)
	}

	// ⛔ A group claimed by a token from ANOTHER provider is nobody's group.
	other := newIDP(t)
	forged := other.joseSign(t, map[string]any{
		"iss": p.URL, "sub": "s-x", "aud": "fileshare", "exp": time.Now().Add(time.Hour).Unix(),
		"preferred_username": "eve@univ-example.fr", "groups": []string{photosGroup},
	})
	if _, err := webdavGetToken(r, forged, "/photos/a.txt"); err == nil {
		t.Error("a forged token's group was believed")
	}

	// ⛔ A local account is not the provider's: alice with a password is
	// alice, and the rules about the provider's people do not make her a
	// member of anything.
	req, _ := http.NewRequest(http.MethodPut, "http://"+r.addrs["webdav"]+"/photos/alice.txt", strings.NewReader("x"))
	req.SetBasicAuth("alice", "hunter2")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode < 300 {
		t.Error("a local account wrote through a rule about the provider's group")
	}
	req, _ = http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+"/photos/a.txt", nil)
	req.SetBasicAuth("alice", "hunter2")
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != http.StatusOK {
		t.Errorf("alice, allowed by name, could not read: %v", res.StatusCode)
	}
}

func TestProviderRulesAreChecked(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "x.img", map[string]string{"/a.txt": "a"})
	for name, c := range map[string]struct{ shares, want string }{
		"a rule with no provider": {fmt.Sprintf(`share "x" {
  image = %q
  allow = ["oidc:groups:g"]
}`, hclPath(img)), "no oidc block"},
		"a malformed rule": {fmt.Sprintf(`oidc {
  issuer   = "https://idp.example.org"
  audience = "fileshare"
}
share "x" {
  image = %q
  allow = ["oidc:roles:g"]
}`, hclPath(img)), "oidc:groups:<value>, oidc:user:<name> or oidc:domain:<domain>"},
		"a writer rule that may not connect": {fmt.Sprintf(`oidc {
  issuer   = "https://idp.example.org"
  audience = "fileshare"
}
share "x" {
  image   = %q
  allow   = ["alice"]
  writers = ["oidc:groups:g"]
}`, hclPath(img)), "does not allow"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "c.hcl")
			os.WriteFile(path, []byte(onlyProtocol(t, dir, "webdav", c.shares)), 0o644)
			cfg, err := loadConfig([]string{path})
			if err == nil {
				var srv *server
				srv, err = open(cfg, &safeBuffer{})
				if srv != nil {
					srv.Close()
				}
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
