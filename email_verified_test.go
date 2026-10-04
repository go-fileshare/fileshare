// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"testing"
	"time"
)

// An email names somebody only once the provider has verified it (OpenID
// Connect Core 5.1, email_verified). With username_claim = "email", a token
// whose email is not verified is refused over WebDAV; the control is the
// same token, verified. And with the default claim, an unverified email is
// not taken as the name: go-authn/oidc v0.2.0 falls back to it only when
// verified (before, a signed token bound as an address nobody checked).
func TestAnUnverifiedEmailNamesNobody(t *testing.T) {
	p := newIDP(t)
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	for _, c := range []struct {
		claim    string
		verified any // nil: no email_verified claim
		ok       bool
	}{
		{"email", true, true},
		{"email", false, false},
		{"email", nil, false},
		{"email", "true", false}, // a string is not the boolean true
		{"", false, false},       // default claim: no preferred_username, unverified email -> sub, unknown
		{"", true, true},         // default claim: verified email is the name
	} {
		claimLine := ""
		if c.claim != "" {
			claimLine = fmt.Sprintf("username_claim = %q", c.claim)
		}
		r := start(t, fmt.Sprintf(`
oidc {
  issuer    = %q
  audience  = "fileshare"
  trust_all = true
  %s
}
share "open" {
  image = %q
  allow = ["oidc:domain:univ.example"]
}
serve "webdav" { addr = "127.0.0.1:0" }
`, p.URL, claimLine, hclPath(img)))
		claims := map[string]any{"iss": p.URL, "sub": "u-9", "aud": "fileshare",
			"exp": time.Now().Add(time.Hour).Unix(), "email": "alice@univ.example"}
		if c.verified != nil {
			claims["email_verified"] = c.verified
		}
		_, err := webdavGetToken(r, p.joseSign(t, claims), "/open/b.txt")
		if (err == nil) != c.ok {
			t.Errorf("username_claim %q, email_verified %v: read = %v, want %v", c.claim, c.verified, err == nil, c.ok)
		}
	}
}
