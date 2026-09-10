// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/oidc"
)

// A token, as a way in.
//
// ⛔ Only WebDAV can carry one, and that is a fact about the protocols rather
// than a limit of this program: SMB authenticates with NTLMv2, SFTP with a key
// or a certificate, and NFS with nothing at all. None of them has anywhere to
// put an Authorization header. So a person who exists only at the identity
// provider can use WebDAV and nothing else here, and `check` says so with the
// same table it uses for everybody else.
//
// The token is verified by go-authn/oidc: signature, issuer, audience,
// expiry, and the refusals that come with them. What this file adds is the
// question that library has no business answering -- WHICH person this token
// is about, in the names this server's shares are written with.

// openOIDC builds the verifier, at startup rather than at the first request:
// a provider that is not answering is a server that cannot authenticate
// anybody through it, and it should say so before it listens.
func openOIDC(b *oidcBlock) (*oidc.Verifier, error) {
	if b == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return oidc.New(ctx, oidc.Config{
		Issuer:        b.Issuer,
		Audience:      b.Audience,
		JWKSURL:       b.JWKSURL,
		UsernameClaim: b.UsernameClaim,
		GroupsClaim:   b.GroupsClaim,
	})
}

// bearer is the person a request's token is about, or "" and a reason.
//
// The reason goes to the server's own output. A client that sent a token this
// server will not accept is told that it was not accepted, and nothing more:
// which check refused it is a fact about the account or the provider.
func (s *server) bearer(r *http.Request) (string, bool) {
	if s.oidc == nil {
		return "", false
	}
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(raw) == "" {
		return "", false
	}
	tok, err := s.oidc.Verify(r.Context(), strings.TrimSpace(raw))
	if err != nil {
		fmt.Fprintf(s.out, "a token was refused: %v\n", err)
		return "", false
	}
	name := tok.Username()
	if name == "" {
		fmt.Fprintf(s.out, "a token carries no %s: nobody to be\n", s.usernameClaim())
		return "", false
	}
	// ⛔ A token proves who the PROVIDER says this is. It does not put them in
	// this server's shares: a name that no source here knows is somebody this
	// server cannot decide about, and the safe reading of "I do not know you"
	// is not "you are allowed".
	//
	// The exception is a configuration with no local names at all, where the
	// provider IS the directory -- said explicitly with `trust_all`, because
	// it is the difference between "these people" and "everybody that
	// provider has".
	if _, known := s.who[name]; !known && !s.trustAllTokens() {
		fmt.Fprintf(s.out, "%s arrived with a valid token and is in %s: refused\n",
			name, nobodyIn(s.dir))
		return "", false
	}
	return name, true
}

// tokenIdentity is what `check` prints for people who exist only as tokens.
//
// A provider's people are not enumerable -- there is no list to read, only
// tokens as they arrive -- so this is what can honestly be said about them:
// the claim their name comes from, and the one protocol that can carry one.
func (s *server) tokenIdentity() *directory.Identity {
	return directory.NewIdentity("(anybody with a token)", directory.From(s.cfg.OIDC.Issuer))
}

func (s *server) usernameClaim() string {
	if s.cfg.OIDC != nil && s.cfg.OIDC.UsernameClaim != "" {
		return s.cfg.OIDC.UsernameClaim
	}
	return "preferred_username"
}

func (s *server) trustAllTokens() bool {
	return s.cfg.OIDC != nil && s.cfg.OIDC.TrustAll
}

// challenge tells a client what this server accepts, which is not always the
// same thing.
//
// RFC 7235 allows several challenges, and a server that offers a token where
// there is a provider AND a password where there are local people is telling
// the truth about both. A client picks the one it can answer.
func (s *server) challenge(w http.ResponseWriter) {
	if s.oidc != nil {
		w.Header().Add("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm=%q, scope="openid"`, s.name))
	}
	if len(s.who) > 0 {
		w.Header().Add("WWW-Authenticate", `Basic realm="`+s.name+`", charset="UTF-8"`)
	}
}
