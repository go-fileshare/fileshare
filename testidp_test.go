package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The test identity provider, for every protocol that hears its word:
// WebDAV (tokens), SFTP (its certificates, and opkssh). In no build-tagged
// file, so that a binary without one protocol still builds the others'
// tests.

// idp is an identity provider: the two documents, and a way to sign.
type idp struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.URL, "jwks_uri": p.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// joseSign signs with go-jose, which nobody in this repository wrote.
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
