// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// transmitter is an SSF transmitter written here from the specifications
// -- SSF 1.0 discovery and stream configuration, RFC 8936 poll delivery, RFC
// 8417 SETs signed with go-jose -- and not with go-ssf, whose receiver half is
// what is being tested: a library judging itself proves only that it agrees
// with itself.
type transmitter struct {
	*httptest.Server
	key     *ecdsa.PrivateKey
	token   string
	mu      sync.Mutex
	queue   map[string]string // jti -> SET
	acked   []string
	setErrs map[string]any
	failing bool
	streams int
	aud     string
	polled  int
	// tokens issued by the client-credentials endpoint, and the secret
	// it checks.
	issued int
	// status, when set, is published as the stream's status_endpoint
	// answer; keys are published beside key; jwksURI replaces the
	// published jwks_uri. Set before the receiver starts.
	status  string
	keys    []jose.JSONWebKey
	jwksURI string
}

func newTransmitter(t *testing.T, token string) *transmitter {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tr := &transmitter{key: key, token: token, queue: map[string]string{}, setErrs: map[string]any{}}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": tr.URL, "token_endpoint": tr.URL + "/token"})
	})
	// RFC 6749 §4.4: client credentials in Basic auth, scope ssf; the access
	// token it returns is the one the streams and the poll take.
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		r.ParseForm()
		if !ok || id != "fileshare" || secret != "client-secret" || r.Form.Get("grant_type") != "client_credentials" ||
			r.Form.Get("scope") != "ssf" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		tr.mu.Lock()
		tr.issued++
		tr.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("GET /.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		c := map[string]any{
			"issuer": tr.URL, "jwks_uri": tr.URL + "/jwks",
			"delivery_methods_supported": []string{"urn:ietf:rfc:8936"},
			"configuration_endpoint":     tr.URL + "/streams",
		}
		if tr.jwksURI != "" {
			c["jwks_uri"] = tr.jwksURI
		}
		if tr.status != "" {
			c["status_endpoint"] = tr.URL + "/streams/status"
		}
		json.NewEncoder(w).Encode(c)
	})
	mux.HandleFunc("GET /streams/status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"stream_id": r.URL.Query().Get("stream_id"), "status": tr.status})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "t1", Algorithm: "ES256", Use: "sig"}}, tr.keys...)})
	})
	stream := func() map[string]any {
		return map[string]any{"stream_id": "s1", "iss": tr.URL, "aud": tr.aud,
			"events_delivered": []string{eventSessionRevoked},
			"delivery":         map[string]any{"method": "urn:ietf:rfc:8936", "endpoint_url": tr.URL + "/poll"}}
	}
	mux.HandleFunc("POST /streams", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req struct {
			Aud json.RawMessage `json:"aud"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		tr.mu.Lock()
		json.Unmarshal(req.Aud, &tr.aud)
		tr.streams++
		tr.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(stream())
	})
	mux.HandleFunc("GET /streams", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if r.URL.Query().Get("stream_id") != "s1" || tr.streams == 0 {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(stream())
	})
	mux.HandleFunc("POST /poll", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var req struct {
			Ack     []string       `json:"ack"`
			SetErrs map[string]any `json:"setErrs"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.polled++
		if tr.failing {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		for _, j := range req.Ack {
			tr.acked = append(tr.acked, j)
			delete(tr.queue, j)
		}
		for j, e := range req.SetErrs {
			tr.setErrs[j] = e
			delete(tr.queue, j)
		}
		json.NewEncoder(w).Encode(map[string]any{"sets": tr.queue, "moreAvailable": false})
	})
	tr.Server = httptest.NewTLSServer(mux)
	t.Cleanup(tr.Close)
	return tr
}

// revoke queues a CAEP session-revoked for a person, addressed to aud.
func (tr *transmitter) revoke(t *testing.T, jti, aud, account, iss, sub string, at time.Time) {
	t.Helper()
	claims := map[string]any{
		"iss": tr.URL, "aud": aud, "iat": time.Now().Unix(), "jti": jti,
		"sub_id": map[string]any{"format": "aliases", "identifiers": []any{
			map[string]any{"format": "account", "uri": "acct:" + account},
			map[string]any{"format": "iss_sub", "iss": iss, "sub": sub},
		}},
		"events": map[string]any{eventSessionRevoked: map[string]any{
			"event_timestamp": at.Unix(), "initiating_entity": "admin"}},
	}
	payload, _ := json.Marshal(claims)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: tr.key},
		(&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "t1"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	tr.mu.Lock()
	tr.queue[jti] = s
	tr.mu.Unlock()
}

// Everything the provider issued to a person before their revocation stops
// counting -- a token over WebDAV here -- while what it issues after is theirs;
// revocations survive a restart; a SET addressed elsewhere is refused and
// said so to the transmitter; and a transmitter not heard from within max_age
// fails closed.
func TestSharedSignalsRevokeWhatWasIssuedBefore(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	tr := newTransmitter(t, "stream-secret")
	caFile := write(t, dir, "tr-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tr.Certificate().Raw})))
	tokenFile := write(t, dir, "ssf.token", "stream-secret\n")
	stateFile := filepath.Join(dir, "revocations.json")
	img := image(t, dir, "t.img", map[string]string{"/x.txt": "x"})
	body := fmt.Sprintf(`
oidc {
  issuer   = %q
  audience = "fileshare"
}
ssf {
  transmitter = %q
  audience    = "https://files.example.org"
  token_file  = %q
  state_file  = %q
  ca_file     = %q
  max_age     = "1m"
}
share "t" {
  image = %q
  allow = ["oidc:user:alice@univ.fr", "oidc:user:bob@univ.fr"]
}
serve "webdav" { addr = "127.0.0.1:0" }
`, p.URL, tr.URL, hclPath(tokenFile), hclPath(stateFile), hclPath(caFile), hclPath(img))

	token := func(user string, iat time.Time) string {
		return p.joseSign(t, map[string]any{"iss": p.URL, "sub": "s-" + user, "aud": "fileshare",
			"iat": iat.Unix(), "exp": time.Now().Add(time.Hour).Unix(), "preferred_username": user})
	}
	get := func(r *running, tok string) bool {
		_, err := webdavGetToken(r, tok, "/t/x.txt")
		return err == nil
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("waiting for %s", what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	r := start(t, body)
	early := token("alice@univ.fr", time.Now().Add(-10*time.Minute))
	// Nothing heard from the transmitter yet: refused, not "nobody revoked".
	if get(r, early) {
		t.Fatal("a token was accepted before the transmitter was ever heard from")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go r.srv.ssf.run(ctx)
	waitFor("the first poll", func() bool { return r.srv.revocations.age() >= 0 })
	if !get(r, early) {
		t.Fatal("control: alice's token, nothing revoked")
	}

	// Alice revoked five minutes ago: her earlier token is void; one issued
	// since is hers. Bob, not revoked, is untouched.
	revokedAt := time.Now().Add(-5 * time.Minute)
	tr.revoke(t, "j1", "https://files.example.org", "alice@univ.fr", p.URL, "s-alice@univ.fr", revokedAt)
	// Addressed to another receiver: refused, and said so in setErrs.
	tr.revoke(t, "j2", "https://elsewhere.example.org", "bob@univ.fr", p.URL, "s-bob@univ.fr", revokedAt)
	waitFor("the ack", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return slices.Contains(tr.acked, "j1") && tr.setErrs["j2"] != nil
	})
	if get(r, early) {
		t.Error("alice's token issued before her revocation still works")
	}
	if !get(r, token("alice@univ.fr", time.Now())) {
		t.Error("a token issued to alice after her revocation is refused")
	}
	if !get(r, token("bob@univ.fr", time.Now().Add(-10*time.Minute))) {
		t.Error("bob was revoked by a SET addressed to another receiver")
	}
	cancel()

	// It was written down before it was acknowledged: a restart keeps it.
	st, err := openRevocationStore(stateFile, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	st.heardFrom()
	if err := st.check("alice@univ.fr", "", "", time.Now().Add(-10*time.Minute)); err == nil {
		t.Error("the revocation did not survive a restart")
	}
	if st.streamID() != "s1" {
		t.Errorf("stream id %q not kept", st.streamID())
	}

	// ⛔ The transmitter goes quiet past max_age: federated tokens are refused.
	r.srv.revocations.mu.Lock()
	r.srv.revocations.now = func() time.Time { return time.Now().Add(time.Minute) }
	r.srv.revocations.mu.Unlock()
	if get(r, token("bob@univ.fr", time.Now())) {
		t.Error("a token was accepted with the transmitter silent past max_age")
	}
}

func TestSubjectFormats(t *testing.T) {
	for raw, want := range map[string][]string{
		`{"format":"account","uri":"acct:alice@univ.fr"}`:          {"acct:alice@univ.fr"},
		`{"format":"iss_sub","iss":"https://b","sub":"42"}`:        {"iss_sub:https://b 42"},
		`{"format":"email","email":"alice@univ.fr"}`:               {"acct:alice@univ.fr"},
		`{"user":{"format":"account","uri":"acct:alice@univ.fr"}}`: {"acct:alice@univ.fr"},
		`{"format":"opaque","id":"x"}`:                             nil,
		`{"format":"account","uri":"mailto:alice@univ.fr"}`:        nil,
	} {
		var id subjectID
		if err := json.Unmarshal([]byte(raw), &id); err != nil {
			t.Fatal(err)
		}
		if got := id.keys(); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}
