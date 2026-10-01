// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	ssf "github.com/hstern/go-ssf"
	ssfclient "github.com/hstern/go-ssf/client"
	"github.com/hstern/go-ssf/receiver"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// The shared signals receiver: see caep.go for what it is for.
//
//	ssf {
//	  transmitter = "https://bridge.example.org"          # its issuer
//	  audience    = "https://files.example.org"           # what this server is to it
//	  client_id          = "fileshare"                    # OAuth client credentials
//	  client_secret_file = "/etc/fileshare/ssf.secret"    #   (RFC 6749 §4.4), scope "ssf"
//	  state_file  = "/var/lib/fileshare/revocations.json"
//	}
//
// or, for a transmitter that hands out a long-lived bearer token instead,
// token_file. go-authn/bridge takes client credentials: the token then comes
// from the transmitter's own token endpoint (its OpenID configuration) and is
// renewed before it expires.
//
// The transport is github.com/hstern/go-ssf -- discovery, the RFC 8936
// poller, the SET's JWS layer -- chosen over the alternatives because it is
// the one with tests on both sides and a conformance harness against the
// OpenID interop suite. What an event MEANS is here: its issuer and audience,
// CAEP session-revoked, the RFC 9493 subject.
type ssfBlock struct {
	Transmitter string `hcl:"transmitter"`
	Audience    string `hcl:"audience"`
	TokenFile   string `hcl:"token_file,optional"`
	// ClientID and ClientSecretFile authenticate this receiver with OAuth
	// client credentials; TokenURL overrides the token endpoint found in the
	// transmitter's OpenID configuration.
	ClientID         string `hcl:"client_id,optional"`
	ClientSecretFile string `hcl:"client_secret_file,optional"`
	TokenURL         string `hcl:"token_url,optional"`
	StateFile        string `hcl:"state_file"`
	CAFile           string `hcl:"ca_file,optional"`
	// MaxAge is how long without hearing from the transmitter before
	// federated credentials are refused (default 10m). Retain is how long a
	// revocation is kept (default 192h: past the longest-lived credential
	// the provider issues, a 168h SSH certificate).
	MaxAge string `hcl:"max_age,optional"`
	Retain string `hcl:"retain,optional"`
}

func (b *ssfBlock) timing() (maxAge, retain time.Duration, err error) {
	maxAge, retain = 10*time.Minute, 192*time.Hour
	if b.MaxAge != "" {
		// At least a minute: the poll backs off up to a quarter of it, plus
		// an HTTP timeout, and anything shorter flaps with a healthy but
		// idle transmitter (found by the security review).
		if maxAge, err = time.ParseDuration(b.MaxAge); err != nil || maxAge < time.Minute {
			return 0, 0, fmt.Errorf("ssf: max_age = %q is not a duration of a minute or more", b.MaxAge)
		}
	}
	if b.Retain != "" {
		// Longer than any credential a revocation voids: bridge's SSH
		// certificates live up to 168h, opkssh's 1week; a revocation
		// forgotten before they expire lets them back in.
		if retain, err = time.ParseDuration(b.Retain); err != nil || retain < 169*time.Hour {
			return 0, 0, fmt.Errorf("ssf: retain = %q is shorter than 169h, longer than any credential a revocation voids", b.Retain)
		}
	}
	return maxAge, retain, nil
}

// check refuses an ssf block that cannot work.
func (b *ssfBlock) check(c *config) error {
	switch {
	case !strings.HasPrefix(b.Transmitter, "https://"):
		return fmt.Errorf("ssf: transmitter = %q: over https, or somebody on the path decides who is revoked", b.Transmitter)
	case b.Audience == "":
		return fmt.Errorf("ssf: no audience: a SET addressed to another receiver would be believed here")
	case b.StateFile == "":
		return fmt.Errorf("ssf: state_file is required: a revocation acknowledged and forgotten at a restart is one that never happened")
	case (b.TokenFile != "") == (b.ClientID != "" || b.ClientSecretFile != ""):
		return fmt.Errorf("ssf: say how this receiver authenticates, once: token_file, or client_id and client_secret_file")
	case b.ClientID != "" && b.ClientSecretFile == "", b.ClientID == "" && b.ClientSecretFile != "":
		return fmt.Errorf("ssf: client_id and client_secret_file go together")
	case b.TokenURL != "" && !strings.HasPrefix(b.TokenURL, "https://"):
		return fmt.Errorf("ssf: token_url = %q: over https, or the client secret crosses the network in the clear", b.TokenURL)
	case c.OIDC == nil && !(c.serveBlockFor("nfs") != nil && c.serveBlockFor("nfs").Identity == "certificate"):
		return fmt.Errorf("ssf: revocations are of federated people, and nothing here serves any: no oidc block, no nfs identity = \"certificate\"")
	}
	_, _, err := b.timing()
	return err
}

// ssfReceiver keeps the stream polled.
type ssfReceiver struct {
	b      *ssfBlock
	store  *revocationStore
	client *http.Client // plain, pinned: discovery and JWKS
	auth   *http.Client // the same, authenticating as this receiver
	out    io.Writer

	mu   sync.Mutex
	keys jose.JSONWebKeySet
	jwks string
	last time.Time // when the keys were last fetched

	secret string // the client secret, for client credentials

	triedKids map[string]time.Time // kids fetched for, and when
}

// jwsKeyID is the kid of a compact JWS's protected header, or "".
func jwsKeyID(jws string) string {
	h, _, ok := strings.Cut(jws, ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return ""
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	json.Unmarshal(raw, &hdr)
	return hdr.Kid
}

func newSSFReceiver(b *ssfBlock, out io.Writer) (*ssfReceiver, error) {
	maxAge, retain, err := b.timing()
	if err != nil {
		return nil, err
	}
	store, err := openRevocationStore(b.StateFile, retain, maxAge)
	if err != nil {
		return nil, fmt.Errorf("ssf: %w", err)
	}
	r := &ssfReceiver{b: b, store: store, out: out, client: &http.Client{Timeout: 60 * time.Second, CheckRedirect: httpsOnlyRedirect}}
	if b.CAFile != "" {
		pem, err := os.ReadFile(b.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ssf: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ssf: %s holds no PEM certificate", b.CAFile)
		}
		r.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	if b.TokenFile != "" {
		tok, err := os.ReadFile(b.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("ssf: token_file: %w", err)
		}
		bearer := "Bearer " + strings.TrimSpace(string(tok))
		r.auth = &http.Client{Timeout: r.client.Timeout, Transport: headerTransport{r.transport(), bearer}}
	} else {
		secret, err := os.ReadFile(b.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("ssf: client_secret_file: %w", err)
		}
		r.secret = strings.TrimSpace(string(secret))
	}
	return r, nil
}

// headerTransport sets one Authorization header on every request.
type headerTransport struct {
	next  http.RoundTripper
	value string
}

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", h.value)
	return h.next.RoundTrip(req)
}

// clientCredentials makes r.auth an OAuth client: a token for scope "ssf"
// from the transmitter's token endpoint, fetched again before it expires.
func (r *ssfReceiver) clientCredentials(ctx context.Context) error {
	tokenURL := r.b.TokenURL
	if tokenURL == "" {
		var oc struct {
			TokenEndpoint string `json:"token_endpoint"`
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(r.b.Transmitter, "/")+"/.well-known/openid-configuration", nil)
		if err != nil {
			return err
		}
		res, err := r.client.Do(req)
		if err != nil {
			return fmt.Errorf("the transmitter's OpenID configuration: %w", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("the transmitter's OpenID configuration: %s; say token_url", res.Status)
		}
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&oc); err != nil || oc.TokenEndpoint == "" {
			return fmt.Errorf("the transmitter's OpenID configuration names no token_endpoint; say token_url")
		}
		if !strings.HasPrefix(oc.TokenEndpoint, "https://") {
			return fmt.Errorf("the token endpoint %s is not https: the client secret would cross in the clear", oc.TokenEndpoint)
		}
		tokenURL = oc.TokenEndpoint
	}
	cc := clientcredentials.Config{ClientID: r.b.ClientID, ClientSecret: r.secret, TokenURL: tokenURL,
		Scopes: []string{"ssf"}}
	// The token endpoint is reached with the same pinned client; the token
	// source outlives this call, so its context must too.
	base := context.WithValue(context.Background(), oauth2.HTTPClient, r.client)
	src := cc.TokenSource(base)
	if _, err := src.Token(); err != nil {
		return fmt.Errorf("client credentials at %s: %w", tokenURL, err)
	}
	r.auth = &http.Client{Timeout: r.client.Timeout, Transport: &oauth2.Transport{Source: src, Base: r.transport()}}
	return nil
}

// run discovers the transmitter, makes sure there is a stream, and polls it
// until stop -- starting again, after a pause, whenever any of that fails.
func (r *ssfReceiver) run(ctx context.Context) {
	for ctx.Err() == nil {
		err := r.session(ctx)
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintf(r.out, "ssf: %v; retrying\n", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *ssfReceiver) session(ctx context.Context) error {
	tc, err := ssfclient.FetchTransmitterConfig(ctx, r.b.Transmitter, ssfclient.WithDiscoveryHTTPDoer(r.client))
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	if tc.Issuer != r.b.Transmitter {
		return fmt.Errorf("the transmitter at %s calls itself %q", r.b.Transmitter, tc.Issuer)
	}
	if tc.JWKSURI == "" || tc.ConfigurationEndpoint == "" {
		return errors.New("the transmitter publishes no jwks_uri or no configuration_endpoint")
	}
	// Over https, every one of them: the keys, the streams, the poll. The
	// rule on `transmitter` is worth nothing if what it points to is not.
	for _, u := range []string{tc.JWKSURI, tc.ConfigurationEndpoint, tc.StatusEndpoint} {
		if u != "" && !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("the transmitter points to %s, which is not https", u)
		}
	}
	r.mu.Lock()
	r.jwks = tc.JWKSURI
	r.mu.Unlock()
	if r.auth == nil {
		if err := r.clientCredentials(ctx); err != nil {
			return err
		}
	}
	if err := r.refreshKeys(ctx, true); err != nil {
		return err
	}
	endpoint, err := r.stream(ctx, tc.ConfigurationEndpoint)
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf("the poll endpoint %s is not https", endpoint)
	}
	// A stream the transmitter has disabled or paused still answers polls
	// with nothing: "heard", and never told. Asked once per session, when
	// the transmitter says where (SSF §8.1.2).
	if tc.StatusEndpoint != "" {
		var st struct {
			Status string `json:"status"`
		}
		if _, err := r.call(ctx, http.MethodGet, tc.StatusEndpoint+"?stream_id="+r.store.streamID(), nil, &st); err != nil {
			return fmt.Errorf("stream status: %w", err)
		}
		if st.Status != "" && st.Status != "enabled" {
			return fmt.Errorf("the stream is %s at the transmitter, so no revocation would arrive", st.Status)
		}
	}
	fmt.Fprintf(r.out, "ssf: polling %s for revocations\n", endpoint)
	p := receiver.NewPoller(endpoint, r, receiver.SinkFunc(r.deliver),
		receiver.WithHTTPClient(&http.Client{Timeout: r.client.Timeout, Transport: consumingTransport{r.auth.Transport, r}}),
		// The library's defaults back off to five minutes without events
		// and an hour after errors; either is longer than max_age, and a
		// short outage would then keep federated people out for the hour.
		receiver.WithNoEventsBackoff(time.Second, r.backoffMax()),
		receiver.WithErrorBackoff(time.Second, r.backoffMax()))
	return p.Run(ctx)
}

func (r *ssfReceiver) transport() http.RoundTripper {
	if r.client.Transport != nil {
		return r.client.Transport
	}
	return http.DefaultTransport
}

// backoffMax is how long the poller may wait between polls: 30s, and never
// more than a quarter of max_age.
func (r *ssfReceiver) backoffMax() time.Duration {
	maxAge, _, _ := r.b.timing()
	return min(30*time.Second, maxAge/4)
}

// consumingTransport is where a poll's SETs are made durable, BEFORE the
// poller sees them.
//
// ⛔ go-ssf's poller answers a SET it could not verify, or whose sink failed,
// with setErrs -- and a transmitter may discard what a receiver reported
// (go-authn/bridge v0.8.0 does). A revocation lost to a key rotated in a
// minute ago, or to a full disk, while this server still counted as "heard"
// is the fail-open the security review found. So here, on the poll's own
// response: every SET is verified (the keys fetched again for one they do
// not verify), read, and a revocation written down; any transient failure
// fails the whole round -- no ack, no setErrs, not heard -- and the round is
// retried. Only then does the poller get the response, and its sink finds
// every revocation already kept.
type consumingTransport struct {
	next http.RoundTripper
	r    *ssfReceiver
}

func (c consumingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err != nil || res.StatusCode < 200 || res.StatusCode > 299 {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	var pr struct {
		Sets map[string]string `json:"sets"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("the poll response: %w", err)
	}
	for jti, jws := range pr.Sets {
		payload, err := c.r.Verify(jws)
		if err != nil {
			return nil, fmt.Errorf("SET %s does not verify with the transmitter's keys, so this round is not accepted: %w", jti, err)
		}
		keys, at, err := parseRevocation(payload, c.r.b.Transmitter, c.r.b.Audience)
		if err != nil && !errors.Is(err, errIssSubOnly) {
			continue // permanent: the poller's sink reports it
		}
		if len(keys) > 0 {
			if err := c.r.store.revoke(keys, at); err != nil {
				return nil, fmt.Errorf("keeping the revocation in SET %s: %w", jti, err)
			}
		}
	}
	c.r.store.heardFrom()
	res.Body = io.NopCloser(bytes.NewReader(body))
	res.ContentLength = int64(len(body))
	return res, nil
}

// stream is the poll endpoint of this receiver's stream: the one the state
// file names when the transmitter still has it, otherwise a new one.
func (r *ssfReceiver) stream(ctx context.Context, configEndpoint string) (string, error) {
	if id := r.store.streamID(); id != "" {
		var cfg ssf.StreamConfig
		status, err := r.call(ctx, http.MethodGet, configEndpoint+"?stream_id="+id, nil, &cfg)
		switch {
		case err == nil && cfg.Delivery.EndpointURL != "":
			return cfg.Delivery.EndpointURL, nil
		case status != http.StatusNotFound && err != nil:
			return "", err
		}
		// 404: the transmitter no longer has it; a new one is made.
	}
	aud, _ := json.Marshal(r.b.Audience)
	req := ssf.StreamConfig{
		Aud:             aud,
		EventsRequested: []string{eventSessionRevoked},
		Delivery:        ssf.Delivery{Method: "urn:ietf:rfc:8936"},
	}
	var cfg ssf.StreamConfig
	if _, err := r.call(ctx, http.MethodPost, configEndpoint, req, &cfg); err != nil {
		return "", err
	}
	if cfg.StreamID == "" || cfg.Delivery.EndpointURL == "" {
		return "", errors.New("the transmitter made a stream with no id or no poll endpoint")
	}
	if err := r.store.setStream(cfg.StreamID); err != nil {
		return "", err
	}
	return cfg.Delivery.EndpointURL, nil
}

func (r *ssfReceiver) call(ctx context.Context, method, url string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := r.auth.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, ssfclient.ParseHTTPError(res)
	}
	return res.StatusCode, json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// refreshKeys fetches the transmitter's JWKS -- always when asked, otherwise
// at most once a minute, so that a SET signed by a key rotated in since the
// last fetch is verified rather than lost, and a stream of bad SETs cannot
// make this server hammer the JWKS.
func (r *ssfReceiver) refreshKeys(ctx context.Context, force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !force && time.Since(r.last) < time.Minute {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwks, nil)
	if err != nil {
		return err
	}
	res, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: %s answered %s", r.jwks, res.Status)
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&keys); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	r.keys, r.last = publicKeys(keys), time.Now()
	return nil
}

// publicKeys keeps the public, asymmetric keys of a set: an HMAC secret
// published in a JWKS would let whoever reads the JWKS sign SETs. Applied
// where keys are fetched AND where they are used, so that no path to the
// verifier carries one.
func publicKeys(keys jose.JSONWebKeySet) jose.JSONWebKeySet {
	var public jose.JSONWebKeySet
	for _, k := range keys.Keys {
		if _, symmetric := k.Key.([]byte); !symmetric && k.Valid() && k.IsPublic() {
			public.Keys = append(public.Keys, k)
		}
	}
	return public
}

// Verify is the SETVerifier the poller asks: the JWS layer, by go-ssf, with
// the transmitter's current keys -- fetched again once when they do not
// verify, for a key rotated in since.
func (r *ssfReceiver) Verify(jws string) ([]byte, error) {
	r.mu.Lock()
	keys := publicKeys(r.keys)
	r.mu.Unlock()
	payload, err := ssf.NewJOSESetVerifier(keys).Verify(jws)
	if err == nil {
		return payload, nil
	}
	// A SET that does not verify may be signed by a key rotated in since
	// the last fetch -- under a new kid, or under the same one: fetched
	// now, whatever the once-a-minute limit says, but once a minute per kid.
	force := false
	if kid := jwsKeyID(jws); kid != "" {
		r.mu.Lock()
		if r.triedKids == nil || len(r.triedKids) > 1024 {
			r.triedKids = map[string]time.Time{}
		}
		if time.Since(r.triedKids[kid]) > time.Minute {
			r.triedKids[kid], force = time.Now(), true
		}
		r.mu.Unlock()
	}
	if rerr := r.refreshKeys(context.Background(), force); rerr != nil {
		return nil, err
	}
	r.mu.Lock()
	keys = publicKeys(r.keys)
	r.mu.Unlock()
	return ssf.NewJOSESetVerifier(keys).Verify(jws)
}

// deliver is the sink: a verified SET, read, checked, and -- for a
// session-revoked event -- written down before the poller acknowledges it.
func (r *ssfReceiver) deliver(ctx context.Context, payload []byte) error {
	keys, at, err := parseRevocation(payload, r.b.Transmitter, r.b.Audience)
	switch {
	case errors.Is(err, errIssSubOnly):
		fmt.Fprintf(r.out, "ssf: %v\n", err)
	case err != nil:
		// Addressed elsewhere, or not an SSF SET: never going to succeed.
		fmt.Fprintf(r.out, "ssf: a SET was refused: %v\n", err)
		return fmt.Errorf("%v: %w", err, receiver.ErrPermanent)
	case len(keys) == 0:
		return nil // an event this receiver does not act on
	}
	if err := r.store.revoke(keys, at); err != nil {
		// Transient: not acknowledged, so the transmitter sends it again.
		return err
	}
	fmt.Fprintf(r.out, "ssf: %s: every session issued before %s is revoked\n",
		strings.Join(keys, ", "), at.UTC().Format(time.RFC3339))
	return nil
}
