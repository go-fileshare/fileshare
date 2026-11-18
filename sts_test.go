// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-volumes/s3/sigv4"
)

// STS AssumeRoleWithWebIdentity: the token is a bridge access token (typ
// at+jwt), a machine's or a person's; the credentials it buys expire, carry a
// session token, and are judged at every request.
//
// The judge is aws-sdk-go-v2 -- its STS client and its S3 client, nothing of
// this repository -- besides the raw requests that probe what an SDK never
// sends.

// accessToken signs an access token the way go-authn/bridge does: typ at+jwt.
func (p *idp) accessToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// machineToken is what bridge's client_credentials gives a machine client:
// sub = azp = client_id, no preferred_username.
func (p *idp) machineToken(t *testing.T, client string, edit func(map[string]any)) string {
	c := map[string]any{
		"iss": p.URL, "sub": client, "azp": client, "client_id": client, "aud": "fileshare",
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Hour).Unix(), "scope": "machine",
	}
	if edit != nil {
		edit(c)
	}
	return p.accessToken(t, c)
}

func (p *idp) personToken(t *testing.T, user string, groups ...string) string {
	return p.accessToken(t, map[string]any{
		"iss": p.URL, "sub": "s-" + user, "aud": "fileshare", "preferred_username": user, "groups": groups,
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Hour).Unix(),
	})
}

// stsConfig serves S3 with STS for the provider p. serve is extra text inside
// the s3 serve block, oidc extra text in the oidc block.
func stsConfig(t *testing.T, p *idp, oidc, serve string) string {
	t.Helper()
	dir := t.TempDir()
	photos := image(t, dir, "photos.img", map[string]string{"/holiday.txt": "a beach"})
	vault := image(t, dir, "vault.img", map[string]string{"/key.txt": "other-pc only"})
	return fmt.Sprintf(`
name = "TESTFS"
oidc {
  issuer   = %q
  audience = "fileshare"
  %s
}
share "photos" {
  image = %q
  allow = ["oidc:user:winpc-17", "oidc:user:other-pc", "oidc:user:alice@univ-example.fr", "oidc:groups:%s"]
}
share "vault" {
  image = %q
  allow = ["oidc:user:other-pc"]
}
serve "s3" {
  addr = "127.0.0.1:0"
  sts  = true
  %s
}
`, p.URL, oidc, hclPath(photos), photosGroup, hclPath(vault), serve)
}

func stsPost(t *testing.T, r *running, form url.Values) (int, string) {
	t.Helper()
	res, err := http.PostForm("http://"+r.addrs["s3"]+"/", form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func assume(token string) url.Values {
	return url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {"arn:aws:iam::0:role/fileshare"}, "RoleSessionName": {"winpc"}, "WebIdentityToken": {token},
	}
}

type tempCreds struct {
	key, secret, token string
	expires            time.Time
}

// credsFor is the raw exchange: temporary credentials, or the error code.
func credsFor(t *testing.T, r *running, form url.Values) (*tempCreds, string) {
	t.Helper()
	status, body := stsPost(t, r, form)
	if status != http.StatusOK {
		var e struct {
			Code string `xml:"Error>Code"`
		}
		xml.Unmarshal([]byte(body), &e)
		return nil, fmt.Sprintf("%d %s", status, e.Code)
	}
	var x struct {
		Key     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
		Secret  string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
		Token   string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
		Expires string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
	}
	if err := xml.Unmarshal([]byte(body), &x); err != nil || x.Key == "" || x.Secret == "" || x.Token == "" {
		t.Fatalf("an STS answer with no credentials: %v\n%s", err, body)
	}
	exp, err := time.Parse(time.RFC3339, x.Expires)
	if err != nil {
		t.Fatalf("Expiration %q: %v", x.Expires, err)
	}
	return &tempCreds{x.Key, x.Secret, x.Token, exp}, ""
}

// signed runs a request signed with the given credentials.
func s3Signed(t *testing.T, r *running, c sigv4.Credentials, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+r.addrs["s3"]+path, nil)
	payload := sigv4.HashSHA256(nil)
	req.Header.Set("x-amz-content-sha256", payload)
	sigv4.New("eu-west-1", "s3", c).SignRaw(req, payload, time.Now().UTC())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func (c *tempCreds) sig() sigv4.Credentials {
	return sigv4.Credentials{AccessKeyID: c.key, SecretAccessKey: c.secret, SessionToken: c.token}
}

type tokenFunc func() string

func (f tokenFunc) GetIdentityToken() ([]byte, error) { return []byte(f()), nil }

// The independent judge: aws-sdk-go-v2 exchanges a machine's token with its own
// STS client, signs S3 requests with what it gets, and sees the buckets the
// machine's share rules give it -- not the other machine's.
func TestSTS_AWSSDKIsTheJudge(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", ""))
	base := "http://" + r.addrs["s3"]
	ctx := context.Background()

	stsClient := sts.New(sts.Options{Region: "eu-west-1", BaseEndpoint: aws.String(base), Credentials: aws.AnonymousCredentials{}})
	provider := stscreds.NewWebIdentityRoleProvider(stsClient, "arn:aws:iam::0:role/fileshare",
		tokenFunc(func() string { return p.machineToken(t, "winpc-17", nil) }),
		func(o *stscreds.WebIdentityRoleOptions) { o.RoleSessionName = "winpc-17" })
	creds, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("the SDK's AssumeRoleWithWebIdentity: %v", err)
	}
	if creds.SessionToken == "" || !creds.CanExpire || time.Until(creds.Expires) > time.Hour+time.Minute || time.Until(creds.Expires) < 50*time.Minute {
		t.Errorf("the credentials: %+v (expires in %s)", creds, time.Until(creds.Expires))
	}

	client := s3.New(s3.Options{Region: "eu-west-1", BaseEndpoint: aws.String(base), UsePathStyle: true,
		Credentials: aws.NewCredentialsCache(provider)})
	buckets, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets with temporary credentials: %v", err)
	}
	var names []string
	for _, b := range buckets.Buckets {
		names = append(names, aws.ToString(b.Name))
	}
	if strings.Join(names, ",") != "photos" {
		t.Errorf("winpc-17 sees %v, want [photos]: a machine gets the shares its rules name", names)
	}
	obj, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("photos"), Key: aws.String("holiday.txt")})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	b, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if string(b) != "a beach" {
		t.Errorf("object = %q", b)
	}
	// And NOT the other machine's vault.
	if o, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("vault"), Key: aws.String("key.txt")}); err == nil {
		o.Body.Close()
		t.Error("winpc-17 read the vault of other-pc")
	}
	// A person's token, same endpoint, same rule.
	person := stscreds.NewWebIdentityRoleProvider(stsClient, "arn:aws:iam::0:role/fileshare",
		tokenFunc(func() string { return p.personToken(t, "alice@univ-example.fr") }))
	if _, err := person.Retrieve(ctx); err != nil {
		t.Errorf("a person named by a rule: %v", err)
	}
}

func TestSTS_TokensThatAreRefused(t *testing.T) {
	p := newIDP(t)
	other := newIDP(t)
	r := start(t, stsConfig(t, p, "", ""))

	// The control first: the exchange works for a good token.
	if _, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil))); why != "" {
		t.Fatalf("CONTROL: %s", why)
	}
	good := func(edit func(map[string]any)) string { return p.machineToken(t, "winpc-17", edit) }
	for name, form := range map[string]url.Values{
		"another issuer":        assume(other.machineToken(t, "winpc-17", func(c map[string]any) { c["iss"] = other.URL })),
		"another audience":      assume(good(func(c map[string]any) { c["aud"] = "somebody-else" })),
		"expired":               assume(good(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })),
		"an ID token (typ JWT)": assume(p.joseSign(t, map[string]any{"iss": p.URL, "sub": "winpc-17", "aud": "fileshare", "exp": time.Now().Add(time.Hour).Unix()})),
		"not a token":           assume("not-a-token"),
		"no token":              assume(""),
		// ⛔ A valid token for a name no source here knows, and no rule names:
		// "I do not know you" is not "you are allowed".
		"a stranger": assume(good(func(c map[string]any) { c["sub"] = "intruder-9"; c["azp"] = "intruder-9" })),
	} {
		if c, why := credsFor(t, r, form); c != nil {
			t.Errorf("%s: ACCEPTED", name)
		} else if !strings.HasPrefix(why, "400 ") {
			t.Errorf("%s: %s", name, why)
		}
	}
	// What the API refuses to ignore, and where parameters may be.
	for name, form := range map[string]url.Values{
		"another action":   {"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}},
		"a policy":         func() url.Values { f := assume(good(nil)); f.Set("Policy", `{}`); return f }(),
		"too short":        func() url.Values { f := assume(good(nil)); f.Set("DurationSeconds", "60"); return f }(),
		"over the maximum": func() url.Values { f := assume(good(nil)); f.Set("DurationSeconds", "7200"); return f }(),
		"a bad name":       func() url.Values { f := assume(good(nil)); f.Set("RoleSessionName", "x"); return f }(),
		"twice":            {"Action": {"AssumeRoleWithWebIdentity"}, "WebIdentityToken": {good(nil), good(nil)}},
	} {
		if c, _ := credsFor(t, r, form); c != nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
	// The token in the URL is refused: it would be in every log on the way.
	res, err := http.Post("http://"+r.addrs["s3"]+"/?WebIdentityToken="+good(nil), "application/x-www-form-urlencoded",
		strings.NewReader(assume(good(nil)).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Error("a request with parameters in the URL was served")
	}
	res, err = http.Get("http://" + r.addrs["s3"] + "/?" + assume(good(nil)).Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Error("a GET was taken for an STS request")
	}
}

// trust_all is the other shape, and the control for the stranger: the provider
// IS the directory.
func TestSTS_TrustAllAdmitsAStranger(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "trust_all = true", ""))
	if _, why := credsFor(t, r, assume(p.machineToken(t, "intruder-9", nil))); why != "" {
		t.Errorf("trust_all: %s", why)
	}
}

func TestSTS_SessionsAreJudgedAtEveryRequest(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", `sts_duration = "15m"`))
	c, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil)))
	if c == nil {
		t.Fatal(why)
	}
	if d := time.Until(c.expires); d > 15*time.Minute || d < 14*time.Minute {
		t.Errorf("expires in %s, want 15m", d)
	}
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode != http.StatusOK || !strings.Contains(body, "photos") {
		t.Fatalf("CONTROL: %d %s", res.StatusCode, body)
	}
	// 16 minutes on, by the store's clock: the same request, the same
	// signature material, is refused.
	r.srv.sts.mu.Lock()
	r.srv.sts.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	r.srv.sts.mu.Unlock()
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode == http.StatusOK || strings.Contains(body, "photos") {
		t.Errorf("an expired session was served: %d %s", res.StatusCode, body)
	}
	// And forgotten: a new exchange is a new session.
	if _, ok := r.srv.sts.get(c.key); ok {
		t.Error("an expired session is still in the store")
	}
}

func TestSTS_TheSessionTokenIsRequiredAndBoundToItsKey(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", ""))
	a, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil)))
	if a == nil {
		t.Fatal(why)
	}
	b, why := credsFor(t, r, assume(p.machineToken(t, "other-pc", nil)))
	if b == nil {
		t.Fatal(why)
	}
	// The controls: each works alone, and sees its own buckets.
	if res, body := s3Signed(t, r, a.sig(), "/"); res.StatusCode != http.StatusOK || strings.Contains(body, "vault") {
		t.Fatalf("CONTROL a: %d %s", res.StatusCode, body)
	}
	if res, body := s3Signed(t, r, b.sig(), "/"); res.StatusCode != http.StatusOK || !strings.Contains(body, "vault") {
		t.Fatalf("CONTROL b: %d %s", res.StatusCode, body)
	}
	for name, c := range map[string]sigv4.Credentials{
		"no session token":             {AccessKeyID: a.key, SecretAccessKey: a.secret},
		"a wrong session token":        {AccessKeyID: a.key, SecretAccessKey: a.secret, SessionToken: "nope"},
		"another session's token":      {AccessKeyID: a.key, SecretAccessKey: a.secret, SessionToken: b.token}, // signed correctly by a's secret
		"another session's secret":     {AccessKeyID: a.key, SecretAccessKey: b.secret, SessionToken: a.token},
		"b's key with a's token":       {AccessKeyID: b.key, SecretAccessKey: b.secret, SessionToken: a.token},
		"an unknown key, a's token":    {AccessKeyID: "ASIAUNKNOWNUNKNOWN", SecretAccessKey: a.secret, SessionToken: a.token},
		"the secret as the access key": {AccessKeyID: a.secret, SecretAccessKey: a.secret, SessionToken: a.token},
	} {
		// Each asks for what the access key it names may read, so that only the
		// credentials -- not the share rules -- can be what refuses it.
		path := "/photos/holiday.txt"
		if c.AccessKeyID == b.key {
			path = "/vault/key.txt"
		}
		if res, body := s3Signed(t, r, c, path); res.StatusCode == http.StatusOK || strings.Contains(body, "a beach") || strings.Contains(body, "other-pc only") {
			t.Errorf("%s: ACCEPTED (%d)", name, res.StatusCode)
		}
	}
	// A token that is not signed is not a token: header sent, not covered.
	req, _ := http.NewRequest("GET", "http://"+r.addrs["s3"]+"/", nil)
	payload := sigv4.HashSHA256(nil)
	req.Header.Set("x-amz-content-sha256", payload)
	sigv4.New("eu-west-1", "s3", sigv4.Credentials{AccessKeyID: a.key, SecretAccessKey: a.secret}).SignRaw(req, payload, time.Now().UTC())
	req.Header.Set("X-Amz-Security-Token", a.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Error("a security token outside the signature was accepted")
	}
	// Static credentials never take an ASIA key's place, nor the reverse.
	if res, _ := s3Signed(t, r, sigv4.Credentials{AccessKeyID: "alice", SecretAccessKey: "hunter2"}, "/"); res.StatusCode == http.StatusOK {
		t.Error("an access key that is a user was accepted with no user")
	}
}

// ⛔ The credentials never outlive the token that bought them.
func TestSTS_TheTokenCapsTheCredentialLifetime(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", `sts_duration = "1h"`))
	short := func(d time.Duration) url.Values {
		return assume(p.machineToken(t, "winpc-17", func(c map[string]any) { c["exp"] = time.Now().Add(d).Unix() }))
	}
	// A token with 30 minutes left, and a default of 1h: 30 minutes at most.
	c, why := credsFor(t, r, short(30*time.Minute))
	if c == nil {
		t.Fatal(why)
	}
	if d := time.Until(c.expires); d > 30*time.Minute+5*time.Second || d < 29*time.Minute {
		t.Errorf("credentials for a 30-minute token last %s", d)
	}
	// And the session really ends then, by the store's clock.
	r.srv.sts.mu.Lock()
	r.srv.sts.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	r.srv.sts.mu.Unlock()
	if _, ok := r.srv.sts.get(c.key); ok {
		t.Error("the session outlived its token")
	}
	r.srv.sts.mu.Lock()
	r.srv.sts.now = time.Now
	r.srv.sts.mu.Unlock()
	// A token with little left buys nothing: shorter credentials than the SDKs'
	// renewal window would be renewed at once, for ever.
	if c, _ := credsFor(t, r, short(3*time.Minute)); c != nil {
		t.Error("a token with 3 minutes left was given credentials")
	}
	if c, _ := credsFor(t, r, short(-time.Minute)); c != nil {
		t.Error("an expired token was given credentials")
	}
	// The control: just over the threshold is served.
	if c, why := credsFor(t, r, short(stsMinTokenLife+time.Minute)); c == nil {
		t.Errorf("a token with %s left: %s", stsMinTokenLife+time.Minute, why)
	}
	// A token with no exp at all is no token (the verifier refuses it).
	if c, _ := credsFor(t, r, assume(p.machineToken(t, "winpc-17", func(c map[string]any) { delete(c, "exp") }))); c != nil {
		t.Error("a token with no expiry was given credentials")
	}
}

// A DurationSeconds that overflows time.Duration is refused, not wrapped.
func TestSTS_DurationSecondsOverflow(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", ""))
	for _, ds := range []string{"9223372037", "9223372036854775807", "99999999999999999999", "-1", "1e3", "0x10"} {
		f := assume(p.machineToken(t, "winpc-17", nil))
		f.Set("DurationSeconds", ds)
		status, _ := stsPost(t, r, f)
		if status != http.StatusBadRequest {
			t.Errorf("DurationSeconds=%s: %d", ds, status)
		}
	}
	f := assume(p.machineToken(t, "winpc-17", nil))
	f.Set("DurationSeconds", "1800")
	if status, body := stsPost(t, r, f); status != http.StatusOK {
		t.Errorf("CONTROL: %d %s", status, body)
	}
}

// One name cannot push another's sessions out, nor fill the store; a source
// that asks too often is throttled.
func TestSTS_PerPrincipalCapAndRate(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "trust_all = true", ""))
	r.srv.sts.perMinute = 1000 // the cap is under test here, not the rate
	victim, why := credsFor(t, r, assume(p.machineToken(t, "victim-pc", nil)))
	if victim == nil {
		t.Fatal(why)
	}
	// The documented limit, spelled once: raising it is a decision the README
	// and this line say together.
	for i := 0; i < 16+5; i++ {
		if c, why := credsFor(t, r, assume(p.machineToken(t, "flooder", nil))); c == nil {
			t.Fatalf("exchange %d: %s", i, why)
		}
	}
	r.srv.sts.mu.Lock()
	n := 0
	for _, s := range r.srv.sts.m {
		if s.caller.name == "flooder" {
			n++
		}
	}
	r.srv.sts.mu.Unlock()
	if n != 16 {
		t.Errorf("one name holds %d sessions, want 16 (the README's number)", n)
	}
	if _, ok := r.srv.sts.get(victim.key); !ok {
		t.Error("another name's session was pushed out")
	}

	// The rate, per source address.
	r.srv.sts.perMinute = 3
	r.srv.sts.mu.Lock()
	clear(r.srv.sts.rate)
	r.srv.sts.mu.Unlock()
	for i := 0; i < 3; i++ {
		if status, body := stsPost(t, r, assume("garbage")); status != http.StatusBadRequest {
			t.Fatalf("request %d: %d %s", i, status, body)
		}
	}
	if status, _ := stsPost(t, r, assume("garbage")); status != http.StatusTooManyRequests {
		t.Errorf("the 4th request in a minute: %d", status)
	}
	// Another source is not throttled by this one, and a minute later this one is served.
	if !r.srv.sts.allow("203.0.113.9") {
		t.Error("another source was throttled")
	}
	r.srv.sts.mu.Lock()
	r.srv.sts.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	r.srv.sts.mu.Unlock()
	if status, _ := stsPost(t, r, assume("garbage")); status != http.StatusBadRequest {
		t.Errorf("a minute later: %d", status)
	}
}

// A name from a token is quoted in the log: a newline in it cannot forge a line.
func TestSTS_ANameWithANewlineCannotForgeALogLine(t *testing.T) {
	p := newIDP(t)
	evil := "mallory\nforged: s3: sts: admin has credentials"
	// Refused (a stranger): oidcauth's line.
	r := start(t, stsConfig(t, p, "", ""))
	credsFor(t, r, assume(p.machineToken(t, evil, func(c map[string]any) { c["azp"] = evil })))
	// Admitted (trust_all): sts's line.
	r2 := start(t, stsConfig(t, p, "trust_all = true", ""))
	if c, why := credsFor(t, r2, assume(p.machineToken(t, evil, nil))); c == nil {
		t.Fatal(why)
	}
	for name, out := range map[string]string{"refused": r.out.String(), "admitted": r2.out.String()} {
		if !strings.Contains(out, "mallory") {
			t.Fatalf("%s: the name is not logged at all: %q", name, out)
		}
		if strings.Contains(out, "\nforged") {
			t.Errorf("%s: a forged line in the log:\n%s", name, out)
		}
	}
}

// What a revocation does is tested with the store the SSF receiver fills
// (caep.go's revocationStore, checked at every request); the receiver's own
// delivery path is covered by ssf_test.go, which this PR does not rewire.
//
// A revocation the provider sent after the token was issued ends the session
// at its next request, not at its expiry.
func TestSTS_ARevokedPersonLosesTheirSession(t *testing.T) {
	p := newIDP(t)
	dir := t.TempDir()
	st, err := openRevocationStore(dir+"/rev.json", 192*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st.heardFrom()
	r := startWith(t, stsConfig(t, p, "", ""), func(s *server) { s.revocations = st })
	c, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil)))
	if c == nil {
		t.Fatal(why)
	}
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("CONTROL: %d %s", res.StatusCode, body)
	}
	// Another machine's revocation changes nothing for this one.
	if err := st.revoke([]string{accountKey("other-pc")}, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode != http.StatusOK {
		t.Fatalf("CONTROL: another machine's revocation ended this session: %d %s", res.StatusCode, body)
	}
	if err := st.revoke([]string{accountKey("winpc-17")}, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode == http.StatusOK || strings.Contains(body, "photos") {
		t.Errorf("a revoked session was served: %d %s", res.StatusCode, body)
	}
	// And no new session either.
	if c2, _ := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil))); c2 != nil {
		t.Error("a revoked machine was given new credentials")
	}
}

// Static keys can be turned off: only temporary credentials sign.
func TestSTS_StaticKeysOff(t *testing.T) {
	needUsers(t)
	p := newIDP(t)
	dir := t.TempDir()
	cfg := func(static string) string {
		alice := write(t, dir, "alice.pw", "hunter2\n")
		img := image(t, dir, "photos.img", map[string]string{"/holiday.txt": "a beach"})
		return fmt.Sprintf(`
name = "TESTFS"
user "alice" { password_file = %q }
oidc {
  issuer   = %q
  audience = "fileshare"
}
share "photos" {
  image = %q
  allow = ["alice", "oidc:user:winpc-17"]
}
serve "s3" {
  addr = "127.0.0.1:0"
  sts  = true
  %s
}
`, hclPath(alice), p.URL, hclPath(img), static)
	}
	// The control: static keys on (the default), alice signs as she always did.
	r := start(t, cfg(""))
	if res, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/"); res.StatusCode != http.StatusOK || !strings.Contains(string(body), "photos") {
		t.Fatalf("CONTROL: static keys: %d %s", res.StatusCode, body)
	}
	if c, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil))); c == nil {
		t.Fatalf("CONTROL: STS beside static keys: %s", why)
	}
	// Off: alice's key is no way in, temporary credentials still are.
	r = start(t, cfg("static_keys = false"))
	if res, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/"); res.StatusCode == http.StatusOK || strings.Contains(string(body), "photos") {
		t.Errorf("a static key was accepted with static_keys = false: %d %s", res.StatusCode, body)
	}
	c, why := credsFor(t, r, assume(p.machineToken(t, "winpc-17", nil)))
	if c == nil {
		t.Fatal(why)
	}
	if res, body := s3Signed(t, r, c.sig(), "/"); res.StatusCode != http.StatusOK || !strings.Contains(body, "photos") {
		t.Errorf("temporary credentials with static keys off: %d %s", res.StatusCode, body)
	}
}

// The STS settings are s3's, whatever else this build serves.
func TestSTS_SettingsBelongToS3(t *testing.T) {
	for _, b := range []serveBlock{{Protocol: "smb", STS: true}, {Protocol: "webdav", STSDuration: "1h"}} {
		c := &config{Serves: []serveBlock{b}}
		if err := c.checkSTS(); err == nil || !strings.Contains(err.Error(), "are for s3") {
			t.Errorf("%s: %v", b.Protocol, err)
		}
	}
	if err := (&config{Serves: []serveBlock{{Protocol: "smb"}}}).checkSTS(); err != nil {
		t.Errorf("the control: %v", err)
	}
}

func TestSTS_ConfigurationRefusals(t *testing.T) {
	p := newIDP(t)
	dir := t.TempDir()
	img := hclPath(image(t, dir, "x.img", map[string]string{"/a": "a"}))
	load := func(body string) error {
		_, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", body)})
		return err
	}
	oidcBlock := fmt.Sprintf("oidc {\n issuer = %q\n audience = \"fileshare\"\n}\n", p.URL)
	share := fmt.Sprintf("share \"x\" {\n image = %q\n allow = [\"oidc:user:m\"]\n}\n", img)
	for name, c := range map[string]struct{ body, want string }{
		"static keys off and no sts": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 static_keys = false
}`, "nobody could sign"},
		"sts and no oidc block": {share[:0] + fmt.Sprintf("share \"x\" {\n image = %q\n}\n", img) + `serve "s3" {
 addr = "127.0.0.1:0"
 sts = true
}`, "no oidc block"},
		"a duration with no sts": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 sts_duration = "1h"
}`, "without sts = true"},
		"a duration that is not": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 sts = true
 sts_duration = "soon"
}`, "sts_duration"},
		"under 15 minutes": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 sts = true
 sts_duration = "1m"
}`, "15m to 12h"},
		"over 12 hours": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 sts = true
 sts_max_duration = "48h"
}`, "15m to 12h"},
		"duration over the maximum": {oidcBlock + share + `serve "s3" {
 addr = "127.0.0.1:0"
 sts = true
 sts_duration = "2h"
 sts_max_duration = "1h"
}`, "longer than"},
		"in the clear off loopback": {oidcBlock + share + `serve "s3" {
 addr = "0.0.0.0:9000"
 sts = true
}`, "in the clear"},
	} {
		err := load(c.body)
		if err == nil {
			t.Errorf("%s: ACCEPTED", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
	// The controls: STS alone, with the clear-text address said to be behind a proxy.
	for name, body := range map[string]string{
		"sts":                     oidcBlock + share + "serve \"s3\" {\n addr = \"127.0.0.1:0\"\n sts = true\n}",
		"sts, static keys off":    oidcBlock + share + "serve \"s3\" {\n addr = \"127.0.0.1:0\"\n sts = true\n static_keys = false\n}",
		"sts behind a proxy":      oidcBlock + share + "serve \"s3\" {\n addr = \"0.0.0.0:9000\"\n sts = true\n plaintext = true\n}",
		"sts with a longer limit": oidcBlock + share + "serve \"s3\" {\n addr = \"127.0.0.1:0\"\n sts = true\n sts_max_duration = \"12h\"\n}",
	} {
		if err := load(body); err != nil {
			t.Errorf("the control %q: %v", name, err)
		}
	}
}
