// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// STS AssumeRoleWithWebIdentity, on the S3 listener.
//
// A person or a machine that holds an access token from the oidc block's
// provider -- go-authn/bridge, a machine's private_key_jwt client_credentials
// token -- exchanges it for CREDENTIALS THAT EXPIRE: an access key, a secret
// key and a session token (the AWS STS API, AssumeRoleWithWebIdentity, version
// 2011-06-15). S3 clients sign with them as with any others, and add the
// session token in x-amz-security-token (AWS SigV4, "Including the session
// token in the signed request"). Nobody holds a password; a machine holds a
// key, renewed by `credential_process`.
//
// ⛔ The token goes through the SAME rule as a bearer token over WebDAV
// (tokenPrincipal): the oidc block's issuer and audience, and admitFederated --
// a name no source here knows is refused unless trust_all or a share's oidc:
// rule names it. STS is not a way round "I do not know you is not you are
// allowed".
//
// ⛔ A session is judged at EVERY request, not once at issue: it expires, it is
// refused when the provider has revoked the person since the token was issued
// (the ssf block), and when the configuration no longer admits the name. The
// session token is bound to its access key, so one that is replayed beside
// another key fails.
//
// Sessions live in memory only: the secret is random, shown once in the
// response and never written anywhere. A restart ends them, and the client
// asks again -- which is what credential_process does when it is asked.

// stsSession is one set of temporary credentials.
type stsSession struct {
	accessKey string
	secret    string
	token     string
	caller    principal
	// iss, sub and iat are the token's, which is what a revocation is
	// compared with.
	iss, sub string
	iat      time.Time
	expires  time.Time
}

// stsStore holds the live sessions, by access key.
type stsStore struct {
	mu  sync.Mutex
	m   map[string]*stsSession
	now func() time.Time
	// max bounds the store, perPrincipal what one name may hold: the oldest of
	// their own is dropped first, so that nobody can push others out.
	max, perPrincipal int
	// rate is the recent STS requests by source address, perMinute allowed.
	rate      map[string][]time.Time
	perMinute int
	rateMax   int
}

// rateKey is what a source is counted as: an IPv4 address itself, an IPv6 one
// as its /64 (a host rotates through the whole /64 for free), anything that
// is not an address as written.
func rateKey(host string) string {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// clientSource is who asked: the address of the connection, unless that is a
// trusted proxy, in which case the right-most X-Forwarded-For hop that is not
// itself a trusted proxy. ⛔ From anybody else X-Forwarded-For is ignored: a
// direct client could write anything in it. A hop that is not an address ends
// the walk at the proxy, which is then the source.
func clientSource(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	isTrusted := func(s string) bool {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return false
		}
		a = a.Unmap().WithZone("")
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !isTrusted(host) {
		return rateKey(host)
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if _, err := netip.ParseAddr(h); err != nil {
			break
		}
		if !isTrusted(h) {
			return rateKey(h)
		}
	}
	return rateKey(host)
}

const (
	stsMaxSessions = 20000
	// stsPerPrincipal bounds what one name holds (credential_process keeps one
	// session per machine per hour); stsMinTokenLife is the least a token may
	// have left; the rate is per source address.
	stsPerPrincipal    = 16
	stsMinTokenLife    = 6 * time.Minute
	stsRatePerMinute   = 60
	stsRateSources     = 10000
	stsMaxBody         = 64 << 10
	stsVersion         = "2011-06-15"
	stsAccessKeyPrefix = "ASIA"
)

func newSTSStore(now func() time.Time) *stsStore {
	return &stsStore{m: map[string]*stsSession{}, now: now, max: stsMaxSessions, perPrincipal: stsPerPrincipal,
		rate: map[string][]time.Time{}, perMinute: stsRatePerMinute, rateMax: stsRateSources}
}

// allow counts one STS request from a source and says whether it is within
// the rate: perMinute a minute each. Every request counts, valid or not,
// before anything is verified -- a flood of tokens is what it is for. The
// source is rateKey's (an IPv6 address is its /64). The table is bounded, and
// never emptied: when full, entries a minute old go first, then the one with
// the fewest recent requests -- so that a flood of fresh sources, each at
// one, cannot push out a source that is at its limit.
func (st *stsStore) allow(source string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	if _, known := st.rate[source]; !known && len(st.rate) >= st.rateMax {
		for k, ts := range st.rate {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= time.Minute {
				delete(st.rate, k)
			}
		}
		if len(st.rate) >= st.rateMax {
			var victim string
			least := int(^uint(0) >> 1)
			for k, ts := range st.rate {
				if len(ts) < least {
					victim, least = k, len(ts)
				}
			}
			delete(st.rate, victim)
		}
	}
	recent := st.rate[source][:0]
	for _, t := range st.rate[source] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= st.perMinute {
		st.rate[source] = recent
		return false
	}
	st.rate[source] = append(recent, now)
	return true
}

var stsEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomString(n int, enc func([]byte) string) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on any platform Go supports
	}
	return enc(b)
}

// issue makes a session lasting d, or reports that the store is full.
func (st *stsStore) issue(who principal, iss, sub string, iat time.Time, d time.Duration) (*stsSession, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := st.now()
	var mine []*stsSession
	for k, s := range st.m {
		if !now.Before(s.expires) {
			delete(st.m, k)
			continue
		}
		if s.caller.name == who.name && s.iss == iss {
			mine = append(mine, s)
		}
	}
	if len(mine) >= st.perPrincipal {
		oldest := mine[0]
		for _, s := range mine {
			if s.expires.Before(oldest.expires) {
				oldest = s
			}
		}
		delete(st.m, oldest.accessKey)
	}
	if len(st.m) >= st.max {
		return nil, fmt.Errorf("too many sessions")
	}
	s := &stsSession{
		accessKey: stsAccessKeyPrefix + randomString(10, stsEncoding.EncodeToString), // 16 characters
		secret:    randomString(30, base64.RawURLEncoding.EncodeToString),            // 40
		token:     randomString(48, base64.RawURLEncoding.EncodeToString),
		caller:    who, iss: iss, sub: sub, iat: iat,
		expires: now.Add(d),
	}
	st.m[s.accessKey] = s
	return s, nil
}

// get is the live session under an access key. Expiry is checked here, on
// every call, and an expired session is forgotten.
func (st *stsStore) get(key string) (*stsSession, bool) {
	if st == nil {
		return nil, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.m[key]
	if !ok {
		return nil, false
	}
	if !st.now().Before(s.expires) {
		delete(st.m, key)
		return nil, false
	}
	return s, true
}

func (st *stsStore) forget(key string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, key)
}

// ---- the API ----

type stsError struct {
	XMLName   xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ ErrorResponse"`
	Type      string   `xml:"Error>Type"`
	Code      string   `xml:"Error>Code"`
	Message   string   `xml:"Error>Message"`
	RequestID string   `xml:"RequestId"`
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

type stsResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials                 stsCredentials
		SubjectFromWebIdentityToken string
		AssumedRoleUser             struct {
			AssumedRoleID string `xml:"AssumedRoleId"`
			Arn           string
		}
		Provider string
		Audience string
	} `xml:"AssumeRoleWithWebIdentityResult"`
	RequestID string `xml:"ResponseMetadata>RequestId"`
}

func stsFail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(stsError{Type: "Sender", Code: code, Message: msg, RequestID: randomString(8, stsEncoding.EncodeToString)})
}

// A RoleSessionName is 2 to 64 of [\w+=,.@-] (the STS API reference).
var stsSessionName = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// isSTSRequest says whether a request is for the STS API rather than S3: a
// form-encoded POST to the root that carries no signature. S3 itself never
// takes one.
func isSTSRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Authorization") != "" {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(ct), "application/x-www-form-urlencoded")
}

// serveSTS answers an STS request.
func (s *server) serveSTS(w http.ResponseWriter, r *http.Request) {
	if !s.sts.allow(clientSource(r, s.cfg.serveBlockFor("s3").proxies)) {
		w.Header().Set("Retry-After", "60")
		stsFail(w, http.StatusTooManyRequests, "Throttling", "too many requests from this address")
		return
	}
	// The body only, never the query string: a token in a URL is in every log
	// on the way.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, stsMaxBody))
	if err != nil {
		stsFail(w, http.StatusBadRequest, "ValidationError", "the request is too large or could not be read")
		return
	}
	v, err := url.ParseQuery(string(body))
	if err != nil {
		stsFail(w, http.StatusBadRequest, "ValidationError", "the request could not be read")
		return
	}
	if len(r.URL.RawQuery) > 0 {
		stsFail(w, http.StatusBadRequest, "ValidationError", "parameters go in the request body, not in the URL")
		return
	}
	for k, vs := range v {
		if len(vs) > 1 {
			stsFail(w, http.StatusBadRequest, "ValidationError", k+" appears more than once")
			return
		}
	}
	if a := v.Get("Action"); a != "AssumeRoleWithWebIdentity" {
		stsFail(w, http.StatusBadRequest, "InvalidAction", "only AssumeRoleWithWebIdentity is served here")
		return
	}
	if ver := v.Get("Version"); ver != "" && ver != stsVersion {
		stsFail(w, http.StatusBadRequest, "InvalidAction", "the version is "+stsVersion)
		return
	}
	// Refused rather than ignored: a client that scoped its session down must
	// not be handed one that is not.
	for _, p := range []string{"Policy", "PolicyArns.member.1.arn"} {
		if v.Has(p) {
			stsFail(w, http.StatusBadRequest, "InvalidParameterValue", p+" is not supported: a session has the access its person has")
			return
		}
	}
	if n := v.Get("RoleSessionName"); n != "" && !stsSessionName.MatchString(n) {
		stsFail(w, http.StatusBadRequest, "ValidationError", "RoleSessionName is 2 to 64 of letters, digits and +=,.@-_")
		return
	}
	raw := strings.TrimSpace(v.Get("WebIdentityToken"))
	if raw == "" {
		stsFail(w, http.StatusBadRequest, "ValidationError", "WebIdentityToken is required")
		return
	}
	b := s.cfg.serveBlockFor("s3")
	def, max, err := b.stsDurations()
	if err != nil {
		stsFail(w, http.StatusInternalServerError, "InternalFailure", "")
		return
	}
	d := def
	if ds := v.Get("DurationSeconds"); ds != "" {
		// Compared as seconds in an int64: n * time.Second overflows a
		// Duration for n past about 9.2e9 and would pass as negative.
		n, err := strconv.ParseInt(ds, 10, 64)
		if err != nil || n < 900 || n > int64(max/time.Second) {
			stsFail(w, http.StatusBadRequest, "ValidationError",
				fmt.Sprintf("DurationSeconds is 900 to %d", int(max.Seconds())))
			return
		}
		d = time.Duration(n) * time.Second
	}

	who, tok, ok := s.tokenPrincipal(r.Context(), s.oidcAccess, raw)
	if !ok {
		// Which check refused it is for this server's log; the caller learns
		// that it was refused.
		stsFail(w, http.StatusBadRequest, "InvalidIdentityToken", "the token was not accepted")
		return
	}
	// ⛔ The credentials never outlive the token: they freeze the person's
	// groups as of the token, and a token with seconds left must not buy hours.
	// And a token with little left is refused rather than given credentials
	// shorter than the SDKs' renewal window (about 5 minutes before
	// Expiration, which awscred also uses): they would be renewed at once,
	// forever. awscred presents a FRESH token at every exchange, so a good
	// client never meets this.
	exp, hasExp := tok.Expiry()
	remaining := exp.Sub(s.sts.now())
	if !hasExp || remaining < stsMinTokenLife {
		fmt.Fprintf(s.out, "s3: sts: %q: the token has %s left, and STS wants %s\n", who.name, remaining.Round(time.Second), stsMinTokenLife)
		stsFail(w, http.StatusBadRequest, "ExpiredTokenException", "the token is too close to its expiry; ask the provider for a new one")
		return
	}
	if d > remaining {
		d = remaining
	}
	iat, _ := tok.IssuedAt()
	sess, err := s.sts.issue(who, tok.Issuer(), tok.Subject(), iat, d)
	if err != nil {
		stsFail(w, http.StatusServiceUnavailable, "ServiceUnavailable", "try again later")
		return
	}
	fmt.Fprintf(s.out, "s3: sts: %q, vouched for by the provider, has credentials %s until %s\n",
		who.name, sess.accessKey, sess.expires.UTC().Format(time.RFC3339))

	var resp stsResponse
	resp.Result.Credentials = stsCredentials{
		AccessKeyID: sess.accessKey, SecretAccessKey: sess.secret, SessionToken: sess.token,
		Expiration: sess.expires.UTC().Format(time.RFC3339),
	}
	resp.Result.SubjectFromWebIdentityToken = tok.Subject()
	resp.Result.AssumedRoleUser.AssumedRoleID = sess.accessKey + ":" + v.Get("RoleSessionName")
	resp.Result.AssumedRoleUser.Arn = "arn:fileshare:sts:::assumed-role/" + who.name + "/" + v.Get("RoleSessionName")
	resp.Result.Provider = tok.Issuer()
	if aud := tok.Audience(); len(aud) > 0 {
		resp.Result.Audience = aud[0]
	}
	resp.RequestID = randomString(8, stsEncoding.EncodeToString)
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(resp)
}

// sessionTokenOf is the x-amz-security-token a request carries, in the header
// or -- for a presigned URL -- the query.
func sessionTokenOf(r *http.Request) string {
	if t := r.Header.Get("X-Amz-Security-Token"); t != "" {
		return t
	}
	return r.URL.Query().Get("X-Amz-Security-Token")
}

// signedHeadersOf is the SignedHeaders of a header-signed request.
func signedHeadersOf(r *http.Request) []string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ")
	if !ok {
		return nil
	}
	for _, part := range strings.Split(v, ",") {
		if h, ok := strings.CutPrefix(strings.TrimSpace(part), "SignedHeaders="); ok {
			return strings.Split(strings.ToLower(h), ";")
		}
	}
	return nil
}

// checkSession is what every request signed with temporary credentials passes
// BEFORE its signature is verified: alive, carrying THIS session's token --
// signed -- and still admitted. A reason is "" when it passes.
func (s *server) checkSession(r *http.Request, sess *stsSession) (code, why string) {
	if _, live := s.sts.get(sess.accessKey); !live {
		return "ExpiredToken", "the provided token has expired"
	}
	got := sessionTokenOf(r)
	if got == "" {
		return "InvalidToken", "temporary credentials need x-amz-security-token"
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(sess.token)) != 1 {
		return "InvalidToken", "the provided token is not valid for this access key"
	}
	if r.Header.Get("Authorization") != "" {
		signed := false
		for _, h := range signedHeadersOf(r) {
			signed = signed || h == "x-amz-security-token"
		}
		if !signed {
			return "InvalidToken", "x-amz-security-token must be a signed header"
		}
	}
	// ⛔ Judged again at every request: a person the provider disabled since
	// this session began, or a name the configuration no longer admits, stops
	// counting at once -- not at expiry.
	if err := s.admitFederated(sess.caller); err != nil {
		fmt.Fprintf(s.out, "s3: sts: %q: %v\n", sess.caller.name, err)
		s.sts.forget(sess.accessKey)
		return "AccessDenied", "access is no longer allowed"
	}
	if err := s.federatedRevoked(sess.caller.name, sess.iss, sess.sub, sess.iat); err != nil {
		fmt.Fprintf(s.out, "s3: sts: %q: %v\n", sess.caller.name, err)
		s.sts.forget(sess.accessKey)
		return "AccessDenied", "access is no longer allowed"
	}
	return "", ""
}
