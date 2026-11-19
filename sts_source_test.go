// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fromAddr(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = remote
	for _, x := range xff {
		r.Header.Add("X-Forwarded-For", x)
	}
	return r
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range s {
		out = append(out, netip.MustParsePrefix(e))
	}
	return out
}

func TestSTS_SourceIsTheConnectionUnlessAProxyVouches(t *testing.T) {
	proxies := prefixes("10.0.0.0/24", "fd00::/64")
	for name, c := range map[string]struct {
		r    *http.Request
		want string
	}{
		// ⛔ A direct client writing X-Forwarded-For is keyed on itself.
		"direct client, spoofed XFF":      {fromAddr("203.0.113.5:4000", "198.51.100.1"), "203.0.113.5"},
		"direct client, no header":        {fromAddr("203.0.113.5:4000"), "203.0.113.5"},
		"untrusted proxy is itself":       {fromAddr("192.0.2.9:80", "198.51.100.7"), "192.0.2.9"},
		"trusted proxy, one client":       {fromAddr("10.0.0.2:80", "198.51.100.7"), "198.51.100.7"},
		"trusted proxy, another client":   {fromAddr("10.0.0.2:80", "198.51.100.8"), "198.51.100.8"},
		"right-most untrusted hop":        {fromAddr("10.0.0.2:80", "6.6.6.6, 198.51.100.7, 10.0.0.3"), "198.51.100.7"},
		"a spoofed left hop is not read":  {fromAddr("10.0.0.2:80", "1.2.3.4", "198.51.100.7"), "198.51.100.7"},
		"all hops trusted: the proxy":     {fromAddr("10.0.0.2:80", "10.0.0.3, 10.0.0.4"), "10.0.0.2"},
		"no header at a proxy":            {fromAddr("10.0.0.2:80"), "10.0.0.2"},
		"a hop that is not an address":    {fromAddr("10.0.0.2:80", "198.51.100.7, garbage"), "10.0.0.2"},
		"IPv6 client behind a proxy: /64": {fromAddr("10.0.0.2:80", "2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64"},
		"IPv6 proxy":                      {fromAddr("[fd00::5]:80", "198.51.100.7"), "198.51.100.7"},
		"IPv6 direct: its /64":            {fromAddr("[2001:db8:1:2:ffff::9]:80"), "2001:db8:1:2::/64"},
		"IPv4-mapped is IPv4":             {fromAddr("[::ffff:203.0.113.5]:80"), "203.0.113.5"},
		"no trusted list: XFF never read": {fromAddr("10.0.0.2:80", "198.51.100.7"), "10.0.0.2"},
	} {
		list := proxies
		if name == "no trusted list: XFF never read" {
			list = nil
		}
		if got := clientSource(c.r, list); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// Behind a proxy that is trusted, two clients are two buckets; without the
// list they are one.
func TestSTS_RateIsPerClientBehindATrustedProxy(t *testing.T) {
	p := newIDP(t)
	post := func(r *running, client string) int {
		f := assume("garbage")
		req, _ := http.NewRequest("POST", "http://"+r.addrs["s3"]+"/", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", client)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	// Trusted: the loopback test client is the proxy.
	r := start(t, stsConfig(t, p, "", `trusted_proxies = ["127.0.0.0/8"]`+"\n"))
	r.srv.sts.lim.perMinute = 2
	for i := 0; i < 2; i++ {
		if s := post(r, "198.51.100.1"); s != http.StatusBadRequest {
			t.Fatalf("client A request %d: %d", i, s)
		}
	}
	if s := post(r, "198.51.100.1"); s != http.StatusTooManyRequests {
		t.Errorf("client A's third: %d", s)
	}
	if s := post(r, "198.51.100.2"); s != http.StatusBadRequest {
		t.Errorf("client B was throttled by A: %d", s)
	}
	// Not trusted: XFF is ignored, every client is the one connection, and
	// rotating the header buys nothing.
	r2 := start(t, stsConfig(t, p, "", ""))
	r2.srv.sts.lim.perMinute = 2
	post(r2, "198.51.100.1")
	post(r2, "198.51.100.2")
	if s := post(r2, "198.51.100.3"); s != http.StatusTooManyRequests {
		t.Errorf("a rotating X-Forwarded-For escaped the limit: %d", s)
	}
}

// A flood of fresh sources cannot reset the count of one that is at its limit.
func TestSTS_AFloodOfSourcesDoesNotResetAnother(t *testing.T) {
	st := newSTSStore(time.Now)
	st.lim = newRateLimiter(time.Now, 3, 50)
	for i := 0; i < 3; i++ {
		if !st.allow("victim") {
			t.Fatalf("request %d", i)
		}
	}
	if st.allow("victim") {
		t.Fatal("CONTROL: the victim is not at its limit")
	}
	for i := 0; i < 500; i++ {
		st.allow("flood-" + strconv.Itoa(i))
	}
	if st.allow("victim") {
		t.Error("a flood of fresh sources reset the victim's count")
	}
	st.lim.mu.Lock()
	n := len(st.lim.cur)
	st.lim.mu.Unlock()
	if n > 50 {
		t.Errorf("the table holds %d sources, bound 50", n)
	}
	// And the flood itself is not served without limit: past the table, the
	// shared overflow bucket (10 x the rate) answers 429.
	served := 0
	for i := 0; i < 500; i++ {
		if st.allow("198.51.100." + strconv.Itoa(i%250+1)) { // one /24: one overflow bucket
			served++
		}
	}
	if served > 3*stsOverflowFactor {
		t.Errorf("%d requests from sources the table could not hold were served", served)
	}
}

// The window slides: a source at its limit is served again once its minute is
// over, and the previous minute counts for the part of it still in the last.
func TestSTS_TheRateWindowSlides(t *testing.T) {
	now := time.Now()
	l := newRateLimiter(func() time.Time { return now }, 4, 100)
	for i := 0; i < 4; i++ {
		if !l.allow("a") {
			t.Fatalf("request %d", i)
		}
	}
	if l.allow("a") {
		t.Fatal("the 5th in a minute")
	}
	now = now.Add(90 * time.Second) // the 4 are in the previous minute, half still in the last
	if !l.allow("a") {
		t.Error("90s later: still refused, a minute is over")
	}
	now = now.Add(5 * time.Minute)
	for i := 0; i < 4; i++ {
		if !l.allow("a") {
			t.Errorf("after a long quiet, request %d refused", i)
		}
	}
	now = now.Add(-time.Hour) // a clock that went back forgets, it does not lock out
	if !l.allow("a") {
		t.Error("a clock set back locked a source out")
	}
}

// get() takes st.mu on every credentialed S3 request. allow() on a full table
// must not hold it: sessions are served while a flood of fresh sources is
// being counted.
func TestSTS_GetIsNotBlockedByAllowOnAFullTable(t *testing.T) {
	st := newSTSStore(time.Now)
	st.lim = newRateLimiter(time.Now, 60, 1000)
	sess, err := st.issue(principal{name: "m"}, "iss", "sub", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		st.allow("seed-" + strconv.Itoa(i))
	}
	// Hold the RATE lock, as a slow allow() would, and let allow() run into it
	// -- if allow() took st.mu first (wrapped in it), it would now be holding
	// it while it waits. get() must still answer within a deadline.
	st.lim.mu.Lock()
	allowing := make(chan struct{})
	go func() { close(allowing); st.allow("fresh-source") }()
	<-allowing
	time.Sleep(100 * time.Millisecond) // allow() is parked on the rate lock
	done := make(chan bool, 1)
	go func() { _, ok := st.get(sess.accessKey); done <- ok }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("the session is gone")
		}
	case <-time.After(2 * time.Second):
		t.Error("get() waits behind allow(): the sessions' lock is held while counting a request")
	}
	st.lim.mu.Unlock()
}

// ⛔ The witness of the review: a sustained flood across a minute boundary
// refuses neither a source that was already here nor a newcomer from another
// network. Counted in cur, a "known" source was one in cur alone, which the
// swap empties and a flood refills: every client then fell into one exhausted
// overflow bucket.
func TestSTS_AFloodAcrossAMinuteRefusesNeitherOldNorNew(t *testing.T) {
	for name, c := range map[string]struct {
		attacker func(i int) string
		existing string
		newcomer []string
	}{
		"IPv6 /48": {
			attacker: func(i int) string { return "2001:db8:aaaa:" + strconv.FormatInt(int64(i), 16) + "::/64" },
			existing: "2001:db8:eeee:1::/64",
			newcomer: []string{"2001:db8:bbbb:1::/64", "203.0.113.7"},
		},
		"IPv4 /24": {
			attacker: func(i int) string { return "198.51.100." + strconv.Itoa(i%250+1) },
			existing: "192.0.2.10",
			newcomer: []string{"203.0.113.7", "2001:db8:bbbb:1::/64"},
		},
	} {
		now := time.Now()
		l := newRateLimiter(func() time.Time { return now }, 60, 100)
		if !l.allow(c.existing) {
			t.Fatalf("%s: the existing source's first request", name)
		}
		flood := func(n int) {
			for i := 0; i < n; i++ {
				l.allow(c.attacker(i))
			}
		}
		flood(2000) // fills the table, then exhausts the attacker's overflow
		now = now.Add(61 * time.Second)
		flood(2000) // the minute swapped: the flood refills the table
		if !l.allow(c.existing) {
			t.Errorf("%s: a source seen in the last minute was refused", name)
		}
		for _, n := range c.newcomer {
			if !l.allow(n) {
				t.Errorf("%s: a newcomer %s from another network was refused", name, n)
			}
		}
		// The control: the attacker itself IS refused, so the flood did exhaust something.
		// (source 200 was past the table in both minutes: it is in no
		// generation, so it is counted in its network's exhausted bucket.)
		if l.allow(c.attacker(200)) {
			t.Errorf("%s: CONTROL: the attacker's own network was not exhausted", name)
		}
	}
}

// The extra memory is bounded: known sources are counted past max, but only
// those of the previous generation, which max bounds in turn.
func TestSTS_TheTableStaysBounded(t *testing.T) {
	now := time.Now()
	l := newRateLimiter(func() time.Time { return now }, 60, 50)
	for round := 0; round < 5; round++ {
		for i := 0; i < 3000; i++ {
			l.allow("2001:db8:aaaa:" + strconv.FormatInt(int64(i), 16) + "::/64")
		}
		now = now.Add(61 * time.Second)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cur) > 2*50 || len(l.prev) > 2*50 {
		t.Errorf("cur %d, prev %d, bound %d", len(l.cur), len(l.prev), 2*50)
	}
	if len(l.ovCur) > stsOverflowBuckets+1 {
		t.Errorf("%d overflow buckets", len(l.ovCur))
	}
}

// ⛔ The reviewer's witness: every minute, max fresh sources plus one request
// from EVERY source of the previous minute. A known source admitted without a
// size check made cur grow by max a minute for ever.
func TestSTS_KnownSourcesDoNotGrowTheTableWithoutBound(t *testing.T) {
	const max = 1000
	now := time.Now()
	l := newRateLimiter(func() time.Time { return now }, 60, max)
	src := func(minute, i int) string {
		return "2001:db8:" + strconv.FormatInt(int64(minute), 16) + ":" + strconv.FormatInt(int64(i), 16) + "::/64"
	}
	// One source that was here from the start and keeps asking once a minute.
	const existing = "198.51.100.77"
	l.allow(existing)
	for minute := 0; minute < 8; minute++ {
		var prevKeys []string
		l.mu.Lock()
		for k := range l.cur {
			prevKeys = append(prevKeys, k)
		}
		l.mu.Unlock()
		now = now.Add(61 * time.Second)
		for i := 0; i < max; i++ {
			l.allow(src(minute, i))
		}
		for _, k := range prevKeys {
			l.allow(k)
		}
		l.mu.Lock()
		n := len(l.cur)
		l.mu.Unlock()
		if n > 2*max {
			t.Fatalf("minute %d: cur holds %d, bound %d", minute, n, 2*max)
		}
		// The control that the witness did reach the bound's neighbourhood.
		if minute >= 3 && n < max {
			t.Fatalf("minute %d: cur holds only %d: the witness is not flooding", minute, n)
		}
		// And a source that keeps asking is served while the cap holds.
		if !l.allow(existing) {
			t.Fatalf("minute %d: the existing source was refused", minute)
		}
	}
}

// open() says so when a trusted_proxies prefix covers more than one host.
func TestSTS_OpenPrintsTheWidePrefixWarning(t *testing.T) {
	p := newIDP(t)
	r := start(t, stsConfig(t, p, "", `trusted_proxies = ["10.0.0.0/24", "192.0.2.1"]`+"\n"))
	out := r.out.String()
	if !strings.Contains(out, "warning: s3: trusted_proxies 10.0.0.0/24") || strings.Contains(out, "192.0.2.1/32 covers") {
		t.Errorf("the start did not warn about the /24 alone:\n%s", out)
	}
}

func TestSTS_WideTrustedProxyWarns(t *testing.T) {
	cfg := func(list ...string) *config {
		return &config{OIDC: &oidcBlock{Issuer: "https://x", Audience: "a"},
			Serves: []serveBlock{{Protocol: "s3", STS: true, Addr: "127.0.0.1:0", TrustedProxies: list}}}
	}
	for name, c := range map[string]struct {
		list []string
		warn []string
	}{
		"single hosts":    {[]string{"10.0.0.2", "10.0.0.3/32", "fd00::5", "fd00::6/128"}, nil},
		"a /29 pool":      {[]string{"10.0.0.0/29"}, []string{"10.0.0.0/29"}},
		"a /24":           {[]string{"10.0.0.0/24", "192.0.2.1"}, []string{"10.0.0.0/24"}},
		"an IPv6 /64":     {[]string{"fd00::/64"}, []string{"fd00::/64"}},
		"mapped /32 host": {[]string{"::ffff:10.0.0.2"}, nil},
	} {
		c0 := cfg(c.list...)
		if err := c0.checkSTS(); err != nil {
			t.Fatalf("%s: a warning is not a refusal: %v", name, err)
		}
		got := c0.stsWarnings()
		if len(got) != len(c.warn) {
			t.Errorf("%s: warnings %q, want %d", name, got, len(c.warn))
			continue
		}
		for i, w := range c.warn {
			if !strings.Contains(got[i], w) || !strings.Contains(got[i], "X-Forwarded-For") {
				t.Errorf("%s: %q does not name %s and the risk", name, got[i], w)
			}
		}
	}
}

func TestSTS_TrustedProxiesConfig(t *testing.T) {
	good := &config{OIDC: &oidcBlock{Issuer: "https://x", Audience: "a"},
		Serves: []serveBlock{{Protocol: "s3", STS: true, Addr: "127.0.0.1:0", TrustedProxies: []string{"10.0.0.0/8", "192.0.2.1", "fd00::/8"}}}}
	if err := good.checkSTS(); err != nil {
		t.Fatalf("CONTROL: %v", err)
	}
	if len(good.Serves[0].proxies) != 3 {
		t.Errorf("parsed %d prefixes", len(good.Serves[0].proxies))
	}
	for name, b := range map[string]serveBlock{
		"not an address": {Protocol: "s3", STS: true, Addr: "127.0.0.1:0", TrustedProxies: []string{"proxy.example"}},
		"without sts":    {Protocol: "s3", Addr: "127.0.0.1:0", TrustedProxies: []string{"10.0.0.0/8"}},
		"on webdav":      {Protocol: "webdav", TrustedProxies: []string{"10.0.0.0/8"}},
	} {
		if err := (&config{OIDC: good.OIDC, Serves: []serveBlock{b}}).checkSTS(); err == nil {
			t.Errorf("%s: ACCEPTED", name)
		}
	}
}
