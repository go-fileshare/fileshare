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
	r.srv.sts.perMinute = 2
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
	r2.srv.sts.perMinute = 2
	post(r2, "198.51.100.1")
	post(r2, "198.51.100.2")
	if s := post(r2, "198.51.100.3"); s != http.StatusTooManyRequests {
		t.Errorf("a rotating X-Forwarded-For escaped the limit: %d", s)
	}
}

// A flood of fresh sources cannot reset the count of one that is at its limit.
func TestSTS_AFloodOfSourcesDoesNotResetAnother(t *testing.T) {
	st := newSTSStore(time.Now)
	st.perMinute, st.rateMax = 3, 50
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
	st.mu.Lock()
	n := len(st.rate)
	st.mu.Unlock()
	if n > 50 {
		t.Errorf("the table holds %d sources, bound 50", n)
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
