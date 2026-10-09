// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
	"github.com/go-fileshare/fileshare/proto/fileshare/admin/v1/adminv1connect"
)

// webAdmin starts a managed server whose admin API is also on HTTPS, for
// two issuers: a lists subjects, b lists a group.
func webAdmin(t *testing.T) (m *managed, a, b *idp, addr string, p *pki) {
	t.Helper()
	dir := t.TempDir()
	p = newPKI(t, dir)
	a, b = newIDP(t), newIDP(t)
	extra := fmt.Sprintf("tls {\n  cert_file = %q\n  key_file  = %q\n}\n", hclPath(p.certFile), hclPath(p.keyFile))
	web := fmt.Sprintf(`  web {
    listen = "127.0.0.1:0"
    issuer %q {
      audience = "fileshare-a"
      subjects = ["alice-sub"]
    }
    issuer %q {
      audience = "fileshare-a.partner"
      groups   = ["fileshare-admins"]
    }
  }
`, a.URL, b.URL)
	m = startManagedAdmin(t, dir, extra, web)
	re := regexp.MustCompile(`https://(127\.0\.0\.1:\d+) — the admin API, for OIDC tokens`)
	for deadline := time.Now().Add(5 * time.Second); addr == ""; time.Sleep(10 * time.Millisecond) {
		if got := re.FindStringSubmatch(m.out.String()); got != nil {
			addr = got[1]
		} else if time.Now().After(deadline) {
			t.Fatalf("no HTTPS admin listener announced:\n%s", m.out)
		}
	}
	return m, a, b, addr, p
}

// webClient is a Connect client of the HTTPS admin API, speaking protocol.
func adminHTTPS(addr string, p *pki, opts ...connecthttp.Option) adminv1connect.AdminServiceClient {
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool}}}
	return adminv1connect.NewAdminServiceClient(connect.NewClient(connecthttp.NewTransport(hc, "https://"+addr, opts...)))
}

func bearerCtx(token string) context.Context {
	ctx, info := connect.NewClientContext(context.Background())
	if token != "" {
		info.RequestHeader().Set("Authorization", "Bearer "+token)
	}
	return ctx
}

func adminToken(t *testing.T, p *idp, aud, sub string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": p.URL, "aud": aud, "sub": sub,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	return p.joseSign(t, claims)
}

func TestAdminOverHTTPSAnswersOnlyAdministrators(t *testing.T) {
	m, a, b, addr, p := webAdmin(t)
	c := adminHTTPS(addr, p)
	other := newIDP(t)
	forged := adminToken(t, a, "fileshare-a", "alice-sub", nil)
	// A token naming issuer a but signed by b's key.
	forgedBy := b.joseSign(t, map[string]any{"iss": a.URL, "aud": "fileshare-a", "sub": "alice-sub",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	for _, tc := range []struct {
		name  string
		token string
		want  connect.Code // 0: answered
	}{
		{"no token", "", connect.CodeUnauthenticated},
		{"a listed subject", forged, 0},
		{"another audience", adminToken(t, a, "another-service", "alice-sub", nil), connect.CodeUnauthenticated},
		{"an expired token", a.joseSign(t, map[string]any{"iss": a.URL, "aud": "fileshare-a", "sub": "alice-sub",
			"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix()}), connect.CodeUnauthenticated},
		{"a subject not listed", adminToken(t, a, "fileshare-a", "mallory", nil), connect.CodePermissionDenied},
		{"a listed group, other issuer", adminToken(t, b, "fileshare-a.partner", "bob-sub", map[string]any{"groups": []string{"x", "fileshare-admins"}}), 0},
		{"no listed group", adminToken(t, b, "fileshare-a.partner", "bob-sub", map[string]any{"groups": []string{"staff"}}), connect.CodePermissionDenied},
		{"a subject listed at ANOTHER issuer", adminToken(t, b, "fileshare-a.partner", "alice-sub", nil), connect.CodePermissionDenied},
		{"an issuer not listed", adminToken(t, other, "fileshare-a", "alice-sub", nil), connect.CodeUnauthenticated},
		{"iss of a, key of b", forgedBy, connect.CodeUnauthenticated},
		{"not a JWT", "not.a.jwt", connect.CodeUnauthenticated},
	} {
		_, err := c.ListShares(bearerCtx(tc.token), &adminv1.ListSharesRequest{})
		if got := connect.CodeOf(err); (tc.want == 0 && err != nil) || (tc.want != 0 && got != tc.want) {
			t.Errorf("%s: %v, want code %v", tc.name, err, tc.want)
		}
	}
	// The refusals are audited, and the caller is told nothing but "refused".
	if out := m.out.String(); !strings.Contains(out, "admin (https): refused") || !strings.Contains(out, "is not an administrator here") {
		t.Errorf("the refusals were not audited:\n%s", out)
	}
}

// The service's refusals keep their codes over Connect, a mutation is audited
// under the caller's issuer and subject, and gRPC-Web and gRPC answer too.
func TestAdminOverHTTPSKeepsTheServicesCodesAndAudit(t *testing.T) {
	m, a, _, addr, p := webAdmin(t)
	ok := bearerCtx(adminToken(t, a, "fileshare-a", "alice-sub", nil))
	c := adminHTTPS(addr, p)
	_, err := c.CreateShare(ok, &adminv1.CreateShareRequest{Name: "bad name!"})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invalid share: %v (%v), want InvalidArgument", err, connect.CodeOf(err))
	}
	if _, err := c.GetShare(ok, &adminv1.GetShareRequest{Name: "nope"}); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a missing share: %v, want NotFound", err)
	}
	if _, err := c.CreateShare(ok, &adminv1.CreateShareRequest{Name: "docs",
		Source: &adminv1.CreateShareRequest_Directory{Directory: m.roots}, Grants: aliceWrites()}); err != nil {
		t.Fatal(err)
	}
	if out := m.out.String(); !strings.Contains(out, "oidc="+a.URL+" alice-sub") {
		t.Errorf("the creation was not audited under the caller:\n%s", out)
	}
	for name, opt := range map[string]connecthttp.Option{"grpc-web": connecthttp.WithGRPCWeb(), "grpc": connecthttp.WithGRPC()} {
		got, err := adminHTTPS(addr, p, opt).ListShares(ok, &adminv1.ListSharesRequest{})
		if err != nil || len(got.GetShares()) != 1 {
			t.Errorf("%s: %v, %d shares", name, err, len(got.GetShares()))
		}
		if _, err := adminHTTPS(addr, p, opt).ListShares(bearerCtx(""), &adminv1.ListSharesRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s without a token: %v", name, err)
		}
	}
}

func TestAdminWebConfigRefusals(t *testing.T) {
	ok := adminWebIssuer{Issuer: "https://i", Audience: "a", Subjects: []string{"s"}}
	for _, tc := range []struct {
		name string
		w    adminWebBlock
		tls  bool
		want string
	}{
		{"no address", adminWebBlock{Listen: "8443", Issuers: []adminWebIssuer{ok}}, true, "not an address"},
		{"no tls", adminWebBlock{Listen: ":8443", Issuers: []adminWebIssuer{ok}}, false, "needs the tls block"},
		{"no issuer", adminWebBlock{Listen: ":8443"}, true, "no issuer block"},
		{"twice", adminWebBlock{Listen: ":8443", Issuers: []adminWebIssuer{ok, ok}}, true, "given twice"},
		{"no audience", adminWebBlock{Listen: ":8443", Issuers: []adminWebIssuer{{Issuer: "https://i", Subjects: []string{"s"}}}}, true, "no audience"},
		{"nobody", adminWebBlock{Listen: ":8443", Issuers: []adminWebIssuer{{Issuer: "https://i", Audience: "a"}}}, true, "names no subject and no group"},
	} {
		if err := tc.w.check(tc.tls); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if err := (&adminWebBlock{Listen: ":8443", Issuers: []adminWebIssuer{ok}}).check(true); err != nil {
		t.Fatal(err)
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	for _, raw := range []string{"", "a.b", "a.!!!.c", "a.bm90IGpzb24.c"} {
		if got := unverifiedIssuer(raw); got != "" {
			t.Errorf("unverifiedIssuer(%q) = %q", raw, got)
		}
	}
}
