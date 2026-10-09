// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-authn/oidc"
	"google.golang.org/grpc/status"

	"github.com/go-fileshare/fileshare/proto/fileshare/admin/v1/adminv1connect"
)

// webIssuer is one issuer block, with its verifier.
type webIssuer struct {
	adminWebIssuer
	v *oidc.Verifier
}

// webGate answers a call only for a token one issuer accepts and names.
type webGate struct {
	issuers []webIssuer
	audit   io.Writer
	refused *atomic.Uint64
}

// oidcCaller is who a call over HTTPS came from, kept in its context for the
// audit line (callerOf).
type oidcCaller struct{ issuer, subject string }

type oidcCallerKey struct{}

func openWebIssuers(b *adminWebBlock) ([]webIssuer, error) {
	var out []webIssuer
	for _, i := range b.Issuers {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		v, err := oidc.New(ctx, oidc.Config{Issuer: i.Issuer, Audience: i.Audience,
			JWKSURL: i.JWKSURL, GroupsClaim: i.GroupsClaim})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("web: issuer %s: %w", i.Issuer, err)
		}
		out = append(out, webIssuer{i, v})
	}
	return out, nil
}

// unverifiedIssuer reads "iss" from a JWT's payload WITHOUT checking anything,
// to pick which issuer's verifier then checks everything. A token naming an
// issuer it was not signed by fails that verifier, as it must.
func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return c.Iss
}

// authorize checks the call's bearer token, from its headers alone: connect-go
// runs interceptors before any byte of the message is decoded, so an
// unauthenticated caller costs a header read and a signature check, as the
// unix socket's tap handle does.
func (g *webGate) authorize(ctx context.Context, procedure string) (context.Context, error) {
	info, _ := connect.CallInfoForServerContext(ctx)
	raw, ok := "", false
	if info != nil {
		raw, ok = strings.CutPrefix(info.RequestHeader().Get("Authorization"), "Bearer ")
	}
	refuse := func(code connect.Code, why string) (context.Context, error) {
		g.refused.Add(1)
		fmt.Fprintf(g.audit, "admin (https): refused %s: %s\n", logSafe(procedure), logSafe(why))
		// The caller is told it was refused, and nothing more: which check
		// failed is a fact about the account or the provider.
		return ctx, connect.NewError(code, "refused")
	}
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return refuse(connect.CodeUnauthenticated, "no bearer token")
	}
	iss := unverifiedIssuer(raw)
	i := slices.IndexFunc(g.issuers, func(w webIssuer) bool { return w.Issuer == iss })
	if i < 0 {
		return refuse(connect.CodeUnauthenticated, "a token from an issuer this server does not list")
	}
	w := g.issuers[i]
	tok, err := w.v.Verify(ctx, raw)
	if err != nil {
		return refuse(connect.CodeUnauthenticated, fmt.Sprintf("a token from %s: %v", w.Issuer, err))
	}
	if !slices.Contains(w.Subjects, tok.Subject()) && !slices.ContainsFunc(tok.Groups(), func(g string) bool { return slices.Contains(w.Groups, g) }) {
		return refuse(connect.CodePermissionDenied, fmt.Sprintf("%s %s is not an administrator here", w.Issuer, tok.Subject()))
	}
	return context.WithValue(ctx, oidcCallerKey{}, oidcCaller{w.Issuer, tok.Subject()}), nil
}

func (g *webGate) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		ctx, err := g.authorize(ctx, spec.Procedure)
		if err != nil {
			return err
		}
		return next(ctx, spec, stream)
	}
}

// connectErrors gives a Connect caller the code the service meant: it
// answers in gRPC statuses (grpcError), which connect-go would otherwise
// report as Unknown. The numbers are the same in both.
func connectErrors(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		err := next(ctx, spec, stream)
		if err == nil {
			return nil
		}
		var ce *connect.Error
		if errors.As(err, &ce) {
			return err
		}
		if st, ok := status.FromError(err); ok {
			return connect.NewError(connect.Code(st.Code()), st.Message())
		}
		return err
	}
}

// countCalls feeds the same fileshare_admin_requests_total as the socket.
func (c *rpcCounts) connect(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		err := next(ctx, spec, stream)
		code := "OK"
		if err != nil {
			code = connect.CodeOf(err).String()
		}
		c.mu.Lock()
		c.n[[2]string{path.Base(spec.Procedure), code}]++
		c.mu.Unlock()
		return err
	}
}

// webMaxBytes bounds one request message: the largest the API takes is a
// share's definition, a few kilobytes.
const webMaxBytes = 1 << 20

// startAdminWeb serves svc over HTTPS on cfg.Admin.Web.Listen.
func startAdminWeb(s *server, cfg *config, svc adminv1connect.AdminServiceHandler, calls *rpcCounts, audit io.Writer) (func(), error) {
	issuers, err := openWebIssuers(cfg.Admin.Web)
	if err != nil {
		return nil, err
	}
	g := &webGate{issuers: issuers, audit: audit, refused: &s.stats.refused}
	// Outermost first: refuse before anything else runs; count what was
	// answered; then translate the service's statuses.
	srv := connect.NewServer(g.intercept, calls.connect, connectErrors)
	adminv1connect.RegisterAdminServiceHandler(srv, svc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, srv, connecthttp.WithReadMaxBytes(webMaxBytes))

	ln, err := net.Listen("tcp", cfg.Admin.Web.Listen)
	if err != nil {
		return nil, fmt.Errorf("admin web: %w", err)
	}
	tc := s.certs.TLSConfig()
	tc.NextProtos = append(tc.NextProtos, "h2", "http/1.1")
	// Every phase of a connection is bounded: a caller that sends its body a
	// byte at a time, or never reads the answer, does not hold a connection
	// open for as long as it likes. No call here is long: they read and
	// change configuration.
	hs := &http.Server{Handler: mux, TLSConfig: tc,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	go hs.Serve(tls.NewListener(ln, tc))
	fmt.Fprintf(s.out, "%-6s on https://%s — the admin API, for OIDC tokens\n", "admin", ln.Addr())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	}, nil
}
