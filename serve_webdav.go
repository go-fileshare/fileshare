// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/go-filesystems/webdav"
)

// WebDAV can tell who is asking -- HTTP Basic -- but a Handler is read-only or
// read-write for its whole life, and it reaches exactly one filesystem. So a
// share whose answer differs by person needs TWO handlers over the same image,
// and something in front to pick.
//
// That "something" is where the authentication happens, once, so the two
// handlers underneath are never asked the same question twice.
//
// Both handlers reach the same driver, which is exactly why lockFS exists:
// their own internal locks are different objects and would not have stopped a
// PROPFIND and a PUT from interleaving inside one image.
func serveWebDAV(s *server, p *protocol, ln net.Listener) error {
	mux := http.NewServeMux()
	served, _ := p.exports(s.shares)
	for _, sh := range served {
		prefix := "/" + sh.name
		read, err := webdav.New(sh.fsys,
			webdav.WithPrefix(prefix), webdav.WithCapacity(sh.size, 0))
		if err != nil {
			return fmt.Errorf("%s: %w", sh.name, err)
		}
		write, err := webdav.New(sh.fsys,
			webdav.WithPrefix(prefix), webdav.WithCapacity(sh.size, 0), webdav.ReadWrite())
		if err != nil {
			return fmt.Errorf("%s: %w", sh.name, err)
		}
		h := &byUser{server: s, share: sh, read: read, write: write}
		mux.Handle(prefix, h)
		mux.Handle(prefix+"/", h)
	}
	mux.HandleFunc("/", s.webdavIndex(served))
	return http.Serve(ln, mux)
}

// byUser authenticates, then hands the request to the handler that matches
// what this person may do.
type byUser struct {
	server      *server
	share       *share
	read, write http.Handler
}

func (b *byUser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, ok := b.authenticated(w, r)
	if !ok {
		return
	}
	if !b.share.mayUse(user) {
		// 404, not 403: a share this person may not use should not be
		// confirmed to exist. They were told the name or they were not.
		http.NotFound(w, r)
		return
	}
	if b.share.readOnlyFor(user) {
		b.read.ServeHTTP(w, r)
		return
	}
	b.write.ServeHTTP(w, r)
}

// authenticated returns the user, or writes the challenge and returns false.
//
// A share nobody is named on still authenticates when there are users: a
// server with credentials should not hand its contents to somebody who never
// gave any. Without users at all, everyone is anonymous and everyone gets in.
func (b *byUser) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	if len(b.server.who) == 0 && b.server.oidc == nil {
		return "", true
	}
	// A token first, because a client that sent one meant it: falling back to
	// asking for a password after refusing a token turns a rejected token
	// into a password prompt, which is confusing for a person and useless for
	// a program.
	if user, ok := b.server.bearer(r); ok {
		return user, true
	}
	// The comparison is the identity's own: it may be against a password this
	// server holds, or a question asked of a directory that holds it and will
	// not give it up. Either way it is constant-time where a comparison is
	// what happens.
	if user, password, ok := r.BasicAuth(); ok && b.server.matches(user, password) {
		return user, true
	}
	b.server.challenge(w)
	http.Error(w, "unauthorised", http.StatusUnauthorized)
	return "", false
}

// webdavIndex lists the shares this person may open, which is what a browser
// pointed at the root should show rather than a 404.
func (s *server) webdavIndex(served []*share) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		user := ""
		if len(s.who) > 0 || s.oidc != nil {
			u, ok := s.bearer(r)
			if !ok {
				var p string
				u, p, ok = r.BasicAuth()
				ok = ok && s.matches(u, p)
			}
			if !ok {
				s.challenge(w)
				http.Error(w, "unauthorised", http.StatusUnauthorized)
				return
			}
			user = u
		}
		var b strings.Builder
		b.WriteString("<!doctype html>\n<title>" + html.EscapeString(s.name) + "</title>\n<ul>\n")
		for _, sh := range served {
			if !sh.mayUse(user) {
				continue
			}
			name := html.EscapeString(sh.name)
			b.WriteString(`<li><a href="/` + name + `/">` + name + "</a></li>\n")
		}
		b.WriteString("</ul>\n")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, b.String())
	}
}
