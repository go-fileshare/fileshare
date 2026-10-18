// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	filesystem "github.com/go-filesystems/interface"
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
	// Routed by the first path segment, compared as a name -- not through
	// ServeMux, whose patterns read a space as a method, braces as a
	// wildcard, and a name as syntax.
	routes := map[string]http.Handler{}
	served, _ := p.exports(s.cfg, s.currentShares())
	for _, sh := range served {
		prefix := "/" + sh.name
		space := webdav.WithCapacity(sh.size, 0)
		if sh.capacity != nil {
			// A directory: what it is now, not what it was at the start.
			space = webdav.WithCapacityFunc(sh.capacity)
		}
		if sh.system {
			// No handler over the tree here: each person gets theirs, over
			// their worker, when they first ask (byUser.asThem).
			routes[sh.name] = &byUser{server: s, share: sh, opts: []webdav.Option{webdav.WithPrefix(prefix), space}}
			continue
		}
		read, err := webdav.New(sh.fsys, webdav.WithPrefix(prefix), space)
		if err != nil {
			return fmt.Errorf("%s: %w", sh.name, err)
		}
		write, err := webdav.New(sh.fsys, webdav.WithPrefix(prefix), space, webdav.ReadWrite())
		if err != nil {
			return fmt.Errorf("%s: %w", sh.name, err)
		}
		routes[sh.name] = &byUser{server: s, share: sh, read: read, write: write}
	}
	index := s.webdavIndex(served)
	return s.httpServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if h, ok := routes[first]; ok && first != "" {
			h.ServeHTTP(w, r)
			return
		}
		if first != "" {
			// No such share -- answered exactly as a share this person may
			// not use is: the challenge first, to anybody who has not
			// authenticated, and 404 only after. Answering 404 here and 401
			// there told an anonymous client which names were shares.
			if _, ok := (&byUser{server: s}).authenticated(w, r); ok {
				http.NotFound(w, r)
			}
			return
		}
		index(w, r)
	})).Serve(ln)
}

// byUser authenticates, then hands the request to the handler that matches
// what this person may do.
type byUser struct {
	server      *server
	share       *share
	read, write http.Handler
	// opts are what a share served as its people builds each person's
	// handlers with.
	opts []webdav.Option
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
	if b.share.system {
		b.asThem(w, r, user)
		return
	}
	if b.share.readOnlyFor(user) {
		b.read.ServeHTTP(w, r)
		return
	}
	b.write.ServeHTTP(w, r)
}

// asThem serves a share served as its people through this person's worker,
// with a handler kept on the worker -- so a WebDAV lock taken by one request
// is there for the next one, for as long as the worker is.
//
// A refusal is told as little as a missing share is: 403 when the launcher
// refused this person (no account, or one the policy forbids), 503 when no
// worker could be started; the reason goes to the log, not to the client.
func (b *byUser) asThem(w http.ResponseWriter, r *http.Request, user principal) {
	wk, release, err := b.server.workerOf(user, b.share)
	if err != nil {
		fmt.Fprintf(b.server.out, "webdav: %s: %s: %v\n", user.name, b.share.name, err)
		var refused *refusedWorker
		if errors.As(err, &refused) {
			http.Error(w, "this share is not served to you", http.StatusForbidden)
			return
		}
		http.Error(w, "this share cannot be served now", http.StatusServiceUnavailable)
		return
	}
	defer release()
	name, opts := "webdav-read", b.opts
	if !b.share.readOnlyFor(user) {
		name, opts = "webdav-write", append(slices.Clone(b.opts), webdav.ReadWrite())
	}
	h, err := wk.attach(name, func(fsys filesystem.Filesystem) (any, error) { return webdav.New(fsys, opts...) })
	if err != nil {
		fmt.Fprintf(b.server.out, "webdav: %s: %s: %v\n", user.name, b.share.name, err)
		http.Error(w, "this share cannot be served now", http.StatusServiceUnavailable)
		return
	}
	h.(http.Handler).ServeHTTP(w, r)
}

// authenticated returns the user, or writes the challenge and returns false.
//
// A share nobody is named on still authenticates when there are users: a
// server with credentials should not hand its contents to somebody who never
// gave any. Only a configuration that declares no source of people and no
// provider is anonymous -- what the configuration SAYS, never how many people
// a directory holds at the moment (see declaresPeople).
func (b *byUser) authenticated(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if !b.server.declaresPeople() && b.server.oidc == nil {
		return principal{}, true
	}
	// A token first, because a client that sent one meant it: falling back to
	// asking for a password after refusing a token turns a rejected token
	// into a password prompt, which is confusing for a person and useless for
	// a program.
	if p, ok := b.server.bearer(r); ok {
		return p, true
	}
	// The comparison is the identity's own: it may be against a password this
	// server holds, or a question asked of a directory that holds it and will
	// not give it up. Either way it is constant-time where a comparison is
	// what happens.
	if user, password, ok := r.BasicAuth(); ok && b.server.matches(user, password) {
		return local(user), true
	}
	b.server.challenge(w)
	http.Error(w, "unauthorised", http.StatusUnauthorized)
	return principal{}, false
}

// webdavIndex answers at the root, which is no share: the shares this person
// may open. A browser gets them as a page (GET); a WebDAV client -- a file
// manager mounting the server, the go-fileshare explorer -- as the collection
// it asks about with PROPFIND (RFC 4918 §9.1), each share a collection in it.
// Nothing can be written there, and a method that would is 405.
func (s *server) webdavIndex(served []*share) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		var user principal
		if s.declaresPeople() || s.oidc != nil {
			u, ok := s.bearer(r)
			if !ok {
				name, pw, basic := r.BasicAuth()
				ok = basic && s.matches(name, pw)
				u = local(name)
			}
			if !ok {
				s.challenge(w)
				http.Error(w, "unauthorised", http.StatusUnauthorized)
				return
			}
			user = u
		}
		var names []string
		for _, sh := range served {
			if sh.mayUse(user) {
				names = append(names, sh.name)
			}
		}
		const allow = "OPTIONS, GET, HEAD, PROPFIND"
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			var b strings.Builder
			b.WriteString("<!doctype html>\n<title>" + html.EscapeString(s.name) + "</title>\n<ul>\n")
			for _, n := range names {
				n = html.EscapeString(n)
				b.WriteString(`<li><a href="/` + n + `/">` + n + "</a></li>\n")
			}
			b.WriteString("</ul>\n")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, b.String())
		case http.MethodOptions:
			w.Header().Set("DAV", "1")
			w.Header().Set("Allow", allow)
		case "PROPFIND":
			rootPropfind(w, r, names)
		default:
			w.Header().Set("Allow", allow)
			http.Error(w, "the root holds the shares and nothing else", http.StatusMethodNotAllowed)
		}
	}
}

// rootPropfind answers a PROPFIND of the root: itself, and at Depth 1 each
// share, all collections with a resourcetype and a displayname. A property
// asked for and not known is reported 404 (§9.1), not left out. Depth
// infinity -- also what no Depth header means -- is refused as §9.1 allows
// (403, propfind-finite-depth): the shares hold everything on the server.
func rootPropfind(w http.ResponseWriter, r *http.Request, shares []string) {
	depth := r.Header.Get("Depth")
	if depth != "0" && depth != "1" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+`<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`)
		return
	}
	var req struct {
		Prop *struct {
			Names []struct{ XMLName xml.Name } `xml:",any"`
		} `xml:"DAV: prop"`
		PropName *struct{} `xml:"DAV: propname"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(body)) > 0 { // an empty body is allprop (§9.1)
		if err := xml.Unmarshal(body, &req); err != nil {
			http.Error(w, "the body is not a propfind", http.StatusBadRequest)
			return
		}
	}
	type res struct{ href, name string }
	all := []res{{"/", "/"}}
	if depth == "1" {
		for _, n := range shares {
			all = append(all, res{"/" + (&url.URL{Path: n}).EscapedPath() + "/", n})
		}
	}
	esc := func(v string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n" + `<D:multistatus xmlns:D="DAV:">`)
	for _, x := range all {
		b.WriteString("<D:response><D:href>" + esc(x.href) + "</D:href>")
		known := map[string]string{
			"resourcetype": "<D:resourcetype><D:collection/></D:resourcetype>",
			"displayname":  "<D:displayname>" + esc(x.name) + "</D:displayname>",
		}
		switch {
		case req.PropName != nil:
			b.WriteString("<D:propstat><D:prop><D:resourcetype/><D:displayname/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
		case req.Prop != nil:
			var found, missing strings.Builder
			for i, n := range req.Prop.Names {
				if v, ok := known[n.XMLName.Local]; ok && n.XMLName.Space == "DAV:" {
					found.WriteString(v)
					continue
				}
				if n.XMLName.Space == "" { // no namespace: no prefix, there being no default one here
					fmt.Fprintf(&missing, `<%s/>`, n.XMLName.Local)
					continue
				}
				fmt.Fprintf(&missing, `<x%d:%s xmlns:x%d="%s"/>`, i, n.XMLName.Local, i, esc(n.XMLName.Space))
			}
			if found.Len() > 0 {
				b.WriteString("<D:propstat><D:prop>" + found.String() + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
			}
			if missing.Len() > 0 {
				b.WriteString("<D:propstat><D:prop>" + missing.String() + "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>")
			}
		default:
			b.WriteString("<D:propstat><D:prop>" + known["resourcetype"] + known["displayname"] + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
		}
		b.WriteString("</D:response>")
	}
	b.WriteString("</D:multistatus>")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, b.String())
}
