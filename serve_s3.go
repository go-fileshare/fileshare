// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	objectapi "github.com/go-filesystems/s3"
)

// S3, over the same per-user tree SFTP serves.
//
// # A share is a bucket
//
// [github.com/go-filesystems/s3] maps the top-level directories of one
// Filesystem to buckets -- and unionFor already builds exactly that: a tree
// whose top level is the shares this person may use. So `GET /` lists their
// shares and `GET /photos/a.txt` reads through the share's driver, with the
// access rules applied by the union rather than by a second copy of them here.
//
// # An access key is a user, and a secret key is their password
//
// SigV4 proves possession of the secret without sending it, the way NTLMv2
// does, so the same column of the directory answers both: a source that holds
// the password or can derive from it can serve S3, and a source that can only
// CHECK a password cannot. `check` already prints that column.
//
// ⛔ The secret never leaves the directory. [directory.Identity.Derive] runs
// the SigV4 key schedule over the password and hands back only the key, which
// is why there is no Password() accessor anywhere in this file.
//
// # Why the outer handler exists
//
// The library verifies a signature against ONE credential lookup and serves
// ONE filesystem, both chosen when the Server is built. But which tree to
// serve depends on WHO signed, and who signed is known only by reading the
// request. So this reads the access key out of the request -- without trusting
// it -- picks that person's server, and lets the library do the actual
// verification. A forged access key selects a tree whose secret will not
// verify the signature, so naming somebody else buys nothing.
func serveS3(s *server, p *protocol, ln net.Listener) error {
	h := &s3ByUser{server: s, proto: p, byUser: map[string]http.Handler{}}
	return http.Serve(ln, h)
}

type s3ByUser struct {
	server *server
	proto  *protocol

	mu     sync.Mutex
	byUser map[string]http.Handler
	// limit bounds byUser; zero means s3CachedUsers. Only somebody the
	// directory knows gets an entry, so the directory already bounds it --
	// this is the second wall, for a directory of a million people.
	limit int

	strangerOnce sync.Once
	stranger     http.Handler
	strangerErr  error
}

// s3CachedUsers is how many people's servers are kept built at once.
const s3CachedUsers = 4096

func (h *s3ByUser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, ok := accessKeyOf(r)
	if !ok {
		// No credential at all. The library answers this the same way, but it
		// cannot be reached without choosing a user first.
		unsignedS3(w, r)
		return
	}
	srv, err := h.forUser(user)
	if err != nil {
		unsignedS3(w, r)
		return
	}
	srv.ServeHTTP(w, r)
}

// forUser builds, once, the server this person sees.
//
// ⛔ The access key is the request's CLAIM, read before any signature is
// checked. A name the directory does not know gets the one shared server
// that knows no secret -- the same answer it always got, the signature
// failing -- and never an entry of its own: keyed by an unverified string,
// the cache grew by a server and a key per request (200 requests with
// 512 KiB keys pinned 101 MiB, after GC, without one valid signature).
func (h *s3ByUser) forUser(user string) (http.Handler, error) {
	if _, known := h.server.person(user); !known {
		return h.strangers()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if srv, ok := h.byUser[user]; ok {
		return srv, nil
	}
	limit := h.limit
	if limit <= 0 {
		limit = s3CachedUsers
	}
	if len(h.byUser) >= limit {
		// Rebuilt on demand: a server is a view over shares already open,
		// cheap to make again, and dropping them all keeps this simple.
		clear(h.byUser)
	}
	shares := h.server.sharesFor(h.proto, local(user))
	if len(shares) == 0 {
		// A person with no shares gets a server over an empty tree rather than
		// an error naming them: whether a user exists is not a thing an
		// unauthenticated request should be able to learn.
		shares = nil
	}
	srv, err := objectapi.New(unionFor(shares, local(user)), h.server.s3Secret(user))
	if err != nil {
		return nil, err
	}
	// Read-only until the write path here is worked out: the library's writes
	// go through the union, and a share this person may only read must refuse
	// them at the same place SFTP does. Left off rather than half-done.
	srv.ReadOnly = true
	h.byUser[user] = srv
	return srv, nil
}

// strangers is the server every access key the directory does not know is
// sent to: an empty tree, and a credential lookup that knows nobody, so the
// library refuses the signature exactly as it would for that key's own.
func (h *s3ByUser) strangers() (http.Handler, error) {
	h.strangerOnce.Do(func() {
		srv, err := objectapi.New(unionFor(nil, principal{}), func(string) (string, bool) { return "", false })
		if err != nil {
			h.strangerErr = err
			return
		}
		srv.ReadOnly = true // as everybody else's
		h.stranger = srv
	})
	return h.stranger, h.strangerErr
}

// s3Secret answers the library's credential lookup for ONE user.
//
// ⛔ It answers for that user and nobody else. A lookup that resolved any
// access key would let a request signed by alice be verified against bob's
// tree, because the tree is chosen from the same untrusted header.
func (s *server) s3Secret(user string) func(string) (string, bool) {
	return func(id string) (string, bool) {
		if id != user {
			return "", false
		}
		idn, ok := s.person(user)
		if !ok {
			return "", false
		}
		// Derive is the generic form of the old KerberosKey: the password goes
		// in, only the result comes out. Here the "derivation" is the identity
		// function, because SigV4's own key schedule lives in the library --
		// but routing it through Derive is what keeps the password from having
		// an accessor at all.
		secret, err := idn.Derive(func(password string) ([]byte, error) {
			return []byte(password), nil
		})
		if err != nil {
			// A source that can only CHECK a password cannot serve S3, and
			// saying nothing here is right: the signature then fails, and
			// `check` already said so at configuration time.
			return "", false
		}
		return string(secret), true
	}
}

// accessKeyOf reads the access key a request CLAIMS, from either form.
//
// ⚠ This is untrusted input and is used only to choose which credential to
// verify against. It is not authentication and nothing is granted by it.
func accessKeyOf(r *http.Request) (string, bool) {
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "AWS4-HMAC-SHA256 ") {
		for _, part := range strings.Split(strings.TrimPrefix(v, "AWS4-HMAC-SHA256 "), ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "Credential=") {
				return keyFromCredential(strings.TrimPrefix(part, "Credential="))
			}
		}
		return "", false
	}
	if v := r.URL.Query().Get("X-Amz-Credential"); v != "" {
		return keyFromCredential(v)
	}
	return "", false
}

func keyFromCredential(v string) (string, bool) {
	if dec, err := url.QueryUnescape(v); err == nil {
		v = dec
	}
	id, _, ok := strings.Cut(v, "/")
	return id, ok && id != ""
}

// unsignedS3 answers in the shape an S3 client parses, rather than with a bare
// status a client reports as "unknown error".
func unsignedS3(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<Error><Code>AccessDenied</Code>` +
		`<Message>the request was not signed by a key this server knows</Message></Error>`))
}
