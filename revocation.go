// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Revocation lists, fetched and kept.
//
// A certificate is checked when it is presented, and the identity provider
// can take a person back afterwards -- go-authn/bridge's DisablePerson. What
// carries that decision here is a list the provider publishes: an OpenSSH
// KRL for the SSH certificates it signed (PROTOCOL.krl), an X.509 CRL for the
// client certificates NFS is given (RFC 5280). This is the part that keeps a
// copy of one.
//
// ⛔ It FAILS CLOSED. A list that could not be fetched, or whose last good
// copy is older than max_age, is not "nothing is revoked": it is "this server
// does not know", and the certificates it governs are refused until it knows
// again. A revocation check that lets everything through when the list is
// unreachable is the one an attacker who can block the list defeats -- the
// reason browsers' soft-fail OCSP was called "a seat-belt that snaps when you
// crash" (Langley, 2014). The price is availability: the provider's list must
// be served as reliably as the logins it governs. max_age is the tolerance.
//
// The copy is kept whole, and replaced only by a list that parsed: a list
// that arrives broken leaves the last good one in place, still counting
// towards max_age from when IT was fetched.

// revocationList is one list: where it comes from, how to read it, and the
// last copy that did read.
type revocationList struct {
	name    string // "ssh_krl", "x509_crl": the metrics label
	url     string
	file    string
	client  *http.Client
	refresh time.Duration
	maxAge  time.Duration
	parse   func([]byte) (revoked, error)
	now     func() time.Time
	out     io.Writer

	mu      sync.RWMutex
	current revoked
	raw     []byte
	etag    string
	fetched time.Time // when the current copy was last confirmed
	lastErr error

	failures atomic.Uint64
}

// revoked is what a list answers once parsed. expires, when not zero, is a
// moment past which the list itself says it must not be trusted -- a CRL's
// NextUpdate -- whatever max_age allows.
type revoked interface {
	describe() string
	expires() time.Time
}

// errRevocationUnknown is why a certificate is refused when the list cannot
// say.
var errRevocationUnknown = errors.New("its revocation list is not known to be current, so it is refused")

func newRevocationList(name, url, file, caFile string, refresh, maxAge time.Duration,
	parse func([]byte) (revoked, error), out io.Writer) (*revocationList, error) {
	l := &revocationList{name: name, url: url, file: file, refresh: refresh, maxAge: maxAge,
		parse: parse, now: time.Now, out: out,
		client: &http.Client{Timeout: 30 * time.Second}}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: %s holds no PEM certificate", name, caFile)
		}
		l.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return l, nil
}

// current is the list as last fetched, or why it cannot be used.
func (l *revocationList) get() (revoked, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	switch now := l.now(); {
	case l.current == nil:
		if l.lastErr != nil {
			return nil, fmt.Errorf("%w: it was never fetched (%v)", errRevocationUnknown, l.lastErr)
		}
		return nil, fmt.Errorf("%w: it was never fetched", errRevocationUnknown)
	case now.Sub(l.fetched) > l.maxAge:
		return nil, fmt.Errorf("%w: the last good copy is %s old, and max_age is %s",
			errRevocationUnknown, now.Sub(l.fetched).Round(time.Second), l.maxAge)
	case !l.current.expires().IsZero() && now.After(l.current.expires()):
		return nil, fmt.Errorf("%w: it said it expires at %s", errRevocationUnknown, l.current.expires().UTC().Format(time.RFC3339))
	}
	return l.current, nil
}

// age is how old the last good copy is, for the metrics; -1 when there is none.
func (l *revocationList) age() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.current == nil {
		return -1
	}
	return l.now().Sub(l.fetched).Seconds()
}

// fetch reads the list once, and keeps it if it parses. It reports whether
// the content changed.
func (l *revocationList) fetch(ctx context.Context) (changed bool, err error) {
	defer func() {
		if err != nil {
			l.failures.Add(1)
			l.mu.Lock()
			l.lastErr = err
			l.mu.Unlock()
		}
	}()
	var body []byte
	if l.file != "" {
		if body, err = os.ReadFile(l.file); err != nil {
			return false, err
		}
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
		if err != nil {
			return false, err
		}
		l.mu.RLock()
		if l.etag != "" && l.current != nil {
			req.Header.Set("If-None-Match", l.etag)
		}
		l.mu.RUnlock()
		res, err := l.client.Do(req)
		if err != nil {
			return false, err
		}
		defer res.Body.Close()
		switch res.StatusCode {
		case http.StatusNotModified:
			l.mu.Lock()
			l.fetched, l.lastErr = l.now(), nil
			l.mu.Unlock()
			return false, nil
		case http.StatusOK:
		default:
			// A 404 is what go-authn/bridge answers when the CA is not
			// configured there: not a list, and so not a list that revokes
			// nothing.
			return false, fmt.Errorf("%s answered %s", l.url, res.Status)
		}
		// Bounded: a list is a few kilobytes, and a server answering with an
		// endless body must not be able to fill this one's memory.
		if body, err = io.ReadAll(io.LimitReader(res.Body, 64<<20)); err != nil {
			return false, err
		}
		defer func(tag string) {
			if err == nil {
				l.mu.Lock()
				l.etag = tag
				l.mu.Unlock()
			}
		}(res.Header.Get("ETag"))
	}
	l.mu.RLock()
	same := l.current != nil && bytes.Equal(body, l.raw)
	l.mu.RUnlock()
	if same {
		l.mu.Lock()
		l.fetched, l.lastErr = l.now(), nil
		l.mu.Unlock()
		return false, nil
	}
	parsed, err := l.parse(body)
	if err != nil {
		return false, fmt.Errorf("%s: %w; the last good copy is kept", l.source(), err)
	}
	l.mu.Lock()
	l.current, l.raw, l.fetched, l.lastErr = parsed, body, l.now(), nil
	l.mu.Unlock()
	return true, nil
}

func (l *revocationList) source() string {
	if l.file != "" {
		return l.file
	}
	return l.url
}

// run fetches every refresh until stop, saying what changed and what failed
// -- a failure once per streak, not once a minute.
func (l *revocationList) run(stop <-chan struct{}) {
	failing := false
	fetch := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		changed, err := l.fetch(ctx)
		switch {
		case err != nil && !failing:
			fmt.Fprintf(l.out, "%s: %v\n", l.name, err)
			failing = true
		case err == nil:
			if failing {
				fmt.Fprintf(l.out, "%s: fetched again from %s\n", l.name, l.source())
			}
			failing = false
			if changed {
				cur, _ := l.get()
				if cur != nil {
					fmt.Fprintf(l.out, "%s: %s\n", l.name, cur.describe())
				}
			}
		}
	}
	fetch()
	t := time.NewTicker(l.refresh)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			fetch()
		}
	}
}
