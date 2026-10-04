// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	// verify, when set, authenticates a list fetched from url before it is
	// read: the KRL's detached signature (krl_sftp.go). tag is the list's
	// ETag, for the If-Match its signature is fetched with.
	// It returns the signature it checked, which the state file keeps.
	verify func(ctx context.Context, body []byte, tag string) (sig []byte, err error)
	// reverify checks a list and signature read back from stateFile.
	reverify func(raw, sig []byte) error
	// stateFile, when set, keeps the last list that verified across a
	// restart: what orders the next one (go-authn/revocation's PROTOCOL.md
	// rule 2). Without it, a restart forgets which list is newer, and a
	// replayed older list -- signed, unexpired -- is taken (found by the
	// adversarial review of v0.15.0).
	stateFile string
	sig       []byte
	now       func() time.Time
	out       io.Writer

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
	// older reports whether this list is older than another of its kind:
	// a lower CRL Number, a lower KRL version.
	older(than revoked) bool
}

// errRevocationUnknown is why a certificate is refused when the list cannot
// say.
var errRevocationUnknown = errors.New("its revocation list is not known to be current, so it is refused")

func newRevocationList(name, url, file, caFile string, refresh, maxAge time.Duration,
	parse func([]byte) (revoked, error), out io.Writer) (*revocationList, error) {
	l := &revocationList{name: name, url: url, file: file, refresh: refresh, maxAge: maxAge,
		parse: parse, now: time.Now, out: out,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: httpsOnlyRedirect}}
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

// httpsOnlyRedirect refuses a redirect that would leave https: the https
// rule is on the configured URL, and a list fetched in the clear after a
// redirect is one a network attacker writes (found by the security review).
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("a redirect to %s leaves https", req.URL.Redacted())
	}
	if len(via) >= 5 {
		return fmt.Errorf("more than 5 redirects")
	}
	return nil
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

// errReissued is a list issued again between its fetch and its signature's:
// the issuer answered 412 to If-Match. Fetched again at once.
var errReissued = errors.New("the list was issued again while its signature was fetched")

// fetch reads the list once, and keeps it if it parses. It reports whether
// the content changed.
func (l *revocationList) fetch(ctx context.Context) (changed bool, err error) {
	changed, err = l.fetchOnce(ctx)
	if errors.Is(err, errReissued) {
		changed, err = l.fetchOnce(ctx)
	}
	return changed, err
}

// fetchSignature fetches url + ".sig", the signature of the list whose ETag
// is tag, with the rules the list itself is fetched with: https, bounded.
func (l *revocationList) fetchSignature(ctx context.Context, tag string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url+".sig", nil)
	if err != nil {
		return nil, err
	}
	if tag != "" {
		req.Header.Set("If-Match", tag)
	}
	res, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.Request != nil && res.Request.URL.Scheme != "https" {
		return nil, fmt.Errorf("%s.sig was answered from %s, which is not https", l.url, res.Request.URL.Redacted())
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusPreconditionFailed:
		return nil, errReissued
	default:
		// go-authn/bridge before v0.10.0 serves no signature: its lists
		// cannot be told from forged ones, and are refused.
		return nil, fmt.Errorf("%s.sig answered %s: the list cannot be verified", l.url, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, 64<<10))
}

func (l *revocationList) fetchOnce(ctx context.Context) (changed bool, err error) {
	defer func() {
		if err != nil {
			l.failures.Add(1)
			l.mu.Lock()
			l.lastErr = err
			l.mu.Unlock()
		}
	}()
	var body []byte
	var tag string
	if l.file != "" {
		if body, err = os.ReadFile(l.file); err != nil {
			return false, err
		}
	} else {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
		if rerr != nil {
			return false, rerr
		}
		// ⛔ Only the tag of the copy held, and only when one is held: a 304
		// is "what you hold is current", and must never vouch for a copy
		// that did not parse (found by the security review: the tag of a
		// broken list, sent back, kept a stale one "fresh" for ever).
		l.mu.RLock()
		if l.etag != "" && l.current != nil {
			req.Header.Set("If-None-Match", l.etag)
		}
		l.mu.RUnlock()
		res, rerr := l.client.Do(req)
		if rerr != nil {
			return false, rerr
		}
		defer res.Body.Close()
		// Where the answer came FROM, whatever client asked: a redirect to
		// http is refused by the client's own policy, and checked here too.
		if res.Request != nil && res.Request.URL.Scheme != "https" {
			return false, fmt.Errorf("%s was answered from %s, which is not https", l.url, res.Request.URL.Redacted())
		}
		switch res.StatusCode {
		case http.StatusNotModified:
			l.mu.Lock()
			held := l.current != nil
			if held {
				l.fetched, l.lastErr = l.now(), nil
			}
			l.mu.Unlock()
			if !held {
				return false, fmt.Errorf("%s answered 304 with no copy held", l.url)
			}
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
		tag = res.Header.Get("ETag")
	}
	l.mu.RLock()
	same := l.current != nil && bytes.Equal(body, l.raw)
	current := l.current
	l.mu.RUnlock()
	if same {
		l.mu.Lock()
		l.fetched, l.lastErr, l.etag = l.now(), nil, tag
		l.mu.Unlock()
		return false, nil
	}
	var sig []byte
	if l.verify != nil && l.file == "" {
		if sig, err = l.verify(ctx, body, tag); err != nil {
			if errors.Is(err, errReissued) {
				return false, err
			}
			return false, fmt.Errorf("%s: %w; the last good copy is kept", l.source(), err)
		}
	}
	parsed, err := l.parse(body)
	if err != nil {
		return false, fmt.Errorf("%s: %w; the last good copy is kept", l.source(), err)
	}
	// ⛔ Never backwards: an older list than the one held would un-revoke
	// what the newer one revoked (a replayed CRL, a restored backup).
	if current != nil && parsed.older(current) {
		return false, fmt.Errorf("%s: %s is older than the %s held; the newer one is kept", l.source(),
			parsed.describe(), current.describe())
	}
	l.mu.Lock()
	l.current, l.raw, l.sig, l.fetched, l.lastErr, l.etag = parsed, body, sig, l.now(), nil, tag
	l.mu.Unlock()
	if l.stateFile != "" {
		if err := writeFileAtomically(l.stateFile, encodeListState(body, sig)); err != nil {
			// Kept in memory and served; only the order across a restart
			// is at stake, and said.
			fmt.Fprintf(l.out, "%s: keeping it in %s: %v\n", l.name, l.stateFile, err)
		}
	}
	return true, nil
}

// listStateMagic heads a state file: the list, its length first, then its
// signature (none for a CRL or a list from a file).
const listStateMagic = "fileshare-list-state 1\n"

func encodeListState(raw, sig []byte) []byte {
	b := append([]byte(listStateMagic), binary.BigEndian.AppendUint64(nil, uint64(len(raw)))...)
	return append(append(b, raw...), sig...)
}

func decodeListState(b []byte) (raw, sig []byte, err error) {
	rest, ok := bytes.CutPrefix(b, []byte(listStateMagic))
	if !ok || len(rest) < 8 {
		return nil, nil, errors.New("not a fileshare list state")
	}
	n := binary.BigEndian.Uint64(rest)
	if rest = rest[8:]; n > uint64(len(rest)) {
		return nil, nil, errors.New("a truncated fileshare list state")
	}
	return rest[:n], rest[n:], nil
}

// restore reads back the list kept in stateFile. It is verified again, and
// held to ORDER the next list only: it is not current -- its fetch time is
// unknown -- until a list is fetched. Anything wrong with it is said, and
// it is not used.
func (l *revocationList) restore() {
	if l.stateFile == "" {
		return
	}
	data, err := os.ReadFile(l.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var raw, sig []byte
	if err == nil {
		raw, sig, err = decodeListState(data)
	}
	if err == nil && l.reverify != nil {
		err = l.reverify(raw, sig)
	}
	var parsed revoked
	if err == nil {
		parsed, err = l.parse(raw)
	}
	if err != nil {
		fmt.Fprintf(l.out, "%s: the list kept in %s is not used: %v\n", l.name, l.stateFile, err)
		return
	}
	l.mu.Lock()
	l.current, l.raw, l.sig = parsed, raw, sig
	l.mu.Unlock()
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
