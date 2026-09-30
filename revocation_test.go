// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// listOf is a trivial list for testing the fetching: the body, parsed as a
// description, refused when it says "broken".
type listOf string

func (l listOf) describe() string { return string(l) }
func (listOf) expires() time.Time { return time.Time{} }
func parseListOf(b []byte) (revoked, error) {
	if strings.Contains(string(b), "broken") {
		return nil, errors.New("not a list")
	}
	return listOf(b), nil
}

// A list served over HTTPS: kept when it parses, confirmed by a 304, kept
// when a broken one arrives, refused when it is older than max_age -- the
// fail-closed rule -- and never "nothing revoked" for want of a copy.
func TestARevocationListFailsClosed(t *testing.T) {
	var body atomic.Value
	body.Store("v1")
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := body.Load().(string)
		if s := int(status.Load()); s != http.StatusOK {
			w.WriteHeader(s)
			return
		}
		if r.Header.Get("If-None-Match") == `"`+b+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"`+b+`"`)
		w.Write([]byte(b))
	}))
	defer srv.Close()
	now := time.Unix(1_000_000, 0)
	l, err := newRevocationList("test", srv.URL, "", "", time.Minute, time.Hour, parseListOf, &safeBuffer{})
	if err != nil {
		t.Fatal(err)
	}
	l.client = srv.Client()
	l.now = func() time.Time { return now }
	ctx := context.Background()

	// Never fetched: refused, not "nothing revoked".
	if _, err := l.get(); !errors.Is(err, errRevocationUnknown) {
		t.Fatalf("before any fetch: %v", err)
	}
	if changed, err := l.fetch(ctx); err != nil || !changed {
		t.Fatalf("first fetch: %v %v", changed, err)
	}
	if got, err := l.get(); err != nil || got.describe() != "v1" {
		t.Fatalf("after it: %v %v", got, err)
	}

	// 59 minutes later a 304 confirms the copy, and resets its age.
	now = now.Add(59 * time.Minute)
	if changed, err := l.fetch(ctx); err != nil || changed {
		t.Fatalf("304: %v %v", changed, err)
	}
	now = now.Add(59 * time.Minute)
	if _, err := l.get(); err != nil {
		t.Fatalf("a copy confirmed 59 minutes ago: %v", err)
	}

	// A broken list arrives: the last good one is kept...
	body.Store("broken")
	if _, err := l.fetch(ctx); err == nil {
		t.Fatal("a broken list was accepted")
	}
	if got, err := l.get(); err != nil || got.describe() != "v1" {
		t.Fatalf("after a broken list: %v %v", got, err)
	}
	// ...and ages: past max_age with nothing better, it is refused.
	now = now.Add(2 * time.Minute)
	if _, err := l.get(); !errors.Is(err, errRevocationUnknown) || !strings.Contains(err.Error(), "max_age") {
		t.Fatalf("a copy past max_age: %v", err)
	}

	// The server says 404 -- bridge does, when its CA is not configured:
	// an error, not an empty list.
	status.Store(http.StatusNotFound)
	if _, err := l.fetch(ctx); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("a 404: %v", err)
	}
	status.Store(http.StatusOK)
	body.Store("v2")
	if changed, err := l.fetch(ctx); err != nil || !changed {
		t.Fatalf("recovering: %v %v", changed, err)
	}
	if got, err := l.get(); err != nil || got.describe() != "v2" {
		t.Fatalf("recovered: %v %v", got, err)
	}
	if l.failures.Load() != 2 {
		t.Fatalf("failures counted %d, want 2", l.failures.Load())
	}
}

// The same from a file, which configuration management may put in place.
func TestARevocationListFromAFile(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "list", "v1")
	l, _ := newRevocationList("test", "", p, "", time.Minute, time.Hour, parseListOf, &safeBuffer{})
	if changed, err := l.fetch(context.Background()); err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if changed, _ := l.fetch(context.Background()); changed {
		t.Fatal("an unchanged file read as changed")
	}
	write(t, dir, "list", "v2")
	if changed, err := l.fetch(context.Background()); err != nil || !changed {
		t.Fatalf("a changed file: %v %v", changed, err)
	}
	if _, err := newRevocationList("test", "", p, filepath.Join(dir, "missing-ca.pem"), time.Minute, time.Hour, parseListOf, nil); err == nil {
		t.Fatal("a pinned CA file that does not exist was accepted")
	}
}

func TestRevocationListSettings(t *testing.T) {
	for _, c := range []struct{ url, file, refresh, maxAge, want string }{
		{"https://bridge.example/ssh/krl", "", "", "", ""},
		{"", "/etc/fileshare/bridge.krl", "30s", "10m", ""},
		{"http://bridge.example/ssh/krl", "", "", "", "over https"},
		{"https://x", "/x", "", "", "once"},
		{"", "relative.krl", "", "", "absolute"},
		{"https://x", "", "0s", "", "a second or more"},
		{"https://x", "", "10m", "1m", "shorter than"},
		{"https://x", "", "", "soon", "not a duration"},
	} {
		err := checkListSource("ssh_krl", c.url, c.file)
		if err == nil {
			_, _, err = listTiming("ssh_krl", c.refresh, c.maxAge)
		}
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v refused: %v", c, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%+v: %v, want %q", c, err, c.want)
		}
	}
}
