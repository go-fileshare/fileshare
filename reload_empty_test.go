// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql && !nowebdav

package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Whether WebDAV asks for a password is what the configuration says -- a
// users block is there -- and never how many people that directory holds
// right now. The audit emptied the SQL directory (the last application
// password deleted), reloaded, and WebDAV served "anyone who authenticates"
// to anonymous clients, read-write: an anonymous PUT planted a file.
func TestAnEmptyDirectoryStillAsksForAPassword(t *testing.T) {
	r := startReloading(t, `serve "webdav" { addr = "127.0.0.1:0" }`)
	anon := func(method, path, body string) *http.Response {
		req, _ := http.NewRequest(method, "http://"+r.webdav+path, strings.NewReader(body))
		res, err := reloadClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}
	// The control: somebody the directory knows gets in, before.
	if code := r.get("dora", "hunter2", "/open/b.txt"); code != http.StatusOK {
		t.Fatalf("before: dora GET /open/b.txt -> %d", code)
	}
	r.exec(t, `delete from staff`)
	r.exec(t, `delete from teams`)
	if res, err := r.srv.reload(); err != nil || len(res.removed) != 2 {
		t.Fatalf("reload: removed=%v err=%v; the directory was not emptied", res.removed, err)
	}
	if len(r.srv.people()) != 0 {
		t.Fatalf("the directory still holds %d people", len(r.srv.people()))
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/open/b.txt", ""},
		{"PUT", "/open/planted.txt", "anonymous write"},
		{"GET", "/", ""},
	} {
		res := anon(c.method, c.path, c.body)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("after: anonymous %s %s -> %d, want 401", c.method, c.path, res.StatusCode)
		}
		if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("after: %s %s offers %q, want the Basic challenge", c.method, c.path, res.Header.Values("WWW-Authenticate"))
		}
	}
	if _, err := os.Stat(filepath.Join(r.srv.shareByName("open").block.Directory, "planted.txt")); err == nil {
		t.Error("an anonymous PUT wrote planted.txt")
	}
}

// The same rule at start: a users block whose directory holds nobody yet is
// a server that asks for a password, not an anonymous one.
func TestADirectoryEmptyAtStartStillAsksForAPassword(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `create table staff (login text primary key, secret text);`)
	open := filepath.Join(dir, "open")
	os.MkdirAll(open, 0o755)
	write(t, open, "b.txt", "anyone who authenticates")
	_, addrs := runServer(t, `
users "sql" {
  driver   = "sqlite"
  dsn_file = "`+hclPath(dsn)+`"
  users    = "select login, secret from staff"
}
share "open" { directory = "`+hclPath(open)+`" }
serve "webdav" { addr = "127.0.0.1:0" }
`)
	res, err := reloadClient.Get("http://" + addrs["webdav"] + "/open/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous GET over an empty directory -> %d, want 401", res.StatusCode)
	}
}
