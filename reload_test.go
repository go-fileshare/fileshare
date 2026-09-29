// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql && !nowebdav

package main

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// reloading is a server whose people are in a SQLite database the test
// changes under it, served over WebDAV through run.
type reloading struct {
	srv    *server
	webdav string
	db     *sql.DB
}

func startReloading(t *testing.T, serves string) *reloading {
	t.Helper()
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
`)
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "engineers only")
	open := filepath.Join(dir, "open")
	os.MkdirAll(open, 0o755)
	write(t, open, "b.txt", "anyone")
	srv, addrs := runServer(t, fmt.Sprintf(`
users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
  groups   = "select team, member from teams"
}
share "t" {
  directory = %q
  allow     = ["@engineers"]
}
share "open" { directory = %q }
%s`, hclPath(dsn), hclPath(tree), hclPath(open), serves))
	path := strings.TrimSpace(readFile(t, dsn))
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &reloading{srv: srv, webdav: addrs["webdav"], db: db}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *reloading) exec(t *testing.T, q string) {
	t.Helper()
	if _, err := r.db.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func (r *reloading) get(user, password, path string) int {
	req, _ := http.NewRequest(http.MethodGet, "http://"+r.webdav+path, nil)
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}

// keepAlive is one WebDAV connection that stays open, asked again and again.
type keepAlive struct {
	c    net.Conn
	r    *bufio.Reader
	auth string
}

func (r *reloading) keepAlive(t *testing.T, user, password string) *keepAlive {
	t.Helper()
	c, err := net.Dial("tcp", r.webdav)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &keepAlive{c: c, r: bufio.NewReader(c), auth: base64.StdEncoding.EncodeToString([]byte(user + ":" + password))}
}

func (k *keepAlive) get(path string) (int, error) {
	fmt.Fprintf(k.c, "GET %s HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n", path, k.auth)
	k.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	res, err := http.ReadResponse(k.r, nil)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode, nil
}

// Somebody new is added in place: nobody is disconnected, and they can log in.
func TestAReloadAddsWithoutDisconnecting(t *testing.T) {
	needUsers(t)
	r := startReloading(t, `serve "webdav" { addr = "127.0.0.1:0" }`)
	dora := r.keepAlive(t, "dora", "hunter2")
	if code, err := dora.get("/t/a.txt"); err != nil || code != http.StatusOK {
		t.Fatalf("control: %d %v", code, err)
	}
	if r.get("fay", "correct horse", "/open/b.txt") != http.StatusUnauthorized {
		t.Fatal("fay is not in the database yet, and got in")
	}

	r.exec(t, `insert into staff values ('fay', 'correct horse')`)
	res, err := r.srv.reload()
	if err != nil || !slices.Equal(res.added, []string{"fay"}) || res.swapped {
		t.Fatalf("reload: %+v %v", res, err)
	}
	if code := r.get("fay", "correct horse", "/open/b.txt"); code != http.StatusOK {
		t.Fatalf("fay after the reload: %d", code)
	}
	if code, err := dora.get("/t/a.txt"); err != nil || code != http.StatusOK {
		t.Fatalf("an addition disconnected somebody else: %d %v", code, err)
	}
	if r.srv.generationNumber() != 1 {
		t.Fatal("an addition started a new generation")
	}
	// Reading an unchanged directory again changes nothing, and says so.
	if _, err := r.srv.reload(); !errors.Is(err, errUnchanged) {
		t.Fatalf("an unchanged directory: %v", err)
	}
}

// Somebody removed, a password changed, somebody out of a group: each is a
// revocation, and reaches the connections already open.
func TestAReloadRevokes(t *testing.T) {
	needUsers(t)
	r := startReloading(t, `serve "webdav" { addr = "127.0.0.1:0" }`)

	// Out of the group, still a person: the share she had is gone, the open
	// connection with it.
	dora := r.keepAlive(t, "dora", "hunter2")
	if code, err := dora.get("/t/a.txt"); err != nil || code != http.StatusOK {
		t.Fatalf("control: %d %v", code, err)
	}
	r.exec(t, `delete from teams where member = 'dora'`)
	res, err := r.srv.reload()
	if err != nil || !res.swapped || res.closed < 1 {
		t.Fatalf("leaving a group: %+v %v", res, err)
	}
	if _, err := dora.get("/t/a.txt"); err == nil {
		t.Fatal("a connection outlived its person leaving the group")
	}
	if code := r.get("dora", "hunter2", "/t/a.txt"); code != http.StatusNotFound {
		t.Fatalf("dora, out of @engineers: %d", code)
	}
	if code := r.get("dora", "hunter2", "/open/b.txt"); code != http.StatusOK {
		t.Fatalf("dora still has the open share: %d", code)
	}
	// The group is now empty -- the only member left it -- so it no longer
	// exists as far as the directory can say, and it is noted, not refused.
	if !slices.ContainsFunc(res.notes, func(n string) bool { return strings.Contains(n, "@engineers") }) {
		t.Errorf("notes: %v", res.notes)
	}

	// A changed password: the old one stops working.
	r.exec(t, `update staff set secret = 'tr0ub4dor' where login = 'eli'`)
	res, err = r.srv.reload()
	if err != nil || !slices.Equal(res.changed, []string{"eli"}) || !res.swapped {
		t.Fatalf("a changed password: %+v %v", res, err)
	}
	if r.get("eli", "swordfish", "/open/b.txt") != http.StatusUnauthorized ||
		r.get("eli", "tr0ub4dor", "/open/b.txt") != http.StatusOK {
		t.Fatal("after a password change, the old one must fail and the new one work")
	}

	// Removed.
	eli := r.keepAlive(t, "eli", "tr0ub4dor")
	if code, err := eli.get("/open/b.txt"); err != nil || code != http.StatusOK {
		t.Fatalf("control: %d %v", code, err)
	}
	r.exec(t, `delete from staff where login = 'eli'`)
	res, err = r.srv.reload()
	if err != nil || !slices.Equal(res.removed, []string{"eli"}) || !res.swapped {
		t.Fatalf("removed: %+v %v", res, err)
	}
	if _, err := eli.get("/open/b.txt"); err == nil {
		t.Fatal("a removed person's open connection still answers")
	}
	if r.get("eli", "tr0ub4dor", "/open/b.txt") != http.StatusUnauthorized {
		t.Fatal("a removed person still gets in")
	}
}

// ⛔ A directory that cannot be read changes NOTHING: an outage must not
// empty a file server.
func TestABrokenDirectoryChangesNothing(t *testing.T) {
	needUsers(t)
	r := startReloading(t, `serve "webdav" { addr = "127.0.0.1:0" }`)
	r.exec(t, `alter table staff rename to gone`)
	if _, err := r.srv.reload(); err == nil || errors.Is(err, errUnchanged) {
		t.Fatalf("a directory that cannot be read: %v", err)
	}
	if len(r.srv.people()) != 2 || r.srv.generationNumber() != 1 {
		t.Fatalf("a failed read changed the server: %d people, generation %d",
			len(r.srv.people()), r.srv.generationNumber())
	}
	if code := r.get("dora", "hunter2", "/t/a.txt"); code != http.StatusOK {
		t.Fatalf("after a failed read: %d", code)
	}
	if r.srv.stats.reloads.failed.Load() != 1 {
		t.Fatal("the failure was not counted")
	}
}
