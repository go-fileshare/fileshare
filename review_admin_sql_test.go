// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav && !nosql

package main

// The review's admin tests that need an SQL directory; see review_admin_test.go.

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
)

// R6: an admin change re-resolves EVERY share against the directory, strictly.
// Once a group a configuration share names has emptied out of SQL (or a person
// it names directly was deleted), every admin change is refused -- including
// Revoke and DisableShare on unrelated API shares -- until a person edits the
// configuration. The directory reload itself tolerates it.
func TestFoundDirectoryDriftBlocksRevoke(t *testing.T) {
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
`)
	engTree := filepath.Join(dir, "eng")
	os.MkdirAll(engTree, 0o755)
	m := startManaged(t, dir, `users "sql" {
  driver   = "sqlite"
  dsn_file = "`+hclPath(dsn)+`"
  users    = "select login, secret from staff"
  groups   = "select team, member from teams"
}
share "eng" {
  directory = "`+hclPath(engTree)+`"
  allow     = ["@engineers"]
}`)
	ctx := context.Background()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "secret")
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ),
			grantOf(userSubject("bob"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(readFile(t, dsn))
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`delete from teams`); err != nil {
		t.Fatal(err)
	}
	if _, err := m.client.ReloadDirectory(ctx, &adminv1.ReloadDirectoryRequest{}); err != nil {
		t.Logf("reload: %v", err)
	}
	_, err = m.client.Revoke(ctx, &adminv1.RevokeRequest{Share: "t", Subject: userSubject("alice")})
	t.Logf("Revoke alice on t: %v", err)
	_, err2 := m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "t"})
	t.Logf("DisableShare t: %v", err2)
	if code, _ := m.get("alice", "hunter2", "/t/a.txt"); code == http.StatusOK && err != nil {
		t.Errorf("BUG: alice could not be revoked (%v) and still reads /t/a.txt", err)
	}
}

// R1b: the same read-only fallback share makes every REVOKING directory reload
// fail -- so a person deleted from the directory keeps authenticating.
func TestFoundReadOnlyFallbackBlocksReload(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	dir := t.TempDir()
	img := image(t, dir, "ro.img", map[string]string{"/a.txt": "x"})
	os.Chmod(img, 0o444)
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
`)
	open := filepath.Join(dir, "open")
	os.MkdirAll(open, 0o755)
	write(t, open, "b.txt", "anyone")
	srv, addrs := runServer(t, `users "sql" {
  driver   = "sqlite"
  dsn_file = "`+hclPath(dsn)+`"
  users    = "select login, secret from staff"
}
share "iso" { image = "`+hclPath(img)+`" }
share "open" { directory = "`+hclPath(open)+`" }
serve "webdav" { addr = "127.0.0.1:0" }`)
	get := func(u, p string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addrs["webdav"]+"/open/b.txt", nil)
		req.SetBasicAuth(u, p)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := get("eli", "swordfish"); c != 200 {
		t.Fatalf("control: %d", c)
	}
	db, _ := sql.Open("sqlite", strings.TrimSpace(readFile(t, dsn)))
	defer db.Close()
	db.Exec(`delete from staff where login = 'eli'`)
	r, err := srv.reload()
	t.Logf("reload: %+v %v", r, err)
	if c := get("eli", "swordfish"); c == 200 {
		t.Errorf("BUG: eli was deleted from the directory and still reads /open/b.txt after the reload")
	}
}
