// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Over WebDAV each person reaches their own worker's tree: what alice writes
// is in alice's, bob reads his own and may not write, carol -- whom the
// launcher refuses -- gets 403, and the reason is in the log only.
func TestIdentityWebDAV(t *testing.T) {
	needSetuid(t)
	needUsers(t)
	l := &fakeLauncher{root: t.TempDir(), refuse: map[string]bool{"carol": true}}
	r := startWith(t, identityConfig(t, `serve "webdav" { addr = "127.0.0.1:0" }`, passwordUsers(t)), func(s *server) {
		s.workers = newWorkerPool(l.get, time.Hour)
		s.closers = append(s.closers, s.workers)
	})
	if err := webdavPut(r, "alice", "alice-pw", "/home/note.txt", "alice's"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(l.root, "home", "alice", "note.txt"))
	if err != nil || string(got) != "alice's" {
		t.Fatalf("alice's write is not in alice's tree: %q %v", got, err)
	}
	if b, err := webdavGet(r, "alice", "alice-pw", "/home/note.txt"); err != nil || string(b) != "alice's" {
		t.Fatalf("alice reads back %q %v", b, err)
	}
	if _, err := webdavGet(r, "bob", "bob-pw", "/home/note.txt"); err == nil {
		t.Fatal("bob reads alice's file: the workers are not per person")
	}
	if err := webdavPut(r, "bob", "bob-pw", "/home/mine.txt", "x"); err == nil {
		t.Fatal("bob, who is not a writer, wrote")
	}
	err = webdavPut(r, "carol", "carol-pw", "/home/x.txt", "x")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("carol, refused by the launcher, got %v", err)
	}
	if !strings.Contains(r.out.String(), "carol: no system account") {
		t.Fatalf("the refusal is not in the log:\n%s", r.out.String())
	}
	if n := l.started.Load(); n != 2 {
		t.Fatalf("%d workers for alice and bob", n)
	}
}

// A server no launcher started serves a share served as its people to
// nobody: 503, never the tree as this process.
func TestIdentityWebDAVWithoutLauncher(t *testing.T) {
	needSetuid(t)
	needUsers(t)
	r := start(t, identityConfig(t, `serve "webdav" { addr = "127.0.0.1:0" }`, passwordUsers(t)))
	err := webdavPut(r, "alice", "alice-pw", "/home/x.txt", "x")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("got %v", err)
	}
}
