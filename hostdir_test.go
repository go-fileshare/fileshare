// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A directory of the host, written in the configuration, served over WebDAV:
// what a client writes lands in the tree, and a link planted in the tree that
// leads out of it is not followed.
func TestADirectoryShareServesTheHostTree(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "volume")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "on the host")
	secret := write(t, dir, "secret.txt", "outside the tree")
	linked := os.Symlink(secret, filepath.Join(tree, "escape")) == nil &&
		// The control: a link that stays in the tree. Without it, a refused
		// escape could mean only that links are never followed at all.
		os.Symlink("a.txt", filepath.Join(tree, "inside")) == nil

	r := start(t, onlyProtocol(t, dir, "webdav", fmt.Sprintf(`share "vol" {
  directory = %q
  allow     = ["alice"]
}
`, hclPath(tree))))

	if body, err := webdavGet(r, "alice", "hunter2", "/vol/a.txt"); err != nil || string(body) != "on the host" {
		t.Fatalf("read: %q %v", body, err)
	}
	if err := webdavPut(r, "alice", "hunter2", "/vol/b.txt", "from a client"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(tree, "b.txt")); err != nil || string(b) != "from a client" {
		t.Fatalf("on the host: %q %v", b, err)
	}
	if _, err := webdavGet(r, "bob", "swordfish", "/vol/a.txt"); err == nil {
		t.Fatal("bob, not allowed, read the share")
	}
	if linked {
		if body, err := webdavGet(r, "alice", "hunter2", "/vol/inside"); err != nil || string(body) != "on the host" {
			t.Fatalf("a link inside the tree: %q %v", body, err)
		}
		if body, err := webdavGet(r, "alice", "hunter2", "/vol/escape"); err == nil {
			t.Fatalf("a link out of the tree was followed: %q", body)
		}
	}
	if sh := r.srv.shareByName("vol"); sh.kind != "directory" || sh.readOnly {
		t.Fatalf("share: kind %q read-only %v", sh.kind, sh.readOnly)
	}
}
