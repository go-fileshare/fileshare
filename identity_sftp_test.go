// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Over SFTP a session takes its worker at login and gives it back when the
// connection ends -- nothing else would: sftp.Server never closes the tree.
func TestIdentitySFTP(t *testing.T) {
	needSetuid(t)
	aliceKey, alicePub := keyPair(t)
	carolKey, carolPub := keyPair(t)
	users := fmt.Sprintf("user \"alice\" { authorized_keys = [%q] }\nuser \"bob\" { authorized_keys = [%q] }\nuser \"carol\" { authorized_keys = [%q] }\n",
		alicePub, alicePub, carolPub)
	l := &fakeLauncher{root: t.TempDir(), refuse: map[string]bool{"carol": true}}
	var pool *workerPool
	r := startWith(t, identityConfig(t, `serve "sftp" { addr = "127.0.0.1:0" }`, users), func(s *server) {
		pool = newWorkerPool(l.get, 10*time.Millisecond)
		s.workers = pool
		s.closers = append(s.closers, s.workers)
	})
	cl, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(aliceKey))
	if err != nil {
		t.Fatal(err)
	}
	f, err := cl.Create("/home/note.txt")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(f, "alice's")
	f.Close()
	if got, err := os.ReadFile(filepath.Join(l.root, "home", "alice", "note.txt")); err != nil || string(got) != "alice's" {
		t.Fatalf("alice's write is not in alice's tree: %q %v", got, err)
	}
	if pool.size() != 1 {
		t.Fatalf("%d workers during alice's session", pool.size())
	}
	done()
	deadline := time.Now().Add(5 * time.Second)
	for pool.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("alice's worker outlived her connection")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// carol: the launcher refuses her, the share is left out of her tree,
	// and a tree with nothing in it is a refused login.
	if _, done, err := sftpAs(t, r.addrs["sftp"], "carol", ssh.PublicKeys(carolKey)); err == nil {
		done()
		t.Fatal("carol, refused by the launcher, logged in to an empty tree")
	}
	if !strings.Contains(r.out.String(), "home left out: carol: no system account") {
		t.Fatalf("the refusal is not in the log:\n%s", r.out.String())
	}
}
