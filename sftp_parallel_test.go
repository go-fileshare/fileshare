// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sftp answers requests concurrently (go-filesystems/sftp v0.8.0): four
// sessions downloading one file of a directory share while a fifth uploads
// another, every request pipelined, and every byte is where it belongs.
// Run under -race this is also the check that nothing in the share's path
// (the union, the revocation wrapper, osfs) is unsafe beside concurrent reads.
func TestSFTPParallelSessionsKeepEveryByte(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	src := make([]byte, 6<<20+4321)
	rand.Read(src)
	if err := os.WriteFile(filepath.Join(tree, "big.bin"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	key, pub := keyPair(t)
	pw := write(t, dir, "alice.pw", "hunter2\n")
	r := start(t, fmt.Sprintf(`name = "PAR"
user "alice" {
  password_file   = %q
  authorized_keys = [%q]
}
share "tree" {
  directory = %q
}
serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(pw), pub, hclPath(tree)))

	want := sha256.Sum256(src)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
			if err != nil {
				t.Errorf("download %d: %v", i, err)
				return
			}
			defer done()
			f, err := c.Open("/tree/big.bin")
			if err != nil {
				t.Errorf("download %d: %v", i, err)
				return
			}
			defer f.Close()
			var got bytes.Buffer
			if _, err := f.WriteTo(&got); err != nil {
				t.Errorf("download %d: %v", i, err)
				return
			}
			if sha256.Sum256(got.Bytes()) != want {
				t.Errorf("download %d: SHA-256 differs (%d bytes)", i, got.Len())
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
		if err != nil {
			t.Errorf("upload: %v", err)
			return
		}
		defer done()
		f, err := c.Create("/tree/up.bin")
		if err != nil {
			t.Errorf("upload: %v", err)
			return
		}
		if _, err := io.Copy(f, bytes.NewReader(src)); err != nil {
			t.Errorf("upload: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("upload close: %v", err)
		}
	}()
	wg.Wait()
	got, err := os.ReadFile(filepath.Join(tree, "up.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != want {
		t.Fatalf("upload: SHA-256 differs (%d bytes)", len(got))
	}
}
