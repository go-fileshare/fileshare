// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb && !nosftp && !wasip1

package main

import (
	"fmt"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The SFTP half of go-fileshare/fileshare#135: an fsync@openssh.com on a lazy
// HFS+ share reaches the volume through the per-person tree (unionFS.Sync), and
// the raw image, copied while the share is open, is marked clean afterwards.
func TestSFTPFsyncMakesLazyHFSPlusDataDurable(t *testing.T) {
	needUsers(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	path := hfsImage(t)
	key, pub := keyPair(t)
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

user "alice" { authorized_keys = [%q] }

share "attic" {
  image                = %q
  hfsplus_writable_max = "8M"
  hfsplus_durability   = "lazy"
}

serve "sftp" { addr = "127.0.0.1:0" }
`, pub, hclPath(path)))

	cl, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f, err := cl.Create("/attic/flushed.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("flushed bytes")); err != nil {
		t.Fatal(err)
	}
	if volumeClean(t, rawCopy(t, path)) {
		t.Fatal("control: the lazy volume is marked clean before any fsync, so this test shows nothing")
	}
	if err := syncFile(f); err != nil {
		t.Fatalf("fsync@openssh.com: %v\n%s", err, r.out.String())
	}
	if !volumeClean(t, rawCopy(t, path)) {
		t.Fatal("after fsync the raw image is still marked as not cleanly unmounted: the fsync did not reach the volume")
	}
}

// syncFile is the client's fsync: pkg/sftp sends fsync@openssh.com when the
// server advertises it, and reports ErrSSHFxOpUnsupported when it does not.
func syncFile(f *sftp.File) error { return f.Sync() }

// With two lazy HFS+ shares, an fsync on a handle in A syncs A only: B, written
// but not flushed, is still marked not clean. (Before SyncPath, the fsync synced
// every writable share of the person.)
func TestSFTPFsyncSyncsOnlyTheShareOfTheHandle(t *testing.T) {
	needUsers(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	pathA, pathB := hfsImage(t), hfsImage(t)
	key, pub := keyPair(t)
	r := start(t, fmt.Sprintf(`
name = "TESTFS"

user "alice" { authorized_keys = [%q] }

share "a" {
  image                = %q
  hfsplus_writable_max = "8M"
  hfsplus_durability   = "lazy"
}

share "b" {
  image                = %q
  hfsplus_writable_max = "8M"
  hfsplus_durability   = "lazy"
}

serve "sftp" { addr = "127.0.0.1:0" }
`, pub, hclPath(pathA), hclPath(pathB)))

	cl, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	var files []*sftp.File
	for _, p := range []string{"/a/x.txt", "/b/y.txt"} {
		f, err := cl.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write([]byte("bytes")); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if volumeClean(t, rawCopy(t, pathA)) || volumeClean(t, rawCopy(t, pathB)) {
		t.Fatal("control: a lazy volume is marked clean before any fsync")
	}
	if err := syncFile(files[0]); err != nil {
		t.Fatalf("fsync on a: %v\n%s", err, r.out.String())
	}
	if !volumeClean(t, rawCopy(t, pathA)) {
		t.Error("after an fsync on a, share a is not marked clean")
	}
	if volumeClean(t, rawCopy(t, pathB)) {
		t.Error("an fsync on a synced share b as well")
	}
}
