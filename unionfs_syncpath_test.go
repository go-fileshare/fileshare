// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// SyncPath syncs only the share under the handle's path: a sync on A leaves B
// alone, a failed B does not fail an fsync on A (and does fail its own), a
// read-only share has nothing to sync, a revoked session is refused, and a path
// under no share is not a file of the tree.
func TestUnionFSSyncPathSyncsOnlyTheShareUnderThePath(t *testing.T) {
	a, b, ro := &ownSyncFS{}, &ownSyncFS{err: errors.New("EIO")}, &ownSyncFS{}
	u := &unionFS{entries: []unionEntry{
		{name: "a", fsys: a},
		{name: "b", fsys: b},
		{name: "frozen", fsys: ro, readOnly: true},
	}}
	if err := u.SyncPath("/a/dir/file.txt"); err != nil {
		t.Fatalf("SyncPath on share a = %v", err)
	}
	if a.n != 1 || b.n != 0 || ro.n != 0 {
		t.Errorf("a fsync on a synced a %d, b %d, frozen %d times; want 1, 0, 0", a.n, b.n, ro.n)
	}
	// B has failed: an fsync on A still succeeds, and one on B fails, naming it.
	if err := u.SyncPath("/a/file.txt"); err != nil {
		t.Errorf("a failed share b failed an fsync on a: %v", err)
	}
	err := u.SyncPath("/b/file.txt")
	if err == nil || !errors.Is(err, b.err) || !strings.Contains(err.Error(), "b") {
		t.Errorf("SyncPath on the failed share = %v, want its EIO, named", err)
	}
	if err := u.SyncPath("/frozen/file.txt"); err != nil || ro.n != 0 {
		t.Errorf("a read-only share: %v, synced %d times; want nil and 0", err, ro.n)
	}
	for _, p := range []string{"/", "/nowhere/x"} {
		if err := u.SyncPath(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("SyncPath(%q) = %v, want ErrNotExist", p, err)
		}
	}
	u.revoked = func() error { return errors.New("revoked") }
	before := a.n
	if err := u.SyncPath("/a/file.txt"); !errors.Is(err, os.ErrPermission) || a.n != before {
		t.Errorf("a revoked session: %v, a synced %d more times", err, a.n-before)
	}
}
