// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs && !nowebdav && !nosmb

package main

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/go-filesystems/osfs"
)

// usageTree is a host tree whose statfs says what the test says.
type usageTree struct {
	hostTree
	total, free *atomic.Uint64
}

func (u usageTree) Usage() (uint64, uint64, error) { return u.total.Load(), u.free.Load(), nil }

// What each protocol's client is told a directory share's size and free
// space are, and that it is told again -- not the numbers of the start --
// after the free space changed.
func TestADirectoryShareReportsItsSpaceLive(t *testing.T) {
	var total, free atomic.Uint64
	total.Store(32 << 20)
	free.Store(24 << 20)
	orig, origTTL := hostTreeOf, spaceTTL
	hostTreeOf = func(fsys *osfs.FS) hostTree { return usageTree{fsys, &total, &free} }
	spaceTTL = 0
	t.Cleanup(func() { hostTreeOf, spaceTTL = orig, origTTL })

	dir := t.TempDir()
	cfg := onlyProtocol(t, dir, "nfs", fmt.Sprintf("share \"space\" {\n  directory = %q\n}\n", hclPath(t.TempDir()))) +
		"serve \"webdav\" { addr = \"127.0.0.1:0\" }\nserve \"smb\" { addr = \"127.0.0.1:0\" }\n"
	r := start(t, cfg)

	for _, want := range []struct{ total, free uint64 }{{32 << 20, 24 << 20}, {32 << 20, 3 << 20}} {
		free.Store(want.free)
		if tb, fb := nfsFsstat(t, r.addrs["nfs"], nfsMount(t, r.addrs["nfs"], "/space")); tb != want.total || fb != want.free {
			t.Errorf("NFS FSSTAT: tbytes %d fbytes %d, want %d/%d", tb, fb, want.total, want.free)
		}
		avail, used := webdavQuota(t, r.addrs["webdav"], "/space/")
		if avail != want.free || used != want.total-want.free {
			t.Errorf("WebDAV: quota-available-bytes %d quota-used-bytes %d, want %d/%d", avail, used, want.free, want.total-want.free)
		}
		fi, err := mountSMB(t, r, "alice", "hunter2", "space").Statfs(".")
		if err != nil {
			t.Fatal(err)
		}
		if tb, ab := fi.TotalBlockCount()*fi.BlockSize(), fi.AvailableBlockCount()*fi.BlockSize(); tb != want.total || ab != want.free {
			t.Errorf("SMB: total %d available %d, want %d/%d", tb, ab, want.total, want.free)
		}
	}
}
