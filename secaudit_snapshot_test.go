// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"sync/atomic"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// noOpenerFS is a driver without Opener (hfsplus, ntfs, xfs, apfs, btrfs,
// zfs, ufs at the versions go.mod pins). Only ReadFile is answered.
type noOpenerFS struct {
	filesystem.Filesystem
	size  int
	bytes *atomic.Int64
}

func (f noOpenerFS) ReadFile(string) ([]byte, error) {
	f.bytes.Add(int64(f.size))
	return make([]byte, f.size), nil
}

// SECAUDIT 2026-11-05: an SFTP open of a file on a driver without Opener
// materialises the whole file, once per handle; one session may hold 1024
// handles (go-filesystems/sftp maxOpenHandles). A reader of a share holding a
// large file pins handles x size bytes.
func TestSecauditOpenFileReadsWholeFilePerHandle(t *testing.T) {
	var n atomic.Int64
	const size = 8 << 20 // stands for a multi-GiB file on a real share
	sh := &share{name: "img", fsys: noOpenerFS{size: size, bytes: &n}, readOnly: true}
	u := unionFor([]*share{sh}, local("reader"))
	var held []filesystem.File
	for i := 0; i < 16; i++ {
		f, err := u.OpenFile("/img/big.bin")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, f)
	}
	_ = held
	if got := n.Load(); got > size {
		t.Fatalf("16 opens of one %d-byte file materialised %d bytes (%dx the file): "+
			"memory is handles x file size, bounded by neither", size, got, got/size)
	}
}
