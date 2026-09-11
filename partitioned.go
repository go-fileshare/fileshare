// SPDX-License-Identifier: BSD-3-Clause

//go:build !nopartitioned

package main

import (
	"fmt"
	"io"
	"os"

	filesystem "github.com/go-filesystems/interface"

	filesystem_apfs "github.com/go-filesystems/apfs"
	filesystem_btrfs "github.com/go-filesystems/btrfs"
	filesystem_xfs "github.com/go-filesystems/xfs"
	filesystem_zfs "github.com/go-filesystems/zfs"
)

// The filesystems that are opened by NAME rather than by sniffing.
//
// apfs, btrfs, xfs and zfs do not fit detect's shape -- an io.ReaderAt and a
// size, which is a filesystem at offset zero. Each of them opens a DISK image
// and picks a partition, over a block backend that answers Size, Sync,
// Truncate and Close as well as reads and writes. So a share says which:
//
//	share "photos" {
//	  image      = "/srv/disk.img"
//	  filesystem = "xfs"
//	  partition  = 2        # or leave it out: -1, the first data partition
//	}
//
// ⛔ Saying `filesystem` turns DETECTION OFF for that share. That is the point
// -- a partitioned disk image has no filesystem magic at offset zero to find --
// and it is also the risk: a name that does not match the image is a driver
// reading somebody else's bytes. The driver refuses, loudly, rather than
// guessing, which is why the refusal is reported with the name that was asked
// for.
func openNamed(name string, f *os.File, size int64, readOnly bool, partition int) (filesystem.Filesystem, error) {
	dev := &blockFile{f: f, size: size, readOnly: readOnly}
	switch name {
	case "xfs":
		return filesystem_xfs.OpenFromDevice(dev, partition)
	case "btrfs":
		return filesystem_btrfs.OpenFromDevice(dev, partition)
	case "zfs":
		return filesystem_zfs.OpenFromDevice(dev, partition)
	case "apfs":
		return filesystem_apfs.OpenFromBlockDevice(dev, partition)
	}
	return nil, fmt.Errorf("there is no %q driver here: %s", name, namedFilesystems())
}

// namedFilesystems is what a `filesystem` may say, for a message that lists
// what would have worked.
func namedFilesystems() string { return "apfs, btrfs, xfs and zfs" }

// hasNamed reports whether this binary carries the named drivers at all.
func hasNamed() bool { return true }

// blockFile is the image, as the block device those four drivers expect.
//
// They are read/write drivers, so the interface has WriteAt, Truncate and Sync
// whether or not this share may be written. A read-only share refuses those
// HERE, with a sentence, rather than letting the kernel answer EBADF from
// somewhere in the middle of a b-tree walk.
type blockFile struct {
	f        *os.File
	size     int64
	readOnly bool
}

func (b *blockFile) ReadAt(p []byte, off int64) (int, error) { return b.f.ReadAt(p, off) }
func (b *blockFile) Size() (int64, error)                    { return b.size, nil }
func (b *blockFile) Close() error                            { return nil } // the server owns the file

func (b *blockFile) WriteAt(p []byte, off int64) (int, error) {
	if b.readOnly {
		return 0, fmt.Errorf("%w: this share is read-only", os.ErrPermission)
	}
	return b.f.WriteAt(p, off)
}

func (b *blockFile) Sync() error {
	if b.readOnly {
		return nil // nothing was written, so there is nothing to flush
	}
	return b.f.Sync()
}

func (b *blockFile) Truncate(size int64) error {
	if b.readOnly {
		return fmt.Errorf("%w: this share is read-only", os.ErrPermission)
	}
	return b.f.Truncate(size)
}

var _ io.ReaderAt = (*blockFile)(nil)
