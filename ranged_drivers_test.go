// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"

	apfs "github.com/go-filesystems/apfs"
	btrfs "github.com/go-filesystems/btrfs"
	hfsplus "github.com/go-filesystems/hfsplus"
	ntfs "github.com/go-filesystems/ntfs"
	ufs "github.com/go-filesystems/ufs"
	xfs "github.com/go-filesystems/xfs"
	zfs "github.com/go-filesystems/zfs"
)

var _ filesystem.Opener = (*ufs.FS)(nil)

// Every driver this program serves reads a file by range (filesystem.Opener),
// so that the whole-file fallback of the servers (bounded at 64 MiB by
// go-filesystems/nfs, and by the SFTP snapshot of unionfs.go) is a safety net
// and not the way a large file is read. A driver that lost the capability in an
// update would be read whole again, silently: this fails instead.
func TestEveryDriverReadsByRange(t *testing.T) {
	dir := t.TempDir()
	mk := map[string]func() (filesystem.Filesystem, error){
		"hfsplus": func() (filesystem.Filesystem, error) {
			return hfsplus.Format(filepath.Join(dir, "h.img"), 16<<20, hfsplus.FormatConfig{Label: "T"})
		},
		"ntfs": func() (filesystem.Filesystem, error) {
			return ntfs.Format(filepath.Join(dir, "n.img"), 16<<20, ntfs.FormatConfig{})
		},
		"xfs": func() (filesystem.Filesystem, error) {
			return xfs.Format(filepath.Join(dir, "x.img"), 64<<20, xfs.FormatConfig{})
		},
		"btrfs": func() (filesystem.Filesystem, error) {
			return btrfs.Format(filepath.Join(dir, "b.img"), 16<<20, btrfs.FormatConfig{})
		},
		"zfs": func() (filesystem.Filesystem, error) {
			return zfs.Format(filepath.Join(dir, "z.img"), 64<<20, zfs.FormatConfig{})
		},
		"apfs": func() (filesystem.Filesystem, error) {
			return apfs.Format(filepath.Join(dir, "a.img"), 16<<20, apfs.FormatConfig{})
		},
	}
	for name, f := range mk {
		t.Run(name, func(t *testing.T) {
			fsys, err := f()
			if err != nil {
				t.Skipf("no image to try: %v", err)
			}
			defer fsys.Close()
			if _, ok := fsys.(filesystem.Opener); !ok {
				t.Fatalf("%s does not implement filesystem.Opener: its files are read whole", name)
			}
		})
	}
}
