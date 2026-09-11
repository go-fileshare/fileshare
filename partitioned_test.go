//go:build !nopartitioned

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"

	filesystem_apfs "github.com/go-filesystems/apfs"
	filesystem_btrfs "github.com/go-filesystems/btrfs"
	filesystem_xfs "github.com/go-filesystems/xfs"
	filesystem_zfs "github.com/go-filesystems/zfs"
)

// The four filesystems a share has to NAME, each made and then served.
//
// They cannot be sniffed: each opens a disk image and picks a partition, so
// there is no magic at offset zero for detect to find. What the test proves is
// the whole path -- a real image of that filesystem, a real file inside it,
// opened through the share's `filesystem =` and read back through the server's
// own tree.
func TestTheFilesystemsAShareMustName(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(path string, size int64) (filesystem.Filesystem, error)
	}{
		{"xfs", func(p string, n int64) (filesystem.Filesystem, error) {
			return filesystem_xfs.Format(p, n, filesystem_xfs.FormatConfig{})
		}},
		{"btrfs", func(p string, n int64) (filesystem.Filesystem, error) {
			return filesystem_btrfs.Format(p, n, filesystem_btrfs.FormatConfig{})
		}},
		{"zfs", func(p string, n int64) (filesystem.Filesystem, error) {
			return filesystem_zfs.Format(p, n, filesystem_zfs.FormatConfig{})
		}},
		{"apfs", func(p string, n int64) (filesystem.Filesystem, error) {
			return filesystem_apfs.Format(p, n, filesystem_apfs.FormatConfig{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			img := filepath.Join(dir, tc.name+".img")
			fsys, err := tc.make(img, 512<<20)
			if err != nil {
				t.Fatalf("formatting: %v", err)
			}
			if err := fsys.WriteFile("/greeting.txt", []byte("hello from "+tc.name), 0o644); err != nil {
				t.Fatalf("writing into the image: %v", err)
			}
			if c, ok := fsys.(interface{ Close() error }); ok {
				if err := c.Close(); err != nil {
					t.Fatalf("closing the image: %v", err)
				}
			}

			body := fmt.Sprintf(`
share "named" {
  image      = %q
  filesystem = %q
}
`, hclPath(img), tc.name) + serveBlocks()
			out, err := execute(t, "check", write(t, dir, "c.hcl", body))
			if err != nil {
				t.Fatalf("check: %v\n%s", err, out)
			}
			// The report names the filesystem the share asked for, which is
			// the only thing that can be said about an image whose driver was
			// chosen rather than found.
			if !strings.Contains(out, tc.name) {
				t.Errorf("check does not name %s:\n%s", tc.name, out)
			}
		})
	}
}

// ⛔ A share that names the wrong filesystem is refused, not opened as
// something else. Naming one turns detection off, so this is the failure mode
// the feature creates and the one it has to answer for.
func TestNamingTheWrongFilesystem(t *testing.T) {
	dir := t.TempDir()
	// A real FAT32 image, told it is xfs.
	img := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	body := fmt.Sprintf(`
share "wrong" {
  image      = %q
  filesystem = "xfs"
}
`, hclPath(img)) + serveBlocks()
	_, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err == nil {
		t.Fatal("a fat32 image opened as xfs")
	}
	if !strings.Contains(err.Error(), "as xfs") {
		t.Errorf("the refusal does not say what it was asked to open it as: %v", err)
	}

	// And the other direction: a sniffable filesystem named wrongly is caught
	// by comparing what detect found against what the share claimed, rather
	// than by trusting either one alone.
	body = fmt.Sprintf(`
share "wrong" {
  image      = %q
  filesystem = "ext4"
}
`, hclPath(img)) + serveBlocks()
	_, err = execute(t, "check", write(t, dir, "c2.hcl", body))
	if err == nil {
		t.Fatal("a fat32 image was served as ext4")
	}
	if !strings.Contains(err.Error(), "says ext4 and the image holds fat32") {
		t.Errorf("the refusal reads %v", err)
	}
}

// Naming a filesystem that a sniff would have found is allowed, and is how a
// site refuses a misdetection rather than discovering one.
func TestNamingAFilesystemThatWouldHaveBeenFound(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	body := fmt.Sprintf(`
share "named" {
  image      = %q
  filesystem = "fat32"
}
`, hclPath(img)) + serveBlocks()
	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "fat32") {
		t.Errorf("check does not name fat32:\n%s", out)
	}
}
