//go:build !nopartitioned && !nosmb

package main

import (
	"fmt"
	"path/filepath"
	"testing"

	filesystem_xfs "github.com/go-filesystems/xfs"
)

// An XFS image, read back over SMB.
//
// `check` proves the driver opened it; this proves a client gets the bytes --
// the whole path, from a filesystem that has to be named, through the share's
// access rules, to a client this project did not write.
func TestANamedFilesystemIsReadOverSMB(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "xfs.img")
	fsys, err := filesystem_xfs.Format(img, 512<<20, filesystem_xfs.FormatConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/greeting.txt", []byte("hello from xfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c, ok := fsys.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// An unrestricted share as well: NFS cannot authenticate and refuses a
	// configuration where it would carry nothing.
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	r := start(t, people(t, dir)+fmt.Sprintf(`
share "xfs" {
  image      = %q
  filesystem = "xfs"
  allow      = ["alice"]
}

share "open" { image = %q }
`, hclPath(img), hclPath(open))+serveBlocks())

	fs := mountSMB(t, r, "alice", "hunter2", "xfs")
	got, err := fs.ReadFile("greeting.txt")
	if err != nil {
		t.Fatalf("reading over smb: %v", err)
	}
	if string(got) != "hello from xfs" {
		t.Errorf("smb read %q", got)
	}
}
