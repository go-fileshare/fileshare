package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-filesystems/detect"
	filesystem_ufs "github.com/go-filesystems/ufs"
)

// Every driver of the one shape is registered, and the list is not a memory.
//
// ⛔ This is asked of detect, not of the source: registerDrivers is a list
// somebody maintains by hand, and a driver added to go-filesystems does not
// announce itself here. What the test can check is that nothing detect knows
// how to RECOGNISE is left without an opener -- which is the failure that
// matters, since detect.Open then answers ErrUnsupported on a real image.
func TestEveryDriverOfTheOneShapeIsRegistered(t *testing.T) {
	registerDrivers()
	// The types detect can name, against the ones a share can actually be
	// opened as. The four missing ones are missing for a reason the server
	// states, and that reason is their SHAPE: they open a disk image and pick
	// a partition, which detect's (io.ReaderAt, size) cannot express.
	knownWithoutOpener := map[detect.Type]string{
		detect.XFS:   "opens a disk image and picks a partition",
		detect.Btrfs: "opens a disk image and picks a partition",
		detect.ZFS:   "opens a disk image and picks a partition",
		detect.APFS:  "opens a disk image and picks a partition",
	}
	for _, tp := range []detect.Type{
		detect.FAT32, detect.ExFAT, detect.Ext4, detect.NTFS,
		detect.ISO9660, detect.SquashFS, detect.HFSPlus, detect.UFS,
	} {
		if _, ok := knownWithoutOpener[tp]; ok {
			continue
		}
		if !detect.Registered(tp) {
			t.Errorf("%s is not registered: a share holding one would be refused as unsupported", tp)
		}
	}
}

// A UFS image, made and then served.
//
// It is the eighth driver, and it was absent for the least interesting reason
// there is: OpenReader had been merged into go-filesystems/ufs and never
// released, so the module a consumer could actually import did not have it.
func TestAUFSImageIsServed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ufs.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	fs, err := filesystem_ufs.Mkfs(f, 16<<20)
	if err != nil {
		t.Fatalf("formatting: %v", err)
	}
	if err := fs.WriteFile("/greeting.txt", []byte("hello from ufs"), 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Through the server's own path: detect sniffs it, opens it, and `check`
	// names the filesystem it found.
	body := "share \"ufs\" { image = " + quote(hclPath(path)) + " }\n" + serveBlocks()
	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ufs") {
		t.Errorf("check did not recognise the image as ufs:\n%s", out)
	}
}

func quote(s string) string { return "\"" + s + "\"" }
