// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-filesystems/hfsplus"
)

// rawCopy copies the image file as it is on the medium right now, without the
// share being closed: what a crash would leave, or what a backup would read.
func rawCopy(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy.img")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// volumeClean is whether the image's volume header says "cleanly unmounted"
// (kHFSVolumeUnmountedBit, 0x100 in the attributes at 1024+4).
func volumeClean(t *testing.T, img string) bool {
	t.Helper()
	b, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint32(b[1024+4:])&0x100 != 0
}

// At the lazy level a write is on the medium only once the volume is synced, and
// a client's flush is what asks for that (go-fileshare/fileshare#135): an SMB
// FLUSH reaches Volume.Sync, and the raw image, copied while the share is still
// open, holds the bytes and passes fsck_hfs. Without the flush it does not.
func TestSMBFlushMakesLazyHFSPlusDataDurable(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n  hfsplus_durability = \"lazy\"\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")

	f, err := share.Create("flushed.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("flushed bytes")); err != nil {
		t.Fatal(err)
	}

	// The page cache hands a copy the bytes before they are on the medium, so
	// the bytes cannot tell a flushed volume from an unflushed one. The volume
	// header can: at the lazy level it says "not cleanly unmounted" (the
	// kHFSVolumeUnmountedBit, 0x100 in the attributes at 1024+4) until the volume
	// is synced, which restores the clean mark.
	clean := func(img string) bool { return volumeClean(t, img) }
	holds := func(img string) bool {
		f, err := os.Open(img)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		st, _ := f.Stat()
		v, err := hfsplus.OpenReader(f, st.Size())
		if err != nil {
			t.Fatalf("opening the copy: %v", err)
		}
		b, err := v.ReadFile("/flushed.txt")
		return err == nil && string(b) == "flushed bytes"
	}
	if clean(rawCopy(t, path)) {
		t.Fatal("control: the lazy volume is marked clean before any flush, so this test shows nothing")
	}

	if err := f.Sync(); err != nil {
		t.Fatalf("FLUSH: %v\n%s", err, r.out.String())
	}
	cp := rawCopy(t, path)
	if !holds(cp) {
		t.Fatal("after FLUSH the raw image does not hold the written bytes")
	}
	if !clean(cp) {
		t.Fatal("after FLUSH the raw image is still marked as not cleanly unmounted: the flush did not sync the volume")
	}
	if runtime.GOOS != "darwin" || os.Getenv("FILESHARE_REQUIRE_DEVICE") == "" {
		t.Skip("fsck_hfs needs the copy attached as a block device (macOS, FILESHARE_REQUIRE_DEVICE=1, as the other device tests); the header and data checks above ran")
	}
	out, err := exec.Command("hdiutil", "attach", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage", cp).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	var dev string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); dev == "" && len(f) > 0 && strings.HasPrefix(f[0], "/dev/disk") {
			dev = f[0]
		}
	}
	if dev == "" {
		t.Fatalf("hdiutil attach said nothing useful:\n%s", out)
	}
	defer func() { _ = exec.Command("hdiutil", "detach", dev, "-force").Run() }()
	raw := strings.Replace(dev, "/dev/disk", "/dev/rdisk", 1)
	if out, err := exec.Command("fsck_hfs", "-fn", raw).CombinedOutput(); err != nil {
		t.Errorf("fsck_hfs -fn %s: %v\n%s", raw, err, out)
	}
}

// syncingFS is a driver with a Sync that can fail: the client's flush must be
// told.
type syncingFS struct {
	plainFS
	err  error
	hits int
}

func (s *syncingFS) Sync() error { s.hits++; return s.err }

// lockedFS.Sync is the one place every protocol's flush arrives: it calls the
// driver's Sync and returns its error, and says nothing for a driver without one.
func TestLockedFSSyncReachesTheDriverAndReturnsItsError(t *testing.T) {
	d := &syncingFS{}
	s, ok := lockFS(d).(interface{ Sync() error })
	if !ok {
		t.Fatal("the locked driver has no Sync")
	}
	if err := s.Sync(); err != nil || d.hits != 1 {
		t.Fatalf("Sync = %v, driver synced %d times, want nil and 1", err, d.hits)
	}
	d.err = errors.New("disk gone")
	if err := s.Sync(); !errors.Is(err, d.err) {
		t.Errorf("a failing driver Sync was returned as %v", err)
	}
	// A driver with no Sync has nothing held back.
	if err := lockFS(plainFS{}).(interface{ Sync() error }).Sync(); err != nil {
		t.Errorf("Sync on a driver without one = %v", err)
	}
}
