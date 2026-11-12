// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/go-filesystems/hfsplus"
	filesystem "github.com/go-filesystems/interface"
)

// hfsImage is an 8 MiB HFS+ image holding /a.txt.
func hfsImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hfs.img")
	v, err := hfsplus.Format(path, 8<<20, hfsplus.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// hfsJournaled marks the image at path journaled, with a journal (inside the
// volume, as macOS lays it out) that holds a transaction: start != end. The
// hfsplus helpers that build one are test code in that module, so the header is
// built here from TN1150: a Volume Header with the journaled bit and a Journal
// Info Block, and a journal header with its checksum (calc_checksum).
func hfsJournaled(t *testing.T, path string, start, end uint64) {
	t.Helper()
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	be, le := binary.BigEndian, binary.LittleEndian
	vh := img[1024:]
	if bs := be.Uint32(vh[40:]); bs != 4096 {
		t.Fatalf("block size %d, the test assumes 4096", bs)
	}
	total := be.Uint32(vh[44:])
	jib, jblk := total-150, total-140 // free blocks clear of the alternate header
	const jsize = 512 << 10
	be.PutUint32(vh[4:], be.Uint32(vh[4:])|1<<13) // kHFSVolumeJournaledBit
	be.PutUint32(vh[12:], jib)
	ji := img[int(jib)*4096:]
	be.PutUint32(ji[0:], 1) // kJIJournalInFSMask
	be.PutUint64(ji[36:], uint64(jblk)*4096)
	be.PutUint64(ji[44:], jsize)
	h := make([]byte, 512)
	le.PutUint32(h[0:], 0x4a4e4c78)
	le.PutUint32(h[4:], 0x12345678)
	le.PutUint64(h[8:], start)
	le.PutUint64(h[16:], end)
	le.PutUint64(h[24:], jsize)
	le.PutUint32(h[32:], 0x2000)
	le.PutUint32(h[40:], 512)
	var sum uint32
	for _, b := range h[:44] {
		sum = sum<<8 ^ (sum + uint32(b))
	}
	le.PutUint32(h[36:], ^sum)
	copy(img[int(jblk)*4096:], h)
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A file written, and a time set, by a go-smb2 client on an HFS+ image share
// are STORED -- in the image, not in the server's memory: the image is read
// back through hfsplus's own read path. Before hfsplus v0.9.0 the share was
// opened through hfsplus.OpenReader, whose volume is read-only, so both failed.
// HFS+ keeps times to the second, so an odd second shows a rounded-down echo.
func TestSMBWritesAndStoresTimesOnAnHFSPlusImage(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")

	if err := share.WriteFile("new.txt", []byte("written over smb"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v\n%s", err, r.out.String())
	}
	mtime := time.Date(2020, 5, 17, 10, 30, 31, 0, time.Local)
	atime := time.Date(2020, 5, 18, 13, 45, 7, 0, time.Local)
	if err := share.Chtimes("a.txt", atime, mtime); err != nil {
		t.Fatalf("Chtimes: %v\n%s", err, r.out.String())
	}

	got, err := share.ReadFile("new.txt")
	if err != nil || string(got) != "written over smb" {
		t.Fatalf("read back %q, %v", got, err)
	}
	fi, err := share.Stat("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(mtime) {
		t.Errorf("LastWriteTime %v, want %v", fi.ModTime(), mtime)
	}
	if a := fi.Sys().(*smb2.FileStat).LastAccessTime; !a.Equal(atime) {
		t.Errorf("LastAccessTime %v, want %v", a, atime)
	}
	if strings.Contains(r.out.String(), "read-only") || strings.Contains(r.out.String(), "SET_INFO times not stored") {
		t.Errorf("a writable HFS+ share logged a refusal:\n%s", r.out.String())
	}

	// On disk, not only in the server: a fresh read-only open of the file.
	v, err := hfsplus.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if b, err := v.ReadFile("/new.txt"); err != nil || string(b) != "written over smb" {
		t.Errorf("image holds %q, %v", b, err)
	}
}

// A journal with transactions in it would be replayed by macOS over what this
// server writes, so hfsplus refuses it (ErrJournaled). The share must not take
// the server down: it opens read-only, readable, and says once why.
func TestHFSPlusJournaledImageFallsBackToReadOnly(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	hfsJournaled(t, path, 0x4400, 0x8800)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")

	if b, err := share.ReadFile("a.txt"); err != nil || string(b) != "hello" {
		t.Fatalf("a journaled image must still be readable: %q, %v", b, err)
	}
	if err := share.WriteFile("new.txt", []byte("x"), 0o644); err == nil {
		t.Error("a write into a journaled image with pending transactions succeeded")
	}
	out := r.out.String()
	if n := strings.Count(out, "journal holds transactions"); n != 1 {
		t.Errorf("fallback logged %d times, want once:\n%s", n, out)
	}
	for _, want := range []string{"attic", "is read-only", hfsplus.ErrJournaled.Error()} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the image changed although the share fell back to read-only")
	}
}

// A journaled image whose journal is empty (start == end) is written directly:
// macOS has nothing to replay.
func TestHFSPlusEmptyJournalStaysWritable(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	hfsJournaled(t, path, 0x4400, 0x4400)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")
	if err := share.WriteFile("new.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v\n%s", err, r.out.String())
	}
	if strings.Contains(r.out.String(), "journal") {
		t.Errorf("an empty journal was reported:\n%s", r.out.String())
	}
}

// A share's driver, as the protocols reach it (behind lockFS), and whether it
// still has the range reads and the times a read-only HFS+ volume has.
func driverOf(t *testing.T, r *running, name string) filesystem.Filesystem {
	t.Helper()
	sh := r.srv.shareByName(name)
	if sh == nil || sh.fsys == nil {
		t.Fatalf("no share %q", name)
	}
	return sh.fsys
}

func wantAbilities(t *testing.T, fsys filesystem.Filesystem) {
	t.Helper()
	if _, ok := fsys.(filesystem.Opener); !ok {
		t.Error("the share lost filesystem.Opener (range reads)")
	}
	if _, ok := fsys.(filesystem.TimesReader); !ok {
		t.Error("the share lost filesystem.TimesReader")
	}
}

// A share configured read_only keeps hfsplus.OpenReader's behaviour. The
// assertion is on the DRIVER, not the protocol (which refuses a write by itself
// on a read_only share): the volume must answer ErrReadOnly, so a writable open
// that merely sits behind a refusing protocol layer fails this. The image is
// not journaled, so a wrongly writable open would succeed silently.
func TestHFSPlusReadOnlyShareStaysReadOnly(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  read_only = true\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")
	if b, err := share.ReadFile("a.txt"); err != nil || string(b) != "hello" {
		t.Fatalf("read: %q, %v", b, err)
	}
	fsys := driverOf(t, r, "attic")
	if err := fsys.WriteFile("/new.txt", []byte("x"), 0o644); !errors.Is(err, hfsplus.ErrReadOnly) {
		t.Errorf("the driver of a read_only share answered %v to a write, want ErrReadOnly", err)
	}
	wantAbilities(t, fsys)
	if out := r.out.String(); strings.Contains(out, "HFS+") {
		t.Errorf("a read_only share logged a fallback:\n%s", out)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("a read_only share changed the image")
	}
}

// The journaled fallback serves what a read-only open always served: range
// reads and times survive lockFS.
func TestHFSPlusJournaledFallbackKeepsItsAbilities(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	hfsJournaled(t, path, 0x4400, 0x8800)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n}\n", hclPath(path))))
	fsys := driverOf(t, r, "attic")
	wantAbilities(t, fsys)
	if err := fsys.WriteFile("/new.txt", []byte("x"), 0o644); !errors.Is(err, hfsplus.ErrReadOnly) {
		t.Errorf("the fallback driver answered %v to a write, want ErrReadOnly", err)
	}
	if !r.srv.shareByName("attic").readOnly {
		t.Error("the fallback share is not marked read-only")
	}
}

// An image over hfsplus_writable_max opens read-only, readable, marked
// read-only, and says so once, naming the share, the size and the cap. The
// default is 256 MiB, so a small cap is set to bring the 8 MiB test image over.
func TestHFSPlusImageOverTheCapIsReadOnly(t *testing.T) {
	needUsers(t)
	for _, max := range []string{"1M", "0"} {
		t.Run(max, func(t *testing.T) {
			path := hfsImage(t)
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = %q\n}\n", hclPath(path), max)))
			share := mountSMB(t, r, "alice", "hunter2", "attic")
			if b, err := share.ReadFile("a.txt"); err != nil || string(b) != "hello" {
				t.Fatalf("read: %q, %v", b, err)
			}
			if err := share.WriteFile("new.txt", []byte("x"), 0o644); err == nil {
				t.Error("a write into an image over the cap succeeded")
			}
			sh := r.srv.shareByName("attic")
			if !sh.readOnly {
				t.Error("the share is not marked read-only")
			}
			wantAbilities(t, sh.fsys)
			out := r.out.String()
			if n := strings.Count(out, "hfsplus_writable_max"); n != 1 {
				t.Errorf("cap logged %d times, want once:\n%s", n, out)
			}
			for _, want := range []string{"attic", "8388608 bytes", "so attic is read-only"} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// At or under the cap the same image is written.
func TestHFSPlusImageUnderTheCapIsWritable(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	share := mountSMB(t, r, "alice", "hunter2", "attic")
	if err := share.WriteFile("new.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v\n%s", err, r.out.String())
	}
}

func TestParseImageSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "512": 512, "256M": 256 << 20, "1G": 1 << 30,
		"2GiB": 2 << 30, "4K": 4096, " 8MB ": 8 << 20, "1T": 1 << 40} {
		if got, err := parseImageSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "M", "-1", "1.5G", "ten", "9999999999T", "1X"} {
		if got, err := parseImageSize(in); err == nil {
			t.Errorf("%q accepted as %d", in, got)
		}
	}
}

func TestBadHFSPlusWritableMaxIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "bad.hcl", onlyProtocol(t, dir, "smb",
		"share \"a\" {\n  directory = \"/tmp\"\n  hfsplus_writable_max = \"lots\"\n}\n"))
	if _, err := loadConfig([]string{p}); err == nil || !strings.Contains(err.Error(), "hfsplus_writable_max") {
		t.Errorf("loadConfig = %v, want a refusal naming hfsplus_writable_max", err)
	}
}

// openHFSPlus decides from what openImage registered for the reader, and
// checks every condition before reading the image into memory.
func TestOpenHFSPlusChoosesByRegistration(t *testing.T) {
	path := hfsImage(t)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	reg := func(o *hfsplusOpen) {
		hfsplusOpens.Store(io.ReaderAt(f), o)
		t.Cleanup(func() { hfsplusOpens.Delete(io.ReaderAt(f)) })
	}

	// No entry: read-only, whatever the reader could do.
	ro, err := openHFSPlus(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.WriteFile("/x", []byte("x"), 0o644); !errors.Is(err, hfsplus.ErrReadOnly) {
		t.Errorf("a volume with no registration answered %v to a write, want ErrReadOnly", err)
	}

	// Size unknown, and over the cap: read-only with a reason, without reading.
	for name, tc := range map[string]struct {
		size int64
		max  int64
		want string
	}{"unknown size": {0, 1 << 30, "size is not known"}, "negative size": {-1, 1 << 30, "size is not known"},
		"over the cap": {st.Size(), 1 << 20, "hfsplus_writable_max"},
		"over 64 GiB":  {hfsplusHardMax + 1, 1 << 62, "hfsplus_writable_max"}} {
		o := &hfsplusOpen{max: tc.max, file: f}
		reg(o)
		// OpenReader refuses a size that is not the file's: the point is the
		// reason, set before any allocation.
		_, _ = openHFSPlus(f, tc.size)
		if !strings.Contains(o.fallback, tc.want) {
			t.Errorf("%s: fallback %q, want it to say %q", name, o.fallback, tc.want)
		}
	}

	// Registered, in range: writable.
	o := &hfsplusOpen{max: 1 << 30, file: f}
	reg(o)
	rw, err := openHFSPlus(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.WriteFile("/x", []byte("x"), 0o644); err != nil {
		t.Errorf("a registered volume refused a write: %v (fallback %q)", err, o.fallback)
	}
	if o.fallback != "" {
		t.Errorf("a writable open set a fallback: %q", o.fallback)
	}

	// Journaled: read-only, ErrJournaled named. f held the image lock.
	f.Close()
	hfsJournaled(t, path, 1, 2)
	g, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	gst, _ := g.Stat()
	jo := &hfsplusOpen{max: 1 << 30, file: g}
	hfsplusOpens.Store(io.ReaderAt(g), jo)
	defer hfsplusOpens.Delete(io.ReaderAt(g))
	jv, err := openHFSPlus(g, gst.Size())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jo.fallback, hfsplus.ErrJournaled.Error()) {
		t.Errorf("fallback %q does not name ErrJournaled", jo.fallback)
	}
	wantAbilities(t, lockFS(jv))
}
