// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/go-filesystems/hfsplus"
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

// A share configured read_only keeps hfsplus.OpenReader's behaviour: no fallback
// message (nothing was refused, nothing was tried), no write, image untouched.
func TestHFSPlusReadOnlyShareStaysReadOnly(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	hfsJournaled(t, path, 0x4400, 0x8800) // would log, were it opened for writing
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
	if err := share.WriteFile("new.txt", []byte("x"), 0o644); err == nil {
		t.Error("a write into a read_only share succeeded")
	}
	if strings.Contains(r.out.String(), "journal") {
		t.Errorf("a read_only share tried the writable open:\n%s", r.out.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("a read_only share changed the image")
	}
}

// openHFSPlus decides writable-or-not from the reader it is handed: the reader
// of a read-only open (readOnlyReader) gets hfsplus.OpenReader's volume, a
// read-write file gets a volume that writes, and a journaled one comes back as
// journaledReadOnly carrying ErrJournaled.
func TestOpenHFSPlusChoosesByReader(t *testing.T) {
	path := hfsImage(t)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()

	ro, err := openHFSPlus(readOnlyReader{f}, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.WriteFile("/x", []byte("x"), 0o644); err == nil {
		t.Error("a volume opened over a readOnlyReader took a write")
	}

	rw, err := openHFSPlus(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.WriteFile("/x", []byte("x"), 0o644); err != nil {
		t.Errorf("a volume opened over a read-write file refused a write: %v", err)
	}

	hfsJournaled(t, path, 1, 2)
	g, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	gst, _ := g.Stat()
	jv, err := openHFSPlus(g, gst.Size())
	if err != nil {
		t.Fatal(err)
	}
	j, ok := jv.(journaledReadOnly)
	if !ok || !errors.Is(j.why, hfsplus.ErrJournaled) {
		t.Fatalf("got %T, want journaledReadOnly carrying ErrJournaled", jv)
	}
	if _, err := j.ReadFile("/a.txt"); err != nil {
		t.Errorf("a journaled volume must stay readable: %v", err)
	}
}
