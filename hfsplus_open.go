// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/go-filesystems/hfsplus"
	filesystem "github.com/go-filesystems/interface"
)

// defaultHFSPlusWritableMax is hfsplus_writable_max when a share does not say.
//
// Why 0 (no HFS+ image is written unless a share asks): hfsplus v0.10.0 writes
// in place, only the sectors a commit changes, with no copy of the image in
// memory, and marks the volume as in use for the length of each commit (the
// unmounted and journaled bits are cleared in the first header write and
// restored at the end), so a crash is visible to fsck_hfs. It is still opt-in
// per share for three reasons that remain open in hfsplus: a durable small write
// costs 3 fsyncs, about 3x slower than macOS (go-filesystems/hfsplus#35); the
// crash tests are not finished (go-filesystems/hfsplus#37); and after a crash a
// journaled volume mounts without its journal until `diskutil enableJournal`.
// A share that sets a size accepts those. v0.44.0 and v0.45.0 defaulted to
// 256 MiB; v0.45.1 to 0 because hfsplus v0.9.0 held the whole image in memory
// and was not crash-safe (go-filesystems/hfsplus#33, #34).
//
// The setting stays a size, not an on/off: memory no longer scales with the
// image, but a share that set "256M" has said how large an image it is willing
// to have written, and v0.46.0 must not write a larger one it never opted in.
const defaultHFSPlusWritableMax = 0

// parseImageSize reads a hfsplus_writable_max: a number of bytes, or one with a
// K, M, G or T suffix (powers of 1024, an optional "B" or "iB" after it). "0"
// means no HFS+ image of this share is ever opened for writing.
func parseImageSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(strings.TrimSuffix(t, "B"), "i")
	shift := 0
	if t != "" {
		if i := strings.IndexByte("KMGT", t[len(t)-1]); i >= 0 {
			shift = 10 * (i + 1)
			t = t[:len(t)-1]
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 63)
	if err != nil {
		return 0, fmt.Errorf("%q is not a size: want a number of bytes, or one with K, M, G or T", s)
	}
	if shift > 0 && n > math.MaxInt64>>shift {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return int64(n) << shift, nil
}

// hfsplusWritableMax is the cap a share's block asks for, validated at load.
func hfsplusWritableMax(b shareBlock) int64 {
	if b.HFSPlusWritableMax == "" {
		return defaultHFSPlusWritableMax
	}
	n, err := parseImageSize(b.HFSPlusWritableMax)
	if err != nil {
		return defaultHFSPlusWritableMax
	}
	return n
}

// hfsplusOpen is what openImage tells the HFS+ opener about the share it is
// opening, and what the opener tells back. detect.Open's Opener takes a reader
// and a size only, so the per-share facts travel in hfsplusOpens, keyed by the
// reader: a reader with no entry (a read-only open, a device, a partition view,
// any other caller) is opened through hfsplus.OpenReader, never for writing.
type hfsplusOpen struct {
	max  int64    // hfsplus_writable_max
	file *os.File // the image the share holds: what the image lock is taken on
	path string   // the image's name, for hfsplus.OpenFileWritable; checked to be file
	// fallback is set by the opener when the volume was opened read-only
	// although the share could have been written: the reason, for the log.
	fallback string
}

var hfsplusOpens sync.Map // io.ReaderAt -> *hfsplusOpen

// openHFSPlus is the opener registered for HFS+. hfsplus.OpenReader is
// read-only whatever the reader is; a writable volume is opened with
// hfsplus.OpenFileWritable, which writes in place (no copy of the image, only
// the sectors a commit changes). It takes a path: hfsplus does not export an
// open over a descriptor, so the image is opened again by name, and refused
// (read-only fallback) unless that name is the very file the share holds, before
// and after the open, so a confined or swapped image is never written by name.
//
// It opens for writing only when all of these hold: the share asked for a
// writable open (an entry in hfsplusOpens), the reader can write, the size is
// known and at or below the cap, an exclusive lock on the image is free, and the
// name is the held file. A journal with transactions, or one that cannot be
// verified, comes back as ErrJournaled (macOS would replay it over what is
// written); hfsplus reads only the journal to say so.
//
// Every fallback is OpenReader's volume, with the reason in o.fallback.
func openHFSPlus(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	v, ok := hfsplusOpens.Load(r)
	if !ok {
		return hfsplus.OpenReader(r, size)
	}
	o := v.(*hfsplusOpen)
	if _, ok := r.(io.WriterAt); !ok {
		return hfsplus.OpenReader(r, size)
	}
	switch {
	case o.max == 0:
		o.fallback = "hfsplus_writable_max is 0, the default: HFS+ images are written only when a share sets a size, " +
			"because a durable small write is about 3x slower than on macOS (go-filesystems/hfsplus#35), " +
			"the crash tests are not finished (go-filesystems/hfsplus#37), and after a crash a journaled volume " +
			"mounts without its journal until diskutil enableJournal"
		return hfsplus.OpenReader(r, size)
	case size <= 0:
		o.fallback = "its size is not known, so it cannot be written in place"
		return hfsplus.OpenReader(r, size)
	case size > o.max:
		o.fallback = fmt.Sprintf("it is %d bytes, over hfsplus_writable_max (%d bytes)", size, o.max)
		return hfsplus.OpenReader(r, size)
	case o.path == "" || !isHeldFile(o.file, o.path):
		o.fallback = "its name no longer leads to the file the share holds, so it is not opened again by name for writing"
		return hfsplus.OpenReader(r, size)
	}
	if err := lockImage(o.file); err != nil {
		o.fallback = fmt.Sprintf("another process holds the image open for writing (%v)", err)
		return hfsplus.OpenReader(r, size)
	}
	vol, err := hfsplus.OpenFileWritable(o.path)
	if err == nil && !isHeldFile(o.file, o.path) {
		// Swapped between the check and the open: nothing was written.
		_ = vol.Close()
		err = errNameMoved
	}
	if err == nil {
		return vol, nil
	}
	unlockImage(o.file)
	if errors.Is(err, errNameMoved) {
		o.fallback = "its name changed while it was being opened, so it is not written"
		return hfsplus.OpenReader(r, size)
	}
	if !errors.Is(err, hfsplus.ErrJournaled) {
		return nil, err
	}
	o.fallback = fmt.Sprintf("its journal holds transactions (%v)", err)
	return hfsplus.OpenReader(r, size)
}

var errNameMoved = errors.New("the image's name leads to another file")

// isHeldFile is whether path names the same file as f.
func isHeldFile(f *os.File, path string) bool {
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := os.Stat(path)
	return err == nil && os.SameFile(a, b)
}
