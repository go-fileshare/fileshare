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

// hfsplusHardMax is the ceiling hfsplus applies to the in-memory image of a
// writable volume (hfsplus v0.9.0, maxImageBytes). No setting goes above it.
const hfsplusHardMax = 64 << 30

// defaultHFSPlusWritableMax is hfsplus_writable_max when a share does not say.
//
// Why 256 MiB: a writable HFS+ volume is the WHOLE image held in memory, and
// hfsplus v0.9.0 writes the whole image back on every operation (measured: 16
// MiB written for a 1-byte write plus a Chtimes on an 8 MiB image). So the size
// is both the memory a share costs and the I/O of every create, write, rename
// or Chtimes a client makes. 256 MiB is the size where one operation is still a
// fraction of a second on an SSD and a server with a dozen such shares still
// fits in a few GiB; it is a default, not a limit of the format. Raise it per
// share knowing both costs. go-filesystems/hfsplus#33 is the real fix (writing
// only what changed); the default can grow when that lands.
const defaultHFSPlusWritableMax = 256 << 20

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
	file *os.File // what the volume writes to, and what the image lock is taken on
	// fallback is set by the opener when the volume was opened read-only
	// although the share could have been written: the reason, for the log.
	fallback string
}

var hfsplusOpens sync.Map // io.ReaderAt -> *hfsplusOpen

// openHFSPlus is the opener registered for HFS+. hfsplus.OpenReader is
// read-only whatever the reader is; a writable volume is opened with
// hfsplus.OpenWritable on the whole image in memory, which is what
// OpenFileWritable does after opening its own path. This takes the descriptor
// the share already holds, so a confined image is not re-opened by name.
//
// It opens for writing only when all of these hold, each checked BEFORE the
// image is read into memory: the share asked for a writable open (an entry in
// hfsplusOpens), the reader can write, the size is known and at or below the
// cap (and hfsplus's own 64 GiB ceiling), and an exclusive lock on the image is
// free. A journal with transactions, or one that cannot be verified, comes back
// from OpenWritable as ErrJournaled: macOS would replay it over what is
// written. hfsplus does not export a journal check that works without the whole
// image, so this one case allocates (at most the cap) before falling back.
//
// Every fallback is OpenReader's volume, with the reason in o.fallback.
func openHFSPlus(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	v, ok := hfsplusOpens.Load(r)
	if !ok {
		return hfsplus.OpenReader(r, size)
	}
	o := v.(*hfsplusOpen)
	wa, ok := r.(io.WriterAt)
	if !ok {
		return hfsplus.OpenReader(r, size)
	}
	limit := min(o.max, hfsplusHardMax)
	switch {
	case size <= 0:
		o.fallback = "its size is not known, so it cannot be held in memory for writing"
		return hfsplus.OpenReader(r, size)
	case size > limit:
		o.fallback = fmt.Sprintf("it is %d bytes, over hfsplus_writable_max (%d bytes): a writable HFS+ image is held in memory and rewritten whole on every change", size, limit)
		return hfsplus.OpenReader(r, size)
	}
	if err := lockImage(o.file); err != nil {
		o.fallback = fmt.Sprintf("another process holds the image open for writing (%v)", err)
		return hfsplus.OpenReader(r, size)
	}
	img := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, size), img); err != nil {
		unlockImage(o.file)
		return nil, fmt.Errorf("hfsplus: read image: %w", err)
	}
	vol, err := hfsplus.OpenWritable(img, wa)
	if err == nil {
		return vol, nil
	}
	unlockImage(o.file)
	if !errors.Is(err, hfsplus.ErrJournaled) {
		return nil, err
	}
	o.fallback = fmt.Sprintf("its journal holds transactions (%v)", err)
	return hfsplus.OpenReader(r, size)
}
