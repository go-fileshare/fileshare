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
// per share for two reasons that remain open in hfsplus: a durable small write
// is about 2.5x slower than macOS (go-filesystems/hfsplus#45, measured in
// #35), 1.6x at hfsplus_durability = "mounted"; and after a crash a
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

// parseHFSPlusDurability reads a hfsplus_durability: strict (the default, and
// what an empty setting means), mounted or lazy. It applies to a writable HFS+
// image only (hfsplus v0.12.0, SetDurability). Per commit, in write barriers:
// strict 3, mounted 1 to 2, lazy 0 (and one or two at Sync or Close). Lazy is
// data-writeback: it must not be used for a share other clients mount at the
// same time, because the volume is not consistent on the medium between flushes.
func parseHFSPlusDurability(s string) (hfsplus.Durability, error) {
	switch strings.TrimSpace(s) {
	case "", "strict":
		return hfsplus.DurabilityStrict, nil
	case "mounted":
		return hfsplus.DurabilityMounted, nil
	case "lazy":
		return hfsplus.DurabilityLazy, nil
	}
	return hfsplus.DurabilityStrict, fmt.Errorf("%q is not a durability: want strict, mounted or lazy", s)
}

// hfsplusDurability is the level a share's block asks for, validated at load.
func hfsplusDurability(b shareBlock) hfsplus.Durability {
	d, err := parseHFSPlusDurability(b.HFSPlusDurability)
	if err != nil {
		return hfsplus.DurabilityStrict
	}
	return d
}

// hfsplusDurable is the part of *hfsplus.Volume a reload changes.
type hfsplusDurable interface {
	Durability() hfsplus.Durability
	SetDurability(hfsplus.Durability) error
}

// applyHFSPlusDurability is run by swap, never while the new list is being
// opened: a reload that fails (another share that does not open, a state file that
// cannot be written) says "nothing changed", so the volume of a share it kept must
// not have moved. swap calls it after the old generation is stopped (no client is
// writing) and BEFORE the new list is published, so no client of the new
// generation ever sees the old level. A level that cannot be set (the sync that
// settles the old one failed) is said in the log: the volume stays at the level it
// had, and hfsplus then refuses every later write until the image is reopened.
func (s *server) applyHFSPlusDurability(shares []*share) {
	for _, sh := range shares {
		if err := sh.setHFSPlusDurability(sh.block); err != nil {
			fmt.Fprintf(s.out, "share %s: hfsplus_durability %q was not applied, the volume stays at %s and the share accepts no write until it is reopened: %v\n",
				sh.block.Name, sh.block.HFSPlusDurability, sh.hfsVol.Durability(), err)
		}
	}
}

// setHFSPlusDurability applies the block's hfsplus_durability to the writable
// HFS+ volume the share holds, under the image's lock (SetDurability must not
// run with a mutator). A share with no writable HFS+ volume ignores the setting.
func (s *share) setHFSPlusDurability(b shareBlock) error {
	if s.hfsVol == nil {
		return nil
	}
	d := hfsplusDurability(b)
	l, ok := s.fsys.(interface{ lock() *sync.Mutex })
	if !ok {
		return nil
	}
	mu := l.lock()
	mu.Lock()
	defer mu.Unlock()
	if s.hfsVol.Durability() == d {
		return nil
	}
	return s.hfsVol.SetDurability(d)
}

// hfsplusOpen is what openImage tells the HFS+ opener about the share it is
// opening, and what the opener tells back. detect.Open's Opener takes a reader
// and a size only, so the per-share facts travel in hfsplusOpens, keyed by the
// reader: a reader with no entry (a read-only open, a device, a partition view,
// any other caller) is opened through hfsplus.OpenReader, never for writing.
type hfsplusOpen struct {
	max  int64    // hfsplus_writable_max
	file *os.File // the image the share holds: what the volume reads and writes, and what the image lock is taken on
	// durability is hfsplus_durability, applied to the volume when it is opened
	// for writing; vol is that volume, nil when the open fell back to read-only.
	durability hfsplus.Durability
	vol        *hfsplus.Volume
	// fallback is set by the opener when the volume was opened read-only
	// although the share could have been written: the reason, for the log.
	fallback string
}

var hfsplusOpens sync.Map // io.ReaderAt -> *hfsplusOpen

// openHFSPlus is the opener registered for HFS+. hfsplus.OpenReader is
// read-only whatever the reader is; a writable volume is opened with
// hfsplus.OpenWritableAt, which writes in place (no copy of the image, only the
// sectors a commit changes) on the share's OWN descriptor, the one already
// confined and locked: the image is never opened again by name. The volume does
// not close the file; the share does.
//
// It opens for writing only when all of these hold: the share asked for a
// writable open (an entry in hfsplusOpens), the reader can write, the size is
// known and at or below the cap, and an exclusive lock on the image is free. A
// journal with transactions, or one that cannot be verified, comes back as
// ErrJournaled (macOS would replay it over what is written; hfsplus reads only
// the journal to say so), and a size that does not match the volume as
// ErrVolumeSize.
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
			"because a durable small write is about 2.5x slower than on macOS (go-filesystems/hfsplus#45), " +
			"1.6x at the \"mounted\" durability level, and after a crash a journaled volume " +
			"mounts without its journal until diskutil enableJournal"
		return hfsplus.OpenReader(r, size)
	case size <= 0:
		o.fallback = "its size is not known, so it cannot be written in place"
		return hfsplus.OpenReader(r, size)
	case size > o.max:
		o.fallback = fmt.Sprintf("it is %d bytes, over hfsplus_writable_max (%d bytes)", size, o.max)
		return hfsplus.OpenReader(r, size)
	}
	if err := lockImage(o.file); err != nil {
		o.fallback = fmt.Sprintf("another process holds the image open for writing (%v)", err)
		return hfsplus.OpenReader(r, size)
	}
	vol, err := hfsplus.OpenWritableAt(o.file, size)
	if err == nil {
		if derr := vol.SetDurability(o.durability); derr != nil {
			unlockImage(o.file)
			return nil, derr
		}
		o.vol = vol
		return vol, nil
	}
	unlockImage(o.file)
	switch {
	case errors.Is(err, hfsplus.ErrJournaled):
		o.fallback = fmt.Sprintf("its journal holds transactions (%v)", err)
	case errors.Is(err, hfsplus.ErrVolumeSize):
		o.fallback = fmt.Sprintf("its size does not match the volume (%v), so it is not written", err)
	default:
		return nil, err
	}
	return hfsplus.OpenReader(r, size)
}
