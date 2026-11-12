// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/go-filesystems/hfsplus"
	filesystem "github.com/go-filesystems/interface"
)

// maxHFSPlusImage bounds the in-memory copy a writable HFS+ volume keeps. It is
// the same ceiling hfsplus.OpenFileWritable applies (hfsplus v0.9.0,
// maxImageBytes): the driver edits a whole image held in memory and flushes it
// back, so an image larger than this is served read-only instead.
const maxHFSPlusImage = 64 << 30

// readOnlyReader is a reader with its WriteAt taken away. Drivers decide
// whether they may write by asking their reader for io.WriterAt, so an image
// that was opened read-only, or on a share configured read-only, is handed one
// of these: the driver then opens read-only, with its own refusal, instead of
// discovering EBADF at the first write.
type readOnlyReader struct{ io.ReaderAt }

// journaledReadOnly is an HFS+ volume that could only be opened read-only
// because its journal holds transactions (hfsplus.ErrJournaled). It is a type of
// its own so openImage can tell it from a share that was asked to be read-only,
// and say why -- once, naming the share.
type journaledReadOnly struct {
	filesystem.Filesystem
	why error
}

// openHFSPlus is the opener registered for HFS+. hfsplus.OpenReader is read-only
// whatever the reader is: a writable volume is opened from the whole image in
// memory with hfsplus.OpenWritable, which is what OpenFileWritable does after it
// has opened its own path. This takes the reader the share already holds -- the
// descriptor opened (and, for a confined image, confined) by openImage -- so no
// second open of a path can leave the confinement.
//
// A volume is opened writable only when r can be written (an *os.File opened
// read-write) and the image fits maxHFSPlusImage. A journal with transactions in
// it, or one that cannot be verified, comes back ErrJournaled: macOS would replay
// it over what this driver writes, so the volume is opened through OpenReader
// instead and handed back as journaledReadOnly.
func openHFSPlus(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	wa, ok := r.(io.WriterAt)
	if !ok || size <= 0 || size > maxHFSPlusImage {
		return hfsplus.OpenReader(r, size)
	}
	img := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, size), img); err != nil {
		return nil, fmt.Errorf("hfsplus: read image: %w", err)
	}
	v, err := hfsplus.OpenWritable(img, wa)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, hfsplus.ErrJournaled) {
		return nil, err
	}
	ro, rerr := hfsplus.OpenReader(r, size)
	if rerr != nil {
		return nil, rerr
	}
	return journaledReadOnly{Filesystem: ro, why: err}, nil
}
