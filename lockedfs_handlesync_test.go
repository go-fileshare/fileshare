// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// flakyFile is a positional file whose own Sync fails once and then succeeds, as
// an fsync does after an EIO the kernel reports once and forgets.
type flakyFile struct{ n int }

func (f *flakyFile) ReadAt([]byte, int64) (int, error)      { return 0, nil }
func (f *flakyFile) WriteAt(p []byte, _ int64) (int, error) { return len(p), nil }
func (f *flakyFile) Truncate(int64) error                   { return nil }
func (f *flakyFile) Close() error                           { return nil }
func (f *flakyFile) Size() int64                            { return 0 }
func (f *flakyFile) Sync() error {
	f.n++
	if f.n == 1 {
		return errors.New("EIO")
	}
	return nil
}

// flakyOpenerFS is a driver that opens positional files and has no Sync of its
// own.
type flakyOpenerFS struct {
	plainFS
	f *flakyFile
}

func (o flakyOpenerFS) OpenFile(string) (filesystem.File, error) { return o.f, nil }

// A handle's own Sync that fails is recorded in the image's latch: the client
// sees the error, and a later COMMIT or Sync on the same image (which fsyncs the
// same descriptor and would succeed) must fail too, without asking the image,
// until the share is reopened. Another handle on the image is refused as well.
func TestFailedHandleSyncLatchesTheImage(t *testing.T) {
	img := &countingImage{}
	fsys := lockFSImage(flakyOpenerFS{f: &flakyFile{}}, img)
	open := func() filesystem.WritableFile {
		f, err := fsys.(filesystem.Opener).OpenFile("/f")
		if err != nil {
			t.Fatal(err)
		}
		w, ok := f.(filesystem.WritableFile)
		if !ok {
			t.Fatal("the locked file is not writable")
		}
		return w
	}
	h := open()
	first := h.Sync()
	if first == nil {
		t.Fatal("control: the handle's Sync did not fail")
	}
	err := fsys.(syncer).Sync()
	if err == nil || !strings.Contains(err.Error(), first.Error()) {
		t.Fatalf("COMMIT after a failed handle Sync = %v, want the latched EIO", err)
	}
	if img.n != 0 {
		t.Errorf("the image was fsynced %d times after the latch", img.n)
	}
	if err := h.Sync(); err == nil {
		t.Error("a second Sync on the same handle reported success")
	}
	if err := open().Sync(); err == nil {
		t.Error("a Sync on another handle of the image reported success")
	}
}

// closedFile is a handle whose Sync reports os.ErrClosed, as fat32 and ext4 do
// after Close.
type closedFile struct{ flakyFile }

func (closedFile) Sync() error { return os.ErrClosed }

// A Sync on a closed handle is returned to its caller but says nothing about
// the image, so it must not latch: a later COMMIT on a healthy image succeeds.
func TestClosedHandleSyncDoesNotLatchTheImage(t *testing.T) {
	img := &countingImage{}
	fsys := lockFSImage(closedOpenerFS{}, img)
	f, err := fsys.(filesystem.Opener).OpenFile("/f")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.(filesystem.WritableFile).Sync(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("handle Sync = %v, want os.ErrClosed returned to the caller", err)
	}
	if err := fsys.(syncer).Sync(); err != nil || img.n != 1 {
		t.Errorf("COMMIT after a closed-handle Sync = %v, image fsynced %d times; want nil and 1", err, img.n)
	}
}

type closedOpenerFS struct{ plainFS }

func (closedOpenerFS) OpenFile(string) (filesystem.File, error) { return &closedFile{}, nil }
