// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// One image, three servers, one lock.
//
// A go-filesystems driver wraps a single *os.File and the interface promises
// NOTHING about concurrent path-based calls: only File.ReadAt and
// non-overlapping File.WriteAt are documented as safe. Every server in this
// family knows that and serialises the driver itself -- smb holds a lock for a
// whole command, webdav has an fsmu, nfs has an fsmu.
//
// Each of them holds ITS OWN lock, and none of them knows about the others.
// Serving one image over three protocols at once therefore has no common lock
// anywhere, which is a promise nobody made being relied on by three callers at
// once.
//
// MEASURED, so as not to overstate it: eight goroutines writing files through
// an UNWRAPPED fat32 driver, under -race, produce no race today -- its write
// path does not share the state that would show one. This wrapper is therefore
// insurance on a contract, not a reproduction of a defect: the interface says
// a driver need not be safe, ext4 and ntfs are not fat32, and a driver update
// is not a thing this program should have to re-audit.
//
// The optional capabilities are carried through rather than hidden: a driver
// that answers Opener gets a locked File back, and a driver whose File answers
// WritableFile keeps its positional writes -- the difference between those and
// the whole-file fallback was measured at ~70x, so losing them to a wrapper
// would be a performance defect disguised as safety.
type lockedFS struct {
	mu   *sync.Mutex
	fsys filesystem.Filesystem
}

// lockFS wraps a driver so that every server shares one lock. It returns
// something that answers exactly the capabilities the driver answered.
func lockFS(fsys filesystem.Filesystem) filesystem.Filesystem {
	l := lockedFS{mu: new(sync.Mutex), fsys: fsys}
	// The combinations are spelled out because Go has no way to build a type
	// whose method set depends on a value. Each one is a real driver shape:
	// fat32 and ext4 answer all of them, iso9660 answers none.
	opener, canOpen := fsys.(filesystem.Opener)
	trunc, canTruncate := fsys.(filesystem.Truncater)
	label, hasLabel := fsys.(filesystem.LabelReader)
	switch {
	case canOpen && canTruncate && hasLabel:
		return lockedFull{l, lockedOpener{l, opener}, lockedTruncater{l, trunc}, lockedLabel{l, label}}
	case canOpen && canTruncate:
		return lockedOpenTrunc{l, lockedOpener{l, opener}, lockedTruncater{l, trunc}}
	case canOpen && hasLabel:
		return lockedOpenLabel{l, lockedOpener{l, opener}, lockedLabel{l, label}}
	case canOpen:
		return lockedOpen{l, lockedOpener{l, opener}}
	case canTruncate && hasLabel:
		return lockedTruncLabel{l, lockedTruncater{l, trunc}, lockedLabel{l, label}}
	case canTruncate:
		return lockedTrunc{l, lockedTruncater{l, trunc}}
	case hasLabel:
		return lockedLabelled{l, lockedLabel{l, label}}
	}
	return l
}

// The Filesystem itself. Every method takes the lock and releases it: nothing
// here is held across a call into anything else, so this cannot deadlock with
// a server's own lock.
func (l lockedFS) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.fsys.Close() }

func (l lockedFS) ReadFile(p string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.ReadFile(p)
}

func (l lockedFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.ListDir(p)
}

func (l lockedFS) Stat(p string) (filesystem.Stat, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.Stat(p)
}

func (l lockedFS) WriteFile(p string, data []byte, perm os.FileMode) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.WriteFile(p, data, perm)
}

func (l lockedFS) ReadLink(p string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.ReadLink(p)
}

func (l lockedFS) MkDir(p string, perm os.FileMode) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.MkDir(p, perm)
}

func (l lockedFS) DeleteFile(p string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.DeleteFile(p)
}

func (l lockedFS) DeleteDir(p string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.DeleteDir(p)
}

func (l lockedFS) Rename(from, to string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fsys.Rename(from, to)
}

// The optional capabilities, each in its own type so the combinations above
// can be assembled.
type lockedOpener struct {
	l  lockedFS
	up filesystem.Opener
}

func (o lockedOpener) OpenFile(p string) (filesystem.File, error) {
	o.l.mu.Lock()
	defer o.l.mu.Unlock()
	f, err := o.up.OpenFile(p)
	if err != nil {
		return nil, err
	}
	if w, ok := f.(filesystem.WritableFile); ok {
		return lockedWritableFile{o.l.mu, w}, nil
	}
	return lockedFile{o.l.mu, f}, nil
}

type lockedTruncater struct {
	l  lockedFS
	up filesystem.Truncater
}

func (t lockedTruncater) Truncate(p string, n int64) error {
	t.l.mu.Lock()
	defer t.l.mu.Unlock()
	return t.up.Truncate(p, n)
}

type lockedLabel struct {
	l  lockedFS
	up filesystem.LabelReader
}

func (b lockedLabel) Label() string {
	b.l.mu.Lock()
	defer b.l.mu.Unlock()
	return b.up.Label()
}

// A file handle is locked too: ReadAt on a driver's File seeks the same
// underlying descriptor as every path-based call.
type lockedFile struct {
	mu *sync.Mutex
	up filesystem.File
}

func (f lockedFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up.ReadAt(p, off)
}
func (f lockedFile) Close() error { f.mu.Lock(); defer f.mu.Unlock(); return f.up.Close() }
func (f lockedFile) Size() int64  { f.mu.Lock(); defer f.mu.Unlock(); return f.up.Size() }

type lockedWritableFile struct {
	mu *sync.Mutex
	up filesystem.WritableFile
}

func (f lockedWritableFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up.ReadAt(p, off)
}
func (f lockedWritableFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up.WriteAt(p, off)
}
func (f lockedWritableFile) Truncate(n int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up.Truncate(n)
}
func (f lockedWritableFile) Sync() error  { f.mu.Lock(); defer f.mu.Unlock(); return f.up.Sync() }
func (f lockedWritableFile) Close() error { f.mu.Lock(); defer f.mu.Unlock(); return f.up.Close() }
func (f lockedWritableFile) Size() int64  { f.mu.Lock(); defer f.mu.Unlock(); return f.up.Size() }

// The assembled shapes. Each embeds the locked Filesystem plus the locked
// capabilities the driver had, and nothing it did not.
type lockedFull struct {
	lockedFS
	lockedOpener
	lockedTruncater
	lockedLabel
}
type lockedOpenTrunc struct {
	lockedFS
	lockedOpener
	lockedTruncater
}
type lockedOpenLabel struct {
	lockedFS
	lockedOpener
	lockedLabel
}
type lockedOpen struct {
	lockedFS
	lockedOpener
}
type lockedTruncLabel struct {
	lockedFS
	lockedTruncater
	lockedLabel
}
type lockedTrunc struct {
	lockedFS
	lockedTruncater
}
type lockedLabelled struct {
	lockedFS
	lockedLabel
}

// Chtimes and the rest of MetadataSetter are deliberately NOT carried: no
// server here calls them, and a wrapper that claims a capability it has not
// been asked to serialise is a promise nobody checked. See interface#14.
var _ = time.Time{}
