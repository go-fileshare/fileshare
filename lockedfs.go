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
//
// MetadataSetter (Chmod, Chown, Chtimes) is the fifth axis, carried since smb
// v0.10.0: its SET_INFO calls Chtimes, so a wrapper that hid it made every
// image drop a client's access and write times, even a driver that can set them.
func lockFS(fsys filesystem.Filesystem) filesystem.Filesystem {
	res := lockFSTimes(fsys)
	ms, ok := fsys.(filesystem.MetadataSetter)
	if !ok {
		return res
	}
	mu := res.(interface{ lock() *sync.Mutex }).lock()
	m := lockedMeta{mu, ms}
	switch b := res.(type) {
	case lockedFullT:
		return lockedFullTM{b, m}
	case lockedOpenTruncT:
		return lockedOpenTruncTM{b, m}
	case lockedOpenLabelT:
		return lockedOpenLabelTM{b, m}
	case lockedOpenT:
		return lockedOpenTM{b, m}
	case lockedTruncLabelT:
		return lockedTruncLabelTM{b, m}
	case lockedTruncT:
		return lockedTruncTM{b, m}
	case lockedLabelledT:
		return lockedLabelledTM{b, m}
	case lockedPlainT:
		return lockedPlainTM{b, m}
	case lockedFull:
		return lockedFullM{b, m}
	case lockedOpenTrunc:
		return lockedOpenTruncM{b, m}
	case lockedOpenLabel:
		return lockedOpenLabelM{b, m}
	case lockedOpen:
		return lockedOpenM{b, m}
	case lockedTruncLabel:
		return lockedTruncLabelM{b, m}
	case lockedTrunc:
		return lockedTruncM{b, m}
	case lockedLabelled:
		return lockedLabelledM{b, m}
	case lockedFS:
		return lockedPlainM{b, m}
	}
	return res
}

// lock is the one mutex of the image, reached through whichever shape wraps it.
func (l lockedFS) lock() *sync.Mutex { return l.mu }

// lockedMeta serialises Chmod, Chown and Chtimes with every other call on the
// image. They write, and the lock is one mutex, so that is the exclusive one.
type lockedMeta struct {
	mu *sync.Mutex
	up filesystem.MetadataSetter
}

func (m lockedMeta) Chmod(p string, perm os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up.Chmod(p, perm)
}

func (m lockedMeta) Chown(p string, uid, gid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up.Chown(p, uid, gid)
}

func (m lockedMeta) Chtimes(p string, atime, mtime time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.up.Chtimes(p, atime, mtime)
}

// The sixteen shapes above, with MetadataSetter.
type lockedFullTM struct {
	lockedFullT
	lockedMeta
}
type lockedOpenTruncTM struct {
	lockedOpenTruncT
	lockedMeta
}
type lockedOpenLabelTM struct {
	lockedOpenLabelT
	lockedMeta
}
type lockedOpenTM struct {
	lockedOpenT
	lockedMeta
}
type lockedTruncLabelTM struct {
	lockedTruncLabelT
	lockedMeta
}
type lockedTruncTM struct {
	lockedTruncT
	lockedMeta
}
type lockedLabelledTM struct {
	lockedLabelledT
	lockedMeta
}
type lockedPlainTM struct {
	lockedPlainT
	lockedMeta
}
type lockedFullM struct {
	lockedFull
	lockedMeta
}
type lockedOpenTruncM struct {
	lockedOpenTrunc
	lockedMeta
}
type lockedOpenLabelM struct {
	lockedOpenLabel
	lockedMeta
}
type lockedOpenM struct {
	lockedOpen
	lockedMeta
}
type lockedTruncLabelM struct {
	lockedTruncLabel
	lockedMeta
}
type lockedTruncM struct {
	lockedTrunc
	lockedMeta
}
type lockedLabelledM struct {
	lockedLabelled
	lockedMeta
}
type lockedPlainM struct {
	lockedFS
	lockedMeta
}

// lockFSTimes is lockFS without MetadataSetter.
func lockFSTimes(fsys filesystem.Filesystem) filesystem.Filesystem {
	locked := lockFSCaps(fsys)
	tr, ok := fsys.(filesystem.TimesReader)
	if !ok {
		return locked
	}
	// TimesReader (interface v0.6.0) is the ninth shape's other axis: carried
	// through, or a FAT image would answer "now" over every protocol.
	var l lockedFS
	switch b := locked.(type) {
	case lockedFull:
		l = b.lockedFS
		return lockedFullT{b, lockedTimes{l, tr}}
	case lockedOpenTrunc:
		l = b.lockedFS
		return lockedOpenTruncT{b, lockedTimes{l, tr}}
	case lockedOpenLabel:
		l = b.lockedFS
		return lockedOpenLabelT{b, lockedTimes{l, tr}}
	case lockedOpen:
		l = b.lockedFS
		return lockedOpenT{b, lockedTimes{l, tr}}
	case lockedTruncLabel:
		l = b.lockedFS
		return lockedTruncLabelT{b, lockedTimes{l, tr}}
	case lockedTrunc:
		l = b.lockedFS
		return lockedTruncT{b, lockedTimes{l, tr}}
	case lockedLabelled:
		l = b.lockedFS
		return lockedLabelledT{b, lockedTimes{l, tr}}
	case lockedFS:
		return lockedPlainT{b, lockedTimes{b, tr}}
	}
	return locked
}

// lockedTimes serialises Times with every other call on the image.
type lockedTimes struct {
	l  lockedFS
	up filesystem.TimesReader
}

func (t lockedTimes) Times(p string) (filesystem.FileTimes, error) {
	t.l.mu.Lock()
	defer t.l.mu.Unlock()
	return t.up.Times(p)
}

// The same eight shapes, with Times.
type lockedFullT struct {
	lockedFull
	lockedTimes
}
type lockedOpenTruncT struct {
	lockedOpenTrunc
	lockedTimes
}
type lockedOpenLabelT struct {
	lockedOpenLabel
	lockedTimes
}
type lockedOpenT struct {
	lockedOpen
	lockedTimes
}
type lockedTruncLabelT struct {
	lockedTruncLabel
	lockedTimes
}
type lockedTruncT struct {
	lockedTrunc
	lockedTimes
}
type lockedLabelledT struct {
	lockedLabelled
	lockedTimes
}
type lockedPlainT struct {
	lockedFS
	lockedTimes
}

func lockFSCaps(fsys filesystem.Filesystem) filesystem.Filesystem {
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

// MetadataSetter (Chmod, Chown, Chtimes) is carried, and only when the driver
// has it: see lockFS and lockedMeta. It was NOT carried until smb v0.10.0, on the
// ground that no server here called it -- which stopped being true when smb's
// SET_INFO began to apply a client's access and write times through Chtimes.
// See interface#14.
