// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	filesystem "github.com/go-filesystems/interface"
)

// Several shares, seen as one tree.
//
// SMB, WebDAV and NFS each have a notion of several exports on one server, so
// each share is handed to them as itself. SFTP has none: a client logs in and
// lands in ONE filesystem. So the shares become the top-level directories of a
// tree assembled here -- /photos/holiday.jpg is holiday.jpg in the share
// called photos -- which is what a person expects from `sftp` anyway.
//
// It is built PER USER, and that is the point: alice's tree has the shares
// alice may use, and a share bob may not use is not a directory bob can see.
// A share that is read-only for this person is read-only in their tree, so a
// write into it is refused here rather than by a driver that would have
// allowed it.
type unionFS struct {
	// entries are the top-level directories, in the order the configuration
	// gave them: a listing that reshuffles itself between two runs is one
	// nobody can trust.
	entries []unionEntry
	// revoked, when set, is asked before every operation: a session whose
	// certificate has since been revoked -- or whose revocation list is no
	// longer known to be current -- is served nothing more. It is the only
	// way a revocation reaches a session already open: SSH checks the
	// certificate once, at login.
	revoked func() error
}

type unionEntry struct {
	name     string
	fsys     filesystem.Filesystem
	readOnly bool
	// snapshots serve the files of a driver without Opener (see snapshotFile).
	snapshots *snapshotCache
}

// errReadOnly is what a write into a read-only share comes back as. It is
// os.ErrPermission because that is what every client turns into "you may not",
// rather than into "the medium is broken".
var errReadOnly = os.ErrPermission

// unionFor builds the tree one person sees, without the shares served as
// their people.
func unionFor(shares []*share, p principal) *unionFS { return unionForWith(shares, p, nil) }

// unionForWith builds it with those shares too, each reached through
// worker: a share it has no filesystem for (false) is left out, as one the
// person may not use is.
func unionForWith(shares []*share, p principal, worker func(*share) (filesystem.Filesystem, bool)) *unionFS {
	u := &unionFS{}
	for _, sh := range shares {
		if !sh.mayUse(p) {
			continue
		}
		fsys := sh.fsys
		if sh.system {
			var ok bool
			if worker == nil {
				continue
			}
			if fsys, ok = worker(sh); !ok {
				continue
			}
		}
		u.entries = append(u.entries, unionEntry{
			name:      sh.name,
			fsys:      fsys,
			readOnly:  sh.readOnlyFor(p),
			snapshots: &snapshotCache{},
		})
	}
	return u
}

// route splits /share/rest into the share and the path inside it.
//
// The root itself, and a share's own name, are answered by the union: they are
// not paths in any filesystem. Anything that escapes -- "/../etc/passwd" -- is
// resolved before the split, so a name that climbs out lands nowhere rather
// than in another share.
func (u *unionFS) route(p string) (*unionEntry, string, bool) {
	if u.gone() {
		return nil, "", false
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	if clean == "/" {
		return nil, "", true
	}
	rest := strings.TrimPrefix(clean, "/")
	name, tail, _ := strings.Cut(rest, "/")
	for i := range u.entries {
		if u.entries[i].name == name {
			return &u.entries[i], "/" + tail, true
		}
	}
	return nil, "", false
}

func (u *unionFS) Close() error { return nil } // the shares are closed by the server

// gone reports whether this session may no longer be served.
func (u *unionFS) gone() bool { return u.revoked != nil && u.revoked() != nil }

func (u *unionFS) ReadFile(p string) ([]byte, error) {
	e, inside, ok := u.route(p)
	if !ok || e == nil {
		return nil, os.ErrNotExist // the root is a directory, not a file
	}
	return e.fsys.ReadFile(inside)
}

func (u *unionFS) ListDir(p string) ([]filesystem.DirEntry, error) {
	e, inside, ok := u.route(p)
	if !ok {
		return nil, os.ErrNotExist
	}
	if e == nil {
		// The root: one directory per share, and nothing else.
		out := make([]filesystem.DirEntry, 0, len(u.entries))
		for i, entry := range u.entries {
			out = append(out, filesystem.NewDirEntry(uint64(i+2), entry.name, dirEntryDirectory))
		}
		return out, nil
	}
	return e.fsys.ListDir(inside)
}

func (u *unionFS) Stat(p string) (filesystem.Stat, error) {
	e, inside, ok := u.route(p)
	if !ok {
		return nil, os.ErrNotExist
	}
	if e == nil {
		return filesystem.NewStat(modeDir|0o555, 0, 1), nil
	}
	if inside == "/" {
		// A share's own directory. Its mode says read-only when this person's
		// view of it is, which is what a client greys out an action on.
		mode := uint16(modeDir | 0o755)
		if e.readOnly {
			mode = modeDir | 0o555
		}
		return filesystem.NewStat(mode, 0, 1), nil
	}
	return e.fsys.Stat(inside)
}

func (u *unionFS) WriteFile(p string, data []byte, perm os.FileMode) error {
	e, inside, err := u.writable(p)
	if err != nil {
		return err
	}
	return e.fsys.WriteFile(inside, data, perm)
}

func (u *unionFS) MkDir(p string, perm os.FileMode) error {
	e, inside, err := u.writable(p)
	if err != nil {
		return err
	}
	return e.fsys.MkDir(inside, perm)
}

func (u *unionFS) DeleteFile(p string) error {
	e, inside, err := u.writable(p)
	if err != nil {
		return err
	}
	return e.fsys.DeleteFile(inside)
}

func (u *unionFS) DeleteDir(p string) error {
	e, inside, err := u.writable(p)
	if err != nil {
		return err
	}
	return e.fsys.DeleteDir(inside)
}

func (u *unionFS) Rename(from, to string) error {
	e, inside, err := u.writable(from)
	if err != nil {
		return err
	}
	dst, insideTo, err := u.writable(to)
	if err != nil {
		return err
	}
	if dst != e {
		// A rename ACROSS shares is a copy and a delete over two different
		// images, which is not what rename promises anywhere: it is atomic or
		// it is not a rename. Refused by name.
		return errors.New("fileshare: a rename cannot cross two shares")
	}
	return e.fsys.Rename(inside, insideTo)
}

func (u *unionFS) ReadLink(p string) (string, error) {
	e, inside, ok := u.route(p)
	if !ok || e == nil {
		return "", os.ErrInvalid
	}
	return e.fsys.ReadLink(inside)
}

// writable resolves a path and refuses the two ways it can fail: no such
// share, and a share this person may only read.
func (u *unionFS) writable(p string) (*unionEntry, string, error) {
	e, inside, ok := u.route(p)
	if !ok {
		return nil, "", os.ErrNotExist
	}
	if e == nil || inside == "/" {
		// The root and a share's own directory belong to the configuration,
		// not to a client.
		return nil, "", errReadOnly
	}
	if e.readOnly {
		return nil, "", errReadOnly
	}
	return e, inside, nil
}

// OpenFile keeps the positional path alive through the union: a driver that
// answers Opener would otherwise be read whole-file for every request, which
// was measured elsewhere in this family at ~70x.
func (u *unionFS) OpenFile(p string) (filesystem.File, error) {
	e, inside, ok := u.route(p)
	if !ok || e == nil || inside == "/" {
		return nil, os.ErrInvalid
	}
	var f filesystem.File
	if o, canOpen := e.fsys.(filesystem.Opener); canOpen {
		var err error
		if f, err = o.OpenFile(inside); err != nil {
			return nil, err
		}
	} else {
		// A driver with no positional reads -- hfsplus, ntfs, xfs... --
		// still has files: read whole, served from memory. The union is an
		// Opener for every share, so refusing here left those files
		// unreadable over SFTP (found by the security review). A write
		// open gets a File that cannot write, and the SFTP server then
		// writes by path, as it does for any such driver.
		c := e.snapshots
		if c == nil { // an entry built by hand: no sharing between its handles
			c = &snapshotCache{}
		}
		f = c.open(e.fsys, inside)
	}
	if e.readOnly {
		// A writable File through a read-only view would be the one way past
		// every check above.
		if _, writable := f.(filesystem.WritableFile); writable {
			f = readOnlyFile{f}
		}
	}
	if u.revoked != nil {
		// A file already open is read without passing through route: a
		// download begun before the revocation would otherwise finish.
		if w, writable := f.(filesystem.WritableFile); writable {
			return revocableWritable{revocableFile{f, u}, w}, nil
		}
		return revocableFile{f, u}, nil
	}
	return f, nil
}

// What a driver without Opener offers is ReadFile: the whole file, in memory.
// The union serves it through a snapshot that is
//
//   - lazy: opening a file reads nothing; the first Size or ReadAt does, so a
//     client that opens and never reads costs nothing, and a handle that is
//     only closed is free;
//   - shared: every handle open on one file of one share holds the same bytes
//     (one read, one copy), counted by handles, and freed when the last one
//     closes -- so memory is bounded by the distinct files open, not by
//     handles x size (one session may hold 1024 handles);
//   - bounded: a file larger than maxSnapshotFile, or one that would take the
//     process's snapshots past maxSnapshotTotal, is refused with errSnapshotTooLarge
//     rather than loaded. The remedy for such a file is a driver that
//     implements Opener, which is read by range.
const (
	maxSnapshotFile  = 64 << 20
	maxSnapshotTotal = 512 << 20
)

// errSnapshotTooLarge says a file cannot be served whole from memory.
var errSnapshotTooLarge = errors.New("this share's driver has no random access, and the file is too large to serve from memory")

// snapshotBytes is what the snapshots of the whole process hold.
var snapshotBytes atomic.Int64

// snapshotCache is the snapshots of one share's files, by path.
type snapshotCache struct {
	mu sync.Mutex
	m  map[string]*snapshot
}

type snapshot struct {
	c    *snapshotCache
	path string
	fsys filesystem.Filesystem
	refs int

	once sync.Once
	data []byte
	err  error
}

// open returns a handle on the snapshot of path, creating it (unread) when no
// handle holds it.
func (c *snapshotCache) open(fsys filesystem.Filesystem, path string) filesystem.File {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*snapshot{}
	}
	s := c.m[path]
	if s == nil {
		s = &snapshot{c: c, path: path, fsys: fsys}
		c.m[path] = s
	}
	s.refs++
	return &snapshotFile{s: s}
}

// bytes loads the snapshot once, within the bounds.
func (s *snapshot) bytes() ([]byte, error) {
	s.once.Do(func() {
		data, err := s.fsys.ReadFile(s.path)
		if err != nil {
			s.err = err
			return
		}
		if len(data) > maxSnapshotFile || snapshotBytes.Add(int64(len(data))) > maxSnapshotTotal {
			if len(data) <= maxSnapshotFile {
				snapshotBytes.Add(-int64(len(data)))
			}
			s.err = errSnapshotTooLarge
			return
		}
		s.data = data
	})
	return s.data, s.err
}

// release drops one handle; the last one frees the bytes.
func (s *snapshot) release() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.refs--; s.refs > 0 {
		return
	}
	delete(s.c.m, s.path)
	snapshotBytes.Add(-int64(len(s.data)))
	s.data = nil
}

// snapshotFile is a handle on a snapshot: a filesystem.File that cannot write.
type snapshotFile struct {
	s      *snapshot
	closed atomic.Bool
}

func (f *snapshotFile) Size() int64 {
	if f.closed.Load() {
		return 0
	}
	data, _ := f.s.bytes()
	return int64(len(data))
}

func (f *snapshotFile) ReadAt(p []byte, off int64) (int, error) {
	if f.closed.Load() {
		return 0, os.ErrClosed
	}
	data, err := f.s.bytes()
	if err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if off >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *snapshotFile) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	f.s.release()
	return nil
}

// revocableFile is an open file that stops answering when its session is
// revoked.
type revocableFile struct {
	filesystem.File
	u *unionFS
}

func (f revocableFile) ReadAt(p []byte, off int64) (int, error) {
	if f.u.gone() {
		return 0, os.ErrPermission
	}
	return f.File.ReadAt(p, off)
}

// revocableWritable keeps a writable file writable, and revocable.
type revocableWritable struct {
	revocableFile
	w filesystem.WritableFile
}

func (f revocableWritable) WriteAt(p []byte, off int64) (int, error) {
	if f.u.gone() {
		return 0, os.ErrPermission
	}
	return f.w.WriteAt(p, off)
}

func (f revocableWritable) Truncate(size int64) error {
	if f.u.gone() {
		return os.ErrPermission
	}
	return f.w.Truncate(size)
}

func (f revocableWritable) Sync() error { return f.w.Sync() }

// readOnlyFile is a File with its writes taken away.
type readOnlyFile struct{ filesystem.File }

// The modes the union reports for the directories it invents. They are the
// POSIX bits: a driver's Stat.Mode is the same encoding.
const (
	modeDir           = 0x4000 // S_IFDIR
	dirEntryDirectory = 4      // DT_DIR
)
