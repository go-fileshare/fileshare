// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"path"
	"strings"

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
}

type unionEntry struct {
	name     string
	fsys     filesystem.Filesystem
	readOnly bool
}

// errReadOnly is what a write into a read-only share comes back as. It is
// os.ErrPermission because that is what every client turns into "you may not",
// rather than into "the medium is broken".
var errReadOnly = os.ErrPermission

// unionFor builds the tree one person sees.
func unionFor(shares []*share, user string) *unionFS {
	u := &unionFS{}
	for _, sh := range shares {
		if !sh.mayUse(user) {
			continue
		}
		u.entries = append(u.entries, unionEntry{
			name:     sh.name,
			fsys:     sh.fsys,
			readOnly: sh.readOnlyFor(user),
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
	o, canOpen := e.fsys.(filesystem.Opener)
	if !canOpen {
		return nil, os.ErrInvalid
	}
	f, err := o.OpenFile(inside)
	if err != nil {
		return nil, err
	}
	if e.readOnly {
		// A writable File through a read-only view would be the one way past
		// every check above.
		if _, writable := f.(filesystem.WritableFile); writable {
			return readOnlyFile{f}, nil
		}
	}
	return f, nil
}

// readOnlyFile is a File with its writes taken away.
type readOnlyFile struct{ filesystem.File }

// The modes the union reports for the directories it invents. They are the
// POSIX bits: a driver's Stat.Mode is the same encoding.
const (
	modeDir           = 0x4000 // S_IFDIR
	dirEntryDirectory = 4      // DT_DIR
)
