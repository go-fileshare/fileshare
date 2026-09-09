package main

import (
	"os"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// The tree one person sees: the shares they may use, as directories, and
// nothing above or beside them.
func unionUnder(t *testing.T) (*unionFS, *memShare, *memShare) {
	t.Helper()
	rw := &memShare{files: map[string][]byte{"/a.txt": []byte("a")}}
	ro := &memShare{files: map[string][]byte{"/b.txt": []byte("b")}}
	return unionFor([]*share{
		{name: "writable", fsys: rw},
		{name: "readable", fsys: ro, readOnly: true},
		{name: "notmine", fsys: rw, allow: []string{"somebody"}},
	}, "alice"), rw, ro
}

func TestTheTreeIsWhatThisPersonMayUse(t *testing.T) {
	u, _, _ := unionUnder(t)
	entries, err := u.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if got := strings.Join(names, ","); got != "writable,readable" {
		t.Errorf("the root holds %q -- a share alice may not use is not a directory alice can see", got)
	}
	if _, err := u.ListDir("/notmine"); !os.IsNotExist(err) {
		t.Errorf("listing a share she may not use gave %v", err)
	}
}

func TestWhatTheTreeRefuses(t *testing.T) {
	u, _, _ := unionUnder(t)
	for _, tc := range []struct {
		name string
		do   func() error
	}{
		{"writing into a read-only share", func() error { return u.WriteFile("/readable/x", nil, 0o644) }},
		{"making a directory in one", func() error { return u.MkDir("/readable/d", 0o755) }},
		{"deleting from one", func() error { return u.DeleteFile("/readable/b.txt") }},
		{"deleting a directory in one", func() error { return u.DeleteDir("/readable/d") }},
		{"writing at the root", func() error { return u.WriteFile("/x", nil, 0o644) }},
		{"making a share", func() error { return u.MkDir("/newshare", 0o755) }},
		{"deleting a share", func() error { return u.DeleteDir("/writable") }},
		{"writing into a share nobody gave them", func() error { return u.WriteFile("/notmine/x", nil, 0o644) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(); err == nil {
				t.Error("it was allowed")
			}
		})
	}

	// A rename across two shares is a copy and a delete over two images, which
	// is not what rename promises anywhere.
	if err := u.Rename("/writable/a.txt", "/readable/a.txt"); err == nil {
		t.Error("a rename crossed two shares")
	}
	if err := u.Rename("/writable/a.txt", "/writable/moved.txt"); err != nil {
		t.Errorf("a rename inside one share: %v", err)
	}
}

// A path that climbs out lands nowhere rather than in another share.
func TestAPathCannotClimbOutOfItsShare(t *testing.T) {
	u, _, ro := unionUnder(t)
	if _, err := u.ReadFile("/writable/../readable/b.txt"); err != nil {
		// Resolved BEFORE the split, so this is readable/b.txt and it reads:
		// what must not happen is reaching something outside the tree at all.
		t.Errorf("a path that resolves inside the tree failed: %v", err)
	}
	if _, err := u.ReadFile("/../../etc/passwd"); err == nil {
		t.Error("a path climbed out of the tree")
	}
	if ro.reads == 0 {
		t.Error("the read never reached a share")
	}
}

// The tree carries the positional path through: a driver that answers Opener
// must not be read whole-file because of the union.
func TestTheTreeKeepsThePositionalPath(t *testing.T) {
	u, _, _ := unionUnder(t)
	f, err := u.OpenFile("/writable/a.txt")
	if err != nil {
		t.Fatalf("OpenFile through the tree: %v", err)
	}
	defer f.Close()
	if _, ok := f.(filesystem.WritableFile); !ok {
		t.Error("a writable share handed back a File that cannot write")
	}

	// …and a read-only share does not, however writable the driver's File is.
	ro, err := u.OpenFile("/readable/b.txt")
	if err != nil {
		t.Fatalf("OpenFile in a read-only share: %v", err)
	}
	defer ro.Close()
	if _, ok := ro.(filesystem.WritableFile); ok {
		t.Error("a read-only share handed back a writable File: that is the way past every other check")
	}
	if _, err := u.OpenFile("/"); err == nil {
		t.Error("the root was opened as a file")
	}
}

// memShare is a share's worth of files, with an Opener whose File can write.
type memShare struct {
	files map[string][]byte
	reads int
}

func (m *memShare) Close() error { return nil }
func (m *memShare) ReadFile(p string) ([]byte, error) {
	m.reads++
	b, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (m *memShare) ListDir(p string) ([]filesystem.DirEntry, error) {
	var out []filesystem.DirEntry
	for name := range m.files {
		out = append(out, filesystem.NewDirEntry(1, strings.TrimPrefix(name, "/"), 8))
	}
	return out, nil
}
func (m *memShare) Stat(p string) (filesystem.Stat, error) {
	if _, ok := m.files[p]; !ok && p != "/" {
		return nil, os.ErrNotExist
	}
	return filesystem.NewStat(0o644, 0, 1), nil
}
func (m *memShare) WriteFile(p string, b []byte, _ os.FileMode) error {
	m.files[p] = b
	return nil
}
func (m *memShare) ReadLink(string) (string, error) { return "", os.ErrInvalid }
func (m *memShare) MkDir(string, os.FileMode) error { return nil }
func (m *memShare) DeleteFile(p string) error       { delete(m.files, p); return nil }
func (m *memShare) DeleteDir(string) error          { return nil }
func (m *memShare) Rename(from, to string) error {
	m.files[to] = m.files[from]
	delete(m.files, from)
	return nil
}
func (m *memShare) OpenFile(p string) (filesystem.File, error) {
	if _, ok := m.files[p]; !ok {
		return nil, os.ErrNotExist
	}
	return memFile{}, nil
}

type memFile struct{}

func (memFile) ReadAt([]byte, int64) (int, error)  { return 0, nil }
func (memFile) WriteAt([]byte, int64) (int, error) { return 0, nil }
func (memFile) Truncate(int64) error               { return nil }
func (memFile) Sync() error                        { return nil }
func (memFile) Close() error                       { return nil }
func (memFile) Size() int64                        { return 1 }
