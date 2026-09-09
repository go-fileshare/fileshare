package main

import (
	"os"
	"sync"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// The wrapper must answer EXACTLY the capabilities the driver answered.
//
// This is the trap it exists to avoid and the one it could itself become: a
// struct that embeds filesystem.Filesystem has that method set and nothing
// more, so a careless wrapper silently erases Opener and WritableFile -- and
// with them the positional read and write paths, measured at ~70x the
// whole-file fallback. Nothing fails; everything gets slower.
func TestTheWrapperKeepsWhatTheDriverHad(t *testing.T) {
	for _, tc := range []struct {
		name              string
		fsys              filesystem.Filesystem
		open, trunc, labl bool
	}{
		{"nothing but the filesystem", plainFS{}, false, false, false},
		{"opener", openerFS{}, true, false, false},
		{"truncater", truncFS{}, false, true, false},
		{"label", labelFS{}, false, false, true},
		{"opener and truncater", openTruncFS{}, true, true, false},
		{"opener and label", openLabelFS{}, true, false, true},
		{"truncater and label", truncLabelFS{}, false, true, true},
		{"all of them", fullFS{}, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := lockFS(tc.fsys)
			if _, ok := w.(filesystem.Opener); ok != tc.open {
				t.Errorf("Opener = %v, want %v", ok, tc.open)
			}
			if _, ok := w.(filesystem.Truncater); ok != tc.trunc {
				t.Errorf("Truncater = %v, want %v", ok, tc.trunc)
			}
			if _, ok := w.(filesystem.LabelReader); ok != tc.labl {
				t.Errorf("LabelReader = %v, want %v", ok, tc.labl)
			}
			// And the wrapped calls reach the driver.
			if _, err := w.Stat("/x"); err != nil {
				t.Errorf("Stat: %v", err)
			}
		})
	}
}

// A file that can be written keeps that too, through the wrapper: the whole
// point of the positional path is that a driver's File answers WritableFile.
func TestALockedFileKeepsItsWrites(t *testing.T) {
	w := lockFS(openerFS{})
	o, ok := w.(filesystem.Opener)
	if !ok {
		t.Fatal("the wrapper lost Opener")
	}
	f, err := o.OpenFile("/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.(filesystem.WritableFile); !ok {
		t.Error("the wrapper handed back a File that cannot write, from a driver whose File could")
	}
	if f.Size() != 42 {
		t.Errorf("Size through the wrapper = %d", f.Size())
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
}

// And the lock is one lock: two goroutines through the wrapper do not overlap
// inside the driver.
func TestTheWrapperSerialises(t *testing.T) {
	c := &counter{}
	w := lockFS(c)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.ReadFile("/x")
		}()
	}
	wg.Wait()
	if c.overlapped {
		t.Error("two calls were inside the driver at once")
	}
	if c.calls != 16 {
		t.Errorf("%d calls reached the driver, want 16", c.calls)
	}
}

// counter notices whether two calls were ever inside it at the same time,
// without a lock of its own -- a driver with a lock is the one shape that
// cannot show this.
type counter struct {
	plainFS
	inside     int
	calls      int
	overlapped bool
}

func (c *counter) ReadFile(string) ([]byte, error) {
	c.inside++
	c.calls++
	if c.inside > 1 {
		c.overlapped = true
	}
	c.inside--
	return nil, nil
}

// The shapes a driver can have. Each is the minimum that answers its
// capability, so the test is about the method set and nothing else.
type plainFS struct{}

func (plainFS) Close() error                                  { return nil }
func (plainFS) ReadFile(string) ([]byte, error)               { return nil, nil }
func (plainFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (plainFS) Stat(string) (filesystem.Stat, error)          { return filesystem.NewStat(0o644, 0, 1), nil }
func (plainFS) WriteFile(string, []byte, os.FileMode) error   { return nil }
func (plainFS) ReadLink(string) (string, error)               { return "", nil }
func (plainFS) MkDir(string, os.FileMode) error               { return nil }
func (plainFS) DeleteFile(string) error                       { return nil }
func (plainFS) DeleteDir(string) error                        { return nil }
func (plainFS) Rename(string, string) error                   { return nil }

type writableFile struct{}

func (writableFile) ReadAt([]byte, int64) (int, error)  { return 0, nil }
func (writableFile) WriteAt([]byte, int64) (int, error) { return 0, nil }
func (writableFile) Truncate(int64) error               { return nil }
func (writableFile) Sync() error                        { return nil }
func (writableFile) Close() error                       { return nil }
func (writableFile) Size() int64                        { return 42 }

type openerFS struct{ plainFS }

func (openerFS) OpenFile(string) (filesystem.File, error) { return writableFile{}, nil }

type truncFS struct{ plainFS }

func (truncFS) Truncate(string, int64) error { return nil }

type labelFS struct{ plainFS }

func (labelFS) Label() string { return "TEST" }

type openTruncFS struct {
	openerFS
	truncFS
}

func (o openTruncFS) Close() error                                    { return nil }
func (o openTruncFS) ReadFile(p string) ([]byte, error)               { return o.openerFS.ReadFile(p) }
func (o openTruncFS) Stat(p string) (filesystem.Stat, error)          { return o.openerFS.Stat(p) }
func (o openTruncFS) ListDir(p string) ([]filesystem.DirEntry, error) { return o.openerFS.ListDir(p) }
func (o openTruncFS) WriteFile(p string, b []byte, m os.FileMode) error {
	return o.openerFS.WriteFile(p, b, m)
}
func (o openTruncFS) ReadLink(p string) (string, error)   { return o.openerFS.ReadLink(p) }
func (o openTruncFS) MkDir(p string, m os.FileMode) error { return o.openerFS.MkDir(p, m) }
func (o openTruncFS) DeleteFile(p string) error           { return o.openerFS.DeleteFile(p) }
func (o openTruncFS) DeleteDir(p string) error            { return o.openerFS.DeleteDir(p) }
func (o openTruncFS) Rename(a, b string) error            { return o.openerFS.Rename(a, b) }

type openLabelFS struct {
	openerFS
	labelFS
}

func (o openLabelFS) Close() error                                    { return nil }
func (o openLabelFS) ReadFile(p string) ([]byte, error)               { return o.openerFS.ReadFile(p) }
func (o openLabelFS) Stat(p string) (filesystem.Stat, error)          { return o.openerFS.Stat(p) }
func (o openLabelFS) ListDir(p string) ([]filesystem.DirEntry, error) { return o.openerFS.ListDir(p) }
func (o openLabelFS) WriteFile(p string, b []byte, m os.FileMode) error {
	return o.openerFS.WriteFile(p, b, m)
}
func (o openLabelFS) ReadLink(p string) (string, error)   { return o.openerFS.ReadLink(p) }
func (o openLabelFS) MkDir(p string, m os.FileMode) error { return o.openerFS.MkDir(p, m) }
func (o openLabelFS) DeleteFile(p string) error           { return o.openerFS.DeleteFile(p) }
func (o openLabelFS) DeleteDir(p string) error            { return o.openerFS.DeleteDir(p) }
func (o openLabelFS) Rename(a, b string) error            { return o.openerFS.Rename(a, b) }

type truncLabelFS struct {
	truncFS
	labelFS
}

func (o truncLabelFS) Close() error                                    { return nil }
func (o truncLabelFS) ReadFile(p string) ([]byte, error)               { return o.truncFS.ReadFile(p) }
func (o truncLabelFS) Stat(p string) (filesystem.Stat, error)          { return o.truncFS.Stat(p) }
func (o truncLabelFS) ListDir(p string) ([]filesystem.DirEntry, error) { return o.truncFS.ListDir(p) }
func (o truncLabelFS) WriteFile(p string, b []byte, m os.FileMode) error {
	return o.truncFS.WriteFile(p, b, m)
}
func (o truncLabelFS) ReadLink(p string) (string, error)   { return o.truncFS.ReadLink(p) }
func (o truncLabelFS) MkDir(p string, m os.FileMode) error { return o.truncFS.MkDir(p, m) }
func (o truncLabelFS) DeleteFile(p string) error           { return o.truncFS.DeleteFile(p) }
func (o truncLabelFS) DeleteDir(p string) error            { return o.truncFS.DeleteDir(p) }
func (o truncLabelFS) Rename(a, b string) error            { return o.truncFS.Rename(a, b) }

type fullFS struct {
	openerFS
	truncFS
	labelFS
}

func (o fullFS) Close() error                                    { return nil }
func (o fullFS) ReadFile(p string) ([]byte, error)               { return o.openerFS.ReadFile(p) }
func (o fullFS) Stat(p string) (filesystem.Stat, error)          { return o.openerFS.Stat(p) }
func (o fullFS) ListDir(p string) ([]filesystem.DirEntry, error) { return o.openerFS.ListDir(p) }
func (o fullFS) WriteFile(p string, b []byte, m os.FileMode) error {
	return o.openerFS.WriteFile(p, b, m)
}
func (o fullFS) ReadLink(p string) (string, error)   { return o.openerFS.ReadLink(p) }
func (o fullFS) MkDir(p string, m os.FileMode) error { return o.openerFS.MkDir(p, m) }
func (o fullFS) DeleteFile(p string) error           { return o.openerFS.DeleteFile(p) }
func (o fullFS) DeleteDir(p string) error            { return o.openerFS.DeleteDir(p) }
func (o fullFS) Rename(a, b string) error            { return o.openerFS.Rename(a, b) }

// Every method goes through the lock and reaches the driver. They are one
// line each and there are ten of them, which is exactly why a test says so
// rather than a reader checking.
func TestEveryMethodReachesTheDriver(t *testing.T) {
	w := lockFS(fullFS{})
	if _, err := w.ReadFile("/x"); err != nil {
		t.Error(err)
	}
	if _, err := w.ListDir("/"); err != nil {
		t.Error(err)
	}
	if err := w.WriteFile("/x", nil, 0o644); err != nil {
		t.Error(err)
	}
	if _, err := w.ReadLink("/x"); err != nil {
		t.Error(err)
	}
	if err := w.MkDir("/d", 0o755); err != nil {
		t.Error(err)
	}
	if err := w.DeleteFile("/x"); err != nil {
		t.Error(err)
	}
	if err := w.DeleteDir("/d"); err != nil {
		t.Error(err)
	}
	if err := w.Rename("/a", "/b"); err != nil {
		t.Error(err)
	}
	if err := w.(filesystem.Truncater).Truncate("/x", 0); err != nil {
		t.Error(err)
	}
	if got := w.(filesystem.LabelReader).Label(); got != "TEST" {
		t.Errorf("Label = %q", got)
	}
	f, err := w.(filesystem.Opener).OpenFile("/x")
	if err != nil {
		t.Fatal(err)
	}
	wf := f.(filesystem.WritableFile)
	if _, err := wf.ReadAt(make([]byte, 1), 0); err != nil {
		t.Error(err)
	}
	if _, err := wf.WriteAt([]byte("x"), 0); err != nil {
		t.Error(err)
	}
	if err := wf.Truncate(0); err != nil {
		t.Error(err)
	}
	if err := wf.Sync(); err != nil {
		t.Error(err)
	}
	if err := wf.Close(); err != nil {
		t.Error(err)
	}
	if err := w.Close(); err != nil {
		t.Error(err)
	}

	// A driver whose File cannot write hands back a File that cannot either.
	ro := lockFS(readOnlyOpenerFS{})
	rf, err := ro.(filesystem.Opener).OpenFile("/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rf.(filesystem.WritableFile); ok {
		t.Error("a read-only File came back writable")
	}
	if rf.Size() != 7 {
		t.Errorf("Size = %d", rf.Size())
	}
	if err := rf.Close(); err != nil {
		t.Error(err)
	}
}

type plainReadOnlyFile struct{}

func (plainReadOnlyFile) ReadAt([]byte, int64) (int, error) { return 0, nil }
func (plainReadOnlyFile) Close() error                      { return nil }
func (plainReadOnlyFile) Size() int64                       { return 7 }

type readOnlyOpenerFS struct{ plainFS }

func (readOnlyOpenerFS) OpenFile(string) (filesystem.File, error) { return plainReadOnlyFile{}, nil }
