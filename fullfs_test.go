// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
)

// fullTree is a host tree that is full: every write fails with errno, the
// way XFS (ENOSPC) or ext4, btrfs and ZFS (EDQUOT) fail one.
type fullTree struct {
	hostTree
	errno error
}

func (f fullTree) full(op, p string) error { return &fs.PathError{Op: op, Path: p, Err: f.errno} }

func (f fullTree) WriteFile(p string, _ []byte, _ os.FileMode) error { return f.full("write", p) }
func (f fullTree) MkDir(p string, _ os.FileMode) error               { return f.full("mkdir", p) }
func (f fullTree) OpenFile(p string) (filesystem.File, error) {
	h, err := f.hostTree.OpenFile(p)
	if err != nil {
		return nil, err
	}
	if w, ok := h.(filesystem.WritableFile); ok {
		return fullFile{w, f.full("write", p)}, nil
	}
	return h, nil
}

type fullFile struct {
	filesystem.WritableFile
	err error
}

func (f fullFile) WriteAt(p []byte, _ int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 0, f.err
}

// serveFull makes every directory share opened during the test full, with
// errno.
func serveFull(t *testing.T, errno error) {
	t.Helper()
	orig := hostTreeOf
	hostTreeOf = func(fsys *osfs.FS) hostTree { return fullTree{fsys, errno} }
	t.Cleanup(func() { hostTreeOf = orig })
}

// The errnos a full share is reported with, by name.
var fullErrnos = []struct {
	name  string
	errno func() error
}{
	{"ENOSPC (XFS)", func() error { return errNoSpace }},
	{"EDQUOT (ext4, btrfs, ZFS)", func() error { return errQuota }},
}

func TestAFullShareSaysSoOneWay(t *testing.T) {
	for _, e := range fullErrnos {
		err := shareFull(&fs.PathError{Op: "write", Path: "/a/not found", Err: e.errno()})
		if !strings.Contains(err.Error(), "no space") {
			t.Errorf("%s: %q does not say no space", e.name, err)
		}
		// The path is left out: the protocols search the text, and "not
		// found" in a file name would be read as the answer.
		if strings.Contains(err.Error(), "not found") {
			t.Errorf("%s: %q carries the path", e.name, err)
		}
		if !errors.Is(err, e.errno()) {
			t.Errorf("%s: %v no longer unwraps to its errno", e.name, err)
		}
		if again := shareFull(err); again != err {
			t.Errorf("%s: rewritten twice: %v", e.name, again)
		}
	}
	other := &fs.PathError{Op: "write", Path: "/a", Err: fs.ErrPermission}
	if shareFull(other) != error(other) || shareFull(nil) != nil {
		t.Error("an error that is not a full share was rewritten")
	}
}

// The wrapper answers every capability osfs answers: hostTree is the whole
// method set of *osfs.FS, and an osfs that grows one must grow it too.
func TestTheFullWrapperKeepsEveryCapability(t *testing.T) {
	ht := reflect.TypeOf((*hostTree)(nil)).Elem()
	of := reflect.TypeOf(&osfs.FS{})
	for i := range of.NumMethod() {
		if _, ok := ht.MethodByName(of.Method(i).Name); !ok {
			t.Errorf("*osfs.FS has %s, which hostTree (and so a directory share) does not", of.Method(i).Name)
		}
	}
	if of.NumMethod() != ht.NumMethod() {
		t.Errorf("*osfs.FS has %d methods, hostTree %d", of.NumMethod(), ht.NumMethod())
	}
	var w filesystem.Filesystem = &fullAware{}
	for name, ok := range map[string]bool{
		"Opener":         is[filesystem.Opener](w),
		"Truncater":      is[filesystem.Truncater](w),
		"Symlinker":      is[filesystem.Symlinker](w),
		"HardLinker":     is[filesystem.HardLinker](w),
		"MetadataSetter": is[filesystem.MetadataSetter](w),
		"Usage": is[interface {
			Usage() (uint64, uint64, error)
		}](w),
	} {
		if !ok {
			t.Errorf("the wrapper lost %s", name)
		}
	}
}

func is[T any](v any) bool { _, ok := v.(T); return ok }

// Every writing method of the wrapper rewrites, and the reading ones pass
// through: driven against a real tree whose every call fails.
func TestEveryWriteOfTheWrapperRewrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys, err := osfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	w := &fullAware{quotaTree{fsys}}
	calls := map[string]error{
		"WriteFile": w.WriteFile("/g", nil, 0o600),
		"MkDir":     w.MkDir("/d", 0o700),
		"Rename":    w.Rename("/f", "/h"),
		"Truncate":  w.Truncate("/f", 0),
		"Symlink":   w.Symlink("f", "/l"),
		"Link":      w.Link("/f", "/k"),
		"Chmod":     w.Chmod("/f", 0o600),
		"Chown":     w.Chown("/f", 1, 1),
		"Chtimes":   w.Chtimes("/f", timeZero, timeZero),
	}
	h, err := w.OpenFile("/f")
	if err != nil {
		t.Fatal(err)
	}
	f := h.(filesystem.WritableFile)
	_, calls["File.WriteAt"] = f.WriteAt([]byte("y"), 0)
	calls["File.Truncate"] = f.Truncate(0)
	calls["File.Sync"] = f.Sync()
	calls["File.Close"] = f.Close()
	for name, err := range calls {
		if err == nil || !strings.Contains(err.Error(), "no space") || !errors.Is(err, errQuota) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := w.OpenFile("/nope"); err == nil {
		t.Error("opening what is not there succeeded")
	}
}

// quotaTree fails every write with EDQUOT, the open file's included.
type quotaTree struct{ hostTree }

func (q quotaTree) e(p string) error                                  { return &fs.PathError{Op: "x", Path: p, Err: errQuota} }
func (q quotaTree) WriteFile(p string, _ []byte, _ os.FileMode) error { return q.e(p) }
func (q quotaTree) MkDir(p string, _ os.FileMode) error               { return q.e(p) }
func (q quotaTree) Rename(p, _ string) error                          { return q.e(p) }
func (q quotaTree) Truncate(p string, _ int64) error                  { return q.e(p) }
func (q quotaTree) Symlink(_, p string) error                         { return q.e(p) }
func (q quotaTree) Link(p, _ string) error                            { return q.e(p) }
func (q quotaTree) Chmod(p string, _ os.FileMode) error               { return q.e(p) }
func (q quotaTree) Chown(p string, _, _ uint32) error                 { return q.e(p) }
func (q quotaTree) Chtimes(p string, _, _ timeT) error                { return q.e(p) }
func (q quotaTree) OpenFile(p string) (filesystem.File, error) {
	h, err := q.hostTree.OpenFile(p)
	if err != nil {
		return nil, err
	}
	return quotaFile{h.(filesystem.WritableFile), q.e(p)}, nil
}

type quotaFile struct {
	filesystem.WritableFile
	err error
}

func (f quotaFile) WriteAt([]byte, int64) (int, error) { return 0, f.err }
func (f quotaFile) Truncate(int64) error               { return f.err }
func (f quotaFile) Sync() error                        { return f.err }
func (f quotaFile) Close() error                       { f.WritableFile.Close(); return f.err }

// fullDirShare is a configuration fragment: one writable directory share.
func fullDirShare(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	return fmt.Sprintf("share \"full\" {\n  directory = %q\n}\n", hclPath(d))
}

type timeT = time.Time

var timeZero time.Time
