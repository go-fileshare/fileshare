// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav && !wasip1

package main

// The one test of review_revocation_test.go that speaks SFTP through
// github.com/pkg/sftp, which does not compile for wasip1 (attrs.go needs
// fileStatFromInfoOs, defined for no wasip1 file). Apart so that the rest of
// that file still runs there.

import (
	"io"
	"net"
	"os"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	fsftp "github.com/go-filesystems/sftp"
	psftp "github.com/pkg/sftp"
)

// F8: a share whose driver has no Opener cannot be read over SFTP through
// the union: OpenFile answers ErrInvalid and go-filesystems/sftp, seeing
// the union IS an Opener, fails the open instead of falling back.
type plainShare struct{ m *memShare }

func (p plainShare) Close() error                                    { return nil }
func (p plainShare) ReadFile(s string) ([]byte, error)               { return p.m.ReadFile(s) }
func (p plainShare) ListDir(s string) ([]filesystem.DirEntry, error) { return p.m.ListDir(s) }
func (p plainShare) Stat(s string) (filesystem.Stat, error)          { return p.m.Stat(s) }
func (p plainShare) WriteFile(s string, b []byte, m os.FileMode) error {
	return p.m.WriteFile(s, b, m)
}
func (p plainShare) ReadLink(s string) (string, error)   { return p.m.ReadLink(s) }
func (p plainShare) MkDir(s string, m os.FileMode) error { return nil }
func (p plainShare) DeleteFile(s string) error           { return p.m.DeleteFile(s) }
func (p plainShare) DeleteDir(s string) error            { return nil }
func (p plainShare) Rename(a, b string) error            { return p.m.Rename(a, b) }

func TestFoundSFTPNonOpenerShareUnreadable(t *testing.T) {
	m := &memShare{files: map[string][]byte{"/a.txt": []byte("hello")}}
	u := &unionFS{entries: []unionEntry{{name: "s", fsys: plainShare{m}}}}
	srv, err := fsftp.New(u, fsftp.ReadWrite())
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	go srv.Serve(c1)
	cl, err := psftp.NewClientPipe(c2, c2)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	f, err := cl.Open("/s/a.txt")
	if err != nil {
		t.Errorf("open of a file on a non-Opener share fails over SFTP: %v", err)
		return
	}
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "hello" {
		t.Errorf("read: %q %v", b, err)
	}
}
