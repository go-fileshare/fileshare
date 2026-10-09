// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"os"
	"testing"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
)

// A writable file of a directory share is still a file of the host: the
// full-disk wrapper passes Read, Seek and SyscallConn on, which is what lets
// a GET go out with sendfile(2) and a COPY be copy_file_range(2). Hidden,
// both silently copied through the process.
func TestAWritableDirectoryFileIsStillAHostFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f", []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsys, err := osfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	h, err := (&fullAware{fsys}).OpenFile("/f")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, ok := h.(filesystem.WritableFile); !ok {
		t.Fatalf("%T is not a WritableFile", h)
	}
	hf, ok := h.(filesystem.HostFile)
	if !ok {
		t.Fatalf("%T is not a HostFile: sendfile and copy_file_range are lost", h)
	}
	hf.HostFile()
	if _, err := hf.SyscallConn(); err != nil {
		t.Fatal(err)
	}
	if _, err := hf.Seek(1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(hf)
	if err != nil || string(b) != "ello" {
		t.Fatalf("read %q, %v", b, err)
	}
}
