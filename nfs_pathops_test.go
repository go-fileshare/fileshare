// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs && !nowebdav && !nosmb && !nosftp

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
)

// Only a host directory is told to go-filesystems/nfs as safe for read-only
// path calls beside each other (nfs.WithConcurrentPathOps). An image driver
// sits behind lockFS and must never get it: the interface promises only ReadAt
// and non-overlapping WriteAt as concurrent (interface@v0.5.0 interface.go:353,
// 426-432), where osfs says "safe for concurrent use" (osfs@v0.3.0 osfs.go:89).
func TestOnlyAHostDirectoryExportsWithConcurrentPathOps(t *testing.T) {
	if protocolByName("nfs") == nil {
		t.Skip("built without nfs")
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	img := image(t, dir, "d.img", map[string]string{"/x.txt": "x"})
	srv, _ := runServer(t, fmt.Sprintf(`share "host" { directory = %q }
share "img" { image = %q }
serve "nfs" { addr = "127.0.0.1:0" }
`, hclPath(tree), hclPath(img)))

	got := map[string]int{}
	for _, sh := range srv.currentShares() {
		if sh.concurrentPathOps != (sh.kind == "directory") {
			t.Errorf("share %q (%s): concurrentPathOps = %v", sh.name, sh.kind, sh.concurrentPathOps)
		}
		got[sh.name] = len(exportOptions(sh))
	}
	if got["host"] != 1 {
		t.Errorf("the host directory export gets %d options, want WithConcurrentPathOps", got["host"])
	}
	if n, ok := got["img"]; !ok || n != 0 {
		t.Errorf("the image export gets %d options (present %v), want none", n, ok)
	}

	// A reload that keeps the driver keeps the word with it.
	next := &share{}
	for _, sh := range srv.currentShares() {
		if sh.kind == "directory" {
			next.adopt(sh)
		}
	}
	if !next.concurrentPathOps {
		t.Error("adopt dropped concurrentPathOps")
	}
}

// probeTree is a host tree that counts what overlaps in the driver: calls made
// for a READ (OpenFile, Size, ReadAt, Close) and calls that write.
type probeTree struct {
	hostTree
	p *probe
}

type probe struct {
	readers, writers       atomic.Int32
	maxReaders             atomic.Int32
	readWriteOverlap, hits atomic.Int32
}

func (p *probe) read() func() {
	if p.writers.Load() > 0 {
		p.readWriteOverlap.Add(1)
	}
	n := p.readers.Add(1)
	for m := p.maxReaders.Load(); n > m && !p.maxReaders.CompareAndSwap(m, n); m = p.maxReaders.Load() {
	}
	time.Sleep(15 * time.Millisecond)
	return func() {
		if p.writers.Load() > 0 {
			p.readWriteOverlap.Add(1)
		}
		p.readers.Add(-1)
	}
}

func (p *probe) write() func() {
	p.hits.Add(1)
	if p.readers.Load() > 0 {
		p.readWriteOverlap.Add(1)
	}
	p.writers.Add(1)
	time.Sleep(15 * time.Millisecond)
	return func() {
		if p.readers.Load() > 0 {
			p.readWriteOverlap.Add(1)
		}
		p.writers.Add(-1)
	}
}

func (t probeTree) OpenFile(path string) (filesystem.File, error) {
	done := t.p.read()
	defer done()
	f, err := t.hostTree.OpenFile(path)
	if err != nil {
		return nil, err
	}
	if w, ok := f.(filesystem.WritableFile); ok {
		return probeFile{w, t.p}, nil
	}
	return f, nil
}

type probeFile struct {
	filesystem.WritableFile
	p *probe
}

func (f probeFile) ReadAt(b []byte, off int64) (int, error) {
	defer f.p.read()()
	return f.WritableFile.ReadAt(b, off)
}

func (f probeFile) WriteAt(b []byte, off int64) (int, error) {
	defer f.p.write()()
	return f.WritableFile.WriteAt(b, off)
}

func (f probeFile) Close() error {
	defer f.p.read()()
	return f.WritableFile.Close()
}

// READs of a host directory export overlap in the driver, and a WRITE of the
// same range never overlaps one.
func TestParallelNFSReadsOverlapAndAWriteNeverDoes(t *testing.T) {
	if protocolByName("nfs") == nil {
		t.Skip("built without nfs")
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	const size = 8192
	if err := os.WriteFile(filepath.Join(tree, "f"), make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	pr := &probe{}
	orig := hostTreeOf
	hostTreeOf = func(fsys *osfs.FS) hostTree { return probeTree{fsys, pr} }
	t.Cleanup(func() { hostTreeOf = orig })
	_, addrs := runServer(t, fmt.Sprintf(`share "host" { directory = %q }
serve "nfs" { addr = "127.0.0.1:0" }
`, hclPath(tree)))
	addr := addrs["nfs"]
	root := nfsMount(t, addr, "/host")

	dial := func() (net.Conn, func(uint32, []byte) []byte) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(30 * time.Second))
		return c, nfsCaller(t, c)
	}
	c0, call0 := dial()
	defer c0.Close()
	res := call0(3, append(xdrOpaque(root), xdrOpaque([]byte("f"))...)) // LOOKUP
	if getBE32(res) != 0 {
		t.Fatalf("LOOKUP: status %d", getBE32(res))
	}
	fh := append([]byte(nil), res[8:8+getBE32(res[4:])]...)
	pr.maxReaders.Store(0)
	pr.hits.Store(0)

	read := func(call func(uint32, []byte) []byte) {
		if r := call(6, append(xdrOpaque(fh), xdrU32(0, 0, size)...)); getBE32(r) != 0 {
			t.Errorf("READ: status %d", getBE32(r))
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, call := dial()
			defer c.Close()
			for range 4 {
				read(call)
			}
		}()
	}
	wg.Wait()
	if n := pr.maxReaders.Load(); n < 2 {
		t.Errorf("READs never overlapped in the driver (max %d): the export lacks WithConcurrentPathOps", n)
	}

	// READs and WRITEs of the same bytes, at once.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, call := dial()
			defer c.Close()
			for range 4 {
				read(call)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, call := dial()
		defer c.Close()
		data := make([]byte, size)
		for range 4 {
			args := append(xdrOpaque(fh), xdrU32(0, 0, size, 2)...) // FILE_SYNC
			args = append(args, xdrOpaque(data)...)
			if r := call(7, args); getBE32(r) != 0 {
				t.Errorf("WRITE: status %d", getBE32(r))
			}
		}
	}()
	wg.Wait()
	if pr.hits.Load() == 0 {
		t.Fatal("control: no WRITE reached the driver's WriteAt")
	}
	if n := pr.readWriteOverlap.Load(); n != 0 {
		t.Errorf("a WRITE overlapped a READ in the driver %d times", n)
	}
}
