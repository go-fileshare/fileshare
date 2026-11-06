// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// readFS answers ReadFile only, from fixed content, and counts what it served.
type readFS struct {
	filesystem.Filesystem
	data  []byte
	reads *atomic.Int64
}

func (f readFS) ReadFile(string) ([]byte, error) {
	f.reads.Add(1)
	return append([]byte(nil), f.data...), nil
}

func openUnion(t *testing.T, data []byte) (*unionFS, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	sh := &share{name: "img", fsys: readFS{data: data, reads: &n}, readOnly: true}
	return unionFor([]*share{sh}, local("reader")), &n
}

// Opening reads nothing; many handles on one file share one read, serve ranges,
// and free the bytes when the last one closes.
func TestSnapshotIsLazySharedAndFreed(t *testing.T) {
	base := snapshotBytes.Load()
	u, reads := openUnion(t, []byte("0123456789abcdef"))
	var hs []filesystem.File
	for range 5 {
		f, err := u.OpenFile("/img/f")
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, f)
	}
	if reads.Load() != 0 || snapshotBytes.Load() != base {
		t.Fatalf("opening read %d times and held %d bytes", reads.Load(), snapshotBytes.Load()-base)
	}
	buf := make([]byte, 4)
	if n, err := hs[0].ReadAt(buf, 10); err != nil || string(buf[:n]) != "abcd" {
		t.Fatalf("ReadAt = %q %v", buf[:n], err)
	}
	if hs[3].Size() != 16 {
		t.Fatalf("Size = %d", hs[3].Size())
	}
	// A read that runs past the end says EOF with the bytes there are.
	if n, err := hs[1].ReadAt(buf, 14); n != 2 || !errors.Is(err, io.EOF) || string(buf[:2]) != "ef" {
		t.Fatalf("ReadAt past the end = %d %v", n, err)
	}
	if n, err := hs[1].ReadAt(buf, 16); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at the end = %d %v", n, err)
	}
	if _, err := hs[1].ReadAt(buf, -1); err == nil {
		t.Error("a negative offset was read")
	}
	if reads.Load() != 1 || snapshotBytes.Load()-base != 16 {
		t.Fatalf("5 handles: %d reads, %d bytes held; want 1 and 16", reads.Load(), snapshotBytes.Load()-base)
	}
	for _, h := range hs {
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		_ = h.Close() // closing twice is not a second release
	}
	if got := snapshotBytes.Load() - base; got != 0 {
		t.Fatalf("%d bytes still held after every handle closed", got)
	}
	if _, err := hs[0].ReadAt(buf, 0); err == nil {
		t.Error("a closed handle was read")
	}
	if hs[0].Size() != 0 {
		t.Error("a closed handle has a size")
	}
}

// A file past the bound is refused, not loaded and held; so is one that would
// take the process past its total.
func TestSnapshotIsBounded(t *testing.T) {
	base := snapshotBytes.Load()
	u, _ := openUnion(t, make([]byte, maxSnapshotFile+1))
	f, err := u.OpenFile("/img/huge")
	if err != nil {
		t.Fatal(err) // the refusal is at the first read, where the size is known
	}
	if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, errSnapshotTooLarge) {
		t.Fatalf("a file past maxSnapshotFile: %v", err)
	}
	_ = f.Close()
	if snapshotBytes.Load() != base {
		t.Fatal("a refused file is held")
	}
	// The total: fill it, then one more file does not fit.
	snapshotBytes.Add(maxSnapshotTotal - base)
	defer snapshotBytes.Add(-(maxSnapshotTotal - base))
	u2, _ := openUnion(t, []byte("x"))
	g, _ := u2.OpenFile("/img/one")
	if _, err := g.ReadAt(make([]byte, 1), 0); !errors.Is(err, errSnapshotTooLarge) {
		t.Fatalf("a file past maxSnapshotTotal: %v", err)
	}
	_ = g.Close()
}

// BenchmarkSnapshotReadAt: 64 KiB reads of a 64 MiB file through one handle.
// The allocations are exact; the time is not, under load.
func BenchmarkSnapshotReadAt(b *testing.B) {
	var n atomic.Int64
	sh := &share{name: "img", fsys: readFS{data: make([]byte, 64<<20), reads: &n}, readOnly: true}
	u := unionFor([]*share{sh}, local("reader"))
	f, err := u.OpenFile("/img/big")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, err := f.ReadAt(buf, int64(i%1000)*int64(len(buf))); err != nil && !errors.Is(err, io.EOF) {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpenManyHandles: 64 opens of a 8 MiB file, each read once at its
// start: before the change each open copied the file (64 x 8 MiB allocated).
func BenchmarkOpenManyHandles(b *testing.B) {
	var n atomic.Int64
	sh := &share{name: "img", fsys: readFS{data: make([]byte, 8<<20), reads: &n}, readOnly: true}
	u := unionFor([]*share{sh}, local("reader"))
	buf := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		var hs []filesystem.File
		for range 64 {
			f, err := u.OpenFile("/img/big")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := f.ReadAt(buf, 0); err != nil {
				b.Fatal(err)
			}
			hs = append(hs, f)
		}
		for _, f := range hs {
			f.Close()
		}
	}
}

type failFS struct{ filesystem.Filesystem }

func (failFS) ReadFile(string) ([]byte, error) { return nil, errors.New("driver: read failed") }

func TestSnapshotReadFailureIsReported(t *testing.T) {
	sh := &share{name: "img", fsys: failFS{}, readOnly: true}
	u := unionFor([]*share{sh}, local("reader"))
	f, err := u.OpenFile("/img/x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.ReadAt(make([]byte, 1), 0); err == nil {
		t.Error("a failing driver read was reported as data")
	}
	if f.Size() != 0 {
		t.Error("a file that cannot be read has a size")
	}
}
