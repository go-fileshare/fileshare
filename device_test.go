package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ⛔ NOTHING IN THIS FILE ATTACHES A DEVICE BY DEFAULT, and that is deliberate
// rather than incidental. Attaching one, or opening /dev/* with O_EXCL, is a
// kernel-level claim on somebody's working disk: one wrong character in a path
// names the system disk, and on macOS that ends in a hang rather than an
// error. The device-backed test below runs only where a lane sets
// FILESHARE_REQUIRE_DEVICE=1 -- which means a CI runner, which is a VM.
//
// Everything that can be checked without a device is checked without one, and
// that turns out to be most of it: the alignment arithmetic, the size rule,
// and the refusals.

// fakeReaderAt records the reads it is asked for, so a test can assert on the
// shape of the I/O rather than only on the bytes that come back.
type fakeReaderAt struct {
	data  []byte
	reads []readCall
	// strict makes it behave like a RAW device: anything not aligned to
	// alignDevice is refused, the way /dev/rdiskN refuses with EINVAL.
	strict bool
}

type readCall struct {
	off int64
	n   int
}

func (f *fakeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	f.reads = append(f.reads, readCall{off: off, n: len(p)})
	if f.strict {
		if off%alignDevice != 0 || len(p)%512 != 0 {
			return 0, os.ErrInvalid
		}
	}
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func testData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251) // 251 is prime, so the pattern does not align with 512
	}
	return b
}

// The case that made this type necessary: a two-byte read at offset 11, which
// is what parsing a FAT BPB is, against a reader that refuses anything
// unaligned.
func TestAlignedReaderAt_ServesAnUnalignedReadFromAStrictDevice(t *testing.T) {
	data := testData(64 << 10)
	raw := &fakeReaderAt{data: data, strict: true}

	// The control: without the wrapper this is exactly what /dev/rdiskN does.
	if _, err := raw.ReadAt(make([]byte, 2), 11); err == nil {
		t.Fatal("the fake strict device accepted an unaligned read; it is not modelling the thing")
	}
	raw.reads = nil // the control's own read is not the wrapper's

	a := alignedReaderAt{r: raw, size: int64(len(data))}
	got := make([]byte, 2)
	n, err := a.ReadAt(got, 11)
	if err != nil || n != 2 {
		t.Fatalf("ReadAt(2 @ 11) = %d, %v", n, err)
	}
	if got[0] != data[11] || got[1] != data[12] {
		t.Errorf("bytes = %v, want %v", got, data[11:13])
	}
	// And it did it with one aligned read, not by reading the whole device.
	if len(raw.reads) != 1 {
		t.Fatalf("made %d underlying reads, want 1: %+v", len(raw.reads), raw.reads)
	}
	if raw.reads[0].off != 0 || raw.reads[0].n != alignDevice {
		t.Errorf("underlying read = %+v, want off 0 length %d", raw.reads[0], alignDevice)
	}
}

// Every offset and length in a range, against the same data read directly.
// A wrapper that is right at offset 11 and wrong across a block boundary is
// the kind of thing a single case misses.
func TestAlignedReaderAt_AgreesWithTheUnwrappedReaderEverywhere(t *testing.T) {
	data := testData(3 * alignDevice)
	a := alignedReaderAt{r: &fakeReaderAt{data: data, strict: true}, size: int64(len(data))}

	for _, off := range []int64{0, 1, 11, 511, 512, 4095, 4096, 4097, 8191, 8192} {
		for _, n := range []int{1, 2, 7, 512, 513, 4096, 4097} {
			if off+int64(n) > int64(len(data)) {
				continue
			}
			got := make([]byte, n)
			c, err := a.ReadAt(got, off)
			if err != nil || c != n {
				t.Errorf("ReadAt(%d @ %d) = %d, %v", n, off, c, err)
				continue
			}
			want := data[off : off+int64(n)]
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("ReadAt(%d @ %d) byte %d = %d, want %d", n, off, i, got[i], want[i])
					break
				}
			}
		}
	}
}

// The end of the medium. A device's length is a whole number of sectors, so
// the clamp must not round a final read past it -- a raw device answers that
// with EINVAL, not with a short read.
func TestAlignedReaderAt_DoesNotReadPastTheEnd(t *testing.T) {
	// Deliberately NOT a multiple of alignDevice: 9 sectors.
	const size = 9 * 512
	data := testData(size)
	raw := &fakeReaderAt{data: data, strict: true}
	a := alignedReaderAt{r: raw, size: size}

	got := make([]byte, 16)
	n, err := a.ReadAt(got, size-16)
	if err != nil || n != 16 {
		t.Fatalf("reading the last 16 bytes = %d, %v", n, err)
	}
	for _, r := range raw.reads {
		if r.off+int64(r.n) > size {
			t.Errorf("underlying read %+v runs past the device end %d", r, size)
		}
	}
	if _, err := a.ReadAt(make([]byte, 1), size); !errors.Is(err, io.EOF) {
		t.Errorf("reading at the end gave %v, want EOF", err)
	}
}

// A regular file keeps its length from Stat; only a device is asked.
func TestImageLength_UsesStatForARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "img")
	if err := os.WriteFile(path, testData(1234), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if isDevice(fi) {
		t.Fatal("a regular file was taken for a device")
	}
	n, err := imageLength(f, fi)
	if err != nil || n != 1234 {
		t.Fatalf("imageLength = %d, %v; want 1234", n, err)
	}
}

// The hint is the whole reason a refusal is worth catching: "permission
// denied" on /dev/sda sends people to sudo, which is what this program exists
// to avoid.
func TestDeviceOpenHint_SaysNothingAboutARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "img")
	if err := os.WriteFile(path, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if h := deviceOpenHint(path, os.ErrPermission); h != "" {
		t.Errorf("hinted about a regular file: %q", h)
	}
}

func TestDeviceOpenHint_ExplainsABusyDevice(t *testing.T) {
	h := deviceOpenHint("/dev/sda", errDeviceBusy)
	if h == "" {
		t.Fatal("a busy device produced no hint")
	}
	for _, want := range []string{"Unmount", "cache"} {
		if !contains(h, want) {
			t.Errorf("the hint does not mention %q: %s", want, h)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
