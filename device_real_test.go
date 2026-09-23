//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fat32 "github.com/go-filesystems/fat32"
)

// A device-backed test, and the rules it obeys.
//
// ⛔ IT DOES NOT RUN ON A DEVELOPER'S MACHINE. Attaching a disk image or
// opening /dev/* with O_EXCL is a kernel-level claim on a working disk, and
// one wrong character in a path names the system disk -- which on macOS ends
// in a hang rather than an error. So it SKIPS unless FILESHARE_REQUIRE_DEVICE
// is set, which only the CI lanes set, and CI runners are VMs.
//
// ⛔ AND WHERE IT IS REQUIRED, A MISSING TOOL IS A FAILURE, NOT A SKIP. That
// is the whole point of the variable: a lane that sets it has promised the
// tool is there, so a skip on that lane would be a test quietly not running --
// which is the thing that let cmd/weft/plugin drift for four commits
// elsewhere in this fleet.

func requireDevice(t *testing.T) bool {
	t.Helper()
	if os.Getenv("FILESHARE_REQUIRE_DEVICE") == "" {
		t.Skip("device-backed: set FILESHARE_REQUIRE_DEVICE=1 to run. " +
			"Not on a workstation -- this attaches a block device.")
		return false
	}
	return true
}

// attachDevice makes a real block device out of a file and returns its path
// plus the detach.
func attachDevice(t *testing.T, img string) (string, func()) {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("hdiutil", "attach", "-nomount",
			"-imagekey", "diskimage-class=CRawDiskImage", img).CombinedOutput()
		if err != nil {
			t.Fatalf("hdiutil attach: %v\n%s", err, out)
		}
		dev := strings.Fields(string(out))
		if len(dev) == 0 {
			t.Fatalf("hdiutil attach said nothing useful:\n%s", out)
		}
		path := dev[0]
		return path, func() { _ = exec.Command("hdiutil", "detach", path, "-force").Run() }
	case "linux":
		out, err := exec.Command("sudo", "losetup", "--find", "--show", img).CombinedOutput()
		if err != nil {
			t.Fatalf("losetup: %v\n%s", err, out)
		}
		path := strings.TrimSpace(string(out))
		return path, func() { _ = exec.Command("sudo", "losetup", "--detach", path).Run() }
	default:
		t.Skipf("no way to attach a device on %s", runtime.GOOS)
		return "", func() {}
	}
}

// The end-to-end claim: a real block device, served by whoever is running the
// tests, with no privilege escalation for the device itself.
func TestServesARealBlockDevice(t *testing.T) {
	if !requireDevice(t) {
		return
	}
	img := filepath.Join(t.TempDir(), "fat.img")
	if _, err := fat32.Format(img, 64<<20, fat32.FormatConfig{Label: "DEVTEST"}); err != nil {
		t.Fatalf("formatting the fixture: %v", err)
	}

	dev, detach := attachDevice(t, img)
	t.Cleanup(detach)

	fi, err := os.Stat(dev)
	if err != nil {
		t.Fatalf("stat %s: %v", dev, err)
	}
	if !isDevice(fi) {
		t.Fatalf("%s is not a device node: mode %v", dev, fi.Mode())
	}
	// The defect this whole change exists for: the inode says zero.
	if fi.Size() != 0 {
		t.Logf("note: %s reports a non-zero Stat size (%d); the device path is "+
			"still the one under test", dev, fi.Size())
	}

	f, err := openDevice(dev)
	if err != nil {
		t.Fatalf("openDevice(%s): %v\n%s", dev, err, deviceOpenHint(dev, err))
	}
	defer f.Close()

	size, err := imageLength(f, fi)
	if err != nil {
		t.Fatalf("imageLength(%s): %v", dev, err)
	}
	if size != 64<<20 {
		t.Errorf("device length = %d, want %d", size, 64<<20)
	}

	// And the drivers can read it through the aligning reader -- which is the
	// part that fails on a RAW node without one.
	r := alignedReaderAt{r: f, size: size}
	boot := make([]byte, 2)
	if _, err := r.ReadAt(boot, 11); err != nil {
		t.Fatalf("reading two bytes at offset 11 (a FAT BPB field): %v", err)
	}
}
