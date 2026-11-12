// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin) && !nosmb

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The OS really mounts the image, and the share notices. Gated like the other
// device-backed test (device_real_test.go): FILESHARE_REQUIRE_DEVICE=1, set by
// the CI lane `device`, which is a disposable VM; it SKIPS on a workstation
// because attaching an image is a claim on the machine's disks. Run it by hand
// on a Mac with FILESHARE_REQUIRE_DEVICE=1.
//
//	macOS  hdiutil attach -nomount      (no privilege)
//	Linux  sudo losetup + sudo mount    (passwordless sudo, as runners have)

// mountImage makes the OS mount img, and returns where and the unmount.
func mountImage(t *testing.T, img string) (string, func()) {
	t.Helper()
	run := func(name string, args ...string) string {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	switch runtime.GOOS {
	case "darwin":
		// -nomount: the fixture is a bare FAT32 volume with no partition map,
		// which hdiutil will attach but not mount. Attached is what matters:
		// the image's blocks are a disk of the OS's.
		out := run("hdiutil", "attach", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage", img)
		var dev string
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "/dev/disk") {
				if dev == "" {
					dev = f[0]
				}
			}
		}
		if dev == "" {
			t.Fatalf("hdiutil attach said nothing useful:\n%s", out)
		}
		return dev, func() { _ = exec.Command("hdiutil", "detach", dev, "-force").Run() }
	default:
		dev := strings.TrimSpace(run("sudo", "losetup", "--find", "--show", img))
		mnt := filepath.Join(t.TempDir(), "mnt")
		run("sudo", "mkdir", "-p", mnt)
		run("sudo", "mount", "-t", "vfat", dev, mnt)
		return mnt, func() {
			_ = exec.Command("sudo", "umount", mnt).Run()
			_ = exec.Command("sudo", "losetup", "--detach", dev).Run()
		}
	}
}

func TestShareOpensReadOnlyWhileTheOSHasTheImageMounted(t *testing.T) {
	if !requireDevice(t) {
		return
	}
	needUsers(t)
	img := fatImageFile(t)
	conf := func() string {
		return onlyProtocol(t, t.TempDir(), "smb", "share \"attic\" {\n  image = \""+hclPath(img)+"\"\n}\n")
	}

	where, unmount := mountImage(t, img)
	t.Cleanup(unmount)

	r := start(t, conf())
	if !r.srv.shareByName("attic").readOnly {
		t.Fatalf("the image is mounted at %s and the share is writable\n%s", where, r.out.String())
	}
	out := r.out.String()
	if n := strings.Count(out, "so attic is read-only"); n != 1 || !strings.Contains(out, filepath.Base(img)) {
		t.Errorf("want one line naming the share and the image:\n%s", out)
	}
	t.Logf("log: %s", strings.TrimSpace(out))

	// The image is the same file under another name: still caught.
	link := filepath.Join(t.TempDir(), "alias.img")
	if err := os.Symlink(img, link); err != nil {
		t.Fatal(err)
	}
	r2 := start(t, onlyProtocol(t, t.TempDir(), "smb", "share \"attic\" {\n  image = \""+hclPath(link)+"\"\n}\n"))
	if !r2.srv.shareByName("attic").readOnly {
		t.Errorf("a symbolic link to a mounted image opened writable\n%s", r2.out.String())
	}

	unmount()
	r3 := start(t, conf())
	if r3.srv.shareByName("attic").readOnly {
		t.Errorf("the image is no longer mounted and the share is still read-only\n%s", r3.out.String())
	}
}
