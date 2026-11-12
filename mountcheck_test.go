// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	fat32 "github.com/go-filesystems/fat32"
)

// fatImageFile is a 64 MiB FAT32 image.
func fatImageFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fat.img")
	if _, err := fat32.Format(path, 64<<20, fat32.FormatConfig{Label: "MNTTEST"}); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- Linux matcher: loop devices from a fake /sys/block -------------------

// fakeSys builds a sysfs block directory: loop0 has nothing attached, and each
// entry of backing is a loop device bound to that path (a trailing newline, as
// sysfs writes it).
func fakeSys(t *testing.T, backing map[string]string) string {
	t.Helper()
	sys := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sys, "loop0", "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "sda"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, path := range backing {
		d := filepath.Join(sys, name, "loop")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "backing_file"), []byte(path+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

func TestLoopHolderMatchesByInodeNotByPath(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	other := filepath.Join(dir, "other.img")
	for _, p := range []string{img, other} {
		if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "alias.img")
	if err := os.Symlink(img, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	hard := filepath.Join(dir, "hard.img")
	if err := os.Link(img, hard); err != nil {
		t.Fatal(err)
	}
	mi := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(mi, []byte(
		"36 35 7:3 / /mnt/my\\040disk rw,relatime shared:1 - vfat /dev/loop3 rw\n"+
			"37 35 8:1 / /boot rw - ext4 /dev/sda1 rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(img)
	if err != nil {
		t.Fatal(err)
	}

	// The loop device was made from a path that is not the one the share has:
	// a symbolic link and a hard link name the same file.
	for name, bound := range map[string]string{"symlink": link, "hard link": hard} {
		t.Run(name, func(t *testing.T) {
			sys := fakeSys(t, map[string]string{"loop3": bound, "loop4": other})
			got, err := loopHolder(fi, sys, mi)
			if err != nil {
				t.Fatal(err)
			}
			if want := "/dev/loop3, mounted at /mnt/my disk"; got != want {
				t.Errorf("loopHolder = %q, want %q", got, want)
			}
		})
	}
	t.Run("attached, not mounted", func(t *testing.T) {
		sys := fakeSys(t, map[string]string{"loop5": img})
		got, err := loopHolder(fi, sys, filepath.Join(dir, "no-such-mountinfo"))
		if err != nil || got != "/dev/loop5, attached" {
			t.Errorf("loopHolder = %q, %v", got, err)
		}
	})
	t.Run("a different file", func(t *testing.T) {
		sys := fakeSys(t, map[string]string{"loop3": other})
		if got, err := loopHolder(fi, sys, mi); err != nil || got != "" {
			t.Errorf("loopHolder = %q, %v; want nobody", got, err)
		}
	})
	t.Run("a backing file that is gone is skipped", func(t *testing.T) {
		sys := fakeSys(t, map[string]string{"loop3": filepath.Join(dir, "deleted.img")})
		if got, err := loopHolder(fi, sys, mi); err != nil || got != "" {
			t.Errorf("loopHolder = %q, %v; want nobody", got, err)
		}
	})
	t.Run("no sysfs is a failure, not nobody", func(t *testing.T) {
		if got, err := loopHolder(fi, filepath.Join(dir, "no-sys"), mi); err == nil {
			t.Errorf("loopHolder = %q, nil; want an error", got)
		}
	})
}

func TestParseMountinfo(t *testing.T) {
	in := "" +
		"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n" +
		"40 36 0:5 / /a\\040b\\134c rw - tmpfs none rw\n" +
		"41 36 0:5 / /no-dash rw\n" +
		"garbage\n" +
		"42 36 0:5 / /nofields rw - ext4\n" +
		"43 36 7:1 / /x rw - vfat /dev/loop1p2 ro\n"
	got, err := parseMountinfo(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []mountEntry{
		{"/mnt2", "ext3", "/dev/root"},
		{`/a b\c`, "tmpfs", "none"},
		{"/x", "vfat", "/dev/loop1p2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseMountinfo = %+v\nwant %+v", got, want)
	}
	if !isPartitionOf("/dev/loop1p2", "/dev/loop1") || isPartitionOf("/dev/loop10", "/dev/loop1") ||
		isPartitionOf("/dev/loop1p", "/dev/loop1") || isPartitionOf("/dev/loop1pa", "/dev/loop1") {
		t.Error("isPartitionOf is wrong")
	}
}

// ---- macOS: hdiutil's property list ---------------------------------------

const hdiutilSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>framework</key>
	<string>710</string>
	<key>images</key>
	<array>
		<dict>
			<key>image-path</key>
			<string>%s</string>
			<key>image-type</key>
			<string>disk image</string>
			<key>writeable</key>
			<true/>
			<key>blockcount</key>
			<integer>131072</integer>
			<key>system-entities</key>
			<array>
				<dict>
					<key>content-hint</key>
					<string>DOS_FAT_32</string>
					<key>dev-entry</key>
					<string>/dev/disk4s1</string>
					<key>mount-point</key>
					<string>/Volumes/A &amp; B</string>
				</dict>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk4</string>
				</dict>
			</array>
		</dict>
		<dict><key>image-path</key><string>/nowhere/else.dmg</string></dict>
	</array>
</dict>
</plist>
`

func TestHdiutilInfoMatchesByInodeNotByPath(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	other := filepath.Join(dir, "other.img")
	for _, p := range []string{img, other} {
		if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "alias.img")
	if err := os.Symlink(img, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	// hdiutil lists the path it was given: here a symbolic link to the image.
	imgs, err := parseHdiutilInfo(strings.NewReader(strings.Replace(hdiutilSample, "%s", link, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 2 || !reflect.DeepEqual(imgs[0].Devs, []string{"/dev/disk4s1", "/dev/disk4"}) ||
		!reflect.DeepEqual(imgs[0].Mounts, []string{"/Volumes/A & B"}) {
		t.Fatalf("parsed %+v", imgs)
	}
	fi, _ := os.Stat(img)
	if got, want := attachedHolder(fi, imgs), "attached as /dev/disk4s1, /dev/disk4, mounted at /Volumes/A & B"; got != want {
		t.Errorf("attachedHolder = %q, want %q", got, want)
	}
	ofi, _ := os.Stat(other)
	if got := attachedHolder(ofi, imgs); got != "" {
		t.Errorf("a different file matched: %q", got)
	}
}

func TestParseHdiutilInfoRefusesWhatIsNotAPlist(t *testing.T) {
	for name, in := range map[string]string{
		"empty":         "",
		"not xml":       "disk4 /dev/disk4\n",
		"wrong root":    "<html></html>",
		"no images":     `<plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>`,
		"images string": `<plist version="1.0"><dict><key>images</key><string>x</string></dict></plist>`,
		"truncated":     `<plist version="1.0"><dict><key>images</key><array><dict>`,
		"value no key":  `<plist version="1.0"><dict><string>x</string></dict></plist>`,
		"two values":    `<plist version="1.0"><dict/><dict/></plist>`,
		"deep":          `<plist>` + strings.Repeat("<array>", 100) + strings.Repeat("</array>", 100) + `</plist>`,
	} {
		if got, err := parseHdiutilInfo(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted, as %+v", name, got)
		}
	}
	// An empty list is a plain answer: nothing attached.
	got, err := parseHdiutilInfo(strings.NewReader(`<plist version="1.0"><dict><key>images</key><array/></dict></plist>`))
	if err != nil || len(got) != 0 {
		t.Errorf("empty images = %+v, %v", got, err)
	}
}

// ---- policy ---------------------------------------------------------------

func TestMountVerdict(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		name     string
		unknown  string
		where    string
		err      error
		ro       bool
		contains []string
	}{
		{"mounted", "", "/dev/loop3, mounted at /mnt/x", nil, true, []string{"attic is read-only", "/dev/loop3"}},
		{"mounted, write policy still read-only", "write", "/dev/loop3", nil, true, []string{"read-only"}},
		{"nobody", "", "", nil, false, nil},
		{"unsupported platform", "", "", errMountUnsupported, false, nil},
		{"failed, default", "", "", boom, true, []string{"boom", "attic is read-only"}},
		{"failed, read_only", "read_only", "", boom, true, []string{"attic is read-only"}},
		{"failed, write", "write", "", boom, false, []string{"boom", "stays writable"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			line, ro := mountVerdict(shareBlock{Name: "attic", ImageMountUnknown: c.unknown}, c.where, c.err)
			if ro != c.ro {
				t.Errorf("readOnly = %v, want %v (%q)", ro, c.ro, line)
			}
			if (line == "") != (len(c.contains) == 0) {
				t.Errorf("line = %q", line)
			}
			for _, w := range c.contains {
				if !strings.Contains(line, w) {
					t.Errorf("line %q lacks %q", line, w)
				}
			}
		})
	}
}

func TestBadImageMountUnknownIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "bad.hcl", onlyProtocol(t, dir, "smb",
		"share \"a\" {\n  directory = \"/tmp\"\n  image_mount_unknown = \"maybe\"\n}\n"))
	if _, err := loadConfig([]string{p}); err == nil || !strings.Contains(err.Error(), "image_mount_unknown") {
		t.Errorf("loadConfig = %v, want a refusal naming image_mount_unknown", err)
	}
}

// ---- the share, with the OS standing in -----------------------------------

func withOS(t *testing.T, where string, err error) {
	t.Helper()
	old := imageMountedBy
	imageMountedBy = func(context.Context, os.FileInfo) (string, error) { return where, err }
	t.Cleanup(func() { imageMountedBy = old })
}

// A writable image of ANY driver (here HFS+ and FAT32) that the OS has mounted
// is opened read-only, marked so, and said once, naming the share, the image
// and the mount.
func TestMountedImageIsServedReadOnly(t *testing.T) {
	needUsers(t)
	for name, mk := range map[string]func(*testing.T) string{"hfsplus": hfsImage, "fat32": fatImageFile} {
		t.Run(name, func(t *testing.T) {
			path := mk(t)
			withOS(t, "/dev/disk4s1, mounted at /Volumes/X", nil)
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				"share \"attic\" {\n  image = \""+hclPath(path)+"\"\n}\n"))
			sh := r.srv.shareByName("attic")
			if !sh.readOnly || !sh.forcedReadOnly {
				t.Errorf("readOnly=%v forced=%v, want both", sh.readOnly, sh.forcedReadOnly)
			}
			out := r.out.String()
			if n := strings.Count(out, "/Volumes/X"); n != 1 {
				t.Errorf("mount named %d times, want once:\n%s", n, out)
			}
			for _, want := range []string{"attic", filepath.Base(path), "so attic is read-only"} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "could not be opened for writing") {
				t.Errorf("a second line for the same fact:\n%s", out)
			}
		})
	}
}

func TestMountCheckFailureFollowsImageMountUnknown(t *testing.T) {
	needUsers(t)
	for _, c := range []struct {
		setting string
		ro      bool
	}{{"", true}, {"read_only", true}, {"write", false}} {
		t.Run("setting="+c.setting, func(t *testing.T) {
			path := hfsImage(t)
			withOS(t, "", errors.New("hdiutil: exploded"))
			extra := ""
			if c.setting != "" {
				extra = "  image_mount_unknown = \"" + c.setting + "\"\n"
			}
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				"share \"attic\" {\n  image = \""+hclPath(path)+"\"\n"+extra+"}\n"))
			if got := r.srv.shareByName("attic").readOnly; got != c.ro {
				t.Errorf("readOnly = %v, want %v\n%s", got, c.ro, r.out.String())
			}
			if n := strings.Count(r.out.String(), "hdiutil: exploded"); n != 1 {
				t.Errorf("failure logged %d times, want once:\n%s", n, r.out.String())
			}
		})
	}
}

func TestUnmountedImageAndUnsupportedPlatformStayWritableAndSilent(t *testing.T) {
	needUsers(t)
	for name, err := range map[string]error{"nobody": nil, "unsupported": errMountUnsupported} {
		t.Run(name, func(t *testing.T) {
			withOS(t, "", err)
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				"share \"attic\" {\n  image = \""+hclPath(hfsImage(t))+"\"\n}\n"))
			if r.srv.shareByName("attic").readOnly {
				t.Errorf("read-only\n%s", r.out.String())
			}
			if strings.Contains(r.out.String(), "OS") {
				t.Errorf("said something:\n%s", r.out.String())
			}
		})
	}
}

// What the platform really answers, on a file nobody has attached.
func TestPlatformAnswersForAnUnattachedImage(t *testing.T) {
	img := filepath.Join(t.TempDir(), "free.img")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(img)
	where, err := platformMountedBy(context.Background(), fi)
	switch runtime.GOOS {
	case "linux", "darwin":
		if err != nil {
			t.Skipf("%s cannot be asked here (a container without sysfs?): %v", runtime.GOOS, err)
		}
		if where != "" {
			t.Errorf("an image nobody attached is held by %q", where)
		}
	default:
		if !errors.Is(err, errMountUnsupported) {
			t.Errorf("err = %v, want errMountUnsupported", err)
		}
	}
}
