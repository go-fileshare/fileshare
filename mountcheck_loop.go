// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The Linux half of the mount check, without a build tag so that its parsing and
// matching run (and are fuzzed) on every platform. mountcheck_linux.go points it
// at the real /sys and /proc.
//
// Sources, opened for this:
//   - loop(4): a loop device is the kernel's attachment of a file as a block
//     device; /sys/block/loopN/loop/backing_file is that file's path (the
//     sysfs ABI, Documentation/ABI/stable/sysfs-block). `mount -o loop`,
//     `losetup`, udisks and systemd all go through it, so it is where a
//     kernel mount of an image shows up.
//   - proc(5), /proc/PID/mountinfo: one line per mount, "mount-ID parent-ID
//     major:minor root mount-point options [optional...] - fstype source
//     super-options", spaces, tabs, newlines and backslashes in a path written
//     as \040, \011, \012, \134.
//
// The image is matched by DEVICE AND INODE (os.SameFile) against the backing
// file, never by comparing path strings: a symbolic link, a bind mount or a
// relative path names one file several ways, and the loop device was made
// from whichever one its creator typed.

// mountEntry is the part of a mountinfo line this check reads.
type mountEntry struct {
	MountPoint string
	FSType     string
	Source     string
}

// parseMountinfo reads /proc/self/mountinfo. A line it cannot read is skipped:
// the entries only name a mount, they are not what decides that there is one.
func parseMountinfo(r io.Reader) ([]mountEntry, error) {
	var out []mountEntry
	sc := bufio.NewScanner(io.LimitReader(r, 64<<20))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		dash := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				dash = i
				break
			}
		}
		if dash < 0 || len(f) < dash+3 {
			continue
		}
		out = append(out, mountEntry{
			MountPoint: unescapeMountinfo(f[4]),
			FSType:     f[dash+1],
			Source:     unescapeMountinfo(f[dash+2]),
		})
	}
	return out, sc.Err()
}

// unescapeMountinfo undoes the \ooo octal escapes the kernel puts in a path.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// loopHolder says which loop device has the image attached, and where it is
// mounted, from the sysfs block directory (/sys/block) and a mountinfo file.
// "" and nil is nobody; an error is a check that could not be made.
//
// A loop device whose backing file is DELETED (sysfs says "(deleted)", or the
// path is not there: ENOENT) is skipped by path; when /dev/loopN can be opened,
// the kernel's own record is asked instead (loop(4), LOOP_GET_STATUS64:
// lo_device and lo_inode, no path), see loopStatusMatches. Any OTHER error on
// a backing path (EACCES, ELOOP, ...) means this loop device could not be
// judged: if no device matches, that error is returned, so the policy
// (image_mount_unknown) decides, and the share is not served writable on the
// strength of a check that did not look.
func loopHolder(fi os.FileInfo, sysBlock, mountinfo string) (string, error) {
	ents, err := os.ReadDir(sysBlock)
	if err != nil {
		return "", fmt.Errorf("listing loop devices: %w", err)
	}
	var unjudged error
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "loop") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sysBlock, name, "loop", "backing_file"))
		if errors.Is(err, fs.ErrNotExist) {
			continue // a loop device with nothing attached has no such file
		}
		if err != nil {
			return "", fmt.Errorf("reading the backing file of %s: %w", name, err)
		}
		path := strings.TrimSuffix(string(raw), "\n")
		dev := "/dev/" + name
		deleted := strings.HasSuffix(path, " (deleted)")
		var bfi os.FileInfo
		if !deleted {
			bfi, err = os.Stat(path)
		}
		switch {
		case deleted || errors.Is(err, fs.ErrNotExist):
			// Not reachable by path: ask the kernel's record, if we may.
			if !loopStatusMatches(fi, dev) {
				continue
			}
		case err != nil:
			if unjudged == nil {
				unjudged = fmt.Errorf("%s: %w", name, err)
			}
			continue
		case !os.SameFile(fi, bfi):
			continue
		}
		mounts := mountsOf(dev, mountinfo)
		if len(mounts) == 0 {
			return dev + ", attached", nil
		}
		return dev + ", mounted at " + strings.Join(mounts, ", "), nil
	}
	if unjudged != nil {
		return "", fmt.Errorf("could not judge a loop device's backing file: %w", unjudged)
	}
	return "", nil
}

// mountsOf lists the mount points of dev and of its partitions (loopNpM).
// Unreadable mountinfo only means no mount point is named.
func mountsOf(dev, mountinfo string) []string {
	f, err := os.Open(mountinfo)
	if err != nil {
		return nil
	}
	defer f.Close()
	ents, _ := parseMountinfo(f)
	var out []string
	for _, m := range ents {
		if m.Source == dev || isPartitionOf(m.Source, dev) {
			out = append(out, m.MountPoint)
		}
	}
	return out
}

// isPartitionOf reports whether src is /dev/loop3p1 for dev /dev/loop3.
func isPartitionOf(src, dev string) bool {
	rest, ok := strings.CutPrefix(src, dev+"p")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}
