// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// A backend is one parent: the storage of one kind under one root. The
// service decides what may be done -- names, ranges, idempotency, the order of
// a delete -- and a backend does it, and says what is its own.
//
// Every method that takes a record is about <root>/<record.Name>.
type backend interface {
	kind() provisionv1.Kind
	// start checks the parent as it is on disk and brings back what a reboot
	// undid (ZFS mounts). It is given this parent's records.
	start(recs []*record) error
	// space is the free and total bytes volumes can come from.
	space() (free, total uint64, err error)

	// present reports whether anything at all is where the volume would be.
	present(r *record) (bool, error)
	// owned is nil when what is there is this provisioner's own, errAbsent
	// when nothing is, and errNotOurs (wrapped) otherwise.
	owned(r *record) error
	// quota is the limit in force now.
	quota(r *record) (uint64, error)
	used(r *record) (uint64, error)

	// create makes the volume, or finishes making it: every step tolerates
	// having been done already, so a pending record can be completed.
	create(r *record) error
	resize(r *record, quota uint64) error
	canSnapshot() bool
	snapshots(r *record) ([]string, error)
	snapshot(r *record, name string) error
	// empty reports whether the volume holds no file at all.
	empty(r *record) (bool, error)
	// destroy removes the volume and the snapshots named.
	destroy(r *record, snaps []string) error
}

// sysOps is what the backends ask of the system rather than of a filesystem
// library, behind a seam so the tests need no root: chown, mount, and what is
// mounted where.
type sysOps interface {
	// setOwner makes path (a directory, never a link) uid:gid with mode.
	setOwner(path string, uid, gid int, mode os.FileMode) error
	mountZFS(dataset, dir string) error
	unmount(dir string) error
	// mountedAt returns what is mounted exactly at dir: its source and
	// filesystem type, or ok=false.
	mountedAt(dir string) (source, fstype string, ok bool, err error)
	// fsType is statfs(2)'s f_type of path.
	fsType(path string) (int64, error)
	space(path string) (free, total uint64, err error)
}

// The statfs magics of linux/magic.h, and ZFS's own (include/sys/zfs_vfsops.h).
const (
	magicBtrfs = 0x9123683E
	magicXFS   = 0x58465342
	magicExt4  = 0xEF53
	magicZFS   = 0x2FC12FC1
)

// checkRoot refuses a parent root the provisioner does not hold alone. A
// root another user can write into is one where a volume's name could be
// taken -- a directory or a link put there first -- and the provisioner would
// then be asked to treat it as its own.
func checkRoot(what, path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", what, path, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("%s %s is not a directory (a link is not followed)", what, path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s is writable by its group or by everybody (%v): only the provisioner may create in it", what, path, st.Mode().Perm())
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Uid != 0 && int(s.Uid) != os.Geteuid() {
		return fmt.Errorf("%s %s belongs to uid %d, neither root nor this process", what, path, s.Uid)
	}
	return nil
}

// ensureDir makes path a directory, or accepts one that is already there; it
// refuses anything else, a link included.
func ensureDir(path string, mode os.FileMode) error {
	err := os.Mkdir(path, mode)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is there and is not a directory", path)
	}
	return nil
}

// isEmpty reports whether the directory path holds nothing.
func isEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}

// presentAt reports whether anything, a dangling link included, is at path.
func presentAt(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// parseMountinfo finds the mount at dir in /proc/self/mountinfo's format
// (proc(5)): field 5 is the mount point, and after the " - " separator come
// the filesystem type and the source. The last match wins, as the last mount
// on a point is the one in force. Paths escape space, tab, newline and
// backslash in octal.
func parseMountinfo(text, dir string) (source, fstype string, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		pre, post, found := strings.Cut(line, " - ")
		if !found {
			continue
		}
		f := strings.Fields(pre)
		g := strings.Fields(post)
		if len(f) < 5 || len(g) < 2 {
			continue
		}
		if unescapeMount(f[4]) == dir {
			source, fstype, ok = unescapeMount(g[1]), g[0], true
		}
	}
	return source, fstype, ok
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
