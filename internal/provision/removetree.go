// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// removeTree removes parent/name and everything below it.
//
// ⛔ It is the provisioner, as root, deleting a tree an unprivileged program
// wrote. Every name is resolved relative to its directory's descriptor with
// O_NOFOLLOW, so a component swapped for a link during the walk is removed as
// a link, never followed out of the tree. And it does not leave the volume's
// filesystem: a directory on another device is a mount, and walking into it
// would delete what is mounted there -- it stops with an error instead, the
// tree half removed and the mount untouched. os.RemoveAll and os.Root's
// RemoveAll both do the first and neither does the second.
func removeTree(parent, name string) error {
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: parent, Err: err}
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "stat", Path: parent + "/" + name, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s/%s is not a directory", parent, name)
	}
	if err := removeBelow(pfd, name, parent+"/"+name, uint64(st.Dev)); err != nil {
		return err
	}
	return unlinkat(pfd, name, unix.AT_REMOVEDIR, parent+"/"+name)
}

// removeBelow empties the directory name of dirfd, which must be on dev.
func removeBelow(dirfd int, name, path string, dev uint64) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if uint64(st.Dev) != dev {
		return fmt.Errorf("%s is on another filesystem (a mount); it is not removed", path)
	}
	for {
		names, err := f.Readdirnames(256)
		for _, n := range names {
			var cst unix.Stat_t
			if err := unix.Fstatat(fd, n, &cst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return &os.PathError{Op: "stat", Path: path + "/" + n, Err: err}
			}
			if cst.Mode&unix.S_IFMT == unix.S_IFDIR {
				if err := removeBelow(fd, n, path+"/"+n, dev); err != nil {
					return err
				}
				if err := unlinkat(fd, n, unix.AT_REMOVEDIR, path+"/"+n); err != nil {
					return err
				}
				continue
			}
			if err := unlinkat(fd, n, 0, path+"/"+n); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) || err == nil && len(names) == 0 {
			return nil
		}
		if err != nil {
			return &os.PathError{Op: "readdir", Path: path, Err: err}
		}
		// What was read has been removed; read again from the start, as
		// a directory's offsets need not survive the removal of entries.
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
	}
}

func unlinkat(dirfd int, name string, flags int, path string) error {
	if err := unix.Unlinkat(dirfd, name, flags); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: path, Err: err}
	}
	return nil
}
