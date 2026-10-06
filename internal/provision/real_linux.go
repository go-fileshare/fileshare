// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package provision

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/go-fsctl/btrfs"
	"github.com/go-fsctl/projquota"
	"github.com/go-fsctl/zfs"
	"golang.org/x/sys/unix"
)

// The real system: go-fsctl and the kernel. Nothing here decides anything;
// it is the other side of the seams the tests fake, kept thin so that what
// the fakes stand in for is only the kernel.

func newSystem() (*system, error) {
	return &system{
		sys:   realSys{},
		zfs:   func() (zfsOps, error) { return zfs.Open() },
		btrfs: realBtrfs{},
		proj:  realProj{},
	}, nil
}

type realSys struct{}

// setOwner opens the directory without following a link and changes it
// through the descriptor: the name cannot be swapped between the check and
// the change.
func (realSys) setOwner(path string, uid, gid int, mode os.FileMode) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}
	// chown clears the setgid bit; the mode is set after it.
	m := uint32(mode.Perm())
	if mode&os.ModeSetgid != 0 {
		m |= unix.S_ISGID
	}
	if err := unix.Fchmod(fd, m); err != nil {
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	return nil
}

func (realSys) mountZFS(dataset, dir string) error {
	return zfs.Mount(dataset, dir, unix.MS_NOSUID|unix.MS_NODEV, "")
}

func (realSys) unmount(dir string) error { return zfs.Unmount(dir, 0) }

func (realSys) mountedAt(dir string) (source, fstype string, ok bool, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", "", false, err
	}
	source, fstype, ok = parseMountinfo(string(data), dir)
	return source, fstype, ok, nil
}

func (realSys) fsType(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Type), nil
}

func (realSys) space(path string) (free, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}

type realBtrfs struct{}

func (realBtrfs) SubvolCreate(parentDir, name string) error {
	return btrfs.SubvolCreate(parentDir, name)
}
func (realBtrfs) SubvolDelete(parentDir, name string) error {
	return btrfs.SubvolDelete(parentDir, name)
}
func (realBtrfs) SubvolLimit(path string, maxRfer uint64) error {
	return btrfs.SubvolLimit(path, maxRfer)
}
func (realBtrfs) SnapshotCreate(src, dst, name string, ro bool) error {
	return btrfs.SnapshotCreate(src, dst, name, ro)
}
func (realBtrfs) ListQgroups(path string) ([]btrfs.Qgroup, error) { return btrfs.ListQgroups(path) }
func (realBtrfs) QgroupDestroy(path string, id uint64) error      { return btrfs.QgroupDestroy(path, id) }
func (realBtrfs) QuotaEnable(path string) error                   { return btrfs.QuotaEnable(path) }
func (realBtrfs) QuotaRescanAndWait(path string) error            { return btrfs.QuotaRescanAndWait(path) }

// btrfsFirstFreeObjectID is the inode number of every subvolume's root
// directory (BTRFS_FIRST_FREE_OBJECTID): a directory with any other is a
// plain directory inside some subvolume.
const btrfsFirstFreeObjectID = 256

func (realBtrfs) subvol(path string) (uint64, [16]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return 0, [16]byte{}, err
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || s.Ino != btrfsFirstFreeObjectID {
		return 0, [16]byte{}, errors.New("not the root of a subvolume")
	}
	info, err := btrfs.GetSubvolInfo(path)
	if err != nil {
		return 0, [16]byte{}, err
	}
	if info.ID < btrfsFirstFreeObjectID {
		return 0, [16]byte{}, fmt.Errorf("subvolume id %d is the filesystem's own", info.ID)
	}
	return info.ID, info.UUID, nil
}

type realProj struct{}

func (realProj) Detect(path string) (projquota.Filesystem, error) { return projquota.Detect(path) }
func (realProj) GetProject(path string) (uint32, bool, error)     { return projquota.GetProject(path) }
func (realProj) SetProjectTree(root string, id uint32) error {
	return projquota.SetProjectTree(root, id)
}
func (realProj) SetLimits(path string, id uint32, l projquota.Limits) error {
	return projquota.SetLimits(path, id, l)
}
func (realProj) Usage(path string, id uint32) (projquota.Quota, error) {
	return projquota.Usage(path, id)
}
