// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-fsctl/zfs"

	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// zfsOps is the part of go-fsctl/zfs the ZFS backend uses. *zfs.Handle is
// one; the tests have another.
type zfsOps interface {
	CreateFilesystemWithProps(name string, props zfs.Nvlist) error
	UserProp(fs, prop string) (value, source string, err error)
	GetProps(name string) (map[string]zfs.Value, error)
	SetRefquota(fs string, bytes uint64) error
	Snapshot(pool string, fullnames []string) error
	ListSnapshotsZCP(fs string) ([]string, error)
	Destroy(name string, defer_ bool) error
}

// ownerProp is the ZFS ownership mark: a user property set LOCALLY on the
// dataset, whose value is <parent id>/<name>.
const ownerProp = "fileshare:volume"

type zfsBackend struct {
	id, dataset, root string
	gid               int
	z                 zfsOps
	sys               sysOps
	logf              func(string, ...any)
}

func (b *zfsBackend) kind() provisionv1.Kind { return provisionv1.Kind_KIND_ZFS }

func (b *zfsBackend) ds(r *record) string  { return b.dataset + "/" + r.Name }
func (b *zfsBackend) dir(r *record) string { return filepath.Join(b.root, r.Name) }

// notExist is how the kernel says there is no such dataset.
func notExist(err error) bool { return errors.Is(err, syscall.ENOENT) }

// start checks the parent dataset and the root, and mounts again the volumes
// a reboot unmounted: a legacy mount is not in any table that comes back by
// itself, and nothing else mounts a legacy dataset (zpool import and `zfs
// mount -a` skip them, libzfs_mount.c zfs_is_mountable).
func (b *zfsBackend) start(recs []*record) error {
	if _, err := b.z.GetProps(b.dataset); err != nil {
		return fmt.Errorf("dataset %s: %w", b.dataset, err)
	}
	if err := checkRoot("root", b.root); err != nil {
		return err
	}
	for _, r := range recs {
		if r.Pending {
			continue
		}
		if err := b.owned(r); err != nil {
			// A volume that vanished or changed hands does not stop the
			// others: it is reported, and not served.
			b.logf("volume %s/%s is not mounted: %v", r.Parent, r.Name, err)
			continue
		}
		if err := b.mount(r); err != nil {
			b.logf("volume %s/%s: %v", r.Parent, r.Name, err)
		}
	}
	return nil
}

func (b *zfsBackend) space() (free, total uint64, err error) {
	p, err := b.z.GetProps(b.dataset)
	if err != nil {
		return 0, 0, err
	}
	avail, used := u64(p["available"]), u64(p["used"])
	return avail, avail + used, nil
}

func u64(v zfs.Value) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

func (b *zfsBackend) present(r *record) (bool, error) {
	_, err := b.z.GetProps(b.ds(r))
	if notExist(err) {
		return false, nil
	}
	return err == nil, err
}

// owned asks the dataset's own mark.
//
// ⛔ User properties are INHERITED: a child of a tagged dataset reports the
// same value, with the ancestor as its source. So ownership is the SOURCE
// being the dataset itself, not the value matching -- a dataset under a
// tagged one, or received in a send stream ("$recvd"), is not ours. And a
// dataset with no mark at all is not ours either, even though zfs_ioc_create
// makes one exist untagged for a moment before it applies the properties: the
// provisioner never mounts or touches it in that window, and if a property is
// refused the kernel destroys it again.
func (b *zfsBackend) owned(r *record) error {
	ds := b.ds(r)
	value, source, err := b.z.UserProp(ds, ownerProp)
	switch {
	case notExist(err):
		return errAbsent
	case errors.Is(err, zfs.ErrPropNotSet):
		return fmt.Errorf("dataset %s has no %s: %w", ds, ownerProp, errNotOurs)
	case err != nil:
		return err
	case source != ds:
		return fmt.Errorf("dataset %s inherits %s from %s rather than carrying its own: %w", ds, ownerProp, source, errNotOurs)
	case value != r.Parent+"/"+r.Name:
		return fmt.Errorf("dataset %s is marked %q: %w", ds, value, errNotOurs)
	}
	return nil
}

func (b *zfsBackend) quota(r *record) (uint64, error) {
	p, err := b.z.GetProps(b.ds(r))
	if err != nil {
		return 0, err
	}
	return u64(p["refquota"]), nil
}

func (b *zfsBackend) used(r *record) (uint64, error) {
	p, err := b.z.GetProps(b.ds(r))
	if err != nil {
		return 0, err
	}
	return u64(p["referenced"]), nil
}

// create makes the dataset in one ioctl with its quota, a legacy mountpoint
// and the mark, then mounts it at <root>/<name>.
//
// refquota rather than quota: it is the space the dataset itself references,
// the size a share's users see, where quota would also charge the snapshots.
func (b *zfsBackend) create(r *record) error {
	ds := b.ds(r)
	ok, err := b.present(r)
	if err != nil {
		return err
	}
	if !ok {
		if err := b.z.CreateFilesystemWithProps(ds, zfs.Nvlist{
			"refquota":   r.Quota,
			"mountpoint": zfs.ZFS_MOUNTPOINT_LEGACY,
			ownerProp:    r.Parent + "/" + r.Name,
		}); err != nil {
			return err
		}
	}
	if err := b.owned(r); err != nil {
		return err
	}
	return b.mount(r)
}

// mount mounts the volume at its directory unless it is mounted there
// already, and gives its root to the group. nosuid and nodev: nothing written
// through a share is a program to run as somebody else, or a device.
func (b *zfsBackend) mount(r *record) error {
	ds, dir := b.ds(r), b.dir(r)
	if err := ensureDir(dir, 0o755); err != nil {
		return err
	}
	src, fstype, ok, err := b.sys.mountedAt(dir)
	if err != nil {
		return err
	}
	switch {
	case ok && (fstype != "zfs" || src != ds):
		return fmt.Errorf("%s has %s (%s) mounted on it, not %s", dir, src, fstype, ds)
	case !ok:
		if err := b.sys.mountZFS(ds, dir); err != nil {
			return err
		}
	}
	return b.sys.setOwner(dir, 0, b.gid, volumeMode)
}

func (b *zfsBackend) resize(r *record, quota uint64) error { return b.z.SetRefquota(b.ds(r), quota) }

func (b *zfsBackend) canSnapshot() bool { return true }

func (b *zfsBackend) snapshots(r *record) ([]string, error) {
	full, err := b.z.ListSnapshotsZCP(b.ds(r))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range full {
		if s, ok := strings.CutPrefix(f, b.ds(r)+"@"); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func (b *zfsBackend) snapshot(r *record, name string) error {
	pool, _, _ := strings.Cut(b.dataset, "/")
	return b.z.Snapshot(pool, []string{b.ds(r) + "@" + name})
}

// empty looks at the mounted dataset. A dataset that is not mounted where it
// should be is not looked at through whatever directory is there instead.
func (b *zfsBackend) empty(r *record) (bool, error) {
	if err := b.mount(r); err != nil {
		return false, err
	}
	return isEmpty(b.dir(r))
}

func (b *zfsBackend) destroy(r *record, snaps []string) error {
	ds, dir := b.ds(r), b.dir(r)
	_, _, ok, err := b.sys.mountedAt(dir)
	if err != nil {
		return err
	}
	if ok {
		if err := b.sys.unmount(dir); err != nil {
			return err
		}
	}
	for _, s := range snaps {
		if err := b.z.Destroy(ds+"@"+s, false); err != nil && !notExist(err) {
			return err
		}
	}
	if err := b.z.Destroy(ds, false); err != nil && !notExist(err) {
		return err
	}
	// The mount point is an empty directory of the root's filesystem now.
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// volumeMode is every volume root's: rwx for root and for the group, nothing
// for anyone else, and setgid so what fileshare creates inside stays in the
// group.
const volumeMode = os.ModeSetgid | 0o770
