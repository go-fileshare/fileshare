// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/go-fsctl/btrfs"

	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// btrfsOps is the part of go-fsctl/btrfs the btrfs backend uses.
type btrfsOps interface {
	SubvolCreate(parentDir, name string) error
	SubvolDelete(parentDir, name string) error
	SubvolLimit(path string, maxRfer uint64) error
	SnapshotCreate(src, destParentDir, name string, readonly bool) error
	// subvol is the id and uuid of the subvolume whose ROOT path is; a
	// plain directory inside a subvolume is an error.
	subvol(path string) (id uint64, uuid [16]byte, err error)
	ListQgroups(path string) ([]btrfs.Qgroup, error)
	QgroupDestroy(path string, qgroupid uint64) error
	QuotaEnable(path string) error
	QuotaRescanAndWait(path string) error
}

// snapshotDir is where a btrfs parent's snapshots live: <root>/.snapshots/
// <volume>/<snapshot>. The leading dot keeps it out of the name grammar, so
// no volume can ever be called that.
const snapshotDir = ".snapshots"

// The btrfs ownership mark is the RECORD: a subvolume is ours when it is
// directly under the root and its tree id and uuid are the ones this
// provisioner wrote down when it created it. A subvolume carries nothing a
// caller could not have set as well, and the root is writable by the
// provisioner alone (checkRoot), so the record is the one fact nobody else
// can forge; the uuid makes "deleted and made again under the same name" a
// different subvolume.
type btrfsBackend struct {
	id, root    string
	gid         int
	enableQuota bool
	b           btrfsOps
	sys         sysOps
}

func (b *btrfsBackend) kind() provisionv1.Kind { return provisionv1.Kind_KIND_BTRFS }

func (b *btrfsBackend) path(r *record) string  { return filepath.Join(b.root, r.Name) }
func (b *btrfsBackend) snaps(r *record) string { return filepath.Join(b.root, snapshotDir, r.Name) }

func (b *btrfsBackend) start([]*record) error {
	if err := checkRoot("btrfs root", b.root); err != nil {
		return err
	}
	if t, err := b.sys.fsType(b.root); err != nil || t != magicBtrfs {
		return fmt.Errorf("btrfs root %s is not on btrfs (f_type %#x, %v)", b.root, t, err)
	}
	// Quotas off: the quota tree does not exist and listing it fails.
	if _, err := b.b.ListQgroups(b.root); err != nil {
		if !b.enableQuota {
			return fmt.Errorf("btrfs root %s: quotas are not enabled (%v); run `btrfs quota enable %s`, or set enable_quota = true", b.root, err, b.root)
		}
		if err := b.b.QuotaEnable(b.root); err != nil {
			return fmt.Errorf("enabling quotas on %s: %w", b.root, err)
		}
		// Enabling queues a rescan; the numbers mean nothing until it ends.
		if err := b.b.QuotaRescanAndWait(b.root); err != nil {
			return fmt.Errorf("the quota rescan of %s: %w", b.root, err)
		}
	}
	return ensureDir(filepath.Join(b.root, snapshotDir), 0o700)
}

func (b *btrfsBackend) space() (free, total uint64, err error) { return b.sys.space(b.root) }

func (b *btrfsBackend) present(r *record) (bool, error) { return presentAt(b.path(r)) }

func (b *btrfsBackend) owned(r *record) error {
	p := b.path(r)
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return errAbsent
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory: %w", p, errNotOurs)
	}
	id, uuid, err := b.b.subvol(p)
	if err != nil {
		return fmt.Errorf("%s is not a subvolume (%v): %w", p, err, errNotOurs)
	}
	if r.SubvolID == 0 {
		// Created and not yet recorded: only a pending record may claim it,
		// and only because nobody else can create in the root.
		if r.Pending {
			return nil
		}
		return fmt.Errorf("subvolume %s is not recorded: %w", p, errNotOurs)
	}
	if id != r.SubvolID || hex.EncodeToString(uuid[:]) != r.SubvolUUID {
		return fmt.Errorf("subvolume %s is id %d, not the %d recorded: %w", p, id, r.SubvolID, errNotOurs)
	}
	return nil
}

// qgroup is the volume's level-0 qgroup: its id is the subvolume's.
func (b *btrfsBackend) qgroup(r *record) (btrfs.Qgroup, error) {
	qs, err := b.b.ListQgroups(b.root)
	if err != nil {
		return btrfs.Qgroup{}, err
	}
	for _, q := range qs {
		if q.Level == 0 && q.SubvolID == r.SubvolID {
			return q, nil
		}
	}
	return btrfs.Qgroup{}, fmt.Errorf("no qgroup 0/%d", r.SubvolID)
}

func (b *btrfsBackend) quota(r *record) (uint64, error) {
	q, err := b.qgroup(r)
	return q.MaxRfer, err
}

func (b *btrfsBackend) used(r *record) (uint64, error) {
	q, err := b.qgroup(r)
	return q.Rfer, err
}

func (b *btrfsBackend) create(r *record) error {
	p := b.path(r)
	ok, err := b.present(r)
	if err != nil {
		return err
	}
	if !ok {
		if err := b.b.SubvolCreate(b.root, r.Name); err != nil {
			return err
		}
	}
	if err := b.owned(r); err != nil {
		return err
	}
	id, uuid, err := b.b.subvol(p)
	if err != nil {
		return err
	}
	r.SubvolID, r.SubvolUUID = id, hex.EncodeToString(uuid[:])
	// The limit before the group: fileshare can never write into it
	// unlimited.
	if err := b.b.SubvolLimit(p, r.Quota); err != nil {
		return err
	}
	return b.sys.setOwner(p, 0, b.gid, volumeMode)
}

func (b *btrfsBackend) resize(r *record, quota uint64) error {
	return b.b.SubvolLimit(b.path(r), quota)
}

func (b *btrfsBackend) canSnapshot() bool { return true }

func (b *btrfsBackend) snapshots(r *record) ([]string, error) {
	return append([]string(nil), r.Snapshots...), nil
}

// snapshot is read-only, under <root>/.snapshots/<volume>/, which only the
// provisioner writes.
func (b *btrfsBackend) snapshot(r *record, name string) error {
	if err := ensureDir(b.snaps(r), 0o700); err != nil {
		return err
	}
	if err := b.b.SnapshotCreate(b.path(r), b.snaps(r), name, true); err != nil {
		return err
	}
	r.Snapshots = append(r.Snapshots, name)
	return nil
}

func (b *btrfsBackend) empty(r *record) (bool, error) { return isEmpty(b.path(r)) }

// destroy deletes the snapshots this provisioner recorded, their directory --
// which must then be empty: anything else in it is not ours -- and the
// subvolume, then its qgroup, which the kernel keeps after the subvolume goes.
func (b *btrfsBackend) destroy(r *record, snaps []string) error {
	for _, s := range snaps {
		if err := b.b.SubvolDelete(b.snaps(r), s); err != nil && !errors.Is(err, syscall.ENOENT) {
			return err
		}
	}
	if err := os.Remove(b.snaps(r)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if ok, _ := b.present(r); ok {
		if err := b.b.SubvolDelete(b.root, r.Name); err != nil {
			return err
		}
	}
	if r.SubvolID != 0 {
		// Best effort: a kernel that cleans stale qgroups itself, or one
		// still busy with the deleted tree, answers with an error that
		// changes nothing about the volume being gone.
		_ = b.b.QgroupDestroy(b.root, btrfs.QgroupID(0, r.SubvolID))
	}
	return nil
}
