// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-fsctl/projquota"

	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// projOps is the part of go-fsctl/projquota the XFS/ext4 backend uses.
type projOps interface {
	Detect(path string) (projquota.Filesystem, error)
	GetProject(path string) (id uint32, inherit bool, err error)
	SetProjectTree(root string, id uint32) error
	SetLimits(path string, id uint32, l projquota.Limits) error
	Usage(path string, id uint32) (projquota.Quota, error)
}

// The XFS/ext4 ownership mark is the project id: a directory is ours when
// its id lies in the parent's configured range AND is the one recorded for
// it. The range alone is not enough -- an id could be set on any directory
// by its owner -- and the record alone is not either, since the directory at
// that name may since have been replaced by one tagged otherwise.
type projBackend struct {
	id, root string
	k        provisionv1.Kind
	lo, hi   uint32
	gid      int
	p        projOps
	sys      sysOps
}

func (b *projBackend) kind() provisionv1.Kind { return b.k }

func (b *projBackend) path(r *record) string { return filepath.Join(b.root, r.Name) }

func (b *projBackend) start([]*record) error {
	if err := checkRoot(kindName(b.k)+" root", b.root); err != nil {
		return err
	}
	want := map[provisionv1.Kind]projquota.Filesystem{provisionv1.Kind_KIND_XFS: projquota.XFS, provisionv1.Kind_KIND_EXT4: projquota.Ext4}[b.k]
	if fsys, err := b.p.Detect(b.root); err != nil || fsys != want {
		return fmt.Errorf("%s root %s is not on %v (%v, %v)", kindName(b.k), b.root, want, fsys, err)
	}
	// Reading a project's usage needs project quotas on, enforced, and a
	// kernel with quotactl_fd: the cheapest question that fails without them.
	if _, err := b.p.Usage(b.root, b.lo); err != nil {
		return fmt.Errorf("%s root %s: project quotas do not answer (%w); mount it with -o prjquota", kindName(b.k), b.root, err)
	}
	return nil
}

func (b *projBackend) space() (free, total uint64, err error) { return b.sys.space(b.root) }

func (b *projBackend) present(r *record) (bool, error) { return presentAt(b.path(r)) }

func (b *projBackend) owned(r *record) error {
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
	id, _, err := b.p.GetProject(p)
	if err != nil {
		return err
	}
	switch {
	case r.Pending && id == 0:
		// Made, not yet tagged.
		return nil
	case id < b.lo || id > b.hi:
		return fmt.Errorf("%s has project id %d, outside %d-%d: %w", p, id, b.lo, b.hi, errNotOurs)
	case r.ProjectID == 0 || id != r.ProjectID:
		return fmt.Errorf("%s has project id %d, not the one recorded for it: %w", p, id, errNotOurs)
	}
	return nil
}

func (b *projBackend) quota(r *record) (uint64, error) {
	q, err := b.p.Usage(b.root, r.ProjectID)
	return q.BlockHard, err
}

// used needs CAP_SYS_ADMIN (check_quotactl_permission lets an unprivileged
// caller read its own user and group quotas, never a project's), which is
// why it is the provisioner that answers it and not fileshare.
func (b *projBackend) used(r *record) (uint64, error) {
	q, err := b.p.Usage(b.root, r.ProjectID)
	return q.Bytes, err
}

// create makes the directory, tags it -- with inheritance, so everything made
// inside is charged to the project -- limits the project, and only then gives
// the directory to the group.
func (b *projBackend) create(r *record) error {
	p := b.path(r)
	if err := ensureDir(p, 0o700); err != nil {
		return err
	}
	if err := b.owned(r); err != nil {
		return err
	}
	if err := b.p.SetProjectTree(p, r.ProjectID); err != nil {
		return err
	}
	if err := b.p.SetLimits(b.root, r.ProjectID, projquota.Limits{BlockHard: r.Quota}); err != nil {
		return err
	}
	return b.sys.setOwner(p, 0, b.gid, volumeMode)
}

func (b *projBackend) resize(r *record, quota uint64) error {
	return b.p.SetLimits(b.root, r.ProjectID, projquota.Limits{BlockHard: quota})
}

func (b *projBackend) canSnapshot() bool                   { return false }
func (b *projBackend) snapshots(*record) ([]string, error) { return nil, nil }
func (b *projBackend) snapshot(*record, string) error {
	return errors.New("XFS and ext4 have no snapshots")
}

func (b *projBackend) empty(r *record) (bool, error) { return isEmpty(b.path(r)) }

// destroy removes the tree without following a link and without leaving its
// filesystem, then lifts the project's limits: the id goes back to the range
// when the record does.
func (b *projBackend) destroy(r *record, _ []string) error {
	if err := removeTree(b.root, r.Name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if r.ProjectID == 0 {
		return nil
	}
	return b.p.SetLimits(b.root, r.ProjectID, projquota.Limits{})
}
