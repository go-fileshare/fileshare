// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"sync"
	"time"
)

// What a client is told a directory share's size and free space are.
//
// An image's size is fixed when it is opened. A directory's is not: free
// space goes down with every write, and a volume's quota can be resized. So
// a directory share hands the protocols a FUNCTION, asked at every FSSTAT,
// PROPFIND and SMB size query (nfs, webdav and smb WithCapacityFunc), and
// not numbers taken once.
//
// For most directories that function is statfs on the tree -- which is also
// right for ZFS volumes (refquota) and XFS/ext4 volumes (a project quota
// with PROJINHERIT): the kernel answers with the quota there.
//
// ⛔ btrfs is the exception. Its statfs ignores qgroups, so a volume of
// 32 MiB reported the whole filesystem. Its size comes from the provisioner
// instead -- the volume's quota, and its level-0 qgroup's referenced bytes
// as used -- because the qgroup tree is readable with CAP_SYS_ADMIN only
// (BTRFS_IOC_TREE_SEARCH), which this server does not hold.

// spaceTTL is how long a statfs answer is reused: a PROPFIND of a directory
// with a thousand subdirectories reports the quota on each, and asks once.
// A variable for the tests that watch a number change.
var spaceTTL = time.Second

// volumeTTL is how often, at most, the provisioner is asked for a btrfs
// volume's usage while clients ask for its size. btrfs updates a qgroup's
// counts when a transaction commits (every 30 s by default, or at a sync),
// so asking more often than this would see the same numbers. A variable for
// the tests that watch a number change.
var volumeTTL = 5 * time.Second

// volumeAskTimeout bounds one question to the provisioner. Nobody waits for
// it: the last numbers known are served meanwhile.
const volumeAskTimeout = 5 * time.Second

// statfsSpace is statfs on a tree, reused for spaceTTL. An error is
// "unknown": zero total, which every protocol reports as such.
type statfsSpace struct {
	usage func() (total, free uint64, err error)
	now   func() time.Time

	mu          sync.Mutex
	at          time.Time
	total, free uint64
	err         error
}

func newStatfsSpace(usage func() (uint64, uint64, error)) *statfsSpace {
	return &statfsSpace{usage: usage, now: time.Now}
}

func (s *statfsSpace) read() (total, free uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := s.now(); s.at.IsZero() || now.Sub(s.at) >= spaceTTL || now.Before(s.at) {
		s.total, s.free, s.err = s.usage()
		s.at = now
	}
	return s.total, s.free, s.err
}

// capacity is read as the protocols want it.
func (s *statfsSpace) capacity() (total, avail uint64) {
	total, free, err := s.read()
	if err != nil {
		return 0, 0
	}
	return total, free
}

// volumeSpace is a btrfs volume's size: the quota as the total, and as
// available the quota less what the qgroup references -- or the
// filesystem's own free space, when the filesystem holding every volume has
// less room left than this one's quota would allow.
//
// The numbers are the provisioner's, asked in the background: capacity
// never waits for it. It starts from what the provisioner said when the
// share was resolved, asks again when a client asks and the last answer is
// older than volumeTTL -- one question at a time, and at most one per
// volumeTTL, answered or not -- and falls back to statfs when it has never
// had a quota.
type volumeSpace struct {
	ref    volumeRef
	ask    func(ctx context.Context, ref volumeRef) (quota, used uint64, err error)
	statfs *statfsSpace
	now    func() time.Time

	mu          sync.Mutex
	quota, used uint64
	at          time.Time
	asking      bool
	// asked is closed and replaced at every answer, for a test to wait on.
	asked chan struct{}
}

func newVolumeSpace(res *volumeResolution, statfs *statfsSpace,
	ask func(context.Context, volumeRef) (uint64, uint64, error)) *volumeSpace {
	v := &volumeSpace{ref: res.ref, ask: ask, statfs: statfs, now: time.Now,
		quota: res.quota, used: res.used, asked: make(chan struct{})}
	v.at = v.now()
	return v
}

func (v *volumeSpace) capacity() (total, avail uint64) {
	v.mu.Lock()
	if now := v.now(); !v.asking && (now.Sub(v.at) >= volumeTTL || now.Before(v.at)) {
		v.asking = true
		go v.refresh()
	}
	quota, used := v.quota, v.used
	v.mu.Unlock()

	fsTotal, fsFree, err := v.statfs.read()
	if quota == 0 {
		// Never told a quota: statfs, which is at least the filesystem.
		if err != nil {
			return 0, 0
		}
		return fsTotal, fsFree
	}
	avail = quota - min(used, quota)
	if err == nil && fsFree < avail {
		avail = fsFree
	}
	return quota, avail
}

// refresh asks the provisioner once. A failure keeps the numbers it had,
// and waits volumeTTL before asking again: a provisioner that is down is not
// asked at every FSSTAT.
func (v *volumeSpace) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), volumeAskTimeout)
	quota, used, err := v.ask(ctx, v.ref)
	cancel()
	v.mu.Lock()
	defer v.mu.Unlock()
	if err == nil && quota > 0 {
		v.quota, v.used = quota, used
	}
	v.at = v.now()
	v.asking = false
	close(v.asked)
	v.asked = make(chan struct{})
}

// capacityOf is the function a directory share's size is reported from:
// the provisioner's numbers for a btrfs volume, statfs for the rest.
func (s *server) capacityOf(b shareBlock, usage func() (uint64, uint64, error)) (func() (uint64, uint64), uint64) {
	fs := newStatfsSpace(usage)
	if b.vol != nil && b.vol.kind == kindBtrfs && b.vol.quota > 0 {
		v := newVolumeSpace(b.vol, fs, s.volumeUsage)
		return v.capacity, b.vol.quota
	}
	total, _ := fs.capacity()
	return fs.capacity, total
}
