// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// countingImage stands for the image file a driver writes through.
type countingImage struct {
	n   int
	err error
}

func (c *countingImage) Sync() error { c.n++; return c.err }

type syncer interface{ Sync() error }

// ownSyncFS is a driver with a Sync of its own, as hfsplus's Volume is.
type ownSyncFS struct {
	plainFS
	n   int
	err error
}

func (o *ownSyncFS) Sync() error { o.n++; return o.err }

// The per-person tree SFTP is served from syncs every share the person may
// write, names the ones that fail, leaves a read-only share alone, and serves
// nothing to a session that has been revoked.
func TestUnionFSSyncReachesTheWritableShares(t *testing.T) {
	ok, bad, ro := &ownSyncFS{}, &ownSyncFS{err: errors.New("EIO")}, &ownSyncFS{}
	u := &unionFS{entries: []unionEntry{
		{name: "fine", fsys: ok},
		{name: "broken", fsys: bad},
		{name: "frozen", fsys: ro, readOnly: true},
		{name: "plain", fsys: plainFS{}},
	}}
	err := u.Sync()
	if err == nil || !errors.Is(err, bad.err) || !strings.Contains(err.Error(), "broken") || strings.Contains(err.Error(), "fine") {
		t.Errorf("Sync = %v, want only the broken share's EIO, named", err)
	}
	if ok.n != 1 || bad.n != 1 || ro.n != 0 {
		t.Errorf("synced fine %d, broken %d, read-only %d; want 1, 1, 0", ok.n, bad.n, ro.n)
	}
	u.revoked = func() error { return errors.New("revoked") }
	if err := u.Sync(); !errors.Is(err, os.ErrPermission) || ok.n != 1 {
		t.Errorf("a revoked session: Sync = %v, fine synced %d times", err, ok.n)
	}
}

// A driver with no Sync of its own is synced by fsyncing the image it writes
// through (fat32, exfat, ext4, ntfs, ufs write each change through to the file),
// and a failure is returned; a driver with a Sync keeps using its own, so the
// image is not synced twice; a share with no image (a directory) has nothing to
// sync.
func TestLockedFSSyncFsyncsTheImageOfADriverWithoutASync(t *testing.T) {
	img := &countingImage{}
	s := lockFSImage(plainFS{}, img).(syncer)
	if err := s.Sync(); err != nil || img.n != 1 {
		t.Fatalf("Sync = %v, image fsynced %d times, want nil and 1", err, img.n)
	}
	img.err = errors.New("EIO")
	if err := s.Sync(); !errors.Is(err, img.err) {
		t.Errorf("a failing image fsync was returned as %v", err)
	}

	img2 := &countingImage{}
	d := &ownSyncFS{}
	if err := lockFSImage(d, img2).(syncer).Sync(); err != nil || d.n != 1 || img2.n != 0 {
		t.Errorf("a driver with a Sync: err %v, driver synced %d, image fsynced %d; want nil, 1, 0", err, d.n, img2.n)
	}

	if err := lockFSImage(plainFS{}, nil).(syncer).Sync(); err != nil {
		t.Errorf("Sync with no image and no driver Sync = %v, want nil", err)
	}
}
