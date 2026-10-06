// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
)

// A full share is one answer on every protocol, whichever errno said so.
//
// A host tree under a quota reports "full" two ways: XFS answers a full
// project quota with ENOSPC, ext4, btrfs and ZFS with EDQUOT. Two of the
// protocol servers read the errno, and two read the TEXT:
//
//	            ENOSPC                         EDQUOT
//	smb         STATUS_DISK_FULL                STATUS_DISK_FULL  (by errno, as Samba)
//	nfs         NFS3ERR_NOSPC                   NFS3ERR_DQUOT     (by errno, RFC 1813)
//	webdav      507 Insufficient Storage        500, before this  (by text)
//	sftp        SSH_FX_FAILURE "no space ..."   "disk quota exceeded", before this
//
// So a directory share's errors are rewritten here, for the two that read
// text: EDQUOT and ENOSPC both read "no space left on device (the share is
// full)" -- without the path, which the tables would search too: a file
// named "not found" would turn the answer into a 404 -- and both still
// unwrap to their errno, which is what smb and nfs look for. SFTP version 3
// has no code for it at all (SSH_FX_NO_SPACE_ON_FILESYSTEM and
// QUOTA_EXCEEDED are version 5's): the text is what the person reads. S3 is
// served read-only.
//
// On Windows the host says it its own way (ERROR_DISK_FULL,
// ERROR_DISK_QUOTA_EXCEEDED), which no protocol library knows: the
// rewritten error also answers errors.Is for the POSIX errno Go defines
// there, so smb and nfs give the same answer as on a unix host.

// errShareFull is what a full share says.
type errShareFull struct{ err error }

func (e *errShareFull) Error() string { return "no space left on device (the share is full)" }
func (e *errShareFull) Unwrap() error { return e.err }

// Is answers for the errno a protocol library asks about -- ENOSPC or
// EDQUOT as Go spells them on this platform -- even where the host's own
// error is another one (Windows). On a unix host it is what Unwrap finds.
func (e *errShareFull) Is(target error) bool {
	if errors.Is(e.err, errQuota) {
		return target == quotaErrno
	}
	return target == noSpaceErrno
}

// shareFull is err, rewritten when it says the share is full.
func shareFull(err error) error {
	if err != nil && (errors.Is(err, errNoSpace) || errors.Is(err, errQuota)) {
		var already *errShareFull
		if errors.As(err, &already) {
			return err
		}
		return &errShareFull{err}
	}
	return err
}

// hostTree is every method of an *osfs.FS: the wrapper embeds it, and so
// answers exactly the capabilities osfs answers -- Opener, Truncater,
// Symlinker, HardLinker, MetadataSetter, Usage. A test checks the two
// method sets stay equal, so an osfs that grows a capability does not lose
// it here without anybody noticing.
type hostTree interface {
	filesystem.Filesystem
	filesystem.Opener
	filesystem.Truncater
	filesystem.Symlinker
	filesystem.HardLinker
	filesystem.MetadataSetter
	Usage() (total, free uint64, err error)
}

var _ hostTree = (*osfs.FS)(nil)

// fullAware is a host tree whose writes say "full" one way.
type fullAware struct{ hostTree }

func (f *fullAware) WriteFile(p string, data []byte, perm os.FileMode) error {
	return shareFull(f.hostTree.WriteFile(p, data, perm))
}
func (f *fullAware) MkDir(p string, perm os.FileMode) error {
	return shareFull(f.hostTree.MkDir(p, perm))
}
func (f *fullAware) Rename(from, to string) error { return shareFull(f.hostTree.Rename(from, to)) }
func (f *fullAware) Truncate(p string, size int64) error {
	return shareFull(f.hostTree.Truncate(p, size))
}
func (f *fullAware) Symlink(target, link string) error {
	return shareFull(f.hostTree.Symlink(target, link))
}
func (f *fullAware) Link(from, to string) error { return shareFull(f.hostTree.Link(from, to)) }

// Chown charges the file to its new owner's quota, and Chmod and Chtimes
// may allocate (an inode's extended attributes): each can be refused full.
func (f *fullAware) Chmod(p string, perm os.FileMode) error {
	return shareFull(f.hostTree.Chmod(p, perm))
}
func (f *fullAware) Chown(p string, uid, gid uint32) error {
	return shareFull(f.hostTree.Chown(p, uid, gid))
}
func (f *fullAware) Chtimes(p string, atime, mtime time.Time) error {
	return shareFull(f.hostTree.Chtimes(p, atime, mtime))
}

func (f *fullAware) OpenFile(p string) (filesystem.File, error) {
	h, err := f.hostTree.OpenFile(p)
	if err != nil {
		return nil, err
	}
	if w, ok := h.(filesystem.WritableFile); ok {
		return fullAwareFile{w}, nil
	}
	return h, nil
}

// fullAwareFile is an open file whose writes say "full" one way. Close and
// Sync are where a filesystem that delays allocation reports it.
type fullAwareFile struct{ filesystem.WritableFile }

func (f fullAwareFile) WriteAt(p []byte, off int64) (int, error) {
	n, err := f.WritableFile.WriteAt(p, off)
	return n, shareFull(err)
}
func (f fullAwareFile) Truncate(size int64) error { return shareFull(f.WritableFile.Truncate(size)) }
func (f fullAwareFile) Sync() error               { return shareFull(f.WritableFile.Sync()) }
func (f fullAwareFile) Close() error              { return shareFull(f.WritableFile.Close()) }
