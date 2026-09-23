package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Serving a block device rather than an image file.
//
// # Why this needs no privilege
//
// Nothing here mounts anything. The go-filesystems drivers read ext4, xfs,
// btrfs and the rest in user space, so there is no mount(2) and therefore no
// CAP_SYS_ADMIN. Opening a device is an ordinary open(2), governed by the
// permissions on the device node and nothing else:
//
//	Linux   /dev/sda     root:disk     0660  -> membership of `disk`
//	macOS   /dev/disk0   root:operator 0640  -> membership of `operator`,
//	                                            plus Full Disk Access
//
// So a disk is served to SMB and NFS clients by an unprivileged user, which a
// kernel mount or a FUSE filesystem could not do. The one privileged act left
// is binding port 445, and --isolate already handles it: the parent binds the
// listener and the child that speaks the protocol never needs the privilege.
//
// # What stopped it, which was not privilege
//
// A block device has no length in its inode. Stat().Size() returns 0 for one,
// on Linux and macOS alike, so every driver was handed a zero-length image and
// failed for a reason that named neither the device nor its size.
//
// # ⛔⛔ THE KERNEL IS ALSO A READER AND A WRITER OF THIS DEVICE
//
// This is the part that makes a device different in kind from a file, and it
// is not only about corruption.
//
// If the kernel has a filesystem mounted from this device, the device's page
// cache and the filesystem's page cache are two views of the same blocks, and
// the filesystem's is ahead. Dirty metadata sits in the mounted filesystem's
// cache until writeback. A reader of the raw device therefore sees a TORN
// view: a directory block from before an update next to an inode block from
// after it. The drivers here are not defensive parsers -- they are given a
// consistent filesystem and told to read it -- so a torn view surfaces as
// nonsense, or as an error naming a structure rather than the cause.
//
// So exclusivity is required for READS, not merely for writes. It is not a
// precaution against damaging the disk; it is what makes the answer correct.
//
// The kernel offers the primitive: O_EXCL on a block device means "nobody
// else, and that includes a mount". It is what mkfs and fsck use to refuse a
// mounted target. Go passes the flag through unchanged, so openDevice asks for
// it, and a device that is in use is refused by name rather than read badly.
//
// Writing is a further question and this does not answer it: a device is
// served READ-ONLY here, for the same reason a share that picked a partition
// already is.

// errEmptyDevice is returned for a device that reports no length. It is its
// own error because the distinction matters: a zero-byte image file is a
// mistake in the configuration, while a device that will not say how big it is
// means the wrong kind of node was named.
var errEmptyDevice = errors.New("the device reported a length of zero")

// errDeviceBusy is returned when the kernel refuses exclusive access.
var errDeviceBusy = errors.New("the device is in use")

// isDevice reports whether this is a device node rather than a regular file.
//
// ⛔ BOTH bits, and the character one is not paranoia. macOS exposes every
// disk twice: /dev/disk0 is the buffered block device and /dev/rdisk0 the raw
// character device -- and the raw one is what anybody doing bulk I/O on macOS
// is told to use. Testing only ModeDevice would accept /dev/disk0 and reject
// /dev/rdisk0 with a message about a zero-length image.
func isDevice(fi fs.FileInfo) bool {
	return fi.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != 0
}

// imageLength is how many bytes the drivers may address.
//
// For a regular file it is the file's length. A device's inode carries no
// length, so the device itself is asked -- by deviceLength, which is per
// platform because the answer is.
//
// ⛔ THE FIRST VERSION OF THIS WAS ONE PORTABLE lseek TO THE END, and it was
// wrong in the worst available way: on Darwin that returns 0 and NO ERROR, on
// a device whose reads work perfectly. A file-backed test would never have
// shown it. Attaching a real device did, immediately.
func imageLength(f *os.File, fi fs.FileInfo) (int64, error) {
	if !isDevice(fi) {
		return fi.Size(), nil
	}
	return deviceLength(f)
}

// openDevice opens a device for reading, exclusively.
//
// O_EXCL without O_CREAT is a no-op on a regular file and is the exclusive
// claim on a block device: the kernel refuses if anything else holds it,
// a mount included. Asking for it is what turns "we might be reading a
// filesystem somebody is writing" into a refusal with a name on it.
//
// ⚠ Darwin does not implement the claim the way Linux does. There, a device
// carrying a mounted volume refuses a WRITE open, and a read open may be
// granted. The refusal below therefore fires where the kernel supports it and
// is not a guarantee this program can make on every platform; that limit is
// stated rather than papered over, and it is why deviceBusyHint says what to
// do rather than asserting the device was idle.
func openDevice(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_EXCL, 0)
	if err == nil {
		return f, nil
	}
	if errors.Is(err, syscall.EBUSY) {
		return nil, fmt.Errorf("%w: %s", errDeviceBusy, path)
	}
	return nil, err
}

// deviceBusyHint is the sentence that resolves a refusal.
func deviceBusyHint(path string) string {
	return fmt.Sprintf("%s is held by something else -- most often a mounted "+
		"filesystem. Unmount it first. This is not caution about damaging the "+
		"disk: a filesystem the kernel is writing keeps its newest metadata in "+
		"its own cache, so the raw device would be read in a state that never "+
		"existed on any one moment's disk.", path)
}

// deviceOpenHint turns a refusal to open a device into the sentence that
// resolves it.
//
// A bare "permission denied" on /dev/sda sends people to sudo, which is the
// one answer this program exists to avoid. The device node says who may read
// it; this reads it back.
func deviceOpenHint(path string, err error) string {
	if errors.Is(err, errDeviceBusy) {
		return deviceBusyHint(path)
	}
	if !errors.Is(err, fs.ErrPermission) {
		return ""
	}
	fi, serr := os.Stat(path)
	if serr != nil || !isDevice(fi) {
		return ""
	}
	group, ok := deviceGroup(fi)
	if !ok {
		return fmt.Sprintf("%s is a device this user may not open. Serving a "+
			"device needs read access to the node, not root.", path)
	}
	return fmt.Sprintf("%s is a device with mode %s, readable by the %q group. "+
		"Joining that group is enough -- this program never mounts anything, so "+
		"it needs no privilege beyond reading the node.",
		path, fi.Mode().Perm(), group)
}
