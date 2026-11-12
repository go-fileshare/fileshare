// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// An image the OS has attached or mounted must not be written by a share.
//
// The advisory flock of hfsplus_lock_flock.go keeps out other processes that
// ask for the lock; the OS does not ask when it mounts an image (macOS
// `hdiutil attach`, Linux `mount -o loop` / `losetup`). Both sides would then
// write the same blocks and each would overwrite the other, for EVERY writable
// image driver, not only HFS+. So before a share's image is used for writing,
// the OS is asked who has it, and an image somebody has is opened read-only.
//
// What is asked, per platform (the sources are in the files):
//
//	linux    mountcheck_linux.go   /sys/block/loop*/loop/backing_file, the
//	                               device and inode of each, /proc/self/mountinfo
//	darwin   mountcheck_darwin.go  `hdiutil info -plist`, image-path of each
//	other    mountcheck_other.go   cannot be asked: the share is writable
//
// What a check before opening CANNOT see: a mount made AFTER the share opened
// the image. There is no re-check while serving; that window is documented in
// the README (image shares), and the way to close it is to not mount an image
// a share serves.

// errMountUnsupported is what a platform answers when it has no way to ask. It
// is not a failure of the check: nothing can be known, so nothing is refused.
var errMountUnsupported = errors.New("this platform cannot tell whether the OS has an image mounted")

// mountCheckTimeout bounds the one external command (hdiutil) a check runs.
const mountCheckTimeout = 15 * time.Second

// imageMountedBy answers who in the OS has the image fi is the file of: a
// non-empty description (a device, a mount point) when somebody does, "" and a
// nil error when nobody does, errMountUnsupported when the platform cannot be
// asked, any other error when it could and it failed. A variable so a test can
// stand in for the OS.
var imageMountedBy = func(ctx context.Context, fi os.FileInfo) (string, error) {
	return platformMountedBy(ctx, fi)
}

// imageMountUnknownValues are the words image_mount_unknown takes. The first is
// the default.
var imageMountUnknownValues = []string{"read_only", "write"}

func checkImageMountUnknown(s shareBlock) error {
	if s.ImageMountUnknown == "" || slices.Contains(imageMountUnknownValues, s.ImageMountUnknown) {
		return nil
	}
	return fmt.Errorf("share %q: image_mount_unknown = %q is not one of %s",
		s.Name, s.ImageMountUnknown, strings.Join(imageMountUnknownValues, ", "))
}

// mountVerdict applies the policy to what the OS said. It returns the sentence
// to log, after the image name, and whether the share must be read-only.
//
//   - mounted: read-only.
//   - nobody has it, or the platform cannot ask: writable, silent.
//   - the check failed: image_mount_unknown decides. The default is read-only:
//     serving read-only costs a person a visible "read-only" they can fix, and
//     serving writable under a mount costs both sides' data, silently.
func mountVerdict(b shareBlock, where string, err error) (line string, readOnly bool) {
	switch {
	case err == nil && where != "":
		return fmt.Sprintf("is in use by the OS (%s), and a second writer would corrupt it, so %s is read-only", where, b.Name), true
	case err == nil, errors.Is(err, errMountUnsupported):
		return "", false
	case b.ImageMountUnknown == "write":
		return fmt.Sprintf("could not be checked for an OS mount (%v), and image_mount_unknown is write, so %s stays writable", err, b.Name), false
	default:
		return fmt.Sprintf("could not be checked for an OS mount (%v), so %s is read-only (image_mount_unknown = \"write\" serves it writable anyway)", err, b.Name), true
	}
}

// mountGuard asks the OS, applies the policy, and writes the one log line.
// It reports whether the image must be opened read-only.
func (s *server) mountGuard(b shareBlock, fi os.FileInfo) bool {
	ctx, cancel := context.WithTimeout(context.Background(), mountCheckTimeout)
	defer cancel()
	where, err := imageMountedBy(ctx, fi)
	line, ro := mountVerdict(b, where, err)
	if line != "" {
		fmt.Fprintf(s.out, "%s %s\n", b.Image, line)
	}
	return ro
}
