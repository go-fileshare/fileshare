// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
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

// A mountMatcher answers who in the OS has the image fi is the file of: a
// non-empty description (a device, a mount point) when somebody does, "" and a
// nil error when nobody does, any error when it could not tell. It answers from
// one look at the OS, taken when the matcher was made.
type mountMatcher func(fi os.FileInfo) (string, error)

// newMountMatcher looks at the OS once and returns the matcher, or
// errMountUnsupported when the platform cannot be asked, any other error when it
// could and it failed. A variable so a test can stand in for the OS.
var newMountMatcher = func(ctx context.Context) (mountMatcher, error) {
	return platformMatcher(ctx)
}

// mountScan is one look at the OS, shared by every share of one load: macOS
// answers it with one `hdiutil info`, not one per share. A load makes a new one
// (server.openSharesExpanding), so a later reload sees a later mount.
type mountScan struct {
	once  sync.Once
	match mountMatcher
	err   error
}

func (m *mountScan) holder(fi os.FileInfo) (string, error) {
	m.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), mountCheckTimeout)
		defer cancel()
		m.match, m.err = newMountMatcher(ctx)
	})
	if m.err != nil {
		return "", m.err
	}
	return m.match(fi)
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
	scan := s.mountScan.Load()
	if scan == nil { // not inside a load: a look of its own
		scan = &mountScan{}
	}
	where, err := scan.holder(fi)
	return s.sayMountVerdict(b, where, err)
}

func (s *server) sayMountVerdict(b shareBlock, where string, err error) bool {
	line, ro := mountVerdict(b, where, err)
	if line != "" {
		fmt.Fprintf(s.out, "%s %s\n", b.Image, line)
	}
	return ro
}

// mountGuardAdopted is the check for a share that is about to adopt the driver
// of an image already open for writing (a reload): the image may have been
// mounted since it was opened. It reports whether the share must be given a
// read-only open of its own instead. A device is never written, so never asked.
func (s *server) mountGuardAdopted(b shareBlock) bool {
	fi, err := statImage(b)
	if err != nil {
		return s.sayMountVerdict(b, "", fmt.Errorf("stat: %w", err))
	}
	if isDevice(fi) {
		return false
	}
	return s.mountGuard(b, fi)
}

// statImage stats the image the way it is opened: through its source root when
// the share is confined.
func statImage(b shareBlock) (os.FileInfo, error) {
	if len(b.confine) == 0 {
		return os.Stat(b.Image)
	}
	root, rel, err := rootOf(b.confine, b.Image)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Stat(rel)
}
