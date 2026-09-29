// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"

	"github.com/go-filesystems/osfs"
)

// A share may serve a directory of the host instead of an image:
//
//	share "photos" {
//	  directory = "/data/photos"   # a container volume, say
//	  allow     = ["@family"]
//	}
//
// It is go-filesystems/osfs, which reaches the tree through an os.Root: a
// path with `..` in it, an absolute one, or a symbolic link pointing out of
// the tree is refused by the kernel-backed root rather than by a string test
// here. A client that plants a link to /etc gets a link it cannot follow.
//
// ⛔ It is NOT wrapped in lockFS. That lock exists because an image driver
// owns one *os.File and promises nothing about two calls at once; a host
// tree is the kernel's, which serialises what must be serialised per call and
// no more. Wrapping it would put one mutex in front of every file of every
// client, which is the single slowest thing a file server can do.
func (s *server) openDirectory(sh *share, b shareBlock) error {
	var opts []osfs.Option
	if b.ReadOnly {
		opts = append(opts, osfs.ReadOnly())
	}
	fsys, err := osfs.Open(b.Directory, opts...)
	if err != nil {
		return fmt.Errorf("share %q: %w", b.Name, err)
	}
	sh.fsys = fsys
	sh.kind = "directory"
	sh.openedReadOnly = b.ReadOnly
	// What a client is told the capacity is: the filesystem the tree lives
	// on. A platform that cannot say leaves it at zero, which the protocols
	// read as "unknown" rather than "full".
	if total, _, err := fsys.Usage(); err == nil {
		sh.size = total
	}
	sh.closers = []io.Closer{fsys}
	return nil
}
