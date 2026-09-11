// SPDX-License-Identifier: BSD-3-Clause

//go:build nopartitioned

package main

import (
	"fmt"
	"os"

	filesystem "github.com/go-filesystems/interface"
)

// Built without the partition-aware drivers: apfs, btrfs, xfs and zfs are the
// four heaviest dependencies here, and a site that shares a FAT32 image should
// not carry them.
//
// A configuration naming one is told THAT, which is a different thing from
// naming a filesystem that does not exist.
func openNamed(name string, _ *os.File, _ int64, _ bool, _ int) (filesystem.Filesystem, error) {
	return nil, fmt.Errorf("this binary was built without %s (-tags nopartitioned)", name)
}

func namedFilesystems() string { return "none: this binary was built with -tags nopartitioned" }

func hasNamed() bool { return false }
