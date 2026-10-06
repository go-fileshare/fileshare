// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"os"

	"github.com/go-fsctl/projquota"
	"golang.org/x/sys/unix"
)

// processQuotaExempt reads the effective uid and /proc/self/status's CapEff.
func processQuotaExempt() string {
	status, err := os.ReadFile("/proc/self/status")
	return quotaExemptFrom(os.Geteuid(), status, err)
}

func statfsMagic(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	// f_type is signed on some architectures (s390x: uint32), and the
	// magics are positive 32-bit values everywhere.
	return int64(uint32(st.Type)), nil
}

func pathDevIno(path string) (dev, ino uint64, dir bool, err error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, 0, false, err
	}
	return uint64(st.Dev), uint64(st.Ino), st.Mode&unix.S_IFMT == unix.S_IFDIR, nil
}

// pathProject asks FS_IOC_FSGETXATTR, which needs no privilege.
func pathProject(path string) (uint32, bool, error) { return projquota.GetProject(path) }
