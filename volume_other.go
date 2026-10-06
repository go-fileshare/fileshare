// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import (
	"errors"
	"os"
)

// Volumes are made by the provisioner, which is Linux only: elsewhere every
// check refuses, and a volume share is never served.

var errVolumesLinuxOnly = errors.New("volumes are served on Linux only")

func processQuotaExempt() string {
	if os.Geteuid() == 0 {
		return "runs as root (uid 0)"
	}
	return ""
}

func statfsMagic(string) (int64, error) { return 0, errVolumesLinuxOnly }

func pathDevIno(string) (uint64, uint64, bool, error) { return 0, 0, false, errVolumesLinuxOnly }

func pathProject(string) (uint32, bool, error) { return 0, false, errVolumesLinuxOnly }
