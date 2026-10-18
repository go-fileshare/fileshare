// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !linux

package launch

import (
	"syscall"
	"testing"
)

func checkPlatformAttr(*testing.T, *syscall.SysProcAttr) {}
