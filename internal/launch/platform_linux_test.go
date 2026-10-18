// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package launch

import (
	"syscall"
	"testing"
)

// A worker dies with its launcher.
func checkPlatformAttr(t *testing.T, a *syscall.SysProcAttr) {
	t.Helper()
	if a.Pdeathsig != syscall.SIGKILL {
		t.Errorf("Pdeathsig %v", a.Pdeathsig)
	}
}
