// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package launch

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// platformAttr: a worker dies with the launcher. Without it, a worker whose
// launcher is gone would serve on as the person, with nobody to stop it.
func platformAttr(attr *syscall.SysProcAttr) { attr.Pdeathsig = syscall.SIGKILL }

// hardenWorker: no execve can ever give this process more than it has
// (PR_SET_NO_NEW_PRIVS, one-way, inherited), and it does not dump core --
// the kernel already reset PR_SET_DUMPABLE when the uid changed; this says
// so rather than relying on it.
func hardenWorker() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
