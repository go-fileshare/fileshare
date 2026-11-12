// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || darwin || freebsd || netbsd || openbsd || dragonfly) && !nosmb

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A writable HFS+ volume is flushed whole, so a second writer would be
// overwritten by the next flush. While another descriptor holds the image's
// lock the share opens read-only, says so, and leaves the image alone.
func TestHFSPlusImageLockedElsewhereOpensReadOnly(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	holder, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	sh := r.srv.shareByName("attic")
	if !sh.readOnly {
		t.Error("a share on a locked image is not read-only")
	}
	out := r.out.String()
	if !strings.Contains(out, "another process holds the image") || !strings.Contains(out, "so attic is read-only") {
		t.Errorf("no fallback line:\n%s", out)
	}
	wantAbilities(t, sh.fsys)
	// And the lock is real: once released, a new server writes.
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	r2 := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	if r2.srv.shareByName("attic").readOnly {
		t.Errorf("a share on an unlocked image is read-only:\n%s", r2.out.String())
	}
	// Two writable shares of one image in two servers exclude each other too.
	r3 := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	if !r3.srv.shareByName("attic").readOnly {
		t.Error("a second writer was let in while the first holds the lock")
	}
}
