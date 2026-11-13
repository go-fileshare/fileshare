// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-filesystems/hfsplus"
)

// A reload that changes whether an HFS+ image is written opens it again instead
// of adopting the open driver (go-fileshare/fileshare#129): the opt-in removed
// makes the share read-only at once, the opt-in added makes it writable, and a
// change of the size that leaves the answer alone keeps the driver (a second
// writer would not get the image lock).
func TestReloadFollowsTheHFSPlusOptIn(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	cur := r.srv.currentShares()
	if cur[0].readOnly {
		t.Fatalf("control: read-only with the opt-in\n%s", r.out.String())
	}
	if err := cur[0].fsys.WriteFile("/before.txt", []byte("1"), 0o644); err != nil {
		t.Fatalf("control: the opted-in share refused a write: %v", err)
	}
	with := func(max string) []shareBlock {
		b := cur[0].block
		b.HFSPlusWritableMax = max
		return []shareBlock{b}
	}
	closeAll := func(shs []*share) {
		t.Cleanup(func() {
			for _, sh := range shs {
				sh.close()
			}
		})
	}

	// Another size that still opts in: the same driver.
	same, err := r.srv.openShares(with("16M"), cur)
	if err != nil || same[0].fsys != cur[0].fsys || same[0].readOnly {
		t.Fatalf("a size change that keeps the opt-in: err=%v adopted=%v readOnly=%v\n%s",
			err, same[0].fsys == cur[0].fsys, same[0].readOnly, r.out.String())
	}

	// The opt-in removed: read-only, on a driver of its own, one line.
	before := r.out.String()
	off, err := r.srv.openShares(with(""), cur)
	if err != nil {
		t.Fatal(err)
	}
	closeAll(off)
	if !off[0].readOnly || !off[0].forcedReadOnly {
		t.Errorf("readOnly=%v forced=%v after the opt-in was removed, want both", off[0].readOnly, off[0].forcedReadOnly)
	}
	if off[0].fsys == cur[0].fsys {
		t.Error("the writable driver was adopted after the opt-in was removed")
	}
	if err := off[0].fsys.WriteFile("/after.txt", []byte("2"), 0o644); !errors.Is(err, hfsplus.ErrReadOnly) {
		t.Errorf("the reopened driver answered %v to a write, want ErrReadOnly", err)
	}
	if n := strings.Count(strings.TrimPrefix(r.out.String(), before), "hfsplus_writable_max is 0"); n != 1 {
		t.Errorf("the reason was logged %d times, want once:\n%s", n, r.out.String())
	}
	if b, err := off[0].fsys.ReadFile("/before.txt"); err != nil || string(b) != "1" {
		t.Errorf("the reopened share lost what was written: %q, %v", b, err)
	}

	// The opt-in added back (the old writable driver is closed with its share,
	// as a swap does): writable again.
	cur[0].close()
	on, err := r.srv.openShares(with("8M"), off)
	if err != nil {
		t.Fatal(err)
	}
	closeAll(on)
	if on[0].readOnly {
		t.Fatalf("read-only after the opt-in was added\n%s", r.out.String())
	}
	if err := on[0].fsys.WriteFile("/again.txt", []byte("3"), 0o644); err != nil {
		t.Errorf("the share opted in again refused a write: %v", err)
	}
}
