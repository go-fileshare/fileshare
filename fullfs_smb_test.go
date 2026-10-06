// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/cloudsoda/go-smb2"
)

// SMB: a full share is STATUS_DISK_FULL (0xC000007F), whichever errno, as
// Samba answers -- go-filesystems/smb reads the errno through the rewrite.
// It used to answer STATUS_ACCESS_DENIED, which a client shows as a
// permission problem: that is the one answer this must never give again.
func TestAFullShareOverSMB(t *testing.T) {
	if protocolByName("smb") == nil {
		t.Skip("built without smb")
	}
	const accessDenied = 0xC0000022
	for _, e := range fullErrnos {
		t.Run(e.name, func(t *testing.T) {
			serveFull(t, e.errno())
			r := start(t, onlyProtocol(t, t.TempDir(), "smb", fullDirShare(t)))
			share := mountSMB(t, r, "alice", "hunter2", "full")
			f, err := share.Create("a.bin")
			if err == nil {
				_, err = f.Write([]byte("data"))
				f.Close()
			}
			// go-smb2 reports STATUS_ACCESS_DENIED as fs.ErrPermission, and
			// any other status as a ResponseError carrying it.
			var code uint32
			var re *smb2.ResponseError
			switch {
			case errors.As(err, &re):
				code = re.Code
			case errors.Is(err, fs.ErrPermission):
				code = accessDenied
			default:
				t.Fatalf("a write to a full share: %v", err)
			}
			t.Logf("create and write: %v (status %#x)", err, code)
			if code != e.smb {
				t.Errorf("a write to a full share: status %#x, want %#x (STATUS_DISK_FULL)", code, e.smb)
			}
		})
	}
}
