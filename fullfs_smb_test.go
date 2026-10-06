// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/cloudsoda/go-smb2"
)

// SMB: CHARACTERISED, not right. go-filesystems/smb maps a driver's error by
// sentinel only, and a full filesystem is none of them: the write falls back
// to STATUS_ACCESS_DENIED whichever errno, where STATUS_DISK_FULL
// (0xC000007F) is the answer -- a constant that library defines and never
// sends. Nothing in this program can reach it; the fix is upstream, and this
// test fails the day it lands, so the answer here is changed with it.
func TestAFullShareOverSMB(t *testing.T) {
	if protocolByName("smb") == nil {
		t.Skip("built without smb")
	}
	const accessDenied, diskFull = 0xC0000022, 0xC000007F
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
			switch code {
			case diskFull:
				t.Errorf("go-filesystems/smb now answers STATUS_DISK_FULL: update this test and fullfs.go")
			case accessDenied:
			default:
				t.Errorf("a write to a full share: status %#x", code)
			}
		})
	}
}
