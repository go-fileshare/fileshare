// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	exfat "github.com/go-filesystems/exfat"
)

// exfatImage is a writable exFAT image holding /a.txt.
func exfatImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exfat.img")
	e, err := exfat.Format(path, 64<<20, exfat.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func fatImage(t *testing.T) string {
	t.Helper()
	return image(t, t.TempDir(), "fat.img", map[string]string{"/a.txt": "hello"})
}

// A time a go-smb2 client sets on a FAT or exFAT image is STORED, at the
// format's resolution, and read back over SMB. Before fat32 v0.13.0 and exfat
// v0.6.0 implemented MetadataSetter (go-filesystems/fat32#49, exfat#31) the
// driver had no Chtimes, the share dropped the time, and `touch -d` and
// `cp -p` on a mounted FAT stick did nothing.
//
// Both instants are on an odd second, so rounding shows: FAT keeps mtime to 2 s
// (rounded down) and atime to the day; exFAT keeps mtime to 10 ms and atime to
// 2 s. A time merely echoed back would not be rounded. The drivers read the
// local wall clock, so the instants are built in time.Local.
func TestSMBStoresTheTimesAClientSetsOnFATAndExFAT(t *testing.T) {
	needUsers(t)
	mtime := time.Date(2020, 5, 17, 10, 30, 31, 0, time.Local)
	atime := time.Date(2020, 5, 18, 13, 45, 7, 0, time.Local)
	for _, tc := range []struct {
		name         string
		image        func(t *testing.T) string
		wantM, wantA time.Time // what the format keeps
	}{
		{"fat", fatImage,
			time.Date(2020, 5, 17, 10, 30, 30, 0, time.Local),
			time.Date(2020, 5, 18, 0, 0, 0, 0, time.Local)},
		{"exfat", exfatImage,
			time.Date(2020, 5, 17, 10, 30, 31, 0, time.Local),
			time.Date(2020, 5, 18, 13, 45, 6, 0, time.Local)},
		// Not HFS+: hfsplus v0.8.0 has Chtimes (go-filesystems/hfsplus#28), but
		// detect.Open reaches it through hfsplus.OpenReader, whose Volume is
		// read-only (writable() needs the in-memory image of OpenWritable), so
		// Chtimes answers ErrReadOnly on a served share. See the README.
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.image(t)
			for _, setting := range []string{"", `unstorable_times = "refuse"`, `unstorable_times = "log"`} {
				t.Run(setting, func(t *testing.T) {
					r := start(t, onlyProtocol(t, t.TempDir(), "smb",
						fmt.Sprintf("share \"attic\" {\n  image = %q\n  %s\n}\n", hclPath(path), setting)))
					share := mountSMB(t, r, "alice", "hunter2", "attic")
					if err := share.Chtimes("a.txt", atime, mtime); err != nil {
						t.Fatalf("Chtimes: %v\n%s", err, r.out.String())
					}
					fi, err := share.Stat("a.txt")
					if err != nil {
						t.Fatal(err)
					}
					if !fi.ModTime().Equal(tc.wantM) {
						t.Errorf("LastWriteTime %v, want %v (set %v)", fi.ModTime(), tc.wantM, mtime)
					}
					if a := fi.Sys().(*smb2.FileStat).LastAccessTime; !a.Equal(tc.wantA) {
						t.Errorf("LastAccessTime %v, want %v (set %v)", a, tc.wantA, atime)
					}
					if strings.Contains(r.out.String(), "SET_INFO times not stored") {
						t.Errorf("a time the driver stored was logged as unstorable:\n%s", r.out.String())
					}
				})
			}
		})
	}
}
