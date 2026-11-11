// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apfs "github.com/go-filesystems/apfs"
	ext4 "github.com/go-filesystems/ext4"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/smb"
)

// unstorable_times: what SMB does with a time a client sets that the storage
// cannot keep. The three words, the default, and the refusals.
func TestUnstorableTimesInTheConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, setting string
		want          smb.TimePolicy
	}{
		{"absent", "", smb.TimesIgnore},
		{"ignore", `unstorable_times = "ignore"`, smb.TimesIgnore},
		{"refuse", `unstorable_times = "refuse"`, smb.TimesRefuse},
		{"log", `unstorable_times = "log"`, smb.TimesLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := write(t, dir, "c.hcl", fmt.Sprintf("share \"s\" {\n  image = \"/i\"\n  %s\n}\nserve \"smb\" {}\n", tc.setting))
			cfg, err := loadConfig([]string{p})
			if err != nil {
				t.Fatal(err)
			}
			if got := timePolicy(cfg.Shares[0].UnstorableTimes); got != tc.want {
				t.Errorf("policy %v, want %v", got, tc.want)
			}
		})
	}

	for _, tc := range []struct{ name, share, want string }{
		{"an unknown word", `unstorable_times = "warn"`, `share "s": unstorable_times = "warn" is not one of ignore, refuse, log`},
		{"the wrong case", `unstorable_times = "Refuse"`, `is not one of ignore, refuse, log`},
		{"a share kept from SMB", "protocols = [\"webdav\"]\n  unstorable_times = \"log\"", `protocols = [webdav] leaves SMB out`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := write(t, dir, "c.hcl", fmt.Sprintf("share \"s\" {\n  image = \"/i\"\n  %s\n}\nserve \"smb\" {}\n", tc.share))
			if _, err := loadConfig([]string{p}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// The three policies end to end, with a go-smb2 client. go-smb2 can set only
// the access and write times, and a host directory CAN store those, so the
// share is a writable apfs image (apfs v0.6.0 has no Chtimes; fat32 had none
// until v0.13.0, and ntfs images are not found by detect): its times are the
// ones the storage cannot keep, which is what the policy is about. apfs cannot
// be sniffed, so the share names it.
func TestUnstorableTimesEndToEnd(t *testing.T) {
	needUsers(t)
	if !withAPFS {
		t.Skip("built with -tags nopartitioned: no apfs to serve")
	}
	path := filepath.Join(t.TempDir(), "apfs.img")
	n, err := apfs.Format(path, 512<<20, apfs.FormatConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.(filesystem.MetadataSetter); ok {
		t.Skip("apfs gained MetadataSetter: pick another driver for this control")
	}
	if err := n.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}

	when := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, setting string
		refused       bool
		lines         int
	}{
		{"default", "", false, 0},
		{"ignore", `unstorable_times = "ignore"`, false, 0},
		{"refuse", `unstorable_times = "refuse"`, true, 0},
		{"log", `unstorable_times = "log"`, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				fmt.Sprintf("share \"attic\" {\n  image = %q\n  filesystem = \"apfs\"\n  %s\n}\n", hclPath(path), tc.setting)))
			share := mountSMB(t, r, "alice", "hunter2", "attic")
			err := share.Chtimes("a.txt", when, when)
			switch {
			case tc.refused && err == nil:
				t.Error("Chtimes succeeded, want a refusal")
			case !tc.refused && err != nil:
				t.Errorf("Chtimes: %v", err)
			}
			var got []string
			for l := range strings.SplitSeq(r.out.String(), "\n") {
				if strings.Contains(l, "SET_INFO times not stored") {
					got = append(got, l)
				}
			}
			if len(got) != tc.lines {
				t.Fatalf("%d log lines, want %d:\n%s", len(got), tc.lines, r.out.String())
			}
			if tc.lines == 1 && (!strings.Contains(got[0], `share="\"attic\""`) || !strings.Contains(got[0], `path="\"/a.txt\""`)) {
				t.Errorf("the line does not name the share and the path: %s", got[0])
			}
		})
	}
}

// A writable image whose driver CAN set and report times (ext4 v0.5.0
// metadata.go:93 and times.go:41): the access and write times a client sets are
// applied, in every mode, and read back over SMB. Before lockFS carried
// MetadataSetter they were dropped.
func TestSMBAppliesTheTimesAClientSetsOnAnImage(t *testing.T) {
	needUsers(t)
	path := filepath.Join(t.TempDir(), "ext4.img")
	e, err := ext4.Format(path, 64<<20, ext4.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.(filesystem.MetadataSetter); !ok {
		t.Skip("ext4 lost MetadataSetter: pick another driver for this control")
	}
	if err := e.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	want := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	for _, setting := range []string{"", `unstorable_times = "refuse"`, `unstorable_times = "log"`} {
		t.Run(setting, func(t *testing.T) {
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				fmt.Sprintf("share \"attic\" {\n  image = %q\n  %s\n}\n", hclPath(path), setting)))
			share := mountSMB(t, r, "alice", "hunter2", "attic")
			if err := share.Chtimes("a.txt", want, want); err != nil {
				t.Fatalf("Chtimes: %v", err)
			}
			fi, err := share.Stat("a.txt")
			if err != nil {
				t.Fatal(err)
			}
			if !fi.ModTime().Equal(want) {
				t.Errorf("LastWriteTime %v after Chtimes, want %v", fi.ModTime(), want)
			}
			if strings.Contains(r.out.String(), "SET_INFO times not stored") {
				t.Errorf("a time the driver stored was logged as unstorable:\n%s", r.out.String())
			}
		})
	}
}
