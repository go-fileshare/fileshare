package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What a configuration cannot mean is refused, with the reason.
func TestConfigurationsThatCannotWork(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no shares", `serve "smb" {}`, "no shares"},
		{"no serve block", `share "s" { image = "/i" }`, "no serve block"},
		{
			"a protocol nobody has",
			`share "s" { image = "/i" }
			 serve "gopher" {}`,
			"there is no \"gopher\" protocol",
		},
		{
			"the same protocol twice",
			`share "s" { image = "/i" }
			 serve "smb" { addr = "127.0.0.1:1" }
			 serve "smb" { addr = "127.0.0.1:2" }`,
			"served twice",
		},
		{
			"two shares under one name, whatever the case",
			`share "Disk" { image = "/a" }
			 share "disk" { image = "/b" }
			 serve "smb" {}`,
			"without case",
		},
		{
			"a share with a path for a name",
			`share "a/b" { image = "/i" }
			 serve "smb" {}`,
			"path separator",
		},
		{
			"allow names somebody who is not a user",
			`user "alice" { password = "x" }
			 share "s" {
			   image = "/i"
			   allow = ["alise"]
			 }
			 serve "smb" {}`,
			`allows "alise"`,
		},
		{
			"a writer who may not connect",
			`user "alice" { password = "x" }
			 user "bob"   { password = "y" }
			 share "s" {
			   image   = "/i"
			   allow   = ["alice"]
			   writers = ["bob"]
			 }
			 serve "smb" {}`,
			"does not allow them to connect",
		},
		{
			"read_only and writers at once",
			`user "alice" { password = "x" }
			 share "s" {
			   image     = "/i"
			   read_only = true
			   writers   = ["alice"]
			 }
			 serve "smb" {}`,
			"say one or the other",
		},
		{
			// The dangerous one: it reads as protected and is not.
			"users, and nowhere to authenticate them",
			`user "alice" { password = "x" }
			 share "s" { image = "/i" }
			 serve "nfs" {}`,
			"can authenticate them",
		},
		{
			// With no users at all, a name in allow belongs to nobody -- and
			// that is the message, because it is the one that says what to fix.
			"a restricted share and nobody to be",
			`share "s" {
			   image = "/i"
			   allow = ["alice"]
			 }
			 serve "smb" {}`,
			`allows "alice", who is not a user here`,
		},
		{
			"an address that is not one",
			`share "s" { image = "/i" }
			 serve "smb" { addr = "not-an-address" }`,
			"is not an address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := write(t, dir, "c.hcl", tc.body)
			_, err := loadConfig([]string{p})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// A directory of small files is ONE configuration, and a protocol with no
// address still lands where a client looks.
func TestADirectoryOfFilesAndTheDefaultPorts(t *testing.T) {
	dir := t.TempDir()
	pw := write(t, dir, "alice.pw", "hunter2\n")
	write(t, dir, "10-users.hcl", `
name = "ATTIC"
user "alice" { password_file = "`+hclPath(pw)+`" }
`)
	write(t, dir, "20-shares.hcl", `
share "photos" {
  image     = "/srv/photos.img"
  read_only = true
}
serve "smb" {}
serve "webdav" { addr = "0.0.0.0:8081" }
`)
	write(t, dir, "notes.txt", `share "ignored" { image = "/nope" }`)

	cfg, err := loadConfig([]string{dir})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Name != "ATTIC" || len(cfg.Shares) != 1 || len(cfg.Users) != 1 {
		t.Fatalf("merged into %+v", cfg)
	}
	if got := cfg.Serves[0].Addr; got != "127.0.0.1:445" {
		t.Errorf("smb with no address landed on %q, want the registered port on loopback", got)
	}
	if got := cfg.Serves[1].Addr; got != "0.0.0.0:8081" {
		t.Errorf("webdav kept %q", got)
	}
	if got, err := cfg.Users[0].password(); err != nil || got != "hunter2" {
		t.Errorf("the password file gave %q, %v", got, err)
	}
}

// An image is opened for what it will be used for.
//
// os.Open is read-only, and *os.File has a WriteAt method whichever way it was
// opened -- so a share served from one would be announced read-write and refuse
// every write from inside a driver.
func TestAnImageIsOpenedForWhatItIsFor(t *testing.T) {
	dir := t.TempDir()
	rw := write(t, dir, "rw.img", "not really an image")
	ro := write(t, dir, "ro.img", "not really an image")
	// os.Chmod with no write bit sets the read-only ATTRIBUTE on Windows, so
	// this is the same experiment on every platform -- and it is put back
	// afterwards, because Windows will not delete a read-only file and the
	// temporary directory's cleanup would fail.
	if err := os.Chmod(ro, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(ro, 0o600) })
	for _, tc := range []struct {
		name   string
		path   string
		asked  bool
		wantRO bool
		opens  bool
	}{
		{"a writable image, wanted writable", rw, false, false, true},
		{"a writable image, wanted read-only", rw, true, true, true},
		{"an unwritable image, wanted writable", ro, false, true, true},
		{"an image that is not there", filepath.Join(dir, "nope.img"), false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, gotRO, err := openImageFile(tc.path, tc.asked)
			if (err == nil) != tc.opens {
				t.Fatalf("opening: %v", err)
			}
			if f != nil {
				defer f.Close()
			}
			if gotRO != tc.wantRO {
				t.Errorf("read-only = %v, want %v", gotRO, tc.wantRO)
			}
			if err == nil && !gotRO {
				if _, err := f.WriteAt([]byte("x"), 0); err != nil {
					t.Errorf("the handle called writable refused a write: %v", err)
				}
			}
		})
	}
}
