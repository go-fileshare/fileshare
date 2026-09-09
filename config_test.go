package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What a configuration cannot mean is refused, with the reason.
func TestConfigurationsThatCannotWork(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no shares", `serve "PROTO" {}`, "no shares"},
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
			 serve "PROTO" { addr = "127.0.0.1:1" }
			 serve "PROTO" { addr = "127.0.0.1:2" }`,
			"served twice",
		},
		{
			"two shares under one name, whatever the case",
			`share "Disk" { image = "/a" }
			 share "disk" { image = "/b" }
			 serve "PROTO" {}`,
			"without case",
		},
		{
			"a share with a path for a name",
			`share "a/b" { image = "/i" }
			 serve "PROTO" {}`,
			"path separator",
		},
		{
			"allow names somebody who is not a user",
			`user "alice" { password = "x" }
			 share "s" {
			   image = "/i"
			   allow = ["alise"]
			 }
			 serve "PROTO" {}`,
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
			 serve "PROTO" {}`,
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
			 serve "PROTO" {}`,
			"say one or the other",
		},

		{
			// With no users at all, a name in allow belongs to nobody -- and
			// that is the message, because it is the one that says what to fix.
			"a restricted share and nobody to be",
			`share "s" {
			   image = "/i"
			   allow = ["alice"]
			 }
			 serve "PROTO" {}`,
			`allows "alice", who is not a user here`,
		},
		{
			"an address that is not one",
			`share "s" { image = "/i" }
			 serve "PROTO" { addr = "not-an-address" }`,
			"is not an address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// PROTO is whichever protocol this binary has: the refusals under
			// test are about the configuration, not about which one it is.
			p := write(t, dir, "c.hcl", strings.ReplaceAll(tc.body, "PROTO", protocols[0].name))
			_, err := loadConfig([]string{p})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

// The dangerous configuration: it reads as protected and is not. It needs a
// protocol that cannot authenticate, so it runs only in a binary that has one.
func TestUsersWithNowhereToAuthenticateThem(t *testing.T) {
	var blind *protocol
	for _, p := range protocols {
		if !p.authenticates {
			blind = p
		}
	}
	if blind == nil {
		t.Skip("this binary has no protocol that cannot authenticate")
	}
	dir := t.TempDir()
	p := write(t, dir, "c.hcl", fmt.Sprintf(`
user "alice" { password = "x" }
share "s" { image = "/i" }
serve %q {}
`, blind.name))
	_, err := loadConfig([]string{p})
	if err == nil || !strings.Contains(err.Error(), "can authenticate them") {
		t.Errorf("error = %v, want one about nowhere to authenticate", err)
	}
}

// A directory of small files is ONE configuration, and a protocol with no
// address still lands where a client looks.
func TestADirectoryOfFilesAndTheDefaultPorts(t *testing.T) {
	dir := t.TempDir()
	pw := write(t, dir, "alice.pw", "hunter2\n")
	users := ""
	if anyAuthenticates() {
		users = `user "alice" { password_file = "` + hclPath(pw) + `" }`
	}
	write(t, dir, "10-users.hcl", "name = \"ATTIC\"\n"+users+"\n")
	// The first protocol this binary has, with no address, and the same one
	// again would be a duplicate -- so the second block only appears when
	// there is a second protocol to put in it.
	first := protocols[0]
	blocks := fmt.Sprintf("serve %q {}\n", first.name)
	if len(protocols) > 1 {
		blocks += fmt.Sprintf("serve %q { addr = \"0.0.0.0:8081\" }\n", protocols[1].name)
	}
	write(t, dir, "20-shares.hcl", `
share "photos" {
  image     = "/srv/photos.img"
  read_only = true
}
`+blocks)
	write(t, dir, "notes.txt", `share "ignored" { image = "/nope" }`)

	cfg, err := loadConfig([]string{dir})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.Name != "ATTIC" || len(cfg.Shares) != 1 {
		t.Fatalf("merged into %+v", cfg)
	}
	want := fmt.Sprintf("127.0.0.1:%d", first.defaultPort)
	if got := cfg.Serves[0].Addr; got != want {
		t.Errorf("%s with no address landed on %q, want %q", first.name, got, want)
	}
	if len(protocols) > 1 && cfg.Serves[1].Addr != "0.0.0.0:8081" {
		t.Errorf("%s kept %q", protocols[1].name, cfg.Serves[1].Addr)
	}
	if anyAuthenticates() {
		if got, err := cfg.Users[0].password(); err != nil || got != "hunter2" {
			t.Errorf("the password file gave %q, %v", got, err)
		}
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
