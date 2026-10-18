// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !nowebdav

package main

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/go-fileshare/fileshare/internal/account"
)

// The launcher resolves a person from the configuration's attributes first:
// uidNumber and gidNumber on the user, gidNumber on each group they are in --
// a group without one gives nothing -- and the policy applies to what it found.
func TestLauncherResolverReadsTheDirectory(t *testing.T) {
	body := fmt.Sprintf(`
user "alice" {
  password   = "x"
  attributes = { uidNumber = "2001", gidNumber = "2001" }
}
user "low" {
  password   = "x"
  attributes = { uidNumber = "500", gidNumber = "2001" }
}
group "staff" {
  members    = ["alice"]
  attributes = { gidNumber = "3000" }
}
group "readers" {
  members = ["alice"]
}
identity {
  service_user = "fileshare"
  deny_uids    = [2002]
}
share "home" {
  directory = %q
  identity  = "system"
}
serve "webdav" { addr = "127.0.0.1:0" }
`, hclPath(t.TempDir()))
	cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", body)})
	if err != nil {
		t.Fatal(err)
	}
	r, closeDir, err := launcherResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDir()
	a, err := r.Resolve("alice")
	if err != nil {
		t.Fatal(err)
	}
	if a.UID != 2001 || a.GID != 2001 || !slices.Equal(a.Groups, []uint32{2001, 3000}) || a.From != "the directory" {
		t.Fatalf("alice resolved to %+v", a)
	}
	if _, err := r.Resolve("low"); !errors.Is(err, account.ErrRefused) {
		t.Fatalf("uid 500 got %v", err)
	}
	if p := r.Policy; p.MinUID != 1000 || !slices.Equal(p.DenyUIDs, []uint32{2002}) {
		t.Fatalf("policy %+v", p)
	}
	if _, err := r.Resolve("fileshare-nobody-has-this-name"); !errors.Is(err, account.ErrNoAccount) {
		t.Fatalf("an unknown person got %v", err)
	}
}
