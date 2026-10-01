// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// What an admin, a metrics or a directory share block may not say, each
// beside a configuration that differs from it by that one thing and loads.
func TestControlAndDirectoryConfigRefusals(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(tree, 0o755)
	img := image(t, dir, "d.img", nil)
	state := hclPath(filepath.Join(dir, "s.json"))
	base := func(extra string) string {
		return configFor(t, dir, fmt.Sprintf("share \"t\" {\n  directory = %q\n}\n", hclPath(tree))) + extra
	}
	admin := func(body string) string { return "admin {\n" + body + "\n}\n" }
	cases := []struct {
		name, body, want string
	}{
		{"a directory share", base(""), ""},
		{"image and directory",
			configFor(t, dir, fmt.Sprintf("share \"t\" {\n  directory = %q\n  image = %q\n}\n", hclPath(tree), hclPath(img))),
			"one or the other"},
		{"neither", configFor(t, dir, "share \"t\" {\n  read_only = true\n}\n"), "neither an image nor a directory"},
		{"a directory with a filesystem",
			configFor(t, dir, fmt.Sprintf("share \"t\" {\n  directory = %q\n  filesystem = \"ext4\"\n}\n", hclPath(tree))),
			"filesystem and partition are for an image"},
		{"a directory with a partition",
			configFor(t, dir, fmt.Sprintf("share \"t\" {\n  directory = %q\n  partition = 1\n}\n", hclPath(tree))),
			"filesystem and partition are for an image"},
		{"metrics on host:port", base("metrics { listen = \"127.0.0.1:9100\" }\n"), ""},
		{"metrics on a unix socket", base("metrics { listen = \"unix:///run/fs/m.sock\" }\n"), ""},
		{"metrics on a relative socket", base("metrics { listen = \"unix://run/m.sock\" }\n"), "absolute path"},
		{"metrics on nothing", base("metrics { listen = \"nowhere\" }\n"), "not an address"},
		{"admin with no state file", base(admin(`listen = "unix:///run/fs/a.sock"`)), "state_file"},
		{"admin with a relative root",
			base(admin(fmt.Sprintf("listen = \"unix:///run/fs/a.sock\"\nstate_file = %q\nsource_roots = [\"srv\"]", state))),
			"not an absolute path"},
	}
	if checkAdminListen(&adminBlock{Listen: "unix:///x.sock"}) == nil {
		// Built with the admin API: its listener is the library's to check.
		cases = append(cases,
			struct{ name, body, want string }{"admin on a unix socket",
				base(admin(fmt.Sprintf("listen = \"unix:///run/fs/a.sock\"\nstate_file = %q", state))), ""},
			struct{ name, body, want string }{"admin over TCP without mutual TLS",
				base(admin(fmt.Sprintf("listen = \"127.0.0.1:7443\"\nstate_file = %q", state))), "admin:"},
		)
	} else {
		cases = append(cases, struct{ name, body, want string }{"admin in a nogrpc build",
			base(admin(fmt.Sprintf("listen = \"unix:///run/fs/a.sock\"\nstate_file = %q", state))), "nogrpc"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(c.body, "unix:///") {
				// "/run/fs/a.sock" is not an absolute path on Windows.
				t.Skip("a unix socket path")
			}
			p := write(t, t.TempDir(), "c.hcl", c.body)
			_, err := loadConfig([]string{p})
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && err == nil:
				t.Fatalf("loaded; want a refusal saying %q", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}

// A share the state file defines and the configuration also defines is
// refused at startup, naming both -- and a state file with only its own
// shares loads.
func TestStateAndConfigurationNeverShareAName(t *testing.T) {
	needUsers(t)
	if runtime.GOOS == "windows" {
		t.Skip("the admin block names a unix socket path")
	}
	if checkAdminListen(&adminBlock{Listen: "unix:///x.sock"}) != nil {
		t.Skip("built without the admin API")
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(tree, 0o755)
	state := filepath.Join(dir, "s.json")
	body := configFor(t, dir, fmt.Sprintf("share \"Photos\" {\n  directory = %q\n}\n", hclPath(tree))) +
		fmt.Sprintf("admin {\n  listen = \"unix:///run/fs/a.sock\"\n  state_file = %q\n  source_roots = [%q]\n}\n", hclPath(state), hclPath(dir))
	p := write(t, dir, "c.hcl", body)

	write(t, dir, "s.json", fmt.Sprintf(`{"version":1,"shares":[{"name":"docs","directory":%q,"grants":[{"subject":"alice"}]}]}`,
		filepath.ToSlash(tree)))
	cfg, err := loadConfig([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if err := withState(cfg); err != nil {
		t.Fatalf("a state with its own shares: %v", err)
	}
	if len(cfg.Shares) != 2 || !cfg.managed["DOCS"] {
		t.Fatalf("shares %v, managed %v", cfg.Shares, cfg.managed)
	}
	var docs shareBlock
	for _, b := range cfg.Shares {
		if b.Name == "docs" {
			docs = b
		}
	}
	// A READ grant is served read-only and opened writable: see block.
	if !docs.noWriters || docs.ReadOnly {
		t.Fatalf("docs: %+v", docs)
	}

	write(t, dir, "s.json", fmt.Sprintf(`{"version":1,"shares":[{"name":"photos","directory":%q,"grants":[{"subject":"alice"}]}]}`,
		filepath.ToSlash(tree)))
	cfg, _ = loadConfig([]string{p})
	if err := withState(cfg); err == nil || !strings.Contains(err.Error(), `"Photos" is in the configuration`) {
		t.Fatalf("two definitions of one name: %v", err)
	}

	write(t, dir, "s.json", `{"version":2,"shares":[]}`)
	cfg, _ = loadConfig([]string{p})
	if err := withState(cfg); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("a state from another version: %v", err)
	}
}

// writeState replaces the file whole, and leaves no temporary file behind.
func TestWriteStateIsAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	write(t, dir, "s.json", "the old one")
	if err := writeState(p, &stateFile{Version: stateVersion, Shares: []managedShare{{Name: "x"}}}); err != nil {
		t.Fatal(err)
	}
	st, err := readState(p)
	if err != nil || len(st.Shares) != 1 {
		t.Fatalf("%v %v", st, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}
	// A directory that cannot be written leaves the old file as it was.
	if err := writeState(filepath.Join(dir, "missing", "s.json"), st); err == nil {
		t.Fatal("wrote into a directory that does not exist")
	}
}
