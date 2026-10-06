// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodBlock = `
provisioner {
  listen     = "unix:///run/fp/p.sock"
  client_uid = 990
  group      = "990"
  max_volume = "10T"
  state_file = "/var/lib/fp/volumes.json"
  %s
}
`

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.hcl")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig([]string{p})
}

func TestAGoodConfiguration(t *testing.T) {
	c, err := loadText(t, strings.Replace(goodBlock, "%s", `
  parent "tank"  {
    zfs  = "tank/fileshare"
    root = "/srv/v/tank"
  }
  parent "fast"  { btrfs = "/srv/v/fast" }
  parent "plain" {
    xfs         = "/srv/v/plain"
    project_ids = "100000-199999"
  }
  parent "four" {
    ext4        = "/srv/v/four"
    project_ids = "200000 - 200009"
  }`, 1))
	if err != nil {
		t.Fatal(err)
	}
	if c.maxVolume != 10<<40 || c.gid != 990 || len(c.Parents) != 4 {
		t.Errorf("%+v", c)
	}
	if p := c.parent("four"); p == nil || p.lo != 200000 || p.hi != 200009 || p.root != "/srv/v/four" {
		t.Errorf("four = %+v", p)
	}
	if c.parent("nope") != nil {
		t.Error("a parent that is not there")
	}
	// A directory of files is one configuration.
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.hcl"), []byte(strings.Replace(goodBlock, "%s", `parent "fast" { btrfs = "/srv/v/fast" }`, 1)), 0o600)
	if _, err := LoadConfig([]string{d}); err != nil {
		t.Errorf("a directory: %v", err)
	}
	if _, err := LoadConfig([]string{t.TempDir()}); err == nil {
		t.Error("an empty directory")
	}
}

func TestConfigurationRefusals(t *testing.T) {
	parent := `parent "fast" { btrfs = "/srv/v/fast" }`
	block := func(attrs map[string]string, body string) string {
		base := map[string]string{"listen": `"unix:///run/fp/p.sock"`, "client_uid": "990", "group": `"990"`,
			"max_volume": `"10T"`, "state_file": `"/var/lib/fp/volumes.json"`}
		for k, v := range attrs {
			if v == "" {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		var b strings.Builder
		b.WriteString("provisioner {\n")
		for k, v := range base {
			b.WriteString("  " + k + " = " + v + "\n")
		}
		b.WriteString(body + "\n}\n")
		return b.String()
	}
	for _, c := range []struct {
		name, text, want string
	}{
		{"no block", `name = "x"`, ""},
		{"no provisioner block", `# nothing`, "no provisioner block"},
		{"fileshare's file", block(nil, parent) + `share "x" { image = "/a" }`, "share"},
		{"tcp", block(map[string]string{"listen": `"tcp://127.0.0.1:1"`}, parent), "unix socket only"},
		{"relative socket", block(map[string]string{"listen": `"unix://run/p.sock"`}, parent), "unix socket only"},
		{"root client", block(map[string]string{"client_uid": "0"}, parent), "not 0"},
		{"negative client", block(map[string]string{"client_uid": "-1"}, parent), "client_uid"},
		{"empty group", block(map[string]string{"group": `""`}, parent), "group is empty"},
		{"group 0", block(map[string]string{"group": `"0"`}, parent), "group 0"},
		{"unknown group", block(map[string]string{"group": `"no-such-group-here"`}, parent), "no-such-group-here"},
		{"bad size", block(map[string]string{"max_volume": `"ten"`}, parent), "max_volume"},
		{"zero size", block(map[string]string{"max_volume": `"0"`}, parent), "max_volume = 0"},
		{"relative state", block(map[string]string{"state_file": `"state.json"`}, parent), "state_file"},
		{"no parent", block(nil, ""), "no parent"},
		{"two parents of one id", block(nil, parent+"\n"+`parent "fast" { btrfs = "/srv/x" }`), "twice"},
		{"bad id", block(nil, `parent "Fast" { btrfs = "/srv/v/fast" }`), "not a name"},
		{"two kinds", block(nil, `parent "f" {
		btrfs = "/a"
		xfs = "/b"
		}`), "exactly one"},
		{"no kind", block(nil, `parent "f" { root = "/a" }`), "exactly one"},
		{"zfs without root", block(nil, `parent "f" { zfs = "tank/f" }`), "needs root"},
		{"root on btrfs", block(nil, `parent "f" {
		btrfs = "/a"
		root = "/b"
		}`), "root is for a zfs parent"},
		{"relative root", block(nil, `parent "f" { btrfs = "srv/a" }`), "absolute"},
		{"unclean root", block(nil, `parent "f" { btrfs = "/srv/../etc" }`), "absolute"},
		{"slash root", block(nil, `parent "f" { btrfs = "/" }`), "absolute"},
		{"bad dataset", block(nil, `parent "f" {
		zfs = "/tank"
		root = "/a"
		}`), "dataset"},
		{"snapshot dataset", block(nil, `parent "f" {
		zfs = "tank@s"
		root = "/a"
		}`), "not allowed"},
		{"dotdot dataset", block(nil, `parent "f" {
		zfs = "tank/../x"
		root = "/a"
		}`), "dataset"},
		{"xfs without range", block(nil, `parent "f" { xfs = "/a" }`), "needs project_ids"},
		{"range on btrfs", block(nil, `parent "f" {
		btrfs = "/a"
		project_ids = "1-2"
		}`), "project_ids is for"},
		{"range without dash", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "100"
		}`), "first"},
		{"range not numbers", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "a-b"
		}`), "two numbers"},
		{"range from 0", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "0-9"
		}`), "1 <= first"},
		{"range to INVALID_PROJID", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "1-4294967295"
		}`), "1 <= first"},
		{"range backwards", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "9-1"
		}`), "1 <= first"},
		{"enable_quota on xfs", block(nil, `parent "f" {
		xfs = "/a"
		project_ids = "1-9"
		enable_quota = true
		}`), "enable_quota"},
		{"nested roots", block(nil, `parent "a" { btrfs = "/srv/v" }
		parent "b" { btrfs = "/srv/v/b" }`), "one inside the other"},
		{"nested datasets", block(nil, `parent "a" {
		zfs = "tank/v"
		root = "/srv/a"
		}
		parent "b" {
		zfs = "tank/v/b"
		root = "/srv/b"
		}`), "one inside the other"},
		{"overlapping ranges", block(nil, `parent "a" {
		xfs = "/srv/a"
		project_ids = "1-10"
		}
		parent "b" {
		ext4 = "/srv/b"
		project_ids = "10-20"
		}`), "overlap"},
		{"state inside a root", block(map[string]string{"state_file": `"/srv/v/state.json"`}, `parent "a" { btrfs = "/srv/v" }`), "inside parent"},
		{"socket inside a root", block(map[string]string{"listen": `"unix:///srv/v/p.sock"`}, `parent "a" { btrfs = "/srv/v" }`), "inside parent"},
	} {
		_, err := loadText(t, c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
	if _, err := LoadConfig([]string{"/nonexistent/p.hcl"}); err == nil {
		t.Error("a missing file")
	}
	if _, err := loadText(t, "provisioner {"); err == nil {
		t.Error("a syntax error")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]uint64{"0": 0, "1048576": 1 << 20, "10T": 10 << 40, "500G": 500 << 30,
		"4K": 4096, "4KiB": 4096, "4KB": 4096, " 2M ": 2 << 20, "1E": 1 << 60, "3P": 3 << 50} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "T", "1.5T", "-1", "10X", "16E", "18446744073709551616"} {
		if got, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d", in, got)
		}
	}
}

func TestTheState(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "v.json")
	st, err := openState(p)
	if err != nil {
		t.Fatal(err)
	}
	// One provisioner per state file.
	if _, err := openState(p); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("a second open: %v", err)
	}
	st.put(&record{Parent: "a", Name: "x", Kind: "xfs", ProjectID: 5})
	st.put(&record{Parent: "a", Name: "x"}) // already there
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("state mode %v", fi.Mode())
	}
	st.close()
	st, err = openState(p)
	if err != nil {
		t.Fatal(err)
	}
	if r := st.get("a", "x"); r == nil || r.ProjectID != 5 || len(st.vols) != 1 {
		t.Errorf("read back: %+v", st.vols)
	}
	st.remove("a", "x")
	if st.get("a", "x") != nil {
		t.Error("remove")
	}
	st.close()

	for what, body := range map[string]string{
		"not json":     "{",
		"a version":    `{"version": 2, "volumes": []}`,
		"a bad name":   `{"version": 1, "volumes": [{"parent": "a", "name": "../x"}]}`,
		"a null entry": `{"version": 1, "volumes": [null]}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if st, err := openState(p); err == nil {
			st.close()
			t.Errorf("%s was read", what)
		}
	}
	if _, err := openState(filepath.Join(d, "nope", "v.json")); err == nil {
		t.Error("a state in a missing directory")
	}
	// A state that cannot be written back.
	os.Remove(p)
	st, err = openState(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if os.Getuid() != 0 {
		os.Chmod(d, 0o500)
		defer os.Chmod(d, 0o755)
		if err := st.save(); err == nil {
			t.Error("saved into a read-only directory")
		}
	}
}

// The state is read at the start, and a record the configuration cannot
// account for stops it.
func TestTheStartChecksTheState(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "a", 1<<20)
	mustCreate(t, s, "plain", "b", 1<<20)
	s.st.close()

	// A reboot: the legacy mount is gone, and the start brings it back.
	w.sys.mounts = map[string][2]string{}
	// And one volume lost its mark meanwhile: reported, not mounted, and
	// not fatal.
	mustCreateRaw(t, w, "tank", "b")
	s = w.service()
	if m := w.sys.mounts[w.path("tank", "a")]; m[0] != "pool/fs/a" {
		t.Errorf("not mounted again: %v", w.sys.mounts)
	}
	if !strings.Contains(w.log.String(), "volume tank/b is not mounted") {
		t.Errorf("the unmarked volume was not reported:\n%s", w.log)
	}
	// Something else mounted where a volume goes is reported too.
	s.st.close()
	w.sys.mounts = map[string][2]string{w.path("tank", "a"): {"/dev/sdb1", "ext4"}}
	s = w.service()
	if !strings.Contains(w.log.String(), "not pool/fs/a") {
		t.Errorf("a foreign mount was not reported:\n%s", w.log)
	}
	s.st.close()

	edit := func(f func(*stateFile)) {
		t.Helper()
		data, err := os.ReadFile(w.cfg.StateFile)
		if err != nil {
			t.Fatal(err)
		}
		var sf stateFile
		if err := json.Unmarshal(data, &sf); err != nil {
			t.Fatal(err)
		}
		f(&sf)
		data, _ = json.Marshal(sf)
		if err := os.WriteFile(w.cfg.StateFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for what, f := range map[string]func(*stateFile){
		"a parent no longer configured": func(sf *stateFile) { sf.Volumes = append(sf.Volumes, &record{Parent: "gone", Name: "x", Kind: "zfs"}) },
		"a kind that changed":           func(sf *stateFile) { sf.Volumes[0].Kind = "btrfs" },
		"a project id outside":          func(sf *stateFile) { sf.Volumes[1].ProjectID = 5 },
	} {
		data, _ := os.ReadFile(w.cfg.StateFile)
		edit(f)
		if s, err := newService(w.cfg, w.system(), w.log.logf); err == nil {
			s.st.close()
			t.Errorf("%s: started", what)
		}
		os.WriteFile(w.cfg.StateFile, data, 0o600)
	}
}

// mustCreateRaw records a ZFS volume whose dataset carries no mark.
func mustCreateRaw(t *testing.T, w *world, parent, name string) {
	t.Helper()
	w.zfs.add("pool/fs/" + name)
	st, err := openState(w.cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	st.put(&record{Parent: parent, Name: name, Kind: "zfs", Quota: 1 << 20})
	if err := st.save(); err != nil {
		t.Fatal(err)
	}
}

func TestParseMountinfo(t *testing.T) {
	text := `22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:40 / /srv/v/tank/a rw,nosuid,nodev shared:20 - zfs pool/fs/a rw,xattr
41 22 0:41 / /srv/v/with\040space rw - zfs pool/fs/sp rw
42 22 0:42 / /srv/v/tank/a rw - tmpfs tmpfs rw
garbage line
43 22 0:43 / /short - x
`
	if src, fs, ok := parseMountinfo(text, "/srv/v/with space"); !ok || src != "pool/fs/sp" || fs != "zfs" {
		t.Errorf("escaped: %q %q %v", src, fs, ok)
	}
	// The last mount on a point is the one in force.
	if src, fs, ok := parseMountinfo(text, "/srv/v/tank/a"); !ok || fs != "tmpfs" || src != "tmpfs" {
		t.Errorf("stacked: %q %q %v", src, fs, ok)
	}
	if _, _, ok := parseMountinfo(text, "/srv/v/tank/b"); ok {
		t.Error("a mount that is not there")
	}
	if got := unescapeMount(`a\134b\0`); got != `a\b\0` {
		t.Errorf("unescape = %q", got)
	}
}
