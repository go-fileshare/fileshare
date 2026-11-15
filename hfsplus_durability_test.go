// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-filesystems/hfsplus"
)

func TestParseHFSPlusDurability(t *testing.T) {
	for in, want := range map[string]hfsplus.Durability{
		"": hfsplus.DurabilityStrict, "strict": hfsplus.DurabilityStrict,
		"mounted": hfsplus.DurabilityMounted, " lazy ": hfsplus.DurabilityLazy} {
		if got, err := parseHFSPlusDurability(in); err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"Strict", "fast", "none", "0"} {
		if got, err := parseHFSPlusDurability(in); err == nil {
			t.Errorf("%q accepted as %v", in, got)
		}
	}
}

// A writable HFS+ share opens its volume at the level hfsplus_durability names,
// strict when it says nothing, and the share still takes a write at each.
func TestHFSPlusDurabilityIsAppliedToAWritableImage(t *testing.T) {
	needUsers(t)
	for name, tc := range map[string]struct {
		setting string
		want    hfsplus.Durability
	}{
		"default": {"", hfsplus.DurabilityStrict},
		"strict":  {"  hfsplus_durability = \"strict\"\n", hfsplus.DurabilityStrict},
		"mounted": {"  hfsplus_durability = \"mounted\"\n", hfsplus.DurabilityMounted},
		"lazy":    {"  hfsplus_durability = \"lazy\"\n", hfsplus.DurabilityLazy},
	} {
		t.Run(name, func(t *testing.T) {
			path := hfsImage(t)
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n%s}\n", hclPath(path), tc.setting)))
			sh := r.srv.shareByName("attic")
			if sh.readOnly || sh.hfsVol == nil {
				t.Fatalf("not writable: readOnly=%v vol=%v\n%s", sh.readOnly, sh.hfsVol, r.out.String())
			}
			if got := sh.hfsVol.Durability(); got != tc.want {
				t.Errorf("durability = %v, want %v", got, tc.want)
			}
			if err := sh.fsys.WriteFile("/new.txt", []byte("x"), 0o644); err != nil {
				t.Errorf("a write at %v: %v", tc.want, err)
			}
			if b, err := sh.fsys.ReadFile("/new.txt"); err != nil || string(b) != "x" {
				t.Errorf("read back %q, %v", b, err)
			}
		})
	}
}

// An unknown value is refused when the configuration loads, naming the share.
func TestBadHFSPlusDurabilityIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "bad.hcl", onlyProtocol(t, dir, "smb",
		"share \"attic\" {\n  directory = \"/tmp\"\n  hfsplus_durability = \"fast\"\n}\n"))
	_, err := loadConfig([]string{p})
	if err == nil {
		t.Fatal("loadConfig accepted hfsplus_durability = \"fast\"")
	}
	for _, want := range []string{`"attic"`, "hfsplus_durability", "strict, mounted or lazy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// The setting is ignored, without an error, wherever the image is not opened
// for writing: the default hfsplus_writable_max of 0, and read_only.
func TestHFSPlusDurabilityIsIgnoredForAReadOnlyOpen(t *testing.T) {
	needUsers(t)
	for name, extra := range map[string]string{
		"default max": "",
		"read_only":   "  hfsplus_writable_max = \"8M\"\n  read_only = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := hfsImage(t)
			r := start(t, onlyProtocol(t, t.TempDir(), "smb",
				fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_durability = \"lazy\"\n%s}\n", hclPath(path), extra)))
			sh := r.srv.shareByName("attic")
			if !sh.readOnly || sh.hfsVol != nil {
				t.Errorf("readOnly=%v vol=%v, want a read-only share with no writable volume", sh.readOnly, sh.hfsVol)
			}
			if b, err := sh.fsys.ReadFile("/a.txt"); err != nil || string(b) != "hello" {
				t.Errorf("read: %q, %v", b, err)
			}
			if strings.Contains(r.out.String(), "hfsplus_durability") {
				t.Errorf("the ignored setting was logged:\n%s", r.out.String())
			}
		})
	}
}

// A reload that changes hfsplus_durability changes the open volume in place:
// the driver is the same one (a second writer could not take the image lock),
// and what was written before survives the change.
func TestReloadAppliesAChangedHFSPlusDurability(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	cur := r.srv.currentShares()
	if got := cur[0].hfsVol.Durability(); got != hfsplus.DurabilityStrict {
		t.Fatalf("control: durability %v, want strict", got)
	}
	if err := cur[0].fsys.WriteFile("/before.txt", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	with := func(d string) []shareBlock {
		b := cur[0].block
		b.HFSPlusDurability = d
		return []shareBlock{b}
	}
	prev := cur
	for _, d := range []struct {
		setting string
		want    hfsplus.Durability
	}{{"mounted", hfsplus.DurabilityMounted}, {"lazy", hfsplus.DurabilityLazy},
		{"mounted", hfsplus.DurabilityMounted}, {"", hfsplus.DurabilityStrict}} {
		next, err := r.srv.openShares(with(d.setting), prev)
		if err != nil {
			t.Fatalf("reload to %q: %v\n%s", d.setting, err, r.out.String())
		}
		if next[0].fsys != cur[0].fsys || next[0].hfsVol != cur[0].hfsVol || next[0].readOnly {
			t.Fatalf("reload to %q did not keep the writable driver (readOnly=%v)", d.setting, next[0].readOnly)
		}
		if got := cur[0].hfsVol.Durability(); got != d.want {
			t.Errorf("after a reload to %q durability = %v, want %v", d.setting, got, d.want)
		}
		if err := next[0].fsys.WriteFile("/after.txt", []byte(d.setting), 0o644); err != nil {
			t.Errorf("write after a reload to %q: %v", d.setting, err)
		}
		prev = next
	}
	if b, err := cur[0].fsys.ReadFile("/before.txt"); err != nil || string(b) != "1" {
		t.Errorf("a write from before the changes: %q, %v", b, err)
	}
}
