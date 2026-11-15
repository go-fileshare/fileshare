// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
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
	srv, _ := runServer(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	r := &running{srv: srv, out: &safeBuffer{}}
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
		if got := cur[0].hfsVol.Durability(); got == d.want && prev[0].block.HFSPlusDurability != d.setting {
			t.Errorf("opening the list for %q already moved the volume to %v", d.setting, got)
		}
		if _, err := r.srv.swap(next); err != nil {
			t.Fatal(err)
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

// A reload that fails after the kept share was looked at says "nothing changed",
// so the kept share's volume must still be at the level it had (share.adopt: a
// change that fails leaves prev exactly as it was). Opening the list moves
// nothing; only a swap does.
func TestRefusedReloadLeavesHFSPlusDurabilityAlone(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	cur := r.srv.currentShares()
	a := cur[0].block
	a.HFSPlusDurability = "lazy"
	bad := a
	bad.Name = "missing"
	bad.Image = filepath.Join(t.TempDir(), "nope.img")
	bad.HFSPlusDurability = ""
	if _, err := r.srv.openShares([]shareBlock{a, bad}, cur); err == nil {
		t.Fatal("control: the list with a missing image was opened")
	}
	if got := cur[0].hfsVol.Durability(); got != hfsplus.DurabilityStrict {
		t.Errorf("the refused reload left the kept share's volume at %v, want strict", got)
	}
	// A list that opens but is not swapped in changes nothing either.
	if _, err := r.srv.openShares([]shareBlock{a}, cur); err != nil {
		t.Fatal(err)
	}
	if got := cur[0].hfsVol.Durability(); got != hfsplus.DurabilityStrict {
		t.Errorf("opening a list moved the volume to %v, want strict until it is swapped in", got)
	}
}

// failingVolume is a volume whose level cannot be set, as when the sync that
// settles the old level fails.
type failingVolume struct{ d hfsplus.Durability }

func (f *failingVolume) Durability() hfsplus.Durability { return f.d }
func (f *failingVolume) SetDurability(hfsplus.Durability) error {
	return errors.New("sync failed")
}

// A level that cannot be set is said in the log, naming the share and the level
// the volume stays at; the share keeps serving.
func TestFailedHFSPlusDurabilityChangeIsReported(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	cur := r.srv.currentShares()
	sh := &share{fsys: cur[0].fsys, hfsVol: &failingVolume{hfsplus.DurabilityStrict}, block: cur[0].block}
	sh.block.HFSPlusDurability = "lazy"
	r.srv.applyHFSPlusDurability([]*share{sh})
	out := r.out.String()
	for _, want := range []string{"share attic", `hfsplus_durability "lazy" was not applied`, "stays at strict", "accepts no write until it is reopened", "sync failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if err := cur[0].fsys.WriteFile("/still.txt", []byte("x"), 0o644); err != nil {
		t.Errorf("the share stopped serving: %v", err)
	}
}

// orderProbe is a volume that records, when its level is set, what the server
// was serving at that moment.
type orderProbe struct {
	srv     *server
	d       hfsplus.Durability
	shares  []*share
	genN    uint64
	ready   bool
	applied bool
}

func (p *orderProbe) Durability() hfsplus.Durability { return p.d }
func (p *orderProbe) SetDurability(d hfsplus.Durability) error {
	p.applied = true
	p.shares = p.srv.currentShares()
	p.genN = p.srv.genN // swap holds runMu: this goroutine may read it
	p.ready = p.srv.ready.Load()
	p.d = d
	return nil
}

// swap sets the level before the new list is published: when the volume's level
// is set, the server still serves the previous list, the new generation has not
// started and the server is not ready.
func TestSwapAppliesHFSPlusDurabilityBeforePublishing(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	srv, _ := runServer(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	r := &running{srv: srv, out: &safeBuffer{}}
	prev := r.srv.currentShares()
	genBefore := r.srv.generationNumber()
	probe := &orderProbe{srv: r.srv, d: hfsplus.DurabilityStrict}
	sh := &share{fsys: prev[0].fsys, hfsVol: probe, block: prev[0].block}
	sh.block.HFSPlusDurability = "lazy"
	if _, err := r.srv.swap([]*share{sh}); err != nil {
		t.Fatal(err)
	}
	if !probe.applied {
		t.Fatal("swap did not set the level")
	}
	if len(probe.shares) != 1 || probe.shares[0] != prev[0] {
		t.Errorf("the new list was already published when the level was set")
	}
	if probe.genN != genBefore {
		t.Errorf("generation %d had started when the level was set, want %d", probe.genN, genBefore)
	}
	if probe.ready {
		t.Errorf("the server was ready when the level was set")
	}
	if got := r.srv.currentShares(); len(got) != 1 || got[0] != sh {
		t.Errorf("the new list is not the one served after swap")
	}
}

// lockProbe is a volume whose SetDurability records whether the image's mutex
// was held when it ran: TryLock succeeds only if nobody held it.
type lockProbe struct {
	mu   *sync.Mutex
	d    hfsplus.Durability
	runs int
	free int // calls that found the mutex free: a defect
}

func (p *lockProbe) Durability() hfsplus.Durability { return p.d }
func (p *lockProbe) SetDurability(d hfsplus.Durability) error {
	p.runs++
	if p.mu.TryLock() {
		p.free++
		p.mu.Unlock()
	}
	p.d = d
	return nil
}

// The level is changed under the image's lock (SetDurability must not run with a
// mutator). Deterministic: the volume itself asserts the mutex is held, so
// removing the lock fails this test on every run, with or without -race.
func TestHFSPlusDurabilityChangeIsSerialisedWithWriters(t *testing.T) {
	needUsers(t)
	path := hfsImage(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb",
		fmt.Sprintf("share \"attic\" {\n  image = %q\n  hfsplus_writable_max = \"8M\"\n}\n", hclPath(path))))
	cur := r.srv.currentShares()[0]
	l, ok := cur.fsys.(interface{ lock() *sync.Mutex })
	if !ok {
		t.Fatal("the writable driver has no image lock")
	}
	probe := &lockProbe{mu: l.lock(), d: hfsplus.DurabilityStrict}
	sh := &share{fsys: cur.fsys, hfsVol: probe, block: cur.block}
	b := sh.block
	for _, s := range []string{"lazy", "mounted", "strict"} {
		b.HFSPlusDurability = s
		if err := sh.setHFSPlusDurability(b); err != nil {
			t.Errorf("set %q: %v", s, err)
		}
	}
	if probe.runs != 3 {
		t.Errorf("SetDurability ran %d times, want 3", probe.runs)
	}
	if probe.free != 0 {
		t.Errorf("SetDurability ran %d times without the image lock held", probe.free)
	}
}
