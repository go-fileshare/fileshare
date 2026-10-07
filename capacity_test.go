// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A clock the tests move by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_000_000, 0)} }

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A fake statfs: the whole filesystem, as btrfs reports it inside a volume.
type fakeStatfs struct {
	calls       atomic.Int64
	total, free atomic.Uint64
	fail        atomic.Bool
}

func (f *fakeStatfs) usage() (uint64, uint64, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return 0, 0, errors.New("statfs: no")
	}
	return f.total.Load(), f.free.Load(), nil
}

func newFakeStatfs(total, free uint64) *fakeStatfs {
	f := &fakeStatfs{}
	f.total.Store(total)
	f.free.Store(free)
	return f
}

func TestStatfsSpaceIsReusedForASecond(t *testing.T) {
	clock := newFakeClock()
	f := newFakeStatfs(100, 40)
	s := newStatfsSpace(f.usage)
	s.now = clock.now
	if total, avail := s.capacity(); total != 100 || avail != 40 {
		t.Fatalf("capacity = %d/%d, want 100/40", total, avail)
	}
	f.free.Store(10)
	s.capacity()
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("statfs asked %d times within spaceTTL, want 1", n)
	}
	clock.add(spaceTTL)
	if _, avail := s.capacity(); avail != 10 {
		t.Fatalf("after spaceTTL: avail %d, want 10", avail)
	}
	// A clock that went backwards asks again rather than trusting an age.
	clock.add(-time.Hour)
	f.free.Store(5)
	if _, avail := s.capacity(); avail != 5 {
		t.Fatalf("after the clock went back: avail %d, want 5", avail)
	}
	clock.add(time.Hour + spaceTTL)
	f.fail.Store(true)
	if total, avail := s.capacity(); total != 0 || avail != 0 {
		t.Fatalf("statfs failing: %d/%d, want 0/0 (unknown)", total, avail)
	}
}

// A provisioner, faked: what GetVolume answers, and a gate a test can hold
// shut to show that nobody waits for it.
type fakeAsk struct {
	calls       atomic.Int64
	quota, used atomic.Uint64
	fail        atomic.Bool
	gate        chan struct{}
}

func (f *fakeAsk) ask(ctx context.Context, _ volumeRef) (uint64, uint64, error) {
	f.calls.Add(1)
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		}
	}
	if f.fail.Load() {
		return 0, 0, errors.New("provisioner: unavailable")
	}
	return f.quota.Load(), f.used.Load(), nil
}

func newVolume(t *testing.T, quota, used uint64, fs *fakeStatfs, a *fakeAsk, clock *fakeClock) *volumeSpace {
	t.Helper()
	st := newStatfsSpace(fs.usage)
	st.now = clock.now
	v := newVolumeSpace(&volumeResolution{ref: volumeRef{"b", "v"}, kind: kindBtrfs, quota: quota, used: used}, st, a.ask)
	v.now = clock.now
	v.at = clock.now()
	return v
}

// waitAsked moves the clock past volumeTTL, asks for the capacity (which
// starts a refresh), and waits for the refresh to end.
func waitAsked(t *testing.T, v *volumeSpace, clock *fakeClock) {
	t.Helper()
	clock.add(volumeTTL)
	v.mu.Lock()
	ch := v.asked
	v.mu.Unlock()
	v.capacity()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh never ended")
	}
}

func TestVolumeSpaceIsTheQuotaNotTheFilesystem(t *testing.T) {
	const fsTotal, fsFree = 64 << 30, 60 << 30 // what btrfs's statfs says
	clock := newFakeClock()
	fs := newFakeStatfs(fsTotal, fsFree)
	a := &fakeAsk{}
	a.quota.Store(32 << 20)
	a.used.Store(8 << 20)
	v := newVolume(t, 32<<20, 1<<20, fs, a, clock)

	// From the resolution, before anybody was asked again.
	if total, avail := v.capacity(); total != 32<<20 || avail != 31<<20 {
		t.Fatalf("capacity = %d/%d, want the quota and quota-used (%d/%d)", total, avail, 32<<20, 31<<20)
	}
	if n := a.calls.Load(); n != 0 {
		t.Fatalf("the provisioner was asked %d times within volumeTTL of the resolution", n)
	}
	waitAsked(t, v, clock)
	if total, avail := v.capacity(); total != 32<<20 || avail != 24<<20 {
		t.Fatalf("after a refresh: %d/%d, want %d/%d", total, avail, 32<<20, 24<<20)
	}
	// Over the quota -- btrfs lets a write that started below it finish --
	// is nothing available, not a wrapped number.
	a.used.Store(40 << 20)
	waitAsked(t, v, clock)
	if total, avail := v.capacity(); total != 32<<20 || avail != 0 {
		t.Fatalf("over quota: %d/%d, want %d/0", total, avail, 32<<20)
	}
	// The filesystem holding every volume has less room than the quota
	// would leave: its free space is what is available.
	a.used.Store(0)
	fs.free.Store(4 << 20)
	clock.add(spaceTTL)
	waitAsked(t, v, clock)
	if _, avail := v.capacity(); avail != 4<<20 {
		t.Fatalf("a full parent filesystem: avail %d, want %d", avail, 4<<20)
	}
	// statfs failing does not lose the quota.
	fs.fail.Store(true)
	clock.add(spaceTTL)
	if total, avail := v.capacity(); total != 32<<20 || avail != 32<<20 {
		t.Fatalf("statfs failing: %d/%d, want the quota's %d/%d", total, avail, 32<<20, 32<<20)
	}
	// A resize reaches the next answer.
	fs.fail.Store(false)
	a.quota.Store(64 << 20)
	a.used.Store(16 << 20)
	fs.free.Store(fsFree)
	clock.add(spaceTTL)
	waitAsked(t, v, clock)
	if total, avail := v.capacity(); total != 64<<20 || avail != 48<<20 {
		t.Fatalf("after a resize: %d/%d, want %d/%d", total, avail, 64<<20, 48<<20)
	}
}

func TestVolumeSpaceNeverWaitsForTheProvisioner(t *testing.T) {
	clock := newFakeClock()
	fs := newFakeStatfs(1<<40, 1<<39)
	a := &fakeAsk{gate: make(chan struct{})}
	a.quota.Store(32 << 20)
	a.used.Store(2 << 20)
	v := newVolume(t, 32<<20, 0, fs, a, clock)
	clock.add(volumeTTL)
	v.mu.Lock()
	ch := v.asked
	v.mu.Unlock()
	// A thousand queries while the provisioner hangs: each answers at once
	// from what is known, and only one question is asked.
	done := make(chan struct{})
	go func() {
		for range 1000 {
			if total, avail := v.capacity(); total != 32<<20 || avail != 32<<20 {
				t.Errorf("while the provisioner hangs: %d/%d", total, avail)
				break
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("capacity waited for the provisioner")
	}
	// The question is asked from a goroutine capacity starts: it may not have
	// reached the provisioner yet when the queries return. Wait for it, then
	// check that it is the only one.
	for deadline := time.Now().Add(10 * time.Second); a.calls.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("no question was ever asked")
		}
		time.Sleep(time.Millisecond)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("%d questions in flight at once, want 1", n)
	}
	close(a.gate)
	<-ch
	if _, avail := v.capacity(); avail != 30<<20 {
		t.Fatalf("after the answer: avail %d, want %d", avail, 30<<20)
	}
}

func TestVolumeSpaceBacksOffAFailingProvisioner(t *testing.T) {
	clock := newFakeClock()
	fs := newFakeStatfs(1<<40, 1<<39)
	a := &fakeAsk{}
	a.fail.Store(true)
	v := newVolume(t, 32<<20, 4<<20, fs, a, clock)
	waitAsked(t, v, clock)
	// Failed: the last numbers stay, and no new question before volumeTTL.
	for range 100 {
		if total, avail := v.capacity(); total != 32<<20 || avail != 28<<20 {
			t.Fatalf("after a failure: %d/%d, want the last known %d/%d", total, avail, 32<<20, 28<<20)
		}
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("a failing provisioner was asked %d times within volumeTTL, want 1", n)
	}
	// A clock that went back asks again.
	clock.add(-time.Hour)
	v.mu.Lock()
	ch := v.asked
	v.mu.Unlock()
	a.fail.Store(false)
	a.quota.Store(32 << 20)
	a.used.Store(30 << 20)
	v.capacity()
	<-ch
	if _, avail := v.capacity(); avail != 2<<20 {
		t.Fatalf("after the clock went back: avail %d, want %d", avail, 2<<20)
	}
}

func TestVolumeSpaceWithNoQuotaIsStatfs(t *testing.T) {
	clock := newFakeClock()
	fs := newFakeStatfs(100, 40)
	a := &fakeAsk{} // answers a zero quota, which never replaces one
	v := newVolume(t, 0, 0, fs, a, clock)
	if total, avail := v.capacity(); total != 100 || avail != 40 {
		t.Fatalf("no quota: %d/%d, want statfs's 100/40", total, avail)
	}
	waitAsked(t, v, clock)
	fs.fail.Store(true)
	clock.add(spaceTTL)
	if total, avail := v.capacity(); total != 0 || avail != 0 {
		t.Fatalf("no quota, statfs failing: %d/%d, want 0/0", total, avail)
	}
}

func TestCapacityOfPicksTheSource(t *testing.T) {
	s := &server{}
	fs := newFakeStatfs(64<<30, 60<<30)
	for _, tc := range []struct {
		name        string
		vol         *volumeResolution
		size, total uint64
	}{
		{"a directory", nil, 64 << 30, 64 << 30},
		{"a btrfs volume", &volumeResolution{kind: kindBtrfs, quota: 32 << 20, used: 1 << 20}, 32 << 20, 32 << 20},
		{"a zfs volume: statfs says the refquota", &volumeResolution{kind: kindZFS, quota: 32 << 20}, 64 << 30, 64 << 30},
		{"an xfs volume: statfs says the project quota", &volumeResolution{kind: kindXFS, quota: 32 << 20}, 64 << 30, 64 << 30},
		{"a btrfs volume of no known quota", &volumeResolution{kind: kindBtrfs}, 64 << 30, 64 << 30},
	} {
		capacity, size := s.capacityOf(shareBlock{vol: tc.vol}, fs.usage)
		total, _ := capacity()
		if size != tc.size || total != tc.total {
			t.Errorf("%s: size %d, total %d; want %d, %d", tc.name, size, total, tc.size, tc.total)
		}
	}
}
