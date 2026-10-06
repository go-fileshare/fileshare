// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-fsctl/btrfs"
	"github.com/go-fsctl/projquota"
	"github.com/go-fsctl/zfs"
)

// The fakes stand in for the kernel and nothing else: the directories they
// are asked about are real ones under the test's temporary directory, so
// ensureDir, isEmpty and removeTree run for real. What they fake is what
// needs root -- datasets, subvolumes, project ids, mounts, chown.

type owner struct {
	uid, gid int
	mode     os.FileMode
}

type fakeSys struct {
	mu      sync.Mutex
	owners  map[string]owner
	mounts  map[string][2]string // dir -> {source, fstype}
	types   map[string]int64
	free    uint64
	total   uint64
	errMnt  error
	errOwn  error
	noSpace bool
}

func newFakeSys() *fakeSys {
	return &fakeSys{owners: map[string]owner{}, mounts: map[string][2]string{}, types: map[string]int64{},
		free: 1 << 40, total: 2 << 40}
}

func (f *fakeSys) setOwner(path string, uid, gid int, mode os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOwn != nil {
		return f.errOwn
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("setOwner: %s is not a directory", path)
	}
	f.owners[path] = owner{uid, gid, mode}
	return nil
}

func (f *fakeSys) mountZFS(dataset, dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errMnt != nil {
		return f.errMnt
	}
	f.mounts[dir] = [2]string{dataset, "zfs"}
	return nil
}

func (f *fakeSys) unmount(dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.mounts[dir]; !ok {
		return syscall.EINVAL
	}
	delete(f.mounts, dir)
	return nil
}

func (f *fakeSys) mountedAt(dir string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.mounts[dir]
	return m[0], m[1], ok, nil
}

func (f *fakeSys) fsType(path string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.types[path]; ok {
		return t, nil
	}
	return 0, syscall.ENOENT
}

func (f *fakeSys) space(string) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noSpace {
		return 0, 0, errors.New("statfs: no")
	}
	return f.free, f.total, nil
}

// fakeZFS is a pool as the ioctls see it: datasets with properties, local
// user properties that children inherit, and snapshots.
type fakeZFS struct {
	mu        sync.Mutex
	ds        map[string]*fakeDataset
	errCreate error
	errResize error
	errSnap   error
	created   []zfs.Nvlist
}

type fakeDataset struct {
	props map[string]zfs.Value
	user  map[string]string // set LOCALLY
	recvd map[string]string // received in a stream
	snaps []string
}

func newFakeZFS(datasets ...string) *fakeZFS {
	z := &fakeZFS{ds: map[string]*fakeDataset{}}
	for _, d := range datasets {
		z.add(d)
	}
	return z
}

func (z *fakeZFS) add(name string) *fakeDataset {
	d := &fakeDataset{props: map[string]zfs.Value{"available": uint64(1 << 40), "used": uint64(1 << 30),
		"referenced": uint64(0), "refquota": uint64(0)}, user: map[string]string{}, recvd: map[string]string{}}
	z.ds[name] = d
	return d
}

func enoent(what string) error { return fmt.Errorf("%s: %w", what, syscall.ENOENT) }

func (z *fakeZFS) CreateFilesystemWithProps(name string, props zfs.Nvlist) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.errCreate != nil {
		return z.errCreate
	}
	parent := name[:strings.LastIndexByte(name, '/')]
	if z.ds[parent] == nil {
		return enoent(parent)
	}
	if z.ds[name] != nil {
		return fmt.Errorf("%s: %w", name, syscall.EEXIST)
	}
	z.created = append(z.created, props)
	d := z.add(name)
	for k, v := range props {
		if strings.Contains(k, ":") {
			d.user[k] = v.(string)
		} else {
			d.props[k] = v
		}
	}
	return nil
}

func (z *fakeZFS) UserProp(fs, prop string) (string, string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	d := z.ds[fs]
	if d == nil {
		return "", "", enoent(fs)
	}
	if v, ok := d.recvd[prop]; ok {
		return v, zfs.PropSourceReceived, nil
	}
	// Inherited: the nearest ancestor that sets it LOCALLY is the source.
	for n := fs; ; {
		if v, ok := z.ds[n].user[prop]; ok {
			return v, n, nil
		}
		i := strings.LastIndexByte(n, '/')
		if i < 0 {
			return "", "", fmt.Errorf("%s of %q: %w", prop, fs, zfs.ErrPropNotSet)
		}
		n = n[:i]
		if z.ds[n] == nil {
			return "", "", fmt.Errorf("%s of %q: %w", prop, fs, zfs.ErrPropNotSet)
		}
	}
}

func (z *fakeZFS) GetProps(name string) (map[string]zfs.Value, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	d := z.ds[name]
	if d == nil {
		return nil, enoent(name)
	}
	out := map[string]zfs.Value{}
	for k, v := range d.props {
		out[k] = v
	}
	return out, nil
}

func (z *fakeZFS) SetRefquota(fs string, bytes uint64) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.errResize != nil {
		return z.errResize
	}
	d := z.ds[fs]
	if d == nil {
		return enoent(fs)
	}
	d.props["refquota"] = bytes
	return nil
}

func (z *fakeZFS) Snapshot(pool string, names []string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.errSnap != nil {
		return z.errSnap
	}
	for _, n := range names {
		ds, snap, _ := strings.Cut(n, "@")
		if !strings.HasPrefix(ds, pool+"/") {
			return fmt.Errorf("snapshot %s is not in pool %s", n, pool)
		}
		d := z.ds[ds]
		if d == nil {
			return enoent(ds)
		}
		d.snaps = append(d.snaps, snap)
	}
	return nil
}

func (z *fakeZFS) ListSnapshotsZCP(fs string) ([]string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	d := z.ds[fs]
	if d == nil {
		return nil, enoent(fs)
	}
	var out []string
	for _, s := range d.snaps {
		out = append(out, fs+"@"+s)
	}
	// A snapshot of another dataset the channel program would not return
	// either; the backend must not trust the prefix blindly.
	return append(out, "other/ds@x"), nil
}

func (z *fakeZFS) Destroy(name string, _ bool) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	ds, snap, isSnap := strings.Cut(name, "@")
	d := z.ds[ds]
	if d == nil {
		return enoent(name)
	}
	if isSnap {
		i := slices.Index(d.snaps, snap)
		if i < 0 {
			return enoent(name)
		}
		d.snaps = slices.Delete(d.snaps, i, i+1)
		return nil
	}
	if len(d.snaps) > 0 {
		return fmt.Errorf("%s has snapshots: %w", name, syscall.EEXIST)
	}
	delete(z.ds, ds)
	return nil
}

// fakeBtrfs is subvolumes as real directories, with ids and uuids.
type fakeBtrfs struct {
	mu        sync.Mutex
	quotasOn  bool
	enabled   bool
	subvols   map[string]fakeSubvol
	next      uint64
	limits    map[uint64]uint64
	rfer      map[uint64]uint64
	errLimit  error
	destroyed []uint64
}

type fakeSubvol struct {
	id   uint64
	uuid [16]byte
	ro   bool
}

func newFakeBtrfs() *fakeBtrfs {
	return &fakeBtrfs{quotasOn: true, subvols: map[string]fakeSubvol{}, next: 256,
		limits: map[uint64]uint64{}, rfer: map[uint64]uint64{}}
}

func (b *fakeBtrfs) newSubvol(path string, ro bool) error {
	if err := os.Mkdir(path, 0o755); err != nil {
		return err
	}
	b.next++
	var u [16]byte
	u[0], u[15] = byte(b.next), byte(b.next>>8)
	b.subvols[path] = fakeSubvol{id: b.next, uuid: u, ro: ro}
	return nil
}

func (b *fakeBtrfs) SubvolCreate(parent, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.newSubvol(filepath.Join(parent, name), false)
}

func (b *fakeBtrfs) SubvolDelete(parent, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := filepath.Join(parent, name)
	if _, ok := b.subvols[p]; !ok {
		return enoent(p)
	}
	delete(b.subvols, p)
	return os.RemoveAll(p)
}

func (b *fakeBtrfs) SubvolLimit(path string, max uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.errLimit != nil {
		return b.errLimit
	}
	s, ok := b.subvols[path]
	if !ok {
		return enoent(path)
	}
	b.limits[s.id] = max
	return nil
}

func (b *fakeBtrfs) SnapshotCreate(src, dst, name string, ro bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subvols[src]; !ok {
		return enoent(src)
	}
	return b.newSubvol(filepath.Join(dst, name), ro)
}

func (b *fakeBtrfs) subvol(path string) (uint64, [16]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.subvols[path]
	if !ok {
		return 0, [16]byte{}, errors.New("not the root of a subvolume")
	}
	return s.id, s.uuid, nil
}

func (b *fakeBtrfs) ListQgroups(string) ([]btrfs.Qgroup, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.quotasOn {
		return nil, enoent("quota tree")
	}
	var out []btrfs.Qgroup
	for _, s := range b.subvols {
		out = append(out, btrfs.Qgroup{ID: s.id, SubvolID: s.id, MaxRfer: b.limits[s.id], Rfer: b.rfer[s.id]})
	}
	return out, nil
}

func (b *fakeBtrfs) QgroupDestroy(_ string, id uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.destroyed = append(b.destroyed, id)
	return nil
}

func (b *fakeBtrfs) QuotaEnable(string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.quotasOn, b.enabled = true, true
	return nil
}

func (b *fakeBtrfs) QuotaRescanAndWait(string) error { return nil }

// fakeProj is project ids on real directories, and the limits and usage the
// quota files would hold.
type fakeProj struct {
	mu       sync.Mutex
	fs       projquota.Filesystem
	ids      map[string]uint32
	limits   map[uint32]projquota.Limits
	usage    map[uint32]uint64
	errUsage error
	errLimit error
}

func newFakeProj(fs projquota.Filesystem) *fakeProj {
	return &fakeProj{fs: fs, ids: map[string]uint32{}, limits: map[uint32]projquota.Limits{}, usage: map[uint32]uint64{}}
}

func (p *fakeProj) Detect(string) (projquota.Filesystem, error) { return p.fs, nil }

func (p *fakeProj) GetProject(path string) (uint32, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := os.Lstat(path); err != nil {
		return 0, false, err
	}
	id, ok := p.ids[path]
	return id, ok, nil
}

func (p *fakeProj) SetProjectTree(root string, id uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := os.Lstat(root); err != nil {
		return err
	}
	p.ids[root] = id
	return nil
}

func (p *fakeProj) SetLimits(_ string, id uint32, l projquota.Limits) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.errLimit != nil {
		return p.errLimit
	}
	if id == 0 {
		return projquota.ErrInvalidProject
	}
	p.limits[id] = l
	return nil
}

func (p *fakeProj) Usage(_ string, id uint32) (projquota.Quota, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.errUsage != nil {
		return projquota.Quota{}, p.errUsage
	}
	return projquota.Quota{Limits: p.limits[id], Bytes: p.usage[id]}, nil
}

// world is one test's machine: fakes, a configuration, and the directories
// the configuration names.
type world struct {
	t     *testing.T
	dir   string
	cfg   *Config
	sys   *fakeSys
	zfs   *fakeZFS
	btrfs *fakeBtrfs
	proj  *fakeProj
	log   *logBuf
	// ext4AsXFS makes the ext4 parent's filesystem say it is XFS.
	ext4AsXFS bool
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuf) logf(format string, args ...any) { fmt.Fprintf(l, format+"\n", args...) }

// shortDir is a directory whose paths fit in a unix socket's sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	base := ""
	if st, err := os.Stat("/tmp"); err == nil && st.IsDir() {
		base = "/tmp"
	}
	d, err := os.MkdirTemp(base, "pv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	// EvalSymlinks: /tmp is a link on a Mac, and the roots are compared as
	// written.
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r
	}
	return d
}

// testGID is a group this process is in, so the socket can be given to it
// without privilege.
var testGID = func() int {
	if g := os.Getgid(); g != 0 {
		return g
	}
	return 65534
}()

// newWorld makes a configuration with one parent of each kind -- zfs "tank",
// btrfs "fast", xfs "plain", ext4 "four" -- over real directories.
func newWorld(t *testing.T) *world {
	t.Helper()
	d := shortDir(t)
	w := &world{t: t, dir: d, sys: newFakeSys(), zfs: newFakeZFS("pool/fs"), btrfs: newFakeBtrfs(),
		proj: newFakeProj(projquota.XFS), log: &logBuf{}}
	for _, sub := range []string{"run", "state", "tank", "fast", "plain", "four"} {
		if err := os.Mkdir(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.sys.types[filepath.Join(d, "fast")] = magicBtrfs
	text := fmt.Sprintf(`
provisioner {
  listen     = "unix://%[1]s/run/p.sock"
  client_uid = %[2]d
  group      = "%[3]d"
  max_volume = "1T"
  state_file = "%[1]s/state/volumes.json"

  parent "tank"  {
    zfs  = "pool/fs"
    root = "%[1]s/tank"
  }
  parent "fast"  { btrfs = "%[1]s/fast" }
  parent "plain" {
    xfs         = "%[1]s/plain"
    project_ids = "100-102"
  }
  parent "four" {
    ext4        = "%[1]s/four"
    project_ids = "200-299"
  }
}
`, d, clientUID(), testGID)
	cfgPath := filepath.Join(d, "p.hcl")
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig([]string{cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	w.cfg = cfg
	return w
}

// clientUID is this process's uid, which is never 0 in a test that means
// it: a test run as root still answers as root, and client_uid 0 is refused.
func clientUID() int {
	if u := os.Getuid(); u != 0 {
		return u
	}
	return 65534
}

func (w *world) system() *system {
	return &system{sys: w.sys, zfs: func() (zfsOps, error) { return w.zfs, nil }, btrfs: w.btrfs, proj: projByRoot{w}}
}

// projByRoot gives the ext4 parent an ext4 answer from Detect and the xfs one
// an xfs answer, over one fake.
type projByRoot struct{ w *world }

func (p projByRoot) Detect(path string) (projquota.Filesystem, error) {
	if filepath.Base(path) == "four" && !p.w.ext4AsXFS {
		return projquota.Ext4, nil
	}
	return p.w.proj.Detect(path)
}
func (p projByRoot) GetProject(path string) (uint32, bool, error) { return p.w.proj.GetProject(path) }
func (p projByRoot) SetProjectTree(root string, id uint32) error {
	return p.w.proj.SetProjectTree(root, id)
}
func (p projByRoot) SetLimits(path string, id uint32, l projquota.Limits) error {
	return p.w.proj.SetLimits(path, id, l)
}
func (p projByRoot) Usage(path string, id uint32) (projquota.Quota, error) {
	return p.w.proj.Usage(path, id)
}

// service starts the parents and returns the service, closed at the end.
func (w *world) service() *service {
	w.t.Helper()
	s, err := newService(w.cfg, w.system(), w.log.logf)
	if err != nil {
		w.t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }
	w.t.Cleanup(func() { s.st.close() })
	return s
}

func (w *world) path(parts ...string) string {
	return filepath.Join(append([]string{w.dir}, parts...)...)
}

var bg = context.Background()
