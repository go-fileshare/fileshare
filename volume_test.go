// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-fileshare/fileshare/internal/peercred"
	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// fakeProvisioner is a ProvisionService on a unix socket, speaking the real
// protocol to the real client: what it answers is set by each test, volumes
// live in a map, and a volume's directory is made under a root the test
// names.
type fakeProvisioner struct {
	provisionv1.UnimplementedProvisionServiceServer
	sock string
	root string

	mu      sync.Mutex
	vols    map[string]*provisionv1.Volume
	fail    map[string]error // by method name: the answer instead of doing it
	kind    provisionv1.Kind
	deleted []string
}

func startFakeProvisioner(t *testing.T, root string) *fakeProvisioner {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the provisioner and the admin tests use unix socket paths")
	}
	f := &fakeProvisioner{sock: filepath.Join(socketDir(t), "p.sock"), root: root,
		vols: map[string]*provisionv1.Volume{}, fail: map[string]error{}, kind: provisionv1.Kind_KIND_XFS}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(peercred.New()))
	provisionv1.RegisterProvisionServiceServer(gs, f)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)
	return f
}

func (f *fakeProvisioner) failing(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[method]
}

func (f *fakeProvisioner) GetCapabilities(context.Context, *provisionv1.GetCapabilitiesRequest) (*provisionv1.GetCapabilitiesResponse, error) {
	if err := f.failing("GetCapabilities"); err != nil {
		return nil, err
	}
	return &provisionv1.GetCapabilitiesResponse{MaxVolumeBytes: 1 << 30, Parents: []*provisionv1.Parent{
		{Id: "plain", Kind: provisionv1.Kind_KIND_XFS, Root: f.root, FreeBytes: 5, TotalBytes: 9}}}, nil
}

func (f *fakeProvisioner) CreateVolume(_ context.Context, r *provisionv1.CreateVolumeRequest) (*provisionv1.CreateVolumeResponse, error) {
	if err := f.failing("CreateVolume"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.GetParent() + "/" + r.GetName()
	if v, ok := f.vols[key]; ok {
		return &provisionv1.CreateVolumeResponse{Volume: v}, nil
	}
	path := filepath.Join(f.root, r.GetName())
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	v := &provisionv1.Volume{Parent: r.GetParent(), Name: r.GetName(), Kind: f.kind, Path: path,
		QuotaBytes: r.GetQuotaBytes(), Created: timestamppb.Now()}
	f.vols[key] = v
	return &provisionv1.CreateVolumeResponse{Volume: v, Created: true}, nil
}

func (f *fakeProvisioner) ResizeVolume(_ context.Context, r *provisionv1.ResizeVolumeRequest) (*provisionv1.ResizeVolumeResponse, error) {
	if err := f.failing("ResizeVolume"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vols[r.GetParent()+"/"+r.GetName()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such volume")
	}
	v.QuotaBytes = r.GetQuotaBytes()
	return &provisionv1.ResizeVolumeResponse{Volume: v}, nil
}

func (f *fakeProvisioner) SnapshotVolume(_ context.Context, r *provisionv1.SnapshotVolumeRequest) (*provisionv1.SnapshotVolumeResponse, error) {
	if err := f.failing("SnapshotVolume"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vols[r.GetParent()+"/"+r.GetName()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such volume")
	}
	v.Snapshots = append(v.Snapshots, r.GetSnapshot())
	return &provisionv1.SnapshotVolumeResponse{Volume: v, Created: true}, nil
}

func (f *fakeProvisioner) DeleteVolume(_ context.Context, r *provisionv1.DeleteVolumeRequest) (*provisionv1.DeleteVolumeResponse, error) {
	if err := f.failing("DeleteVolume"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.GetParent() + "/" + r.GetName()
	if _, ok := f.vols[key]; !ok {
		return &provisionv1.DeleteVolumeResponse{}, nil
	}
	delete(f.vols, key)
	f.deleted = append(f.deleted, key)
	return &provisionv1.DeleteVolumeResponse{Deleted: true}, nil
}

func (f *fakeProvisioner) GetVolume(_ context.Context, r *provisionv1.GetVolumeRequest) (*provisionv1.GetVolumeResponse, error) {
	if err := f.failing("GetVolume"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vols[r.GetParent()+"/"+r.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "there is no volume %s/%s", r.GetParent(), r.GetName())
	}
	return &provisionv1.GetVolumeResponse{Volume: v}, nil
}

func (f *fakeProvisioner) ListVolumes(context.Context, *provisionv1.ListVolumesRequest) (*provisionv1.ListVolumesResponse, error) {
	if err := f.failing("ListVolumes"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out provisionv1.ListVolumesResponse
	for _, v := range f.vols {
		out.Volumes = append(out.Volumes, v)
	}
	return &out, nil
}

// fakeKernel answers the questions checkVolume asks the kernel, as a
// correctly made volume of the fake's kind would; a test then breaks one.
type fakeKernel struct {
	exempt  string
	magic   int64
	mounted bool
	ino     uint64
	project uint32
	inherit bool
}

func goodKernel(kind string) *fakeKernel {
	k := &fakeKernel{mounted: true, ino: btrfsSubvolRoot, project: 100000, inherit: true}
	k.magic = map[string]int64{kindZFS: zfsSuperMagic, kindBtrfs: btrfsSuperMagic, kindXFS: xfsSuperMagic, kindExt4: ext4SuperMagic}[kind]
	return k
}

// install makes the checks ask k, for the rest of the test.
func (k *fakeKernel) install(t *testing.T, volumesRoot string) {
	t.Helper()
	q, m, d, p := quotaExempt, fsMagic, devIno, projectOf
	t.Cleanup(func() { quotaExempt, fsMagic, devIno, projectOf = q, m, d, p })
	quotaExempt = func() string { return k.exempt }
	fsMagic = func(string) (int64, error) { return k.magic, nil }
	devIno = func(path string) (uint64, uint64, bool, error) {
		fi, err := os.Stat(path)
		if err != nil {
			return 0, 0, false, err
		}
		dev := uint64(1)
		if k.mounted && filepath.Dir(path) != filepath.Clean(path) && strings.HasPrefix(path, volumesRoot+string(filepath.Separator)) {
			dev = 2
		}
		return dev, k.ino, fi.IsDir(), nil
	}
	projectOf = func(string) (uint32, bool, error) { return k.project, k.inherit, nil }
}

// volumeWorld is a managed server with a provisioner.
type volumeWorld struct {
	*managed
	prov   *fakeProvisioner
	kernel *fakeKernel
	dir    string
}

func volumeAdmin(prov *fakeProvisioner) string {
	return fmt.Sprintf("  provisioner     = \"unix://%s\"\n  provisioner_uid = %d\n", prov.sock, os.Getuid())
}

func startVolumes(t *testing.T) *volumeWorld {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real // macOS: /var is /private/var
	}
	volumes := filepath.Join(dir, "roots", "volumes")
	prov := startFakeProvisioner(t, volumes)
	k := goodKernel(kindXFS)
	k.install(t, volumes)
	m := startManagedAdmin(t, dir, "", volumeAdmin(prov))
	return &volumeWorld{managed: m, prov: prov, kernel: k, dir: dir}
}

// restart stops the server and starts another on the same state.
func (w *volumeWorld) restart(t *testing.T) {
	t.Helper()
	w.stop()
	w.stop = nil
	w.managed = startManagedAdmin(t, w.dir, "", volumeAdmin(w.prov))
}

func volumeSource(parent, name string) *adminv1.CreateShareRequest_Volume {
	return &adminv1.CreateShareRequest_Volume{Volume: &adminv1.VolumeRef{Parent: parent, Name: name}}
}

func aliceWrites() []*adminv1.Grant {
	return []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_WRITE)}
}

func TestVolumeCallsWithoutAProvisioner(t *testing.T) {
	m := startManaged(t, t.TempDir(), "")
	ctx := context.Background()
	calls := map[string]error{}
	_, calls["ListParents"] = m.client.ListParents(ctx, &adminv1.ListParentsRequest{})
	_, calls["CreateVolume"] = m.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "p", Name: "v", QuotaBytes: 1})
	_, calls["ResizeVolume"] = m.client.ResizeVolume(ctx, &adminv1.ResizeVolumeRequest{Parent: "p", Name: "v", QuotaBytes: 1})
	_, calls["SnapshotVolume"] = m.client.SnapshotVolume(ctx, &adminv1.SnapshotVolumeRequest{Parent: "p", Name: "v", Snapshot: "s"})
	_, calls["DeleteVolume"] = m.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "p", Name: "v"})
	_, calls["GetVolume"] = m.client.GetVolume(ctx, &adminv1.GetVolumeRequest{Parent: "p", Name: "v"})
	_, calls["ListVolumes"] = m.client.ListVolumes(ctx, &adminv1.ListVolumesRequest{})
	_, calls["CreateShare"] = m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "v",
		Source: volumeSource("p", "v"), Grants: aliceWrites()})
	for name, err := range calls {
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "provisioner") {
			t.Errorf("%s with no provisioner: %v", name, err)
		}
	}
}

// Each call reaches the provisioner, and its code comes back as it was given
// -- except a refusal of this server's uid, which is the deployment's to fix.
func TestVolumeCallsAreRelayed(t *testing.T) {
	w := startVolumes(t)
	ctx := context.Background()

	parents, err := w.client.ListParents(ctx, &adminv1.ListParentsRequest{})
	if err != nil || len(parents.GetParents()) != 1 || parents.GetParents()[0].GetKind() != adminv1.VolumeKind_VOLUME_KIND_XFS ||
		parents.GetMaxVolumeBytes() != 1<<30 || parents.GetParents()[0].GetFreeBytes() != 5 {
		t.Fatalf("ListParents: %v %v", parents, err)
	}
	c, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1 << 20})
	if err != nil || !c.GetCreated() || c.GetVolume().GetQuotaBytes() != 1<<20 || c.GetVolume().GetPath() == "" {
		t.Fatalf("CreateVolume: %v %v", c, err)
	}
	if again, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1 << 20}); err != nil || again.GetCreated() {
		t.Fatalf("CreateVolume again: %v %v", again, err)
	}
	if r, err := w.client.ResizeVolume(ctx, &adminv1.ResizeVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 2 << 20}); err != nil ||
		r.GetVolume().GetQuotaBytes() != 2<<20 {
		t.Fatalf("ResizeVolume: %v %v", r, err)
	}
	if s, err := w.client.SnapshotVolume(ctx, &adminv1.SnapshotVolumeRequest{Parent: "plain", Name: "home", Snapshot: "monday"}); err != nil ||
		len(s.GetVolume().GetSnapshots()) != 1 {
		t.Fatalf("SnapshotVolume: %v %v", s, err)
	}
	if g, err := w.client.GetVolume(ctx, &adminv1.GetVolumeRequest{Parent: "plain", Name: "home"}); err != nil || g.GetVolume().GetName() != "home" {
		t.Fatalf("GetVolume: %v %v", g, err)
	}
	if l, err := w.client.ListVolumes(ctx, &adminv1.ListVolumesRequest{}); err != nil || len(l.GetVolumes()) != 1 {
		t.Fatalf("ListVolumes: %v %v", l, err)
	}
	if !strings.Contains(w.out.String(), "created volume plain/home of 1048576 bytes") {
		t.Errorf("the creation is not audited:\n%s", w.out)
	}

	// Refused here, before the provisioner is asked.
	_, err = w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "../etc", QuotaBytes: 1})
	wantCode(t, err, codes.InvalidArgument)
	_, err = w.client.SnapshotVolume(ctx, &adminv1.SnapshotVolumeRequest{Parent: "plain", Name: "home", Snapshot: "Bad Name"})
	wantCode(t, err, codes.InvalidArgument)

	for _, c := range []struct {
		method string
		code   codes.Code
		want   codes.Code
		call   func() error
	}{
		{"CreateVolume", codes.AlreadyExists, codes.AlreadyExists, func() error {
			_, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "x", QuotaBytes: 1})
			return err
		}},
		{"CreateVolume", codes.ResourceExhausted, codes.ResourceExhausted, func() error {
			_, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "x", QuotaBytes: 1})
			return err
		}},
		{"CreateVolume", codes.OutOfRange, codes.OutOfRange, func() error {
			_, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "x", QuotaBytes: 1})
			return err
		}},
		{"CreateVolume", codes.InvalidArgument, codes.InvalidArgument, func() error {
			_, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "x", QuotaBytes: 0})
			return err
		}},
		{"ResizeVolume", codes.FailedPrecondition, codes.FailedPrecondition, func() error {
			_, err := w.client.ResizeVolume(ctx, &adminv1.ResizeVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1})
			return err
		}},
		{"SnapshotVolume", codes.Unimplemented, codes.Unimplemented, func() error {
			_, err := w.client.SnapshotVolume(ctx, &adminv1.SnapshotVolumeRequest{Parent: "plain", Name: "home", Snapshot: "s"})
			return err
		}},
		{"GetVolume", codes.NotFound, codes.NotFound, func() error {
			_, err := w.client.GetVolume(ctx, &adminv1.GetVolumeRequest{Parent: "plain", Name: "home"})
			return err
		}},
		{"ListVolumes", codes.PermissionDenied, codes.FailedPrecondition, func() error {
			_, err := w.client.ListVolumes(ctx, &adminv1.ListVolumesRequest{})
			return err
		}},
		{"GetCapabilities", codes.Unavailable, codes.Unavailable, func() error {
			_, err := w.client.ListParents(ctx, &adminv1.ListParentsRequest{})
			return err
		}},
		{"DeleteVolume", codes.FailedPrecondition, codes.FailedPrecondition, func() error {
			_, err := w.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "plain", Name: "home"})
			return err
		}},
	} {
		w.prov.mu.Lock()
		w.prov.fail = map[string]error{c.method: status.Error(c.code, "the fake says "+c.code.String())}
		w.prov.mu.Unlock()
		err := c.call()
		if status.Code(err) != c.want || !strings.Contains(err.Error(), "the fake says") {
			t.Errorf("%s answering %v: the admin API said %v", c.method, c.code, err)
		}
	}
	w.prov.mu.Lock()
	w.prov.fail = map[string]error{}
	w.prov.mu.Unlock()
	if !strings.Contains(w.out.String(), "refused, nothing changed -- would have created volume plain/x") {
		t.Errorf("a refused creation is not audited:\n%s", w.out)
	}
}

// A provisioner running as another uid than provisioner_uid is not spoken to.
func TestTheProvisionersUIDIsChecked(t *testing.T) {
	dir := t.TempDir()
	prov := startFakeProvisioner(t, filepath.Join(dir, "roots", "v"))
	m := startManagedAdmin(t, dir, "", fmt.Sprintf("  provisioner = \"unix://%s\"\n  provisioner_uid = %d\n", prov.sock, os.Getuid()+1))
	_, err := m.client.ListParents(context.Background(), &adminv1.ListParentsRequest{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "runs as uid") {
		t.Fatalf("a provisioner of another uid: %v", err)
	}
}

// The whole life of a share made from a volume.
func TestAShareFromAVolume(t *testing.T) {
	w := startVolumes(t)
	ctx := context.Background()
	if _, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	created, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "home",
		Source: volumeSource("plain", "home"), Grants: aliceWrites()})
	if err != nil {
		t.Fatal(err)
	}
	sh := created.GetShare()
	if sh.GetVolume().GetName() != "home" || sh.GetUnavailable() != "" || !sh.GetEnabled() || sh.GetFilesystem() != "directory" {
		t.Fatalf("created: %v", sh)
	}
	if code := w.put("alice", "hunter2", "/home/a.txt", "on a volume"); code != http.StatusCreated {
		t.Fatalf("alice writes: %d", code)
	}
	if b, err := os.ReadFile(filepath.Join(w.prov.root, "home", "a.txt")); err != nil || string(b) != "on a volume" {
		t.Fatalf("on the volume: %q %v", b, err)
	}
	// Kept by name, not only by path.
	var st stateFile
	data, _ := os.ReadFile(w.state)
	if err := json.Unmarshal(data, &st); err != nil || len(st.Shares) != 1 || st.Shares[0].Volume == nil ||
		*st.Shares[0].Volume != (volumeRef{"plain", "home"}) {
		t.Fatalf("the state file: %s", data)
	}

	vols, err := w.client.ListVolumes(ctx, &adminv1.ListVolumesRequest{})
	if err != nil || len(vols.GetVolumes()) != 1 || strings.Join(vols.GetVolumes()[0].GetShares(), ",") != "home" {
		t.Fatalf("ListVolumes does not say who uses it: %v %v", vols, err)
	}
	// A second share from the same volume is the same source.
	_, err = w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "again",
		Source: volumeSource("plain", "home"), Grants: aliceWrites()})
	wantCode(t, err, codes.FailedPrecondition)

	_, err = w.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "plain", Name: "home", DestroyData: true})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "used by home") {
		t.Errorf("the refusal does not name the share: %v", err)
	}
	// UpdateShare has no source to change; DeleteShare leaves the volume.
	if _, err := w.client.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: "home"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.client.GetVolume(ctx, &adminv1.GetVolumeRequest{Parent: "plain", Name: "home"}); err != nil {
		t.Fatalf("DeleteShare took the volume with it: %v", err)
	}
	if code, _ := w.get("alice", "hunter2", "/home/a.txt"); code != http.StatusNotFound {
		t.Fatalf("after DeleteShare: %d", code)
	}
	if d, err := w.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "plain", Name: "home", DestroyData: true}); err != nil || !d.GetDeleted() {
		t.Fatalf("DeleteVolume once unused: %v %v", d, err)
	}
	if d, err := w.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "plain", Name: "home"}); err != nil || d.GetDeleted() {
		t.Fatalf("DeleteVolume of nothing: %v %v", d, err)
	}
}

// A share of the configuration files whose directory lies inside a volume
// uses it as surely as one made from it.
func TestADirectoryInsideAVolumeUsesIt(t *testing.T) {
	w := startVolumes(t)
	ctx := context.Background()
	v, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(v.GetVolume().GetPath(), "inner")
	os.MkdirAll(inner, 0o755)
	if _, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "inner",
		Source: &adminv1.CreateShareRequest_Directory{Directory: inner}, Grants: aliceWrites()}); err != nil {
		t.Fatal(err)
	}
	_, err = w.client.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: "plain", Name: "home", DestroyData: true})
	wantCode(t, err, codes.FailedPrecondition)
	if g, err := w.client.GetVolume(ctx, &adminv1.GetVolumeRequest{Parent: "plain", Name: "home"}); err != nil ||
		strings.Join(g.GetVolume().GetShares(), ",") != "inner" {
		t.Fatalf("GetVolume: %v %v", g, err)
	}
}

// Every check made before a volume is served refuses what it is for.
func TestAVolumeThatFailsACheckIsNotServed(t *testing.T) {
	for _, c := range []struct {
		name   string
		kind   provisionv1.Kind
		break_ func(w *volumeWorld, k *fakeKernel)
		code   codes.Code
		want   string
	}{
		{"root or CAP_SYS_RESOURCE", provisionv1.Kind_KIND_EXT4, func(_ *volumeWorld, k *fakeKernel) {
			k.exempt = "holds CAP_SYS_RESOURCE in its effective set"
		}, codes.FailedPrecondition, "CAP_SYS_RESOURCE"},
		{"wrong filesystem", provisionv1.Kind_KIND_BTRFS, func(_ *volumeWorld, k *fakeKernel) { k.magic = ext4SuperMagic },
			codes.FailedPrecondition, "not btrfs"},
		{"zfs not mounted", provisionv1.Kind_KIND_ZFS, func(_ *volumeWorld, k *fakeKernel) { k.mounted = false },
			codes.FailedPrecondition, "not mounted"},
		{"btrfs not a subvolume", provisionv1.Kind_KIND_BTRFS, func(_ *volumeWorld, k *fakeKernel) { k.ino = 4242 },
			codes.FailedPrecondition, "not the root of a btrfs subvolume"},
		{"xfs with no project", provisionv1.Kind_KIND_XFS, func(_ *volumeWorld, k *fakeKernel) { k.project = 0 },
			codes.FailedPrecondition, "project id 0"},
		{"ext4 not inherited", provisionv1.Kind_KIND_EXT4, func(_ *volumeWorld, k *fakeKernel) { k.inherit = false },
			codes.FailedPrecondition, "inherited: false"},
		{"not a directory", provisionv1.Kind_KIND_XFS, func(w *volumeWorld, _ *fakeKernel) {
			p := filepath.Join(w.prov.root, "v")
			os.Remove(p)
			os.WriteFile(p, nil, 0o600)
		}, codes.FailedPrecondition, "not a directory"},
		{"outside the source roots", provisionv1.Kind_KIND_XFS, func(w *volumeWorld, _ *fakeKernel) {
			out := filepath.Join(w.dir, "elsewhere")
			os.MkdirAll(out, 0o755)
			w.prov.mu.Lock()
			w.prov.vols["plain/v"].Path = out
			w.prov.mu.Unlock()
		}, codes.FailedPrecondition, "not under any of the source roots"},
		{"a path that is not clean", provisionv1.Kind_KIND_XFS, func(w *volumeWorld, _ *fakeKernel) {
			w.prov.mu.Lock()
			w.prov.vols["plain/v"].Path = w.prov.root + "/../volumes/v"
			w.prov.mu.Unlock()
		}, codes.FailedPrecondition, "not a clean absolute path"},
		{"an unknown kind", provisionv1.Kind_KIND_UNSPECIFIED, func(*volumeWorld, *fakeKernel) {},
			codes.FailedPrecondition, "does not know"},
		{"no such volume", provisionv1.Kind_KIND_XFS, func(w *volumeWorld, _ *fakeKernel) {
			w.prov.mu.Lock()
			delete(w.prov.vols, "plain/v")
			w.prov.mu.Unlock()
		}, codes.NotFound, "does not exist"},
		{"a provisioner that does not answer", provisionv1.Kind_KIND_XFS, func(w *volumeWorld, _ *fakeKernel) {
			w.prov.mu.Lock()
			w.prov.fail["GetVolume"] = status.Error(codes.Unavailable, "down")
			w.prov.mu.Unlock()
		}, codes.Unavailable, "did not answer"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := startVolumes(t)
			ctx := context.Background()
			w.prov.kind = c.kind
			*w.kernel = *goodKernel(kindName(c.kind))
			if _, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "v", QuotaBytes: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			c.break_(w, w.kernel)
			_, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "v",
				Source: volumeSource("plain", "v"), Grants: aliceWrites()})
			if status.Code(err) != c.code || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CreateShare: %v, want %v saying %q", err, c.code, c.want)
			}
			if l, _ := w.client.ListShares(ctx, &adminv1.ListSharesRequest{}); len(l.GetShares()) != 0 {
				t.Fatalf("a refused share exists: %v", l)
			}
		})
	}
}

// The control for the table above: each kind, made right, is served.
func TestEachKindMadeRightIsServed(t *testing.T) {
	for _, kind := range []provisionv1.Kind{provisionv1.Kind_KIND_ZFS, provisionv1.Kind_KIND_BTRFS,
		provisionv1.Kind_KIND_XFS, provisionv1.Kind_KIND_EXT4} {
		t.Run(kind.String(), func(t *testing.T) {
			w := startVolumes(t)
			ctx := context.Background()
			w.prov.kind = kind
			*w.kernel = *goodKernel(kindName(kind))
			if _, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "v", QuotaBytes: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			if _, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "v",
				Source: volumeSource("plain", "v"), Grants: aliceWrites()}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// At a restart the volume is asked for again and checked again; one that
// is gone leaves its share defined and unserved, and the server serving
// the rest. EnableShare tries again.
func TestAVolumeShareAcrossARestart(t *testing.T) {
	w := startVolumes(t)
	ctx := context.Background()
	if _, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "home", QuotaBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "home",
		Source: volumeSource("plain", "home"), Grants: aliceWrites()}); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(w.roots, "plain-dir")
	os.MkdirAll(tree, 0o755)
	if _, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "other",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree}, Grants: aliceWrites()}); err != nil {
		t.Fatal(err)
	}
	w.put("alice", "hunter2", "/home/a.txt", "kept")

	w.restart(t)
	if code, body := w.get("alice", "hunter2", "/home/a.txt"); code != http.StatusOK || body != "kept" {
		t.Fatalf("after a restart: %d %q", code, body)
	}

	// The volume fails a check now: the server starts, without it.
	w.kernel.magic = ext4SuperMagic
	w.restart(t)
	if code, _ := w.get("alice", "hunter2", "/home/a.txt"); code != http.StatusNotFound {
		t.Fatalf("a volume that fails its check is served: %d", code)
	}
	if code := w.put("alice", "hunter2", "/other/b.txt", "x"); code != http.StatusCreated {
		t.Fatalf("the other share is not served: %d", code)
	}
	g, err := w.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "home"})
	if err != nil || !strings.Contains(g.GetShare().GetUnavailable(), "magic") || !g.GetShare().GetEnabled() ||
		len(g.GetShare().GetServedOver()) != 0 {
		t.Fatalf("GetShare does not say why: %v %v", g, err)
	}
	if !strings.Contains(w.out.String(), "share home is not served:") {
		t.Errorf("the start does not say so:\n%s", w.out)
	}
	// Nor does `check`.
	cfg, _, _, _ := managedConfigAdmin(t, w.dir, "", volumeAdmin(w.prov))
	if err := withState(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.unavailable) != 1 || cfg.unavailable[0].block.volume != "plain/home" {
		t.Fatalf("withState: %+v", cfg.unavailable)
	}
	out, err := execute(t, "check", "-c", filepath.Join(w.dir, "test.hcl"))
	if err != nil || !strings.Contains(out, "home: made from volume plain/home, and NOT served") ||
		!strings.Contains(out, "this process is held by their quotas") {
		t.Fatalf("check: %v\n%s", err, out)
	}
	w.kernel.exempt = "runs as root (uid 0)"
	if out, _ := execute(t, "check", "-c", filepath.Join(w.dir, "test.hcl")); !strings.Contains(out,
		"volumes: this process runs as root (uid 0), so it serves no volume share") {
		t.Fatalf("check as root:\n%s", out)
	}
	w.kernel.exempt = ""

	// EnableShare is refused while it still fails, and serves it once not.
	_, err = w.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "home"})
	wantCode(t, err, codes.FailedPrecondition)
	w.kernel.magic = xfsSuperMagic
	if _, err := w.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "home"}); err != nil {
		t.Fatal(err)
	}
	if code, body := w.get("alice", "hunter2", "/home/a.txt"); code != http.StatusOK || body != "kept" {
		t.Fatalf("after EnableShare: %d %q", code, body)
	}

	// Gone altogether, and a provisioner that does not answer: the same.
	w.prov.mu.Lock()
	w.prov.fail["GetVolume"] = status.Error(codes.NotFound, "gone")
	w.prov.mu.Unlock()
	w.restart(t)
	if g, _ := w.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "home"}); !strings.Contains(g.GetShare().GetUnavailable(), "does not exist") {
		t.Fatalf("a volume that is gone: %v", g)
	}
	// Disabled, it says disabled and not why it would not be served.
	if _, err := w.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "home"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := w.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "home"}); g.GetShare().GetEnabled() || g.GetShare().GetUnavailable() != "" {
		t.Fatalf("disabled: %v", g)
	}
	w.prov.mu.Lock()
	w.prov.fail = map[string]error{}
	w.prov.mu.Unlock()
	if _, err := w.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "home"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := w.get("alice", "hunter2", "/home/a.txt"); code != http.StatusOK {
		t.Fatalf("enabled again: %d", code)
	}
}

// allowed_uids answers only the uids it names, the health service included,
// and audits the others.
func TestAllowedUIDs(t *testing.T) {
	if !peerUIDReadable() {
		t.Skip("no peer credentials here")
	}
	other := startManagedAdmin(t, t.TempDir(), "", fmt.Sprintf("  allowed_uids = [%d]\n", os.Getuid()+1))
	_, err := other.client.GetServerInfo(context.Background(), &adminv1.GetServerInfoRequest{})
	wantCode(t, err, codes.PermissionDenied)
	_, err = other.client.ListShares(context.Background(), &adminv1.ListSharesRequest{})
	wantCode(t, err, codes.PermissionDenied)
	if !strings.Contains(other.out.String(), fmt.Sprintf("admin (uid=%d", os.Getuid())) ||
		!strings.Contains(other.out.String(), "not in the admin block's allowed_uids") {
		t.Errorf("the refusal is not audited:\n%s", other.out)
	}

	self := startManagedAdmin(t, t.TempDir(), "", fmt.Sprintf("  allowed_uids = [0, %d]\n", os.Getuid()))
	ctx := context.Background()
	if _, err := self.client.GetServerInfo(ctx, &adminv1.GetServerInfoRequest{}); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(self.roots, "t")
	os.MkdirAll(tree, 0o755)
	if _, err := self.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree}, Grants: aliceWrites()}); err != nil {
		t.Fatal(err)
	}
	// The audit line still names the caller.
	if !strings.Contains(self.out.String(), fmt.Sprintf("admin (uid=%d): created share t", os.Getuid())) {
		t.Errorf("the audit does not name the caller:\n%s", self.out)
	}
}

func TestTheAdminBlocksVolumeSettings(t *testing.T) {
	uid := uint32(5)
	for _, c := range []struct {
		a    adminBlock
		want string
	}{
		{adminBlock{Listen: "unix:///s", Provisioner: "/run/p.sock"}, "unix:///absolute"},
		{adminBlock{Listen: "unix:///s", Provisioner: "unix://run/p.sock"}, "unix:///absolute"},
		{adminBlock{Listen: "unix:///s", Provisioner: "unix:///run/../p.sock"}, "unix:///absolute"},
		{adminBlock{Listen: "unix:///s", ProvisionerUID: &uid}, "provisioner_uid without provisioner"},
		{adminBlock{Listen: "127.0.0.1:1", AllowedUIDs: []uint32{1}}, "client certificate"},
	} {
		if err := c.a.checkVolumes(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.a, err, c.want)
		}
	}
	good := adminBlock{Listen: "unix:///s", Provisioner: "unix:///run/p.sock", ProvisionerUID: &uid}
	if err := good.checkVolumes(); err != nil || good.provisionerUID() != 5 {
		t.Errorf("a good block: %v", err)
	}
	if (&adminBlock{}).provisionerUID() != 0 {
		t.Error("the provisioner's uid is not root by default")
	}
}

// The gate's second line, per call and per stream, refuses a call whose
// peer it cannot name.
func TestTheUIDGateWithoutPeer(t *testing.T) {
	var refused atomic.Uint64
	var audit strings.Builder
	g := &uidGate{allowed: []uint32{1}, audit: &audit, refused: &refused}
	ctx := context.Background()
	if _, err := g.unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, nil); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unary: %v", err)
	}
	if err := g.stream(nil, fakeStream{ctx}, &grpc.StreamServerInfo{FullMethod: "/x/Z"}, nil); status.Code(err) != codes.PermissionDenied {
		t.Errorf("stream: %v", err)
	}
	if refused.Load() != 2 || !strings.Contains(audit.String(), "the caller's uid is unknown") {
		t.Errorf("not audited: %d\n%s", refused.Load(), audit.String())
	}
}

type fakeStream struct{ ctx context.Context }

func (f fakeStream) Context() context.Context   { return f.ctx }
func (fakeStream) SetHeader(metadata.MD) error  { return nil }
func (fakeStream) SendHeader(metadata.MD) error { return nil }
func (fakeStream) SetTrailer(metadata.MD)       {}
func (fakeStream) SendMsg(any) error            { return nil }
func (fakeStream) RecvMsg(any) error            { return nil }

// A btrfs volume's size is its quota, and its free space the quota less
// what the provisioner says its qgroup uses -- not statfs, which on btrfs is
// the whole filesystem -- in the admin API and over WebDAV, and the usage is
// asked again while the share is served.
func TestABtrfsVolumeIsTheSizeOfItsQuota(t *testing.T) {
	origTTL, origSpace := volumeTTL, spaceTTL
	volumeTTL, spaceTTL = 0, 0
	t.Cleanup(func() { volumeTTL, spaceTTL = origTTL, origSpace })
	w := startVolumes(t)
	goodKernel(kindBtrfs).install(t, filepath.Join(w.dir, "roots", "volumes"))
	w.prov.mu.Lock()
	w.prov.kind = provisionv1.Kind_KIND_BTRFS
	w.prov.mu.Unlock()
	ctx := context.Background()
	const quota = 32 << 20
	if _, err := w.client.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: "plain", Name: "b", QuotaBytes: quota}); err != nil {
		t.Fatal(err)
	}
	setUsed := func(n uint64) {
		// A new message, not an edit: the old one may be on its way out.
		w.prov.mu.Lock()
		v := proto.Clone(w.prov.vols["plain/b"]).(*provisionv1.Volume)
		v.UsedBytes = n
		w.prov.vols["plain/b"] = v
		w.prov.mu.Unlock()
	}
	setUsed(1 << 20)
	created, err := w.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "bv",
		Source: volumeSource("plain", "b"), Grants: aliceWrites()})
	if err != nil {
		t.Fatal(err)
	}
	if got := created.GetShare().GetSizeBytes(); got != quota {
		t.Fatalf("the share's size is %d, want the quota %d (statfs would say the whole filesystem)", got, quota)
	}
	// The numbers the resolution brought, then the provisioner's new ones:
	// asked in the background, so the answer arrives on a later PROPFIND.
	want := func(used uint64) {
		t.Helper()
		var avail, u uint64
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if avail, u = webdavQuota(t, w.webdav, "/bv/"); u == used && avail == quota-used {
				return
			}
		}
		t.Fatalf("WebDAV: available %d, used %d; want %d, %d", avail, u, quota-used, used)
	}
	want(1 << 20)
	setUsed(20 << 20)
	want(20 << 20)
	// The provisioner gone: the last numbers known are served.
	w.prov.mu.Lock()
	w.prov.fail["GetVolume"] = status.Error(codes.Unavailable, "down")
	w.prov.mu.Unlock()
	for range 5 {
		if avail, u := webdavQuota(t, w.webdav, "/bv/"); u != 20<<20 || avail != quota-20<<20 {
			t.Fatalf("with the provisioner down: available %d, used %d", avail, u)
		}
	}
}
