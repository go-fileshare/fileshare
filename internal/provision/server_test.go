// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/go-fileshare/fileshare/internal/provisionclient"
	pb "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// serve runs the provisioner of w on its real socket until the test ends.
func (w *world) serve() string {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, w.cfg, w.log, w.system()) }()
	sock := mustSocket(w.cfg.Listen)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if st, err := os.Stat(sock); err == nil && st.Mode().Perm() == 0o660 {
			break
		}
		select {
		case err := <-done:
			cancel()
			w.t.Fatalf("the provisioner stopped: %v\n%s", err, w.log)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			w.t.Fatalf("no socket at %s\n%s", sock, w.log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			w.t.Errorf("run: %v", err)
		}
		if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
			w.t.Errorf("the socket outlived the provisioner: %v", err)
		}
	})
	return sock
}

// dialer counts the connections a client makes: a connection the server
// closed shows as a second one.
type dialer struct{ n atomic.Int32 }

func (d *dialer) dial(ctx context.Context, addr string) (net.Conn, error) {
	d.n.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix://"))
}

func (w *world) client(sock string, d *dialer, opts ...provisionclient.Option) *provisionclient.Client {
	w.t.Helper()
	if d != nil {
		opts = append(opts, provisionclient.WithDialOption(grpc.WithContextDialer(d.dial)))
	}
	c, err := provisionclient.Dial(sock, opts...)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	return c
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestOverTheSocket(t *testing.T) {
	w := newWorld(t)
	sock := w.serve()
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v, %v", st.Mode(), err)
	}
	c := w.client(sock, nil, provisionclient.ServerUID(uint32(os.Getuid())))
	ctx := ctxT(t)
	caps, err := c.Capabilities(ctx)
	if err != nil || len(caps.GetParents()) != 4 {
		t.Fatalf("capabilities = %v, %v", caps, err)
	}
	v, created, err := c.Create(ctx, "tank", "data", 1<<20)
	if err != nil || !created || v.GetPath() != w.path("tank", "data") {
		t.Fatalf("create = %v, %v, %v", v, created, err)
	}
	if v, err := c.Resize(ctx, "tank", "data", 2<<20); err != nil || v.GetQuotaBytes() != 2<<20 {
		t.Errorf("resize = %v, %v", v, err)
	}
	if v, created, err := c.Snapshot(ctx, "tank", "data", "s"); err != nil || !created || len(v.GetSnapshots()) != 1 {
		t.Errorf("snapshot = %v, %v, %v", v, created, err)
	}
	if v, err := c.Get(ctx, "tank", "data"); err != nil || v.GetName() != "data" {
		t.Errorf("get = %v, %v", v, err)
	}
	if l, err := c.List(ctx, ""); err != nil || len(l) != 1 {
		t.Errorf("list = %v, %v", l, err)
	}
	if _, err := c.Delete(ctx, "tank", "data", false); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("delete with a snapshot = %v", err)
	}
	if ok, err := c.Delete(ctx, "tank", "data", true); err != nil || !ok {
		t.Errorf("delete = %v, %v", ok, err)
	}
	if !strings.Contains(w.log.String(), "audit: delete volume tank/data") ||
		!strings.Contains(w.log.String(), "uid ") {
		t.Errorf("the audit line does not say who:\n%s", w.log)
	}
}

// ⛔ The uid check, with the kernel's answer and no seam: the test process
// connects as itself, and the provisioner is configured to answer somebody
// else.
func TestAnotherUIDIsRefused(t *testing.T) {
	w := newWorld(t)
	w.cfg.ClientUID = int64(clientUID()) + 1
	sock := w.serve()
	c := w.client(sock, nil)
	ctx := ctxT(t)
	if _, err := c.Capabilities(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("capabilities from another uid = %v", err)
	}
	if _, _, err := c.Create(ctx, "tank", "v", 1<<20); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("create from another uid = %v", err)
	}
	if w.zfs.ds["pool/fs/v"] != nil {
		t.Fatal("a refused peer created a dataset")
	}
	if !strings.Contains(w.log.String(), "refused uid") {
		t.Errorf("the refusal was not logged:\n%s", w.log)
	}
	// And the interceptor alone, should the tap ever not run.
	g := &gate{clientUID: 1}
	if _, err := g.unary(context.Background(), nil, &grpc.UnaryServerInfo{}, nil); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unary with no peer = %v", err)
	}
	if _, err := g.tap(context.Background(), nil); status.Code(err) != codes.PermissionDenied {
		t.Errorf("tap with no peer = %v", err)
	}
}

// A client refuses a socket where the wrong uid answers.
func TestTheClientCanRequireTheProvisionersUID(t *testing.T) {
	w := newWorld(t)
	sock := w.serve()
	c := w.client(sock, nil, provisionclient.ServerUID(uint32(os.Getuid())+1))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Capabilities(ctx); err == nil {
		t.Fatal("a provisioner running as another uid was trusted")
	}
	if _, err := provisionclient.Dial("relative.sock"); err == nil {
		t.Error("a relative socket path was accepted")
	}
}

// ⛔ A method the provisioner does not have gets no answer: its connection is
// closed. The client's next call works -- on a NEW connection.
func TestAnUnknownMethodClosesTheConnection(t *testing.T) {
	w := newWorld(t)
	sock := w.serve()
	d := &dialer{}
	c := w.client(sock, d)
	ctx := ctxT(t)
	if _, err := c.Capabilities(ctx); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{
		"/fileshare.provision.v1.ProvisionService/MountAnything",
		"/grpc.health.v1.Health/Check",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/fileshare.admin.v1.AdminService/ListShares",
	} {
		before := d.n.Load()
		err := c.Conn().Invoke(ctx, method, &pb.GetCapabilitiesRequest{}, &pb.GetCapabilitiesResponse{})
		if err == nil {
			t.Fatalf("%s was answered", method)
		}
		if _, err := c.Capabilities(ctx); err != nil {
			t.Fatalf("after %s: %v", method, err)
		}
		if d.n.Load() == before {
			t.Errorf("%s: the connection survived (still %d dials)", method, before)
		}
	}
	if !strings.Contains(w.log.String(), "not a provisioner verb") {
		t.Errorf("not logged:\n%s", w.log)
	}
}

// rawCodec sends bytes as they are, to put on the wire what no protobuf
// encoder would.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	return mem.BufferSlice{mem.SliceBuffer(v.([]byte))}, nil
}
func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	*v.(*[]byte) = data.Materialize()
	return nil
}

// ⛔ So does a message that does not decode, or that carries a field this
// version does not define -- here a Volume's path, sent as a CreateVolume.
func TestAMalformedMessageClosesTheConnection(t *testing.T) {
	w := newWorld(t)
	sock := w.serve()
	d := &dialer{}
	c := w.client(sock, d)
	ctx := ctxT(t)
	if _, err := c.Capabilities(ctx); err != nil {
		t.Fatal(err)
	}
	extra, err := proto.Marshal(&pb.Volume{Parent: "tank", Name: "x", Path: "/etc"})
	if err != nil {
		t.Fatal(err)
	}
	for what, body := range map[string][]byte{
		"bytes that are not protobuf": {0xff, 0xff, 0xff},
		"a field it does not define":  extra,
	} {
		before := d.n.Load()
		var out []byte
		err := c.Conn().Invoke(ctx, "/fileshare.provision.v1.ProvisionService/CreateVolume", body, &out,
			grpc.ForceCodecV2(rawCodec{}))
		if err == nil {
			t.Fatalf("%s: answered", what)
		}
		if _, err := c.Capabilities(ctx); err != nil {
			t.Fatalf("after %s: %v", what, err)
		}
		if d.n.Load() == before {
			t.Errorf("%s: the connection survived", what)
		}
	}
	if w.zfs.ds["pool/fs/x"] != nil {
		t.Error("a malformed request created a volume")
	}
	if !strings.Contains(w.log.String(), malformed) {
		t.Errorf("not logged:\n%s", w.log)
	}
	// The second net: what the tap handle would have closed already.
	g := &gate{}
	if err := g.unknown(nil, fakeStream{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("unknown = %v", err)
	}
}

type fakeStream struct{ grpc.ServerStream }

func (fakeStream) Context() context.Context { return context.Background() }

func TestTheSocketsDirectory(t *testing.T) {
	w := newWorld(t)
	sock := mustSocket(w.cfg.Listen)
	run := filepath.Dir(sock)

	// Writable by the group: refused.
	if err := os.Chmod(run, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(sock, testGID); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a group-writable directory: %v", err)
	}
	os.Chmod(run, 0o755)

	// Something that is not a socket at the path: refused, and left alone.
	if err := os.WriteFile(sock, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(sock, testGID); err == nil {
		t.Error("a file at the socket's path was replaced")
	}
	if b, _ := os.ReadFile(sock); string(b) != "keep" {
		t.Error("the file was touched")
	}
	os.Remove(sock)

	// A socket left behind: replaced.
	old, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	ln, err := listen(sock, testGID)
	if err != nil {
		t.Fatalf("a stale socket: %v", err)
	}
	ln.Close()

	// A directory that is not there.
	if _, err := listen(filepath.Join(w.dir, "nope", "s"), testGID); err == nil {
		t.Error("a missing directory")
	}
	// A group this process may not give the socket to.
	if os.Getuid() != 0 {
		if _, err := listen(sock, 1999999999); err == nil {
			t.Error("the socket was given to a foreign group without privilege")
		}
	}
}

func TestRunRefusesWhatItCannotStart(t *testing.T) {
	w := newWorld(t)
	// A btrfs parent that is not on btrfs.
	delete(w.sys.types, w.path("fast"))
	if err := run(context.Background(), w.cfg, w.log, w.system()); err == nil || !strings.Contains(err.Error(), "not on btrfs") {
		t.Errorf("btrfs root on something else: %v", err)
	}
	w.sys.types[w.path("fast")] = magicBtrfs

	// Quotas off on btrfs, without enable_quota.
	w.btrfs.quotasOn = false
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "quotas are not enabled") {
		t.Errorf("btrfs quotas off: %v", err)
	}
	// With it, they are turned on.
	w.cfg.Parents[1].EnableQuota = true
	s, err := newService(w.cfg, w.system(), w.log.logf)
	if err != nil || !w.btrfs.enabled {
		t.Fatalf("enable_quota: %v, enabled %v", err, w.btrfs.enabled)
	}
	s.st.close()

	// XFS without project quotas.
	w.proj.errUsage = errors.New("ESRCH")
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "prjquota") {
		t.Errorf("xfs without prjquota: %v", err)
	}
	w.proj.errUsage = nil
	// An ext4 parent on XFS.
	w.ext4AsXFS = true
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "is not on") {
		t.Errorf("an ext4 parent on xfs: %v", err)
	}
	w.ext4AsXFS = false

	// A ZFS parent whose dataset is not there.
	delete(w.zfs.ds, "pool/fs")
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "pool/fs") {
		t.Errorf("a missing dataset: %v", err)
	}
	w.zfs.add("pool/fs")
	sys := w.system()
	sys.zfs = func() (zfsOps, error) { return nil, errors.New("no /dev/zfs") }
	if _, err := newService(w.cfg, sys, w.log.logf); err == nil || !strings.Contains(err.Error(), "/dev/zfs") {
		t.Errorf("no /dev/zfs: %v", err)
	}

	// A root anybody may write into.
	os.Chmod(w.path("plain"), 0o777)
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a world-writable root: %v", err)
	}
	os.Chmod(w.path("plain"), 0o755)
	// A root that is a link.
	os.Rename(w.path("plain"), w.path("plain-real"))
	os.Symlink(w.path("plain-real"), w.path("plain"))
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a root that is a link: %v", err)
	}
	os.Remove(w.path("plain"))
	os.Rename(w.path("plain-real"), w.path("plain"))
	// A state directory anybody may write into.
	os.Chmod(w.path("state"), 0o777)
	if _, err := newService(w.cfg, w.system(), w.log.logf); err == nil {
		t.Error("a world-writable state directory")
	}
	os.Chmod(w.path("state"), 0o755)

	// The real system: on a Mac it refuses outright; on Linux, without
	// /dev/zfs or root, the ZFS parent stops it.
	if err := Run(context.Background(), w.cfg, w.log); err == nil {
		t.Error("Run with the real system started on fake parents")
	}
}
