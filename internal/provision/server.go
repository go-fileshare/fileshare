// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	gproto "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
	"google.golang.org/protobuf/proto"

	"github.com/go-fileshare/fileshare/internal/peercred"
	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// The verbs are closed, and three mechanisms keep them closed, each where
// grpc-go gives a hook:
//
//   - The TAP HANDLE runs when a call's headers arrive, before grpc-go looks
//     the method up and before a byte of its message is decoded. A method
//     outside the service's own list closes the connection there -- the
//     caller gets no answer at all, OpenSSH privsep's fatal "unpermitted
//     request" -- and a peer whose uid is not client_uid is refused with
//     PERMISSION_DENIED, so nothing from it is ever parsed.
//   - The CODEC refuses a message that does not decode, or that carries a
//     field this version does not define, and marks the error.
//   - The STATS HANDLER sees every call end, and closes the connection of
//     one that ended with the codec's mark. It is needed because grpc-go
//     decodes inside the generated handler, before any interceptor: an
//     interceptor never sees a malformed request at all.
//
// The UnknownServiceHandler would be the obvious place for the first, and
// is kept only as a second net: the tap handle has already closed the
// connection by the time grpc-go would route a call to it.

// methods is the closed set: the service's own methods and nothing else --
// no health service, no reflection.
var methods = func() map[string]bool {
	m := map[string]bool{}
	sd := provisionv1.ProvisionService_ServiceDesc
	for _, d := range sd.Methods {
		m["/"+sd.ServiceName+"/"+d.MethodName] = true
	}
	return m
}()

type gate struct {
	clientUID uint32
	logf      func(string, ...any)
}

func closeConn(ctx context.Context) {
	if a, ok := peercred.FromContext(ctx); ok {
		a.CloseConn()
	}
}

func (g *gate) tap(ctx context.Context, info *tap.Info) (context.Context, error) {
	a, ok := peercred.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no peer credentials")
	}
	if !methods[info.FullMethodName] {
		g.logf("closing the connection of uid %d pid %d: it called %q, which is not a provisioner verb", a.UID, a.PID, info.FullMethodName)
		a.CloseConn()
		return nil, status.Error(codes.Unimplemented, "not a provisioner verb")
	}
	if a.UID != g.clientUID {
		g.logf("refused uid %d pid %d calling %s: only uid %d is answered", a.UID, a.PID, info.FullMethodName, g.clientUID)
		return nil, status.Errorf(codes.PermissionDenied, "uid %d may not call the provisioner", a.UID)
	}
	return ctx, nil
}

// unary checks the uid again, per call. The tap handle has already refused
// any other: this is the line that would still hold if grpc-go ever stopped
// calling it.
func (g *gate) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	a, ok := peercred.FromContext(ctx)
	if !ok || a.UID != g.clientUID {
		return nil, status.Error(codes.PermissionDenied, "only the configured client_uid may call the provisioner")
	}
	return h(ctx, req)
}

func (g *gate) unknown(_ any, stream grpc.ServerStream) error {
	closeConn(stream.Context())
	return status.Error(codes.Unimplemented, "not a provisioner verb")
}

// malformed is the codec's mark on a message it refused.
const malformed = "fileshare-provisioner: malformed message"

// strictCodec is protobuf, refusing what the default codec lets through: a
// field this version does not define is kept by protobuf as "unknown" and
// silently ignored, and a field a newer client relies on is the wrong thing
// to ignore in a privileged process.
type strictCodec struct{ base encoding.CodecV2 }

func (c strictCodec) Name() string                           { return c.base.Name() }
func (c strictCodec) Marshal(v any) (mem.BufferSlice, error) { return c.base.Marshal(v) }

func (c strictCodec) Unmarshal(data mem.BufferSlice, v any) error {
	if err := c.base.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %v", malformed, err)
	}
	if m, ok := v.(proto.Message); ok && len(m.ProtoReflect().GetUnknown()) > 0 {
		return fmt.Errorf("%s: it carries fields this provisioner does not define", malformed)
	}
	return nil
}

// closer is the stats handler that closes the connection of a call whose
// message the codec refused.
type closer struct{ logf func(string, ...any) }

func (closer) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context   { return ctx }
func (closer) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (closer) HandleConn(context.Context, stats.ConnStats)                       {}

func (c closer) HandleRPC(ctx context.Context, s stats.RPCStats) {
	end, ok := s.(*stats.End)
	if !ok || end.Error == nil || !strings.Contains(status.Convert(end.Error).Message(), malformed) {
		return
	}
	if a, ok := peercred.FromContext(ctx); ok {
		c.logf("closing the connection of uid %d pid %d: %v", a.UID, a.PID, status.Convert(end.Error).Message())
		a.CloseConn()
	}
}

// newGRPCServer is the provisioner's gRPC server around svc.
func newGRPCServer(svc provisionv1.ProvisionServiceServer, clientUID uint32, logf func(string, ...any)) *grpc.Server {
	g := &gate{clientUID: clientUID, logf: logf}
	gs := grpc.NewServer(
		grpc.Creds(peercred.New()),
		grpc.InTapHandle(g.tap),
		grpc.UnknownServiceHandler(g.unknown),
		grpc.ForceServerCodecV2(strictCodec{base: encoding.GetCodecV2(gproto.Name)}),
		grpc.StatsHandler(closer{logf: logf}),
		grpc.ChainUnaryInterceptor(g.unary),
		// Every request is a few ids and a number.
		grpc.MaxRecvMsgSize(16<<10),
	)
	provisionv1.RegisterProvisionServiceServer(gs, svc)
	return gs
}

// listen makes the socket. Its directory must be the provisioner's alone --
// owned by it or root, writable by nobody else -- because whoever can write
// there can put their own socket in its place. The socket is made 0600
// (umask) and only then opened to the group, 0660.
func listen(path string, gid int) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := checkRoot("the socket's directory", dir); err != nil {
		return nil, err
	}
	switch st, err := os.Lstat(path); {
	case err == nil && st.Mode()&fs.ModeSocket == 0:
		return nil, fmt.Errorf("%s is there and is not a socket", path)
	case err == nil:
		// A socket left by a provisioner that did not exit cleanly. The
		// state file's lock is held, so it is not a live one.
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, -1, gid); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Run is `fileshare provisioner`: it checks every parent on disk, mounts
// again what a reboot unmounted, and serves until ctx is done.
func Run(ctx context.Context, cfg *Config, out io.Writer) error {
	sys, err := newSystem()
	if err != nil {
		return err
	}
	return run(ctx, cfg, out, sys)
}

// system is everything Run takes from the machine; the tests give a fake one.
type system struct {
	sys   sysOps
	zfs   func() (zfsOps, error)
	btrfs btrfsOps
	proj  projOps
}

func run(ctx context.Context, cfg *Config, out io.Writer, sys *system) error {
	var mu sync.Mutex
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(out, "provisioner: "+format+"\n", args...)
	}
	svc, err := newService(cfg, sys, logf)
	if err != nil {
		return err
	}
	defer svc.st.close()
	path, _ := socketPath(cfg.Listen)
	ln, err := listen(path, cfg.gid)
	if err != nil {
		return err
	}
	gs := newGRPCServer(svc, uint32(cfg.ClientUID), logf)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(ln) }()
	logf("serving uid %d on %s, %d parents", cfg.ClientUID, cfg.Listen, len(cfg.Parents))
	select {
	case <-ctx.Done():
	case err := <-served:
		return err
	}
	done := make(chan struct{})
	go func() { gs.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		gs.Stop()
	}
	os.Remove(path)
	return nil
}

// newService opens the state and starts every parent's backend.
func newService(cfg *Config, sys *system, logf func(string, ...any)) (*service, error) {
	// The state decides what is ours: whoever can replace it can make the
	// provisioner treat anything as its own.
	if err := checkRoot("the state file's directory", filepath.Dir(cfg.StateFile)); err != nil {
		return nil, err
	}
	st, err := openState(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	s := &service{cfg: cfg, st: st, backends: map[string]backend{}, logf: logf, now: time.Now}
	fail := func(err error) (*service, error) { st.close(); return nil, err }
	// ⛔ A record whose parent the configuration no longer names stops the
	// start: forgetting it would hand its project id out again, and leave
	// storage nobody accounts for.
	for _, r := range st.vols {
		p := cfg.parent(r.Parent)
		if p == nil {
			return fail(fmt.Errorf("%s records volume %s/%s, and the configuration has no parent %q", cfg.StateFile, r.Parent, r.Name, r.Parent))
		}
		if r.Kind != kindName(p.kind) {
			return fail(fmt.Errorf("%s records volume %s/%s as %s, and parent %q is %s", cfg.StateFile, r.Parent, r.Name, r.Kind, r.Parent, kindName(p.kind)))
		}
		if p.hi != 0 && (r.ProjectID < p.lo || r.ProjectID > p.hi) && !(r.Pending && r.ProjectID == 0) {
			return fail(fmt.Errorf("%s records volume %s/%s with project id %d, outside %s", cfg.StateFile, r.Parent, r.Name, r.ProjectID, p.ProjectIDs))
		}
	}
	var z zfsOps
	for i := range cfg.Parents {
		p := &cfg.Parents[i]
		var b backend
		switch p.kind {
		case provisionv1.Kind_KIND_ZFS:
			if z == nil {
				if z, err = sys.zfs(); err != nil {
					return fail(fmt.Errorf("parent %q: /dev/zfs: %w", p.ID, err))
				}
			}
			b = &zfsBackend{id: p.ID, dataset: p.ZFS, root: p.root, gid: cfg.gid, z: z, sys: sys.sys, logf: logf}
		case provisionv1.Kind_KIND_BTRFS:
			b = &btrfsBackend{id: p.ID, root: p.root, gid: cfg.gid, enableQuota: p.EnableQuota, b: sys.btrfs, sys: sys.sys}
		default:
			b = &projBackend{id: p.ID, root: p.root, k: p.kind, lo: p.lo, hi: p.hi, gid: cfg.gid, p: sys.proj, sys: sys.sys}
		}
		var recs []*record
		for _, r := range st.vols {
			if r.Parent == p.ID {
				recs = append(recs, r)
			}
		}
		if err := b.start(recs); err != nil {
			return fail(fmt.Errorf("parent %q: %w", p.ID, err))
		}
		s.backends[p.ID] = b
	}
	return s, nil
}
