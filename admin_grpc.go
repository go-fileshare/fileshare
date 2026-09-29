// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package main

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-net-health/endpoint"
	"github.com/grpc-transports/control"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
)

// The admin API, over gRPC. See proto/fileshare/admin/v1/admin.proto for
// what it promises, and state.go for how a change is applied.
//
// It is compiled in unless -tags nogrpc. gRPC and protobuf are the largest
// thing in this binary -- see the note on plugins in protocol.go -- and a
// site that manages its shares in files does not need to carry them.

func controlConfig(a *adminBlock) control.Config {
	return control.Config{Listen: a.Listen, TLSCertFile: a.TLSCertFile,
		TLSKeyFile: a.TLSKeyFile, ClientCAFile: a.ClientCAFile}
}

func checkAdminListen(a *adminBlock) error { return controlConfig(a).Check() }

// startAdmin serves the admin API and grpc.health.v1 on the admin listener.
func startAdmin(ctx context.Context, s *server, cfg *config) (func(), error) {
	mgr, err := newManager(s, cfg)
	if err != nil {
		return nil, err
	}
	ln, opts, err := control.Listen(controlConfig(cfg.Admin))
	if err != nil {
		return nil, err
	}
	calls := &rpcCounts{n: map[[2]string]uint64{}}
	s.stats.rpcs = calls.collect
	gs := grpc.NewServer(append(opts, grpc.ChainUnaryInterceptor(calls.intercept))...)
	adminv1.RegisterAdminServiceServer(gs, &adminService{m: mgr})
	hs := health.NewServer()
	hs.SetServingStatus(adminv1.AdminService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(gs, hs)
	if cfg.Admin.Reflection {
		reflection.Register(gs)
	}
	s.mgr.Store(mgr)
	go gs.Serve(ln)
	fmt.Fprintf(s.out, "%-6s on %s — the admin API\n", "admin", cfg.Admin.Listen)
	return func() {
		hs.Shutdown()
		done := make(chan struct{})
		go func() { gs.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			gs.Stop()
		}
	}, nil
}

// rpcCounts is fileshare_admin_requests_total.
type rpcCounts struct {
	mu sync.Mutex
	n  map[[2]string]uint64
}

func (c *rpcCounts) intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	resp, err := h(ctx, req)
	c.mu.Lock()
	c.n[[2]string{path.Base(info.FullMethod), status.Code(err).String()}]++
	c.mu.Unlock()
	return resp, err
}

func (c *rpcCounts) collect(w *endpoint.Writer) {
	c.mu.Lock()
	keys := make([][2]string, 0, len(c.n))
	for k := range c.n {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return strings.Compare(a[0]+a[1], b[0]+b[1]) })
	samples := make([]endpoint.Sample, 0, len(keys))
	for _, k := range keys {
		samples = append(samples, endpoint.S(float64(c.n[k]), endpoint.L("method", k[0]), endpoint.L("code", k[1])))
	}
	c.mu.Unlock()
	w.Counter("fileshare_admin_requests_total", "Admin API calls, by method and status code.", samples...)
}

type adminService struct {
	adminv1.UnimplementedAdminServiceServer
	m *manager
}

// grpcError maps a refusal onto the status code that says what kind it is.
func grpcError(err error) error {
	var r *refusal
	if !errors.As(err, &r) {
		return status.Error(codes.Internal, err.Error())
	}
	switch r.kind {
	case refusedNotFound:
		return status.Error(codes.NotFound, r.msg)
	case refusedExists:
		return status.Error(codes.AlreadyExists, r.msg)
	case refusedPrecondition:
		return status.Error(codes.FailedPrecondition, r.msg)
	}
	return status.Error(codes.InvalidArgument, r.msg)
}

func (a *adminService) GetServerInfo(ctx context.Context, _ *adminv1.GetServerInfoRequest) (*adminv1.GetServerInfoResponse, error) {
	s := a.m.srv
	info := &adminv1.ServerInfo{Name: s.name, Version: version(),
		Started: timestamppb.New(s.stats.started), Generation: s.generationNumber()}
	s.runMu.Lock()
	for _, f := range s.feeds {
		info.Listeners = append(info.Listeners, &adminv1.Listener{Protocol: f.proto, Address: f.ln.Addr().String()})
	}
	s.runMu.Unlock()
	return &adminv1.GetServerInfoResponse{Info: info}, nil
}

func (a *adminService) ListShares(ctx context.Context, _ *adminv1.ListSharesRequest) (*adminv1.ListSharesResponse, error) {
	m := a.m
	m.mu.Lock()
	defer m.mu.Unlock()
	var out adminv1.ListSharesResponse
	all, _ := m.blocks(m.state)
	for _, b := range all {
		out.Shares = append(out.Shares, m.view(b.Name))
	}
	return &out, nil
}

func (a *adminService) GetShare(ctx context.Context, req *adminv1.GetShareRequest) (*adminv1.GetShareResponse, error) {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	if !a.m.exists(a.m.state, req.GetName()) {
		return nil, status.Errorf(codes.NotFound, "there is no share %q", req.GetName())
	}
	return &adminv1.GetShareResponse{Share: a.m.view(req.GetName())}, nil
}

// shareNow is a share as it is after a change, with what the change did.
func (a *adminService) shareNow(name string) *adminv1.Share {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	return a.m.view(name)
}

func appliedOf(ap applied) *adminv1.Applied {
	return &adminv1.Applied{Generation: ap.generation, ConnectionsClosed: ap.closed}
}

func (a *adminService) CreateShare(ctx context.Context, req *adminv1.CreateShareRequest) (*adminv1.CreateShareResponse, error) {
	m := a.m
	name := req.GetName()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "a share needs a name")
	}
	ms := managedShare{Name: name, ReadOnly: req.GetReadOnly(), Filesystem: req.GetFilesystem(),
		PartitionLabel: req.GetPartitionLabel(), PartitionUUID: req.GetPartitionUuid(),
		Protocols: req.GetProtocols()}
	if req.Partition != nil {
		p := int(req.GetPartition())
		ms.Partition = &p
	}
	var from string
	switch src := req.GetSource().(type) {
	case *adminv1.CreateShareRequest_Image:
		p, err := m.withinRoots(src.Image)
		if err != nil {
			return nil, grpcError(err)
		}
		ms.Image, from = p, p
	case *adminv1.CreateShareRequest_Directory:
		p, err := m.withinRoots(src.Directory)
		if err != nil {
			return nil, grpcError(err)
		}
		ms.Directory, from = p, p
	default:
		return nil, status.Error(codes.InvalidArgument, "a share needs an image or a directory")
	}
	grants, err := grantsOf(req.GetGrants())
	if err != nil {
		return nil, grpcError(err)
	}
	if len(grants) == 0 {
		return nil, status.Error(codes.InvalidArgument, "a share needs at least one grant: "+
			"one with none is open to anyone who authenticates, which an API call should not say by omission")
	}
	if ms.ReadOnly && slices.ContainsFunc(grants, func(g grant) bool { return g.Write }) {
		return nil, status.Error(codes.InvalidArgument, "the share is read_only and a grant says write: say one or the other")
	}
	ms.Grants = grants
	what := fmt.Sprintf("created share %s from %s for %s", name, from, describeGrants(grants))
	if req.GetDisabled() {
		what += ", disabled"
	}
	ap, err := m.change(control.Caller(ctx), what,
		func(st *stateFile) error {
			if m.fromFiles(name) {
				return refuse(refusedExists, "share %q is defined in the configuration files", name)
			}
			if indexOf(st, name) >= 0 {
				return refuse(refusedExists, "there is already a share %q", name)
			}
			st.Shares = append(st.Shares, ms)
			// A name left disabled by a share deleted earlier must not
			// silently decide whether this new one is served.
			st.Disabled = slices.DeleteFunc(st.Disabled, func(d string) bool { return strings.EqualFold(d, name) })
			if req.GetDisabled() {
				st.Disabled = append(st.Disabled, name)
			}
			return nil
		})
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.CreateShareResponse{Share: a.shareNow(name), Applied: appliedOf(ap)}, nil
}

func (a *adminService) UpdateShare(ctx context.Context, req *adminv1.UpdateShareRequest) (*adminv1.UpdateShareResponse, error) {
	var said []string
	if req.ReadOnly != nil {
		said = append(said, fmt.Sprintf("read_only=%t", req.GetReadOnly()))
	}
	if req.Protocols != nil {
		said = append(said, fmt.Sprintf("protocols=[%s]", strings.Join(req.GetProtocols().GetNames(), ", ")))
	}
	if len(said) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nothing to change: say read_only, protocols, or both")
	}
	ap, err := a.edit(ctx, req.GetName(), "updated share "+req.GetName()+": "+strings.Join(said, ", "),
		func(ms *managedShare) error {
			if req.ReadOnly != nil {
				if req.GetReadOnly() && slices.ContainsFunc(ms.Grants, func(g grant) bool { return g.Write }) {
					return refuse(refusedPrecondition, "share %q has grants that write: change them to read before making it read_only", ms.Name)
				}
				ms.ReadOnly = req.GetReadOnly()
			}
			if req.Protocols != nil {
				ms.Protocols = slices.Clone(req.GetProtocols().GetNames())
			}
			return nil
		})
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.UpdateShareResponse{Share: a.shareNow(req.GetName()), Applied: appliedOf(ap)}, nil
}

func (a *adminService) DeleteShare(ctx context.Context, req *adminv1.DeleteShareRequest) (*adminv1.DeleteShareResponse, error) {
	name := req.GetName()
	ap, err := a.m.change(control.Caller(ctx), "deleted share "+name, func(st *stateFile) error {
		i, err := a.m.managed(st, name)
		if err != nil {
			return err
		}
		st.Shares = slices.Delete(st.Shares, i, i+1)
		st.Disabled = slices.DeleteFunc(st.Disabled, func(d string) bool { return strings.EqualFold(d, name) })
		return nil
	})
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.DeleteShareResponse{Applied: appliedOf(ap)}, nil
}

func (a *adminService) DisableShare(ctx context.Context, req *adminv1.DisableShareRequest) (*adminv1.DisableShareResponse, error) {
	ap, err := a.setDisabled(ctx, req.GetName(), true)
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.DisableShareResponse{Share: a.shareNow(req.GetName()), Applied: appliedOf(ap)}, nil
}

func (a *adminService) EnableShare(ctx context.Context, req *adminv1.EnableShareRequest) (*adminv1.EnableShareResponse, error) {
	ap, err := a.setDisabled(ctx, req.GetName(), false)
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.EnableShareResponse{Share: a.shareNow(req.GetName()), Applied: appliedOf(ap)}, nil
}

// setDisabled takes a share offline or brings it back. It is the one change
// a share of the configuration takes too. Asking for what already is, is
// refused rather than applied: applying it would close every connection for
// nothing.
func (a *adminService) setDisabled(ctx context.Context, name string, off bool) (applied, error) {
	what := "disabled share " + name
	if !off {
		what = "enabled share " + name
	}
	return a.m.change(control.Caller(ctx), what, func(st *stateFile) error {
		if !a.m.exists(st, name) {
			return refuse(refusedNotFound, "there is no share %q", name)
		}
		if st.isDisabled(name) == off {
			if off {
				return refuse(refusedPrecondition, "share %q is already disabled", name)
			}
			return refuse(refusedPrecondition, "share %q is not disabled", name)
		}
		if off {
			st.Disabled = append(st.Disabled, name)
		} else {
			st.Disabled = slices.DeleteFunc(st.Disabled, func(d string) bool { return strings.EqualFold(d, name) })
		}
		return nil
	})
}

func (a *adminService) Grant(ctx context.Context, req *adminv1.GrantRequest) (*adminv1.GrantResponse, error) {
	gs, err := grantsOf([]*adminv1.Grant{req.GetGrant()})
	if err != nil {
		return nil, grpcError(err)
	}
	g := gs[0]
	ap, err := a.edit(ctx, req.GetShare(), fmt.Sprintf("granted %s on %s to %s", accessWord(g.Write), req.GetShare(), g.Subject),
		func(ms *managedShare) error {
			if g.Write && ms.ReadOnly {
				return refuse(refusedPrecondition, "share %q is read_only: nobody can be granted write on it", ms.Name)
			}
			if i := slices.IndexFunc(ms.Grants, func(o grant) bool { return o.Subject == g.Subject }); i >= 0 {
				ms.Grants[i] = g
				return nil
			}
			ms.Grants = append(ms.Grants, g)
			return nil
		})
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.GrantResponse{Share: a.shareNow(req.GetShare()), Applied: appliedOf(ap)}, nil
}

func (a *adminService) Revoke(ctx context.Context, req *adminv1.RevokeRequest) (*adminv1.RevokeResponse, error) {
	subject, err := subjectOf(req.GetSubject())
	if err != nil {
		return nil, grpcError(err)
	}
	ap, err := a.edit(ctx, req.GetShare(), fmt.Sprintf("revoked %s on %s", subject, req.GetShare()),
		func(ms *managedShare) error {
			i := slices.IndexFunc(ms.Grants, func(o grant) bool { return o.Subject == subject })
			if i < 0 {
				return refuse(refusedNotFound, "share %q grants nothing to %s", ms.Name, subject)
			}
			if len(ms.Grants) == 1 {
				return refuse(refusedPrecondition, "%s is the last grant on %q: without it the share would be "+
					"open to anyone who authenticates. Delete the share, or grant somebody else first", subject, ms.Name)
			}
			ms.Grants = slices.Delete(ms.Grants, i, i+1)
			return nil
		})
	if err != nil {
		return nil, grpcError(err)
	}
	return &adminv1.RevokeResponse{Share: a.shareNow(req.GetShare()), Applied: appliedOf(ap)}, nil
}

// edit changes one share the API manages.
func (a *adminService) edit(ctx context.Context, name, what string, fn func(*managedShare) error) (applied, error) {
	return a.m.change(control.Caller(ctx), what, func(st *stateFile) error {
		i, err := a.m.managed(st, name)
		if err != nil {
			return err
		}
		return fn(&st.Shares[i])
	})
}

// managed is where an API share is in a state, or why a change to it is
// refused: a share the configuration defines is changed there.
func (m *manager) managed(st *stateFile, name string) (int, error) {
	if m.fromFiles(name) {
		return 0, refuse(refusedPrecondition, "share %q is defined in the configuration files: change it there", name)
	}
	i := indexOf(st, name)
	if i < 0 {
		return 0, refuse(refusedNotFound, "there is no share %q", name)
	}
	return i, nil
}

func (a *adminService) ListUsers(ctx context.Context, _ *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	s := a.m.srv
	var out adminv1.ListUsersResponse
	for _, id := range s.sortedIdentities() {
		u := &adminv1.User{Name: id.Name(), Source: id.Where()}
		for _, b := range s.cfg.Serves {
			if protocolByName(b.Protocol).authenticates && canServeUser(b.Protocol, id, s.cfg) {
				u.CanUse = append(u.CanUse, b.Protocol)
			}
		}
		out.Users = append(out.Users, u)
	}
	return &out, nil
}

func (a *adminService) ListGroups(ctx context.Context, _ *adminv1.ListGroupsRequest) (*adminv1.ListGroupsResponse, error) {
	names, err := a.m.srv.dir.GroupNames()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "the directory could not list its groups: %v", err)
	}
	var out adminv1.ListGroupsResponse
	for _, n := range names {
		members, err := a.m.srv.dir.Members(n)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "group %s: %v", n, err)
		}
		out.Groups = append(out.Groups, &adminv1.Group{Name: n, Members: members})
	}
	return &out, nil
}

// view is a share as the API describes it: its definition, and -- when it is
// served -- what serving it found. The caller holds m.mu, so the state and
// the served list agree.
func (m *manager) view(name string) *adminv1.Share {
	var b shareBlock
	v := &adminv1.Share{}
	if i := indexOf(m.state, name); i >= 0 {
		ms := m.state.Shares[i]
		v.Origin = adminv1.Origin_ORIGIN_API
		v.ReadOnly = ms.ReadOnly
		b = ms.block()
		for _, g := range ms.Grants {
			v.Grants = append(v.Grants, grantView(g))
		}
	} else {
		v.Origin = adminv1.Origin_ORIGIN_CONFIG
		for _, fb := range m.files.Shares {
			if strings.EqualFold(fb.Name, name) {
				b = fb
			}
		}
		v.ReadOnly = b.ReadOnly
		for _, g := range grantsOfBlock(b) {
			v.Grants = append(v.Grants, grantView(g))
		}
	}
	v.Name = b.Name
	v.Protocols = slices.Clone(b.Protocols)
	if b.Directory != "" {
		v.Source = &adminv1.Share_Directory{Directory: b.Directory}
	} else {
		v.Source = &adminv1.Share_Image{Image: b.Image}
	}
	var sh *share
	for _, c := range m.srv.currentShares() {
		if strings.EqualFold(c.name, name) {
			sh = c
		}
	}
	if sh == nil {
		// Taken offline: nothing is open, so there is nothing found to say,
		// and nothing is served over anything.
		v.EffectiveReadOnly = true
		return v
	}
	v.Enabled = true
	v.EffectiveReadOnly = sh.readOnly
	v.Filesystem = string(sh.kind)
	v.SizeBytes = sh.size
	for _, sb := range m.srv.cfg.Serves {
		p := protocolByName(sb.Protocol)
		served, refused := p.exports(m.srv.cfg, []*share{sh})
		switch {
		case len(served) == 1:
			v.ServedOver = append(v.ServedOver, p.name)
		case len(refused) == 1:
			v.Refusals = append(v.Refusals, &adminv1.Refusal{Protocol: p.name, Reason: p.refusal(sh)})
		}
	}
	return v
}

// grantsOfBlock is what a configuration share's two lists mean, grant by
// grant, by the rules on share.
func grantsOfBlock(b shareBlock) []grant {
	var out []grant
	for _, who := range b.Allow {
		w := !b.ReadOnly && (len(b.Writers) == 0 || slices.Contains(b.Writers, who))
		out = append(out, grant{Subject: who, Write: w})
	}
	for _, who := range b.Writers {
		if len(b.Allow) == 0 && !b.ReadOnly {
			out = append(out, grant{Subject: who, Write: true})
		}
	}
	return out
}

func grantsOf(in []*adminv1.Grant) ([]grant, error) {
	var out []grant
	for _, g := range in {
		subject, err := subjectOf(g.GetSubject())
		if err != nil {
			return nil, err
		}
		var write bool
		switch g.GetAccess() {
		case adminv1.Access_ACCESS_READ:
		case adminv1.Access_ACCESS_WRITE:
			write = true
		default:
			return nil, refuse(refusedInvalid, "the grant to %s says no access: ACCESS_READ or ACCESS_WRITE", subject)
		}
		if slices.ContainsFunc(out, func(o grant) bool { return o.Subject == subject }) {
			return nil, refuse(refusedInvalid, "%s is granted twice", subject)
		}
		out = append(out, grant{Subject: subject, Write: write})
	}
	return out, nil
}

// subjectOf spells a subject the way the configuration does, and refuses one
// that would be read as something else -- a user called "@staff" is a group,
// and one called "oidc:user:x" is a rule.
func subjectOf(s *adminv1.Subject) (string, error) {
	bad := func(v string) bool { return v == "" || strings.ContainsAny(v, " \t\n") }
	switch k := s.GetKind().(type) {
	case *adminv1.Subject_User:
		if bad(k.User) || strings.HasPrefix(k.User, "@") || isRule(k.User) {
			return "", refuse(refusedInvalid, "%q is not a user name", k.User)
		}
		return k.User, nil
	case *adminv1.Subject_Group:
		if bad(k.Group) || strings.HasPrefix(k.Group, "@") {
			return "", refuse(refusedInvalid, "%q is not a group name (it is written without the @)", k.Group)
		}
		return "@" + k.Group, nil
	case *adminv1.Subject_OidcGroup:
		if k.OidcGroup == "" {
			return "", refuse(refusedInvalid, "an oidc_group needs a value")
		}
		return "oidc:groups:" + k.OidcGroup, nil
	case *adminv1.Subject_OidcUser:
		if k.OidcUser == "" {
			return "", refuse(refusedInvalid, "an oidc_user needs a name")
		}
		return "oidc:user:" + k.OidcUser, nil
	}
	return "", refuse(refusedInvalid, "a grant needs a subject: user, group, oidc_group or oidc_user")
}

func grantView(g grant) *adminv1.Grant {
	s := &adminv1.Subject{}
	switch {
	case strings.HasPrefix(g.Subject, "@"):
		s.Kind = &adminv1.Subject_Group{Group: strings.TrimPrefix(g.Subject, "@")}
	case strings.HasPrefix(g.Subject, "oidc:groups:"):
		s.Kind = &adminv1.Subject_OidcGroup{OidcGroup: strings.TrimPrefix(g.Subject, "oidc:groups:")}
	case strings.HasPrefix(g.Subject, "oidc:user:"):
		s.Kind = &adminv1.Subject_OidcUser{OidcUser: strings.TrimPrefix(g.Subject, "oidc:user:")}
	default:
		s.Kind = &adminv1.Subject_User{User: g.Subject}
	}
	access := adminv1.Access_ACCESS_READ
	if g.Write {
		access = adminv1.Access_ACCESS_WRITE
	}
	return &adminv1.Grant{Subject: s, Access: access}
}

func accessWord(write bool) string {
	if write {
		return "write"
	}
	return "read"
}

func describeGrants(gs []grant) string {
	var said []string
	for _, g := range gs {
		said = append(said, g.Subject+" ("+accessWord(g.Write)+")")
	}
	return list(said)
}
