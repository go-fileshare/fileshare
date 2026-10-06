// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-fileshare/fileshare/internal/provisionclient"
	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// The admin API's volume calls, relayed to `fileshare provisioner`, and
// what a share made from a volume asks of it. See volume.go and
// docs/volumes.md.

// volumeService is the provisioner, as internal/provisionclient speaks to it.
type volumeService interface {
	Capabilities(ctx context.Context) (*provisionv1.GetCapabilitiesResponse, error)
	Create(ctx context.Context, parent, name string, quota uint64) (*provisionv1.Volume, bool, error)
	Resize(ctx context.Context, parent, name string, quota uint64) (*provisionv1.Volume, error)
	Snapshot(ctx context.Context, parent, name, snapshot string) (*provisionv1.Volume, bool, error)
	Delete(ctx context.Context, parent, name string, destroyData bool) (bool, error)
	Get(ctx context.Context, parent, name string) (*provisionv1.Volume, error)
	List(ctx context.Context, parent string) ([]*provisionv1.Volume, error)
	Close() error
}

// dialProvisioner prepares a connection to the provisioner, refusing at
// every connection a socket where anything but provisioner_uid answers.
func dialProvisioner(a *adminBlock) (volumeService, error) {
	return provisionclient.Dial(a.Provisioner, provisionclient.ServerUID(a.provisionerUID()))
}

// resolveTimeout bounds asking for one volume at a start: a provisioner that
// hangs must not hold every other share back for longer.
const resolveTimeout = 10 * time.Second

// resolveVolumes asks the provisioner for every volume share's volume and
// checks each, for a start. What fails is said, and the share waits
// unserved; the rest of the server starts.
func resolveVolumes(a *adminBlock, shares []managedShare) map[string]*volumeResolution {
	out := map[string]*volumeResolution{}
	var c volumeService
	for _, m := range shares {
		if m.Volume == nil {
			continue
		}
		key := strings.ToUpper(m.Name)
		if a.Provisioner == "" {
			out[key] = &volumeResolution{why: "the admin block names no provisioner to ask for volume " + m.Volume.String()}
			continue
		}
		if c == nil {
			var err error
			if c, err = dialProvisioner(a); err != nil {
				out[key] = &volumeResolution{why: err.Error()}
				c = nil
				continue
			}
			defer c.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		path, err := resolveVolume(ctx, c, a.SourceRoots, *m.Volume)
		cancel()
		if err != nil {
			out[key] = &volumeResolution{why: err.Error()}
			continue
		}
		out[key] = &volumeResolution{path: path}
	}
	return out
}

// resolveVolume asks the provisioner where a volume is, and checks it before
// it is served. A refusal says what kind it is: a volume that does not exist,
// a provisioner that does not answer, anything else.
func resolveVolume(ctx context.Context, c volumeService, roots []string, ref volumeRef) (string, error) {
	v, err := c.Get(ctx, ref.Parent, ref.Name)
	if err != nil {
		st, _ := status.FromError(err)
		switch st.Code() {
		case codes.NotFound:
			return "", refuse(refusedNotFound, "volume %s does not exist (the provisioner: %s)", ref, st.Message())
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
			return "", refuse(refusedUnavailable, "the provisioner did not answer for volume %s: %s", ref, st.Message())
		case codes.InvalidArgument:
			return "", refuse(refusedInvalid, "volume %s: %s", ref, st.Message())
		}
		return "", refuse(refusedPrecondition, "volume %s: the provisioner: %s: %s", ref, st.Code(), st.Message())
	}
	path, err := checkVolume(volumeFound{ref: ref, kind: kindName(v.GetKind()), path: v.GetPath()}, roots)
	if err != nil {
		return "", refuse(refusedPrecondition, "%v", err)
	}
	return path, nil
}

func kindName(k provisionv1.Kind) string {
	switch k {
	case provisionv1.Kind_KIND_ZFS:
		return kindZFS
	case provisionv1.Kind_KIND_BTRFS:
		return kindBtrfs
	case provisionv1.Kind_KIND_XFS:
		return kindXFS
	case provisionv1.Kind_KIND_EXT4:
		return kindExt4
	}
	return k.String()
}

// The provisioner's kinds are the admin API's, number for number: the two
// enums are kept apart so that the provisioner's protocol, which runs
// privileged and refuses unknown fields, never has to change for the API's
// sake.
func kindView(k provisionv1.Kind) adminv1.VolumeKind { return adminv1.VolumeKind(k) }

// errNoProvisioner is every volume call on a server with none.
var errNoProvisioner = status.Error(codes.FailedPrecondition,
	"no provisioner configured: name one in the admin block (provisioner = \"unix:///run/fileshare-provisioner/provisioner.sock\")")

// relayed is a provisioner's error as the admin API answers it: its code, as
// given -- except a refusal of THIS server's uid, which is not the caller's
// to fix by asking differently, and is a precondition of the deployment.
func relayed(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return status.Errorf(codes.Unavailable, "the provisioner: %v", err)
	}
	switch st.Code() {
	case codes.PermissionDenied, codes.Unauthenticated:
		return status.Errorf(codes.FailedPrecondition, "the provisioner refuses this server (its client_uid is not "+
			"the uid `fileshare serve` runs as): %s", st.Message())
	}
	return status.Error(st.Code(), "the provisioner: "+st.Message())
}

// nameGrammar is the provisioner's own, checked here too so a refusal names
// the field before anything is asked of anybody.
var nameGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func checkVolumeRef(parent, name string) error {
	if parent == "" || len(parent) > 64 || strings.ContainsFunc(parent, notPrintable) {
		return status.Errorf(codes.InvalidArgument, "%q is not a parent: name one ListParents lists", parent)
	}
	if !nameGrammar.MatchString(name) {
		return status.Errorf(codes.InvalidArgument, "%q is not a volume name: ^[a-z0-9][a-z0-9_-]{0,62}$", name)
	}
	return nil
}

// usersOf is the shares that use a volume: made from it, or with a source
// inside its path -- a share of the configuration files included, and those
// taken offline or waiting unserved. The caller holds m.mu.
func (m *manager) usersOf(ref volumeRef, path string) []string {
	var out []string
	for _, s := range m.state.Shares {
		if s.Volume != nil && *s.Volume == ref {
			out = append(out, s.Name)
		}
	}
	if path != "" {
		inside := filepath.Clean(path)
		if real, err := filepath.EvalSymlinks(path); err == nil {
			inside = real
		}
		all, _ := m.blocks(m.state)
		for _, b := range all {
			if !slices.Contains(out, b.Name) && pathWithin(inside, resolvedSource(b)) {
				out = append(out, b.Name)
			}
		}
	}
	slices.Sort(out)
	return out
}

func (m *manager) volumeView(v *provisionv1.Volume) *adminv1.Volume {
	if v == nil {
		return nil
	}
	return &adminv1.Volume{Parent: v.GetParent(), Name: v.GetName(), Kind: kindView(v.GetKind()),
		Path: v.GetPath(), QuotaBytes: v.GetQuotaBytes(), UsedBytes: v.GetUsedBytes(),
		Created: v.GetCreated(), Snapshots: v.GetSnapshots(),
		Shares: m.usersOf(volumeRef{v.GetParent(), v.GetName()}, v.GetPath())}
}

// viewLocked is volumeView under m.mu.
func (m *manager) viewLocked(v *provisionv1.Volume) *adminv1.Volume {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.volumeView(v)
}

// auditVolume writes what a volume call did, or would have done.
func (m *manager) auditVolume(ctx context.Context, what string, err error) {
	if err != nil {
		m.srv.stats.refused.Add(1)
		fmt.Fprintf(m.audit, "admin (%s): refused, nothing changed -- would have %s: %s\n",
			logSafe(callerOf(ctx)), logSafe(what), logSafe(status.Convert(err).Message()))
		return
	}
	m.srv.stats.applied.Add(1)
	fmt.Fprintf(m.audit, "admin (%s): %s\n", logSafe(callerOf(ctx)), logSafe(what))
}

func (a *adminService) ListParents(ctx context.Context, _ *adminv1.ListParentsRequest) (*adminv1.ListParentsResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	r, err := c.Capabilities(ctx)
	if err != nil {
		return nil, relayed(err)
	}
	out := &adminv1.ListParentsResponse{MaxVolumeBytes: r.GetMaxVolumeBytes()}
	for _, p := range r.GetParents() {
		out.Parents = append(out.Parents, &adminv1.Parent{Id: p.GetId(), Kind: kindView(p.GetKind()), Root: p.GetRoot(),
			FreeBytes: p.GetFreeBytes(), TotalBytes: p.GetTotalBytes(), Snapshots: p.GetSnapshots()})
	}
	return out, nil
}

func (a *adminService) CreateVolume(ctx context.Context, req *adminv1.CreateVolumeRequest) (*adminv1.CreateVolumeResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	if err := checkVolumeRef(req.GetParent(), req.GetName()); err != nil {
		return nil, err
	}
	what := fmt.Sprintf("created volume %s/%s of %d bytes", req.GetParent(), req.GetName(), req.GetQuotaBytes())
	v, created, err := c.Create(ctx, req.GetParent(), req.GetName(), req.GetQuotaBytes())
	if err != nil {
		err = relayed(err)
		a.m.auditVolume(ctx, what, err)
		return nil, err
	}
	if !created {
		what += " (it existed already)"
	}
	a.m.auditVolume(ctx, what, nil)
	return &adminv1.CreateVolumeResponse{Volume: a.m.viewLocked(v), Created: created}, nil
}

func (a *adminService) ResizeVolume(ctx context.Context, req *adminv1.ResizeVolumeRequest) (*adminv1.ResizeVolumeResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	if err := checkVolumeRef(req.GetParent(), req.GetName()); err != nil {
		return nil, err
	}
	what := fmt.Sprintf("resized volume %s/%s to %d bytes", req.GetParent(), req.GetName(), req.GetQuotaBytes())
	v, err := c.Resize(ctx, req.GetParent(), req.GetName(), req.GetQuotaBytes())
	if err != nil {
		err = relayed(err)
		a.m.auditVolume(ctx, what, err)
		return nil, err
	}
	a.m.auditVolume(ctx, what, nil)
	return &adminv1.ResizeVolumeResponse{Volume: a.m.viewLocked(v)}, nil
}

func (a *adminService) SnapshotVolume(ctx context.Context, req *adminv1.SnapshotVolumeRequest) (*adminv1.SnapshotVolumeResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	if err := checkVolumeRef(req.GetParent(), req.GetName()); err != nil {
		return nil, err
	}
	if !nameGrammar.MatchString(req.GetSnapshot()) {
		return nil, status.Errorf(codes.InvalidArgument, "%q is not a snapshot name: ^[a-z0-9][a-z0-9_-]{0,62}$", req.GetSnapshot())
	}
	what := fmt.Sprintf("snapshotted volume %s/%s as %s", req.GetParent(), req.GetName(), req.GetSnapshot())
	v, created, err := c.Snapshot(ctx, req.GetParent(), req.GetName(), req.GetSnapshot())
	if err != nil {
		err = relayed(err)
		a.m.auditVolume(ctx, what, err)
		return nil, err
	}
	a.m.auditVolume(ctx, what, nil)
	return &adminv1.SnapshotVolumeResponse{Volume: a.m.viewLocked(v), Created: created}, nil
}

// DeleteVolume holds the manager's lock from the question "who uses it?" to
// the provisioner's answer, so no share can be made from the volume in
// between.
func (a *adminService) DeleteVolume(ctx context.Context, req *adminv1.DeleteVolumeRequest) (*adminv1.DeleteVolumeResponse, error) {
	m := a.m
	c := m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	if err := checkVolumeRef(req.GetParent(), req.GetName()); err != nil {
		return nil, err
	}
	ref := volumeRef{req.GetParent(), req.GetName()}
	what := "deleted volume " + ref.String()
	if req.GetDestroyData() {
		what += ", its data and its snapshots"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var path string
	v, err := c.Get(ctx, ref.Parent, ref.Name)
	switch {
	case err == nil:
		path = v.GetPath()
	case status.Code(err) != codes.NotFound:
		err = relayed(err)
		m.auditVolume(ctx, what, err)
		return nil, err
	}
	if users := m.usersOf(ref, path); len(users) > 0 {
		err := status.Errorf(codes.FailedPrecondition, "volume %s is used by %s: delete the share first "+
			"(DeleteShare never deletes a volume)", ref, list(users))
		m.auditVolume(ctx, what, err)
		return nil, err
	}
	deleted, err := c.Delete(ctx, ref.Parent, ref.Name, req.GetDestroyData())
	if err != nil {
		err = relayed(err)
		m.auditVolume(ctx, what, err)
		return nil, err
	}
	if !deleted {
		what += " (there was none)"
	}
	m.auditVolume(ctx, what, nil)
	return &adminv1.DeleteVolumeResponse{Deleted: deleted}, nil
}

func (a *adminService) GetVolume(ctx context.Context, req *adminv1.GetVolumeRequest) (*adminv1.GetVolumeResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	if err := checkVolumeRef(req.GetParent(), req.GetName()); err != nil {
		return nil, err
	}
	v, err := c.Get(ctx, req.GetParent(), req.GetName())
	if err != nil {
		return nil, relayed(err)
	}
	return &adminv1.GetVolumeResponse{Volume: a.m.viewLocked(v)}, nil
}

func (a *adminService) ListVolumes(ctx context.Context, req *adminv1.ListVolumesRequest) (*adminv1.ListVolumesResponse, error) {
	c := a.m.vols
	if c == nil {
		return nil, errNoProvisioner
	}
	vs, err := c.List(ctx, req.GetParent())
	if err != nil {
		return nil, relayed(err)
	}
	out := &adminv1.ListVolumesResponse{}
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	for _, v := range vs {
		out.Volumes = append(out.Volumes, a.m.volumeView(v))
	}
	return out, nil
}

// resolveFor is resolveVolume on this manager's provisioner, for a change
// that serves a volume: CreateShare, EnableShare.
func (m *manager) resolveFor(ctx context.Context, ref volumeRef) (*volumeResolution, error) {
	if m.vols == nil {
		return nil, refuse(refusedPrecondition, "no provisioner configured: name one in the admin block to serve volume %s", ref)
	}
	path, err := resolveVolume(ctx, m.vols, m.roots, ref)
	if err != nil {
		return nil, err
	}
	return &volumeResolution{path: path}, nil
}
