// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-fileshare/fileshare/internal/peercred"
	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// service is the ProvisionService. One lock serializes every call: they are
// rare, an operator's or an API's pace, and a provisioner that never runs
// two changes at once never has to reason about two allocations of one
// project id, or a delete racing a resize.
type service struct {
	provisionv1.UnimplementedProvisionServiceServer

	mu       sync.Mutex
	cfg      *Config
	st       *state
	backends map[string]backend
	logf     func(format string, args ...any)
	now      func() time.Time
}

// parentOf resolves a request's parent id, which is the only way a request
// can point anywhere: a path is never accepted.
func (s *service) parentOf(id string) (*ParentBlock, backend, error) {
	p := s.cfg.parent(id)
	if p == nil {
		return nil, nil, refuse(codes.InvalidArgument, "there is no parent %q", id)
	}
	return p, s.backends[id], nil
}

// target checks a request's parent and name.
func (s *service) target(parent, name string) (*ParentBlock, backend, error) {
	if err := checkName("a volume", name); err != nil {
		return nil, nil, err
	}
	return s.parentOf(parent)
}

func (s *service) checkQuota(q uint64) error {
	if q == 0 {
		return refuse(codes.InvalidArgument, "quota_bytes = 0: an unbounded volume is a configuration mistake, not a request")
	}
	if q > s.cfg.maxVolume {
		return refuse(codes.OutOfRange, "quota_bytes = %d is above max_volume (%d)", q, s.cfg.maxVolume)
	}
	return nil
}

// checkRoom refuses a quota the parent cannot hold now. It is a check on the
// request, not a reservation: quotas are limits, and the space is taken when
// it is written. A parent whose free space cannot be read is not refused for
// it.
func (s *service) checkRoom(b backend, want uint64) error {
	free, _, err := b.space()
	if err == nil && want > free {
		return refuse(codes.ResourceExhausted, "the parent has %d bytes free, and %d were asked", free, want)
	}
	return nil
}

func (s *service) volume(p *ParentBlock, b backend, r *record) *provisionv1.Volume {
	v := &provisionv1.Volume{Parent: r.Parent, Name: r.Name, Kind: b.kind(),
		Path: filepath.Join(p.root, r.Name), QuotaBytes: r.Quota, Created: timestamppb.New(r.Created)}
	if used, err := b.used(r); err == nil {
		v.UsedBytes = used
	}
	if snaps, err := b.snapshots(r); err == nil {
		v.Snapshots = snaps
	}
	return v
}

// allocate gives out the lowest project id of the parent's range that no
// record holds -- a pending one included. An id goes back to the range only
// when the record holding it is removed, after its limits were lifted.
func (s *service) allocate(p *ParentBlock) (uint32, error) {
	held := map[uint32]bool{}
	for _, r := range s.st.vols {
		if r.ProjectID != 0 {
			held[r.ProjectID] = true
		}
	}
	for id := uint64(p.lo); id <= uint64(p.hi); id++ {
		if !held[uint32(id)] {
			return uint32(id), nil
		}
	}
	return 0, refuse(codes.ResourceExhausted, "parent %q has given out every project id of %s", p.ID, p.ProjectIDs)
}

func peerOf(ctx context.Context) string {
	if a, ok := peercred.FromContext(ctx); ok {
		return "uid " + strconv.FormatUint(uint64(a.UID), 10) + " pid " + strconv.FormatInt(int64(a.PID), 10)
	}
	return "an unknown peer"
}

func (s *service) GetCapabilities(context.Context, *provisionv1.GetCapabilitiesRequest) (*provisionv1.GetCapabilitiesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &provisionv1.GetCapabilitiesResponse{MaxVolumeBytes: s.cfg.maxVolume}
	for i := range s.cfg.Parents {
		p := &s.cfg.Parents[i]
		b := s.backends[p.ID]
		pp := &provisionv1.Parent{Id: p.ID, Kind: b.kind(), Root: p.root, Snapshots: b.canSnapshot()}
		if free, total, err := b.space(); err == nil {
			pp.FreeBytes, pp.TotalBytes = free, total
		}
		out.Parents = append(out.Parents, pp)
	}
	return out, nil
}

func (s *service) CreateVolume(ctx context.Context, req *provisionv1.CreateVolumeRequest) (*provisionv1.CreateVolumeResponse, error) {
	v, created, err := s.create(ctx, req)
	if err != nil {
		return nil, statusOf(err)
	}
	return &provisionv1.CreateVolumeResponse{Volume: v, Created: created}, nil
}

func (s *service) create(ctx context.Context, req *provisionv1.CreateVolumeRequest) (*provisionv1.Volume, bool, error) {
	p, b, err := s.target(req.GetParent(), req.GetName())
	if err != nil {
		return nil, false, err
	}
	if err := s.checkQuota(req.GetQuotaBytes()); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, quota := req.GetName(), req.GetQuotaBytes()

	r := s.st.get(p.ID, name)
	switch {
	case r != nil && r.Quota != quota:
		return nil, false, refuse(codes.AlreadyExists, "volume %s/%s exists with quota_bytes = %d", p.ID, name, r.Quota)
	case r != nil && !r.Pending:
		if err := b.owned(r); err != nil {
			return nil, false, ownership(p.ID, name, err)
		}
		return s.volume(p, b, r), false, nil
	case r == nil:
		probe := &record{Parent: p.ID, Name: name, Kind: kindName(b.kind())}
		there, err := b.present(probe)
		if err != nil {
			return nil, false, err
		}
		if there {
			// Something is already where the volume would be. A ZFS
			// dataset carrying our own mark is ours even if the record was
			// lost; anything else was not made here and is not touched.
			if err := b.owned(probe); err != nil {
				return nil, false, refuse(codes.AlreadyExists, "%s/%s is taken by something this provisioner did not create (%v)", p.ID, name, err)
			}
			q, err := b.quota(probe)
			if err != nil {
				return nil, false, err
			}
			probe.Quota, probe.Created = q, s.now().UTC()
			s.st.put(probe)
			if err := s.st.save(); err != nil {
				return nil, false, err
			}
			s.logf("volume %s/%s: found with its mark and no record, and recorded again", p.ID, name)
			if q != quota {
				return nil, false, refuse(codes.AlreadyExists, "volume %s/%s exists with quota_bytes = %d", p.ID, name, q)
			}
			return s.volume(p, b, probe), false, nil
		}
		if err := s.checkRoom(b, quota); err != nil {
			return nil, false, err
		}
		r = &record{Parent: p.ID, Name: name, Kind: kindName(b.kind()), Quota: quota, Created: s.now().UTC(), Pending: true}
		if p.hi != 0 {
			if r.ProjectID, err = s.allocate(p); err != nil {
				return nil, false, err
			}
		}
		s.st.put(r)
		if err := s.st.save(); err != nil {
			s.st.remove(p.ID, name)
			return nil, false, err
		}
	}

	// r is pending: new, or left by a creation that did not finish.
	s.logf("create volume %s/%s quota_bytes=%d for %s", p.ID, name, quota, peerOf(ctx))
	if err := b.create(r); err != nil {
		if errors.Is(err, errNotOurs) {
			return nil, false, refuse(codes.AlreadyExists, "%s/%s: %v", p.ID, name, err)
		}
		// Nothing made: the record goes, and its project id with it. Made
		// in part: the record stays pending, for a retry or a delete.
		if there, perr := b.present(r); perr == nil && !there {
			s.st.remove(p.ID, name)
			if serr := s.st.save(); serr != nil {
				s.logf("volume %s/%s: %v", p.ID, name, serr)
			}
		}
		return nil, false, err
	}
	r.Pending = false
	if err := s.st.save(); err != nil {
		return nil, false, err
	}
	return s.volume(p, b, r), true, nil
}

// ownership turns an ownership check's answer about a recorded volume into a
// status.
func ownership(parent, name string, err error) error {
	switch {
	case errors.Is(err, errAbsent):
		return refuse(codes.FailedPrecondition, "volume %s/%s is recorded and is not there any more", parent, name)
	case errors.Is(err, errNotOurs):
		return refuse(codes.FailedPrecondition, "volume %s/%s: %v; it is not touched", parent, name, err)
	}
	return err
}

// recorded is a finished volume of the request, checked to be ours.
func (s *service) recorded(parent, name string) (*ParentBlock, backend, *record, error) {
	p, b, err := s.target(parent, name)
	if err != nil {
		return nil, nil, nil, err
	}
	r := s.st.get(p.ID, name)
	if r == nil {
		return nil, nil, nil, refuse(codes.NotFound, "there is no volume %s/%s", p.ID, name)
	}
	if r.Pending {
		return nil, nil, nil, refuse(codes.FailedPrecondition, "volume %s/%s was not finished: CreateVolume it again, or DeleteVolume it", p.ID, name)
	}
	if err := b.owned(r); err != nil {
		return nil, nil, nil, ownership(p.ID, name, err)
	}
	return p, b, r, nil
}

func (s *service) ResizeVolume(ctx context.Context, req *provisionv1.ResizeVolumeRequest) (*provisionv1.ResizeVolumeResponse, error) {
	if err := s.checkQuota(req.GetQuotaBytes()); err != nil {
		return nil, statusOf(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, b, r, err := s.recorded(req.GetParent(), req.GetName())
	if err != nil {
		return nil, statusOf(err)
	}
	quota := req.GetQuotaBytes()
	if quota != r.Quota {
		used, err := b.used(r)
		if err != nil {
			return nil, statusOf(err)
		}
		if quota < used {
			return nil, statusOf(refuse(codes.FailedPrecondition, "volume %s/%s uses %d bytes, more than %d", p.ID, r.Name, used, quota))
		}
		if quota > r.Quota {
			if err := s.checkRoom(b, quota-r.Quota); err != nil {
				return nil, statusOf(err)
			}
		}
		s.logf("resize volume %s/%s quota_bytes=%d->%d for %s", p.ID, r.Name, r.Quota, quota, peerOf(ctx))
		if err := b.resize(r, quota); err != nil {
			return nil, statusOf(err)
		}
		r.Quota = quota
		if err := s.st.save(); err != nil {
			return nil, statusOf(err)
		}
	}
	return &provisionv1.ResizeVolumeResponse{Volume: s.volume(p, b, r)}, nil
}

func (s *service) SnapshotVolume(ctx context.Context, req *provisionv1.SnapshotVolumeRequest) (*provisionv1.SnapshotVolumeResponse, error) {
	if err := checkName("a snapshot", req.GetSnapshot()); err != nil {
		return nil, statusOf(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, b, r, err := s.recorded(req.GetParent(), req.GetName())
	if err != nil {
		return nil, statusOf(err)
	}
	if !b.canSnapshot() {
		return nil, statusOf(refuse(codes.Unimplemented, "a %s volume has no snapshots", kindName(b.kind())))
	}
	snaps, err := b.snapshots(r)
	if err != nil {
		return nil, statusOf(err)
	}
	if slices.Contains(snaps, req.GetSnapshot()) {
		return &provisionv1.SnapshotVolumeResponse{Volume: s.volume(p, b, r)}, nil
	}
	s.logf("snapshot volume %s/%s@%s for %s", p.ID, r.Name, req.GetSnapshot(), peerOf(ctx))
	if err := b.snapshot(r, req.GetSnapshot()); err != nil {
		return nil, statusOf(err)
	}
	if err := s.st.save(); err != nil {
		return nil, statusOf(err)
	}
	return &provisionv1.SnapshotVolumeResponse{Volume: s.volume(p, b, r), Created: true}, nil
}

func (s *service) DeleteVolume(ctx context.Context, req *provisionv1.DeleteVolumeRequest) (*provisionv1.DeleteVolumeResponse, error) {
	deleted, err := s.delete(ctx, req)
	if err != nil {
		return nil, statusOf(err)
	}
	return &provisionv1.DeleteVolumeResponse{Deleted: deleted}, nil
}

func (s *service) delete(ctx context.Context, req *provisionv1.DeleteVolumeRequest) (bool, error) {
	p, b, err := s.target(req.GetParent(), req.GetName())
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := req.GetName()
	r := s.st.get(p.ID, name)
	if r == nil {
		// Not recorded. Nothing there is CSI's OK. A ZFS dataset with our
		// own mark lost its record and is still ours; anything else is not.
		r = &record{Parent: p.ID, Name: name, Kind: kindName(b.kind())}
		there, err := b.present(r)
		if err != nil {
			return false, err
		}
		if !there {
			return false, nil
		}
		if err := b.owned(r); err != nil {
			return false, refuse(codes.FailedPrecondition, "%s/%s was not created by this provisioner (%v); it is not touched", p.ID, name, err)
		}
	}
	err = b.owned(r)
	switch {
	case errors.Is(err, errAbsent):
		// Gone already: forget it, and lift what limits it had.
		s.logf("audit: delete volume %s/%s (already absent) for %s", p.ID, name, peerOf(ctx))
		if err := b.destroy(r, nil); err != nil {
			return false, err
		}
		return false, s.forget(r)
	case err != nil:
		return false, ownership(p.ID, name, err)
	}
	snaps, err := b.snapshots(r)
	if err != nil {
		return false, err
	}
	if len(snaps) > 0 && !req.GetDestroyData() {
		return false, refuse(codes.FailedPrecondition, "volume %s/%s has %d snapshots; destroy_data = true deletes them with it", p.ID, name, len(snaps))
	}
	if !req.GetDestroyData() {
		empty, err := b.empty(r)
		if err != nil {
			return false, err
		}
		if !empty {
			return false, refuse(codes.FailedPrecondition, "volume %s/%s is not empty; destroy_data = true deletes what is in it", p.ID, name)
		}
	}
	// ⛔ Logged BEFORE: a delete that crashes half way is still in the log.
	s.logf("audit: delete volume %s/%s kind=%s path=%s snapshots=%d destroy_data=%v for %s",
		p.ID, name, kindName(b.kind()), filepath.Join(p.root, name), len(snaps), req.GetDestroyData(), peerOf(ctx))
	if err := b.destroy(r, snaps); err != nil {
		return false, fmt.Errorf("deleting %s/%s: %w", p.ID, name, err)
	}
	return true, s.forget(r)
}

func (s *service) forget(r *record) error {
	s.st.remove(r.Parent, r.Name)
	return s.st.save()
}

func (s *service) GetVolume(_ context.Context, req *provisionv1.GetVolumeRequest) (*provisionv1.GetVolumeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, b, r, err := s.recorded(req.GetParent(), req.GetName())
	if err != nil {
		return nil, statusOf(err)
	}
	return &provisionv1.GetVolumeResponse{Volume: s.volume(p, b, r)}, nil
}

// ListVolumes lists the finished volumes the state records. A pending one is
// not a volume yet.
func (s *service) ListVolumes(_ context.Context, req *provisionv1.ListVolumesRequest) (*provisionv1.ListVolumesResponse, error) {
	if req.GetParent() != "" {
		if _, _, err := s.parentOf(req.GetParent()); err != nil {
			return nil, statusOf(err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &provisionv1.ListVolumesResponse{}
	for _, r := range s.st.vols {
		if r.Pending || req.GetParent() != "" && r.Parent != req.GetParent() {
			continue
		}
		p, b, _ := s.parentOf(r.Parent)
		out.Volumes = append(out.Volumes, s.volume(p, b, r))
	}
	return out, nil
}
