// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provisionclient

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-fileshare/fileshare/internal/peercred"
	pb "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// echo is a provisioner that answers with what it was asked, and says who
// asked: what is under test here is the client's half of the wire.
type echo struct {
	pb.UnimplementedProvisionServiceServer
}

func uidOf(ctx context.Context) uint32 {
	a, _ := peercred.FromContext(ctx)
	return a.UID
}

func (echo) GetCapabilities(ctx context.Context, _ *pb.GetCapabilitiesRequest) (*pb.GetCapabilitiesResponse, error) {
	return &pb.GetCapabilitiesResponse{MaxVolumeBytes: uint64(uidOf(ctx))}, nil
}
func (echo) CreateVolume(_ context.Context, r *pb.CreateVolumeRequest) (*pb.CreateVolumeResponse, error) {
	if r.GetQuotaBytes() == 0 {
		return nil, status.Error(codes.InvalidArgument, "0")
	}
	return &pb.CreateVolumeResponse{Volume: &pb.Volume{Parent: r.GetParent(), Name: r.GetName(), QuotaBytes: r.GetQuotaBytes()}, Created: true}, nil
}
func (echo) ResizeVolume(_ context.Context, r *pb.ResizeVolumeRequest) (*pb.ResizeVolumeResponse, error) {
	return &pb.ResizeVolumeResponse{Volume: &pb.Volume{Name: r.GetName(), QuotaBytes: r.GetQuotaBytes()}}, nil
}
func (echo) SnapshotVolume(_ context.Context, r *pb.SnapshotVolumeRequest) (*pb.SnapshotVolumeResponse, error) {
	if r.GetSnapshot() == "" {
		return nil, status.Error(codes.InvalidArgument, "no name")
	}
	return &pb.SnapshotVolumeResponse{Volume: &pb.Volume{Name: r.GetName(), Snapshots: []string{r.GetSnapshot()}}, Created: true}, nil
}
func (echo) DeleteVolume(_ context.Context, r *pb.DeleteVolumeRequest) (*pb.DeleteVolumeResponse, error) {
	return &pb.DeleteVolumeResponse{Deleted: r.GetDestroyData()}, nil
}
func (echo) GetVolume(_ context.Context, r *pb.GetVolumeRequest) (*pb.GetVolumeResponse, error) {
	return &pb.GetVolumeResponse{Volume: &pb.Volume{Parent: r.GetParent(), Name: r.GetName()}}, nil
}
func (echo) ListVolumes(_ context.Context, r *pb.ListVolumesRequest) (*pb.ListVolumesResponse, error) {
	return &pb.ListVolumesResponse{Volumes: []*pb.Volume{{Parent: r.GetParent()}}}, nil
}

func serve(t *testing.T) string {
	t.Helper()
	base := ""
	if st, err := os.Stat("/tmp"); err == nil && st.IsDir() {
		base = "/tmp"
	}
	d, err := os.MkdirTemp(base, "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(peercred.New()))
	pb.RegisterProvisionServiceServer(gs, echo{})
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)
	return sock
}

func TestEveryCall(t *testing.T) {
	sock := serve(t)
	c, err := Dial(sock, ServerUID(uint32(os.Getuid())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	caps, err := c.Capabilities(ctx)
	if err != nil || caps.GetMaxVolumeBytes() != uint64(os.Getuid()) {
		t.Fatalf("capabilities = %v, %v (the server saw the wrong uid?)", caps, err)
	}
	if v, created, err := c.Create(ctx, "p", "n", 5); err != nil || !created || v.GetQuotaBytes() != 5 || v.GetName() != "n" {
		t.Errorf("create = %v, %v, %v", v, created, err)
	}
	if _, _, err := c.Create(ctx, "p", "n", 0); status.Code(err) != codes.InvalidArgument {
		t.Errorf("create's error = %v", err)
	}
	if v, err := c.Resize(ctx, "p", "n", 9); err != nil || v.GetQuotaBytes() != 9 {
		t.Errorf("resize = %v, %v", v, err)
	}
	if v, created, err := c.Snapshot(ctx, "p", "n", "s"); err != nil || !created || v.GetSnapshots()[0] != "s" {
		t.Errorf("snapshot = %v, %v, %v", v, created, err)
	}
	if _, _, err := c.Snapshot(ctx, "p", "n", ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("snapshot's error = %v", err)
	}
	if ok, err := c.Delete(ctx, "p", "n", true); err != nil || !ok {
		t.Errorf("delete = %v, %v", ok, err)
	}
	if v, err := c.Get(ctx, "p", "n"); err != nil || v.GetParent() != "p" {
		t.Errorf("get = %v, %v", v, err)
	}
	if l, err := c.List(ctx, "p"); err != nil || len(l) != 1 || l[0].GetParent() != "p" {
		t.Errorf("list = %v, %v", l, err)
	}
	if c.Conn() == nil {
		t.Error("no conn")
	}
}

func TestDialForms(t *testing.T) {
	sock := serve(t)
	for _, target := range []string{sock, "unix://" + sock} {
		c, err := Dial(target)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := c.Capabilities(ctx); err != nil {
			t.Errorf("%s: %v", target, err)
		}
		cancel()
		c.Close()
	}
	if _, err := Dial("relative.sock"); err == nil {
		t.Error("a relative path was accepted")
	}
	if _, err := Dial("unix://"+sock, WithDialOption(grpc.WithUserAgent("x"))); err != nil {
		t.Error(err)
	}
}

// A socket where somebody else answers is refused before any call is made.
func TestTheWrongServerIsRefused(t *testing.T) {
	sock := serve(t)
	c, err := Dial(sock, ServerUID(uint32(os.Getuid())+1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Capabilities(ctx); err == nil {
		t.Fatal("answered by the wrong uid")
	}
}
