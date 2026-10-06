// SPDX-License-Identifier: BSD-3-Clause

// Package provisionclient is how `fileshare serve` talks to `fileshare
// provisioner`: a unix socket, typed calls, and nothing that could carry a
// path. See proto/fileshare/provision/v1/provision.proto for what each call
// promises, and the status codes it answers with.
package provisionclient

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/go-fileshare/fileshare/internal/peercred"
	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// Client is a connection to a provisioner. It is safe for concurrent use;
// the provisioner serializes the changes itself.
type Client struct {
	conn *grpc.ClientConn
	api  provisionv1.ProvisionServiceClient
}

// An Option changes how Dial connects.
type Option func(*options)

type options struct {
	creds credentials.TransportCredentials
	extra []grpc.DialOption
}

// ServerUID refuses a socket where something other than uid answers. A
// provisioner normally runs as root, and the socket's directory is root's;
// this is the check that does not depend on either.
func ServerUID(uid uint32) Option {
	return func(o *options) { o.creds = peercred.RequireServer(uid) }
}

// WithDialOption passes a gRPC dial option through, for the tests.
func WithDialOption(d grpc.DialOption) Option {
	return func(o *options) { o.extra = append(o.extra, d) }
}

// Dial prepares a connection to the provisioner on socket, which is
// "unix:///path" or an absolute path. Like grpc.NewClient it does not
// connect: the first call does, and fails if nothing answers.
func Dial(socket string, opts ...Option) (*Client, error) {
	o := options{creds: peercred.New()}
	for _, f := range opts {
		f(&o)
	}
	target := socket
	if !strings.HasPrefix(target, "unix://") {
		if !strings.HasPrefix(target, "/") {
			return nil, fmt.Errorf("provisioner socket %q: want unix:///path or an absolute path", socket)
		}
		target = "unix://" + target
	}
	conn, err := grpc.NewClient(target, append([]grpc.DialOption{grpc.WithTransportCredentials(o.creds)}, o.extra...)...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, api: provisionv1.NewProvisionServiceClient(conn)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Capabilities lists the parents and the limits.
func (c *Client) Capabilities(ctx context.Context) (*provisionv1.GetCapabilitiesResponse, error) {
	return c.api.GetCapabilities(ctx, &provisionv1.GetCapabilitiesRequest{})
}

// Create creates parent/name with quota bytes, or answers with the volume
// that exists with that quota already (created false).
func (c *Client) Create(ctx context.Context, parent, name string, quota uint64) (v *provisionv1.Volume, created bool, err error) {
	r, err := c.api.CreateVolume(ctx, &provisionv1.CreateVolumeRequest{Parent: parent, Name: name, QuotaBytes: quota})
	if err != nil {
		return nil, false, err
	}
	return r.GetVolume(), r.GetCreated(), nil
}

// Resize changes a volume's quota.
func (c *Client) Resize(ctx context.Context, parent, name string, quota uint64) (*provisionv1.Volume, error) {
	r, err := c.api.ResizeVolume(ctx, &provisionv1.ResizeVolumeRequest{Parent: parent, Name: name, QuotaBytes: quota})
	return r.GetVolume(), err
}

// Snapshot takes a read-only snapshot of a ZFS or btrfs volume.
func (c *Client) Snapshot(ctx context.Context, parent, name, snapshot string) (v *provisionv1.Volume, created bool, err error) {
	r, err := c.api.SnapshotVolume(ctx, &provisionv1.SnapshotVolumeRequest{Parent: parent, Name: name, Snapshot: snapshot})
	if err != nil {
		return nil, false, err
	}
	return r.GetVolume(), r.GetCreated(), nil
}

// Delete deletes a volume; deleted is false when there was none. Without
// destroyData a volume holding data or snapshots is refused.
func (c *Client) Delete(ctx context.Context, parent, name string, destroyData bool) (deleted bool, err error) {
	r, err := c.api.DeleteVolume(ctx, &provisionv1.DeleteVolumeRequest{Parent: parent, Name: name, DestroyData: destroyData})
	return r.GetDeleted(), err
}

// Get returns one volume.
func (c *Client) Get(ctx context.Context, parent, name string) (*provisionv1.Volume, error) {
	r, err := c.api.GetVolume(ctx, &provisionv1.GetVolumeRequest{Parent: parent, Name: name})
	return r.GetVolume(), err
}

// List returns the volumes of parent, or of every parent when it is "".
func (c *Client) List(ctx context.Context, parent string) ([]*provisionv1.Volume, error) {
	r, err := c.api.ListVolumes(ctx, &provisionv1.ListVolumesRequest{Parent: parent})
	return r.GetVolumes(), err
}

// Conn is the underlying connection, for a caller that needs the raw
// service -- or, in a test, a method the provisioner does not have.
func (c *Client) Conn() *grpc.ClientConn { return c.conn }
