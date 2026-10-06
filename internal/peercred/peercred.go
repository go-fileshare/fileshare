// SPDX-License-Identifier: BSD-3-Clause

// Package peercred is gRPC transport credentials for a unix socket that say
// WHO is at the other end: the uid, gid and pid the kernel recorded for the
// peer when it connected (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS).
//
// ⛔ grpc-go's credentials/local does not do this. It tells a unix socket from
// a TCP one and reports a security level, and the uid is not in its AuthInfo
// -- so a server built on it can say "somebody local" and never "fileshare".
// The provisioner must say the second: it answers one uid, and the socket's
// mode alone is a file permission any root process can widen.
//
// Nothing is encrypted and nothing needs to be: the bytes never leave the
// kernel. What these credentials add is the identity, read once at the
// handshake. The kernel records it at connect(2), so a peer cannot change it
// afterwards by changing its own uid, nor pass the connection to another
// process and have the new holder's uid reported.
package peercred

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// AuthInfo is what the handshake learned about the peer. The server finds it
// in a call's peer.Peer (FromContext).
type AuthInfo struct {
	credentials.CommonAuthInfo
	UID uint32
	GID uint32
	// PID is the peer's process id, or -1 where the system does not report
	// one. It is for logs only: a pid can be reused once its process exits.
	PID int32

	conn *closeOnce
}

// AuthType is "peercred".
func (AuthInfo) AuthType() string { return "peercred" }

// CloseConn closes the connection this AuthInfo was read from -- the whole
// transport, not one call. It is how a server that keeps a closed set of
// verbs answers anything outside it: there is no reply, the peer just loses
// its connection.
func (a AuthInfo) CloseConn() error {
	if a.conn == nil {
		return errors.New("peercred: no connection to close")
	}
	return a.conn.close()
}

// closeOnce lets several callers close one connection.
type closeOnce struct {
	once sync.Once
	c    net.Conn
	err  error
}

func (c *closeOnce) close() error {
	c.once.Do(func() { c.err = c.c.Close() })
	return c.err
}

// FromContext returns the peer credentials of a call's connection.
func FromContext(ctx context.Context) (AuthInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return AuthInfo{}, false
	}
	a, ok := p.AuthInfo.(AuthInfo)
	return a, ok
}

type creds struct {
	// serverUID, when set, is the only uid a CLIENT accepts at the other end:
	// a socket where something else answers is a socket somebody replaced.
	serverUID *uint32
}

// New returns credentials that read the peer's identity and accept any. A
// server checks the uid it needs per call; a client made with New accepts
// whatever answers.
func New() credentials.TransportCredentials { return &creds{} }

// RequireServer returns client credentials that refuse the connection unless
// the process answering on the socket runs as uid.
func RequireServer(uid uint32) credentials.TransportCredentials {
	return &creds{serverUID: &uid}
}

// ErrNotUnix is returned for a connection that is not a unix socket: only a
// unix socket has a peer the kernel can name.
var ErrNotUnix = errors.New("peercred: not a unix socket connection")

func (c *creds) handshake(conn net.Conn) (net.Conn, AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, AuthInfo{}, fmt.Errorf("%w (%T)", ErrNotUnix, conn)
	}
	uid, gid, pid, err := peerOf(uc)
	if err != nil {
		return nil, AuthInfo{}, fmt.Errorf("peercred: reading the peer's credentials: %w", err)
	}
	return conn, AuthInfo{
		// The bytes never leave the kernel, which is what the local
		// credentials of grpc-go call PrivacyAndIntegrity for a unix socket.
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		UID:            uid, GID: gid, PID: pid,
		conn: &closeOnce{c: conn},
	}, nil
}

func (c *creds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, ai, err := c.handshake(conn)
	if err != nil {
		return nil, nil, err
	}
	if c.serverUID != nil && ai.UID != *c.serverUID {
		conn.Close()
		return nil, nil, fmt.Errorf("peercred: the process answering runs as uid %d, not %d", ai.UID, *c.serverUID)
	}
	return conn, ai, nil
}

func (c *creds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, ai, err := c.handshake(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, ai, nil
}

func (c *creds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (c *creds) Clone() credentials.TransportCredentials {
	n := *c
	return &n
}

// OverrideServerName is meaningless on a unix socket.
func (c *creds) OverrideServerName(string) error { return nil }
