// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package peercred

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// socketDir is short on purpose: a unix socket's path is limited to about a
// hundred bytes, and a Mac's per-user temporary directory uses half of it.
func socketDir(t *testing.T) string {
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
	return d
}

// pair is one connection seen from both ends.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(socketDir(t), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		got <- c
	}()
	client, err = net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-got
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func TestTheServerSeesTheClientsUID(t *testing.T) {
	_, s := pair(t)
	_, ai, err := New().ServerHandshake(s)
	if err != nil {
		t.Fatal(err)
	}
	a := ai.(AuthInfo)
	if a.UID != uint32(os.Getuid()) {
		t.Errorf("uid = %d, want %d (this process)", a.UID, os.Getuid())
	}
	if a.GID != uint32(os.Getgid()) {
		// Not an error everywhere: LOCAL_PEERCRED reports the first of the
		// groups, which is the effective gid on every Mac seen so far.
		t.Logf("gid = %d, this process's is %d", a.GID, os.Getgid())
	}
	if a.PID != int32(os.Getpid()) && a.PID != -1 {
		t.Errorf("pid = %d, want %d", a.PID, os.Getpid())
	}
	if a.AuthType() != "peercred" || a.SecurityLevel != credentials.PrivacyAndIntegrity {
		t.Errorf("AuthType %q, level %v", a.AuthType(), a.SecurityLevel)
	}
}

func TestAClientCanRequireTheServersUID(t *testing.T) {
	c, _ := pair(t)
	me := uint32(os.Getuid())
	if _, ai, err := RequireServer(me).ClientHandshake(context.Background(), "x", c); err != nil || ai.(AuthInfo).UID != me {
		t.Fatalf("own uid refused: %v", err)
	}

	c, s := pair(t)
	if _, _, err := RequireServer(me+1).ClientHandshake(context.Background(), "x", c); err == nil {
		t.Fatal("a server running as another uid was accepted")
	}
	// The refusal closes the connection: the server reads EOF.
	if _, err := s.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("server read after the refusal: %v, want EOF", err)
	}

	c, _ = pair(t)
	if _, _, err := New().ClientHandshake(context.Background(), "x", c); err != nil {
		t.Errorf("New() as a client refused: %v", err)
	}
}

func TestOnlyAUnixSocketHasAPeer(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, err := New().ServerHandshake(a); !errors.Is(err, ErrNotUnix) {
		t.Errorf("server over a pipe: %v, want ErrNotUnix", err)
	}
	if _, _, err := New().ClientHandshake(context.Background(), "x", b); !errors.Is(err, ErrNotUnix) {
		t.Errorf("client over a pipe: %v, want ErrNotUnix", err)
	}
	// A closed unix connection cannot be asked either.
	_, s := pair(t)
	s.Close()
	if _, _, err := New().ServerHandshake(s); err == nil {
		t.Error("a closed connection reported a peer")
	}
}

func TestCloseConnClosesTheTransportOnce(t *testing.T) {
	c, s := pair(t)
	_, ai, err := New().ServerHandshake(s)
	if err != nil {
		t.Fatal(err)
	}
	a := ai.(AuthInfo)
	if err := a.CloseConn(); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseConn(); err != nil {
		t.Errorf("a second close: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("client read after CloseConn: %v, want EOF", err)
	}
	if err := (AuthInfo{}).CloseConn(); err == nil {
		t.Error("an AuthInfo with no connection closed something")
	}
}

func TestFromContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Error("a context with no peer had credentials")
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{})
	if _, ok := FromContext(ctx); ok {
		t.Error("a peer with no AuthInfo had credentials")
	}
	ctx = peer.NewContext(context.Background(), &peer.Peer{AuthInfo: AuthInfo{UID: 7}})
	if a, ok := FromContext(ctx); !ok || a.UID != 7 {
		t.Errorf("FromContext = %+v, %v", a, ok)
	}
}

func TestTheRestOfTheInterface(t *testing.T) {
	c := RequireServer(3)
	if c.Info().SecurityProtocol != "peercred" {
		t.Errorf("Info = %+v", c.Info())
	}
	cl := c.Clone().(*creds)
	if cl.serverUID == nil || *cl.serverUID != 3 {
		t.Error("Clone lost the required uid")
	}
	if err := c.OverrideServerName("x"); err != nil {
		t.Error(err)
	}
}
