// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A server whose shares come from the admin API starts with none. NFS has
// nothing to export then, and go-filesystems/nfs refuses to serve nothing:
// that refusal used to stop the whole server, every protocol with it, before
// the first share could be created.
func TestAManagedServerWithNoSharesYetKeepsServing(t *testing.T) {
	// Short: a unix socket path holds about 100 bytes, and t.TempDir's
	// is longer than that on macOS.
	dir, err := os.MkdirTemp("", "fs-empty-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "serve.hcl")
	if err := os.WriteFile(p, []byte(`name = "empty"
serve "webdav" { addr = "127.0.0.1:0" }
serve "sftp"   { addr = "127.0.0.1:0" }
serve "nfs"    { addr = "127.0.0.1:0" }
serve "smb"    { addr = "127.0.0.1:0" }
admin {
  listen     = "unix://`+dir+`/admin.sock"
  state_file = "`+dir+`/shares.json"
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if err := withState(cfg); err != nil {
		t.Fatal(err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.run(ctx, cfg); close(done) }()
	defer func() {
		cancel()
		<-done // closed, when a check below has already taken the error
	}()

	for deadline := time.Now().Add(5 * time.Second); !srv.ready.Load(); time.Sleep(10 * time.Millisecond) {
		select {
		case err := <-done:
			t.Fatalf("the server stopped: %v\n%s", err, out)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("never ready:\n%s", out)
		}
	}
	var nfsAddr string
	srv.runMu.Lock()
	for _, f := range srv.feeds {
		if f.proto == "nfs" {
			nfsAddr = f.ln.Addr().String()
		}
	}
	srv.runMu.Unlock()

	// A client is hung up on, not left waiting in the backlog.
	c, err := net.DialTimeout("tcp", nfsAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("reading from the NFS port before any share = %v, want EOF", err)
	}

	select {
	case err := <-done:
		t.Fatalf("the server stopped: %v\n%s", err, out)
	case <-time.After(500 * time.Millisecond):
	}
	if !srv.ready.Load() {
		t.Fatalf("no longer ready:\n%s", out)
	}
}
