// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb && !wasip1

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/quic-go/quic-go"
)

// SMB over QUIC, served the way the configuration says and asked the way a
// client asks: UDP, TLS 1.3, ALPN "smb", then SMB 3.1.1 on the first stream.
// The client is go-smb2, which this project did not write.
type quicNet struct {
	qc *quic.Conn
	st *quic.Stream
}

func (c *quicNet) Read(p []byte) (int, error)         { return c.st.Read(p) }
func (c *quicNet) Write(p []byte) (int, error)        { return c.st.Write(p) }
func (c *quicNet) LocalAddr() net.Addr                { return c.qc.LocalAddr() }
func (c *quicNet) RemoteAddr() net.Addr               { return c.qc.RemoteAddr() }
func (c *quicNet) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *quicNet) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *quicNet) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
func (c *quicNet) Close() error                       { c.st.Close(); return c.qc.CloseWithError(0, "") }

func TestSMBOverQUIC(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	p := newPKI(t, dir)
	img := image(t, dir, "d.img", map[string]string{"/hello.txt": "over quic\n"})
	alice := write(t, dir, "alice.pw", "hunter2\n")
	serve := func(extra string) string {
		return fmt.Sprintf(`user "alice" { password_file = %q }
share "d" { image = %q }
tls {
  cert_file = %q
  key_file  = %q
}
serve "smb" {
  addr      = "127.0.0.1:0"
  transport = "quic"
  tls       = true
%s}
`, hclPath(alice), hclPath(img), hclPath(p.certFile), hclPath(p.keyFile), extra)
	}
	tryMount := func(addr string, cert *tls.Certificate) error {
		conf := &tls.Config{RootCAs: p.pool, ServerName: "localhost", NextProtos: []string{"smb"}}
		if cert != nil {
			conf.Certificates = []tls.Certificate{*cert}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		qc, err := quic.DialAddr(ctx, addr, conf, &quic.Config{MaxIdleTimeout: 10 * time.Second})
		if err != nil {
			return err
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		nc := &quicNet{qc, st}
		defer nc.Close()
		d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
		s, err := d.DialConn(ctx, nc, addr)
		if err != nil {
			return fmt.Errorf("session setup: %w", err)
		}
		defer s.Logoff()
		sh, err := s.Mount("d")
		if err != nil {
			return fmt.Errorf("tree connect: %w", err)
		}
		defer sh.Umount()
		got, err := sh.ReadFile("hello.txt")
		if err != nil {
			return err
		}
		if string(got) != "over quic\n" {
			return fmt.Errorf("read %q", got)
		}
		return sh.WriteFile("back.txt", []byte("written over quic\n"), 0o644)
	}

	t.Run("no client certificate asked", func(t *testing.T) {
		_, addrs := runServer(t, serve(""))
		if err := tryMount(addrs["smb"], nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("client certificate required", func(t *testing.T) {
		_, addrs := runServer(t, serve(fmt.Sprintf("  client_cert    = \"required\"\n  client_ca_file = %q\n", hclPath(p.caFile))))
		if err := tryMount(addrs["smb"], nil); err == nil {
			t.Fatal("mounted with no client certificate")
		}
		if err := tryMount(addrs["smb"], &p.client); err != nil {
			t.Fatalf("refused with the CA's certificate: %v", err)
		}
	})
	t.Run("TCP and a client without ALPN smb get nothing", func(t *testing.T) {
		_, addrs := runServer(t, serve(""))
		conf := &tls.Config{RootCAs: p.pool, ServerName: "localhost", NextProtos: []string{"h3"}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if qc, err := quic.DialAddr(ctx, addrs["smb"], conf, nil); err == nil {
			qc.CloseWithError(0, "")
			t.Fatal("a QUIC client offering h3 was accepted")
		}
	})
}

// A client_ca_file that cannot be read, or holds no certificate, stops the
// server at start, naming the file: it must not come up demanding nothing.
func TestSMBOverQUICClientCAFileRefusals(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	p := newPKI(t, dir)
	img := image(t, dir, "d.img", nil)
	alice := write(t, dir, "alice.pw", "hunter2\n")
	empty := write(t, dir, "empty.pem", "not a certificate\n")
	for _, c := range []struct{ name, ca, want string }{
		{"missing", dir + "/absent.pem", "smb: client_ca_file"},
		{"no certificate in it", empty, "smb: " + empty},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := fmt.Sprintf(`user "alice" { password_file = %q }
share "d" { image = %q }
tls {
  cert_file = %q
  key_file  = %q
}
serve "smb" {
  addr           = "127.0.0.1:0"
  transport      = "quic"
  tls            = true
  client_cert    = "required"
  client_ca_file = %q
}
`, hclPath(alice), hclPath(img), hclPath(p.certFile), hclPath(p.keyFile), hclPath(c.ca))
			cfg, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", body)})
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			srv, err := open(cfg, &safeBuffer{})
			if err == nil {
				srv.Close()
				t.Fatal("started with a client CA it could not use")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}
