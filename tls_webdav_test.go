// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WebDAV over TLS, through run: a TLS client reads, a plain one is refused on
// the same port, and a connection already open under TLS is closed when the
// shares change -- the TLS is over the generation's listener, not around it.
func TestWebDAVOverTLS(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	p := newPKI(t, dir)
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "over tls")
	alice := write(t, dir, "alice.pw", "hunter2\n")
	srv, addrs := runServer(t, fmt.Sprintf(`user "alice" { password_file = %q }
share "t" {
  directory = %q
  allow     = ["alice"]
}
tls {
  cert_file = %q
  key_file  = %q
}
serve "webdav" {
  addr = "127.0.0.1:0"
  tls  = true
}
`, hclPath(alice), hclPath(tree), hclPath(p.certFile), hclPath(p.keyFile)))
	addr := addrs["webdav"]
	cfg := &tls.Config{RootCAs: p.pool, ServerName: "localhost"}

	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("a TLS client: %v", err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	ask := func() (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodGet, "https://localhost/t/a.txt", nil)
		req.SetBasicAuth("alice", "hunter2")
		if err := req.Write(c); err != nil {
			return nil, err
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(r, req)
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if string(b) != "over tls" {
				return res, fmt.Errorf("body %q", b)
			}
		}
		return res, err
	}
	if res, err := ask(); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("over TLS: %v %v", res, err)
	}

	// The same port, spoken to in the clear.
	plain, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(plain, "GET /t/a.txt HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n")
	plain.SetReadDeadline(time.Now().Add(3 * time.Second))
	if res, err := http.ReadResponse(bufio.NewReader(plain), nil); err == nil && res.StatusCode == http.StatusOK {
		t.Fatal("the TLS port answered a plain HTTP request with the file")
	}
	plain.Close()

	// A change of shares closes the connection under the TLS too.
	closed, err := srv.swap(srv.currentShares())
	if err != nil || closed < 1 {
		t.Fatalf("swap closed %d connection(s): %v", closed, err)
	}
	if _, err := ask(); err == nil {
		t.Fatal("a TLS connection outlived the generation that accepted it")
	}
}
