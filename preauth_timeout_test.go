// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav && !nos3 && !nosftp

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Nothing waits for ever on a client that has not said who it is. A request
// whose headers never end (WebDAV, S3) and an SSH handshake that stops after
// the version string are closed once the pre-authentication deadline passes;
// the audit held all three open for 20 s, and they would have stayed open for
// good. The control is a session that DID log in: it outlives the deadline,
// because the deadline is lifted at login.
func TestAConnectionThatNeverAuthenticatesIsClosed(t *testing.T) {
	needUsers(t)
	const preAuth = 300 * time.Millisecond
	was := defaultPreAuthTimeout
	defaultPreAuthTimeout = preAuth
	t.Cleanup(func() { defaultPreAuthTimeout = was }) // after the server's own cleanup

	dir := t.TempDir()
	key, pub := keyPair(t)
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
user "alice" {
  password_file   = %q
  authorized_keys = [%q]
}
share "photos" { image = %q }
serve "webdav" { addr = "127.0.0.1:0" }
serve "s3"     { addr = "127.0.0.1:0" }
serve "sftp"   { addr = "127.0.0.1:0" }
`, hclPath(write(t, dir, "alice.pw", "hunter2\n")), pub,
		hclPath(image(t, dir, "photos.img", map[string]string{"/a.txt": "a"}))))
	if r.srv.preAuthTimeout != preAuth {
		t.Fatalf("the server took %v, not the %v asked for", r.srv.preAuthTimeout, preAuth)
	}

	alice, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatalf("alice's login: %v", err)
	}
	defer done()

	partial := map[string]string{
		"webdav": "GET / HTTP/1.1\r\nHost: x\r\n", // the headers never end
		"s3":     "GET / HTTP/1.1\r\nHost: x\r\n",
		"sftp":   "SSH-2.0-silent\r\n", // a version, and no key exchange
	}
	start := time.Now()
	for proto, data := range partial {
		c, err := net.Dial("tcp", r.addrs[proto])
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(data))
		// Drain what the server says (an SSH banner, its KEXINIT) until it
		// hangs up -- or until a limit far past the deadline says it did not.
		c.SetReadDeadline(start.Add(20 * preAuth))
		buf := make([]byte, 4096)
		for err == nil {
			_, err = c.Read(buf)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s still holds a connection that never authenticated, %v after it was opened",
				proto, time.Since(start).Round(time.Millisecond))
		}
	}

	time.Sleep(preAuth - time.Since(start)) // in case the loop above was quicker
	if _, err := alice.ReadDir("/"); err != nil {
		t.Errorf("CONTROL: alice's session, logged in, did not outlive the handshake deadline: %v", err)
	}
}
