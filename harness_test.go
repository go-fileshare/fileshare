package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	fat32 "github.com/go-filesystems/fat32"
)

// A real image, made here rather than committed: a binary in testdata is a
// thing nobody can review, and Format takes two lines.
func image(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	fsys, err := fat32.Format(path, 64<<20, fat32.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	for p, body := range files {
		if err := fsys.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hcl quotes a path the way an HCL string wants it: on Windows a path is full
// of backslashes, and "C:\Users\alice" has three invalid escape sequences in
// it.
func hclPath(p string) string { return filepath.ToSlash(p) }

// running is a server under test: started on ports the kernel chose, and
// stopped when the test ends.
type running struct {
	srv   *server
	cfg   *config
	addrs map[string]string
	out   *bytes.Buffer
}

// start opens the configuration and serves it, on port 0 for every protocol,
// and hands back the addresses a client should dial.
func start(t *testing.T, body string) *running {
	t.Helper()
	dir := t.TempDir()
	path := write(t, dir, "test.hcl", body)
	cfg, err := loadConfig([]string{path})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	out := &bytes.Buffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}

	// Bind first, announce second -- and hand the test what was actually
	// bound, because :0 is not what a client dials.
	addrs := map[string]string{}
	var listeners []net.Listener
	for i := range cfg.Serves {
		b := &cfg.Serves[i]
		ln, err := net.Listen("tcp", b.Addr)
		if err != nil {
			t.Fatalf("%s: %v", b.Protocol, err)
		}
		addrs[b.Protocol] = ln.Addr().String()
		listeners = append(listeners, ln)
		p := protocolByName(b.Protocol)
		// The same announcement the real run makes, so a test can read what a
		// person would have been told.
		srv.announce(p, ln.Addr().String())
		go func() { _ = p.serve(srv, p, ln) }()
	}
	t.Cleanup(func() {
		for _, ln := range listeners {
			ln.Close()
		}
		srv.Close()
	})
	// Give the goroutines a moment to be inside Serve, so a client that
	// connects immediately is not racing the accept loop.
	for _, addr := range addrs {
		waitFor(t, addr)
	}
	return &running{srv: srv, cfg: cfg, addrs: addrs, out: out}
}

func waitFor(t *testing.T, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("nothing is listening on %s", addr)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// config text used by several tests: two users, one image, three protocols.
func configFor(t *testing.T, dir string, shares string) string {
	t.Helper()
	alice := write(t, dir, "alice.pw", "hunter2\n")
	bob := write(t, dir, "bob.pw", "swordfish\n")
	return fmt.Sprintf(`
name = "TESTFS"

user "alice" { password_file = %q }
user "bob"   { password_file = %q }

%s

serve "smb"    { addr = "127.0.0.1:0" }
serve "webdav" { addr = "127.0.0.1:0" }
serve "nfs"    { addr = "127.0.0.1:0" }
`, hclPath(alice), hclPath(bob), shares)
}
