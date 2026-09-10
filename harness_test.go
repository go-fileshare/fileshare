package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	out   *safeBuffer
}

// safeBuffer is what the server writes its announcements to during a test.
//
// The server locks its own writes -- the protocols announce themselves from
// their own goroutines -- but a test that READS the buffer while one of them
// is writing races just as surely. The lock has to cover both sides, so it
// lives here, where both are.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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
	out := &safeBuffer{}
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
	users := fmt.Sprintf("user \"alice\" { password_file = %q }\nuser \"bob\"   { password_file = %q }\n",
		hclPath(alice), hclPath(bob))
	if !anyAuthenticates() {
		// A binary whose only protocol cannot tell people apart is refused a
		// configuration with users in it, and rightly: it would read as
		// protected and not be.
		users = ""
	}
	return fmt.Sprintf("name = \"TESTFS\"\n\n%s\n%s\n%s", users, shares, serveBlocks())
}

// anyAuthenticates reports whether this binary has a protocol that can tell
// who is asking. Without one, users -- and so every per-user rule -- cannot be
// configured at all, and the tests about them have nothing to run against.
func anyAuthenticates() bool {
	for _, p := range protocols {
		if p.authenticates {
			return true
		}
	}
	return false
}

// firstAuthenticating is a protocol that can tell people apart, or nil.
func firstAuthenticating() *protocol {
	for _, p := range protocols {
		if p.authenticates {
			return p
		}
	}
	return nil
}

// needUsers skips a test that cannot mean anything in this build.
func needUsers(t *testing.T) {
	t.Helper()
	if !anyAuthenticates() {
		t.Skip("this binary has no protocol that can authenticate, so it can have no users")
	}
}

// serveBlocks names the protocols THIS BINARY has. A build with -tags nonfs
// has no NFS to serve, and a test that named it anyway would be testing the
// configuration's refusal rather than the thing it came to test.
func serveBlocks() string {
	var b strings.Builder
	for _, p := range protocols {
		fmt.Fprintf(&b, "serve %q { addr = \"127.0.0.1:0\" }\n", p.name)
	}
	return b.String()
}

// names is what a failure message should say about a set of shares.
func names(shares []*share) []string {
	var out []string
	for _, s := range shares {
		out = append(out, s.name)
	}
	return out
}

// onlyProtocol is a configuration that serves ONE protocol: a test about one
// of them should not have to satisfy the others, and a share that names one
// protocol makes every other serve block carry nothing -- which is refused,
// correctly, and would be the thing under test rather than the thing it came
// to test.
func onlyProtocol(t *testing.T, dir, name, shares string) string {
	t.Helper()
	alice := write(t, dir, "alice.pw", "hunter2\n")
	bob := write(t, dir, "bob.pw", "swordfish\n")
	return fmt.Sprintf(`
name = "TESTFS"

user "alice" { password_file = %q }
user "bob"   { password_file = %q }

%s

serve %q { addr = "127.0.0.1:0" }
`, hclPath(alice), hclPath(bob), shares, name)
}

// privatePEM writes a key in the PKCS#8 PEM that every other language reads.
func privatePEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// people is three users with passwords in files, as a configuration fragment.
func people(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, u := range []struct{ name, password string }{
		{"alice", "hunter2"}, {"bob", "swordfish"}, {"carol", "correct horse"},
	} {
		f := write(t, dir, u.name+".pw", u.password+"\n")
		fmt.Fprintf(&b, "user %q { password_file = %q }\n", u.name, hclPath(f))
	}
	return b.String() + "\n"
}
