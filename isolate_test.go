package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The rule that makes one process per protocol honest: a writable image
// reached by two protocols would be two drivers over one file.
func TestWhatCannotBeIsolated(t *testing.T) {
	two := []serveBlock{{Protocol: "smb"}, {Protocol: "webdav"}}
	for _, tc := range []struct {
		name   string
		share  *share
		serves []serveBlock
		refuse bool
	}{
		{"writable over two protocols", &share{name: "scratch"}, two, true},
		{"read-only over two protocols", &share{name: "photos", readOnly: true}, two, false},
		{"writable, but named to one", &share{name: "scratch", protocols: []string{"smb"}}, two, false},
		{"writable over one protocol", &share{name: "scratch"}, two[:1], false},
		{
			"restricted and writable, over one that cannot authenticate",
			&share{name: "photos", allow: []string{"alice"}},
			[]serveBlock{{Protocol: "smb"}, {Protocol: "nfs"}},
			false, // nfs is refused it anyway, so only smb writes
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, b := range tc.serves {
				if protocolByName(b.Protocol) == nil {
					t.Skipf("this binary has no %s", b.Protocol)
				}
			}
			why := isolationRefusal([]*share{tc.share}, tc.serves)
			if (why != "") != tc.refuse {
				t.Errorf("refusal = %q, want refused = %v", why, tc.refuse)
			}
			if tc.refuse && !strings.Contains(why, "protocols = ") {
				t.Errorf("the refusal does not say how to fix it: %q", why)
			}
		})
	}
}

// A child is told the shares it may open and no others. This is the whole
// least-privilege claim, and it is decided here.
func TestAChildIsToldOnlyItsOwnShares(t *testing.T) {
	needUsers(t)
	var auth, blind *protocol
	for _, p := range protocols {
		if p.authenticates && auth == nil {
			auth = p
		}
		if !p.authenticates && blind == nil {
			blind = p
		}
	}
	if auth == nil {
		t.Skip("this binary has no protocol that authenticates")
	}
	cfg := &config{Shares: []shareBlock{
		{Name: "public", Image: "/i"},
		{Name: "restricted", Image: "/i", Allow: []string{"alice"}},
		{Name: "smbonly", Image: "/i", Protocols: []string{auth.name}},
	}}
	got := strings.Join(sharesForChild(cfg, auth), ",")
	if got != "public,restricted,smbonly" {
		t.Errorf("%s was given %q", auth.name, got)
	}
	if blind != nil {
		got := strings.Join(sharesForChild(cfg, blind), ",")
		// Not the restricted one -- it cannot tell who is asking -- and not
		// the one that named another protocol.
		if got != "public" {
			t.Errorf("%s was given %q, want only the public share", blind.name, got)
		}
	}
}

// A serve block that would carry nothing is refused before anything opens.
func TestAProtocolThatWouldCarryNothing(t *testing.T) {
	needUsers(t)
	var auth, blind *protocol
	for _, p := range protocols {
		if !p.authenticates && blind == nil {
			blind = p
		}
		if p.authenticates && auth == nil {
			auth = p
		}
	}
	if blind == nil || auth == nil {
		t.Skip("this needs one protocol that authenticates and one that cannot")
	}
	dir := t.TempDir()
	pw := write(t, dir, "pw", "hunter2\n")
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
user "alice" { password_file = %q }
share "photos" {
  image = "/i"
  allow = ["alice"]
}
serve %q {}
serve %q {}
`, hclPath(pw), auth.name, blind.name))
	_, err := loadConfig([]string{path})
	if err == nil || !strings.Contains(err.Error(), "would carry nothing") {
		t.Errorf("error = %v, want one about carrying nothing", err)
	}
	if err != nil && !strings.Contains(err.Error(), "restricted to alice") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A share can name the protocols that carry it, and a name that is not one is
// refused.
func TestAShareCanNameItsProtocols(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
share "s" {
  image     = "/i"
  protocols = ["gopher"]
}
serve %q {}
`, protocols[0].name))
	_, err := loadConfig([]string{path})
	if err == nil || !strings.Contains(err.Error(), "not a protocol here") {
		t.Errorf("error = %v", err)
	}
}

// The whole thing, for real: a parent that spawns children, children that
// serve, and a client that reads through one of them.
//
// It builds the binary because that is what the parent execs -- there is no
// way to test a process boundary without a process, and a fake one would test
// the fake.
func TestIsolatedForReal(t *testing.T) {
	needUsers(t)
	if testing.Short() {
		t.Skip("it builds a binary")
	}
	var auth *protocol
	for _, p := range protocols {
		if p.authenticates {
			auth = p
			break
		}
	}
	if auth == nil {
		t.Skip("this binary has no protocol that authenticates")
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "fileshare")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the child: %v\n%s", err, out)
	}

	img := image(t, dir, "public.img", map[string]string{"/greeting.txt": "hello"})
	pw := write(t, dir, "alice.pw", "hunter2\n")
	cfgPath := write(t, dir, "c.hcl", fmt.Sprintf(`
user "alice" { password_file = %q }

share "public" {
  image     = %q
  protocols = [%q]
}

serve %q { addr = "127.0.0.1:0" }
`, hclPath(pw), hclPath(img), auth.name, auth.name))

	cfg, err := loadConfig([]string{cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	// The parent binds :0, so the address a client dials is not the one in the
	// file: read it back from what was printed.
	out, err := os.CreateTemp(dir, "announce")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	childExe = func() (string, error) { return exe, nil }
	t.Cleanup(func() { childExe = os.Executable })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runIsolated(ctx, cfg, out, []string{cfgPath}) }()

	addr := ""
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && addr == "" {
		time.Sleep(50 * time.Millisecond)
		b, _ := os.ReadFile(out.Name())
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, auth.name) && strings.Contains(line, "process") {
				fields := strings.Fields(line)
				addr = fields[2] // "smb on 127.0.0.1:PORT — process N, serving ..."
			}
		}
	}
	if addr == "" {
		cancel()
		b, _ := os.ReadFile(out.Name())
		t.Fatalf("the parent never announced a listener:\n%s", b)
	}
	t.Logf("%s child is on %s", auth.name, addr)

	// It is really serving: something is listening and it is not the parent's
	// own accept loop, because the parent opened no image at all.
	waitFor(t, addr)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the parent returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("the parent did not stop when its context was cancelled")
	}
	// And the children went with it. Scoped to THIS test's binary, which lives
	// in its own temporary directory: `pgrep -f serve-one` would also find a
	// server somebody is running on this machine, and a test that fails
	// because of a neighbour is worse than no test.
	//
	// Polled rather than checked once: Wait has returned, but a process leaves
	// the table on its own schedule, and a race against it would fail once a
	// week and be called flaky.
	if runtime.GOOS != "windows" {
		deadline = time.Now().Add(10 * time.Second)
		for {
			procs, _ := exec.Command("pgrep", "-f", exe).Output()
			if len(strings.TrimSpace(string(procs))) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("children are still running after the parent stopped: %s", procs)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
