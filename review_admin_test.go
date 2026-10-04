// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
)

// The tests in this file were written by an adversarial review of the admin
// API, each proving a defect it found; they stay as the regression tests of
// the fixes. A "BUG:" in a failure names the defect come back.

// R1: a configuration share whose image file is not writable (an ISO, a
// 0444 file, any device) and which does not say read_only is served
// read-only by fallback -- and from then on EVERY admin change is refused,
// including a Revoke on an unrelated share.
func TestFoundReadOnlyFallbackBricksAdmin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a 0444 file for writing")
	}
	dir := t.TempDir()
	img := image(t, dir, "ro.img", map[string]string{"/a.txt": "x"})
	if err := os.Chmod(img, 0o444); err != nil {
		t.Fatal(err)
	}
	m := startManaged(t, dir, `share "iso" { image = "`+hclPath(img)+`" }`)
	ctx := context.Background()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ),
			grantOf(userSubject("bob"), adminv1.Access_ACCESS_READ)}})
	t.Logf("CreateShare of an unrelated share: %v", err)
	_, err2 := m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "iso"})
	t.Logf("DisableShare iso: %v", err2)
	if err != nil {
		t.Errorf("BUG: an unrelated change is refused because of a read-only fallback share: %v", err)
	}
	// And a directory reload that needs a new generation is refused too.
	r, rerr := m.srv.reload()
	t.Logf("reload: %+v %v", r, rerr)
}

// R3: a share name with a newline forges an audit line.
func TestFoundNameChild(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	name := os.Getenv("FOUND_NAME")
	if name == "" {
		t.Skip("run through TestFoundNamesKillTheServer")
	}
	_, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: name,
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}})
	t.Logf("create: %v", err)
	time.Sleep(500 * time.Millisecond)
	t.Logf("output:\n%s", m.out.String())
	if os.Getenv("FOUND_RESTART") != "" && err == nil {
		m.stop()
		m.stop = nil
		t.Logf("restarting with the state file as written")
		again := startManaged(t, dir, "")
		time.Sleep(500 * time.Millisecond)
		t.Logf("after restart: %s", again.out.String())
	}
}

var _ = codes.OK

// R4: share names the API accepts and a protocol cannot serve. The admin call
// returns success, the state file is written, and then the new generation
// panics (WebDAV's ServeMux) or fails (NFS Export) -- in a child process,
// because a panic in a generation goroutine kills the test binary.
func TestFoundNamesKillTheServer(t *testing.T) {
	for _, name := range []string{"my photos", "{x}", "t\nadmin (uid=0): deleted share payroll -- generation 9\nx"} {
		for _, restart := range []string{"", "1"} {
			cmd := exec.Command(os.Args[0], "-test.run=^TestFoundNameChild$", "-test.v")
			cmd.Env = append(os.Environ(), "FOUND_NAME="+name, "FOUND_RESTART="+restart)
			out, err := cmd.CombinedOutput()
			s := string(out)
			panicked := strings.Contains(s, "panic:")
			t.Logf("name %q restart=%q: exit=%v panicked=%v", name, restart, err, panicked)
			if i := strings.Index(s, "panic:"); i >= 0 {
				t.Logf("  %s", strings.SplitN(s[i:], "\n", 2)[0])
			}
			if strings.Contains(s, "\nadmin (uid=0): deleted share payroll") || strings.Contains(s, "\n    admin (uid=0): deleted share payroll") {
				t.Logf("  forged audit line present")
			}
			if panicked {
				t.Errorf("BUG: CreateShare(%q) crashed the server (restart=%q)", name, restart)
			}
		}
	}
}

// R4b: the state file as the crashing call left it: every restart panics too.
func TestFoundStateNameChild(t *testing.T) {
	name := os.Getenv("FOUND_STATE_NAME")
	if name == "" {
		t.Skip("child")
	}
	dir := t.TempDir()
	tree := filepath.Join(dir, "roots", "t")
	os.MkdirAll(tree, 0o755)
	b, _ := json.Marshal(stateFile{Version: 1, Shares: []managedShare{{Name: name, Directory: tree,
		Grants: []grant{{Subject: "alice"}}}}})
	write(t, dir, "shares.json", string(b))
	m := startManaged(t, dir, "")
	time.Sleep(500 * time.Millisecond)
	t.Logf("%s", m.out.String())
}

func TestFoundRestartCrashLoops(t *testing.T) {
	for _, name := range []string{"my photos", "."} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFoundStateNameChild$", "-test.v")
		cmd.Env = append(os.Environ(), "FOUND_STATE_NAME="+name)
		out, err := cmd.CombinedOutput()
		s := string(out)
		t.Logf("state name %q: exit=%v panicked=%v", name, err, strings.Contains(s, "panic:"))
		if i := strings.Index(s, "panic:"); i >= 0 {
			t.Logf("  %s", strings.SplitN(s[i:], "\n", 2)[0])
		}
		if strings.Contains(s, "panic:") {
			t.Errorf("BUG: a server whose state file names %q panics at every start", name)
		}
	}
}

// R5: with no host_key_file, the SFTP host key is generated per GENERATION,
// not per start: every admin change and every revoking reload changes the
// server's SSH identity.
func TestFoundSFTPHostKeyChangesPerGeneration(t *testing.T) {
	if protocolByName("sftp") == nil {
		t.Skip("no sftp")
	}
	dir := t.TempDir()
	m := startManaged(t, dir, `serve "sftp" { addr = "127.0.0.1:0" }`)
	var addr string
	m.srv.runMu.Lock()
	for _, f := range m.srv.feeds {
		if f.proto == "sftp" {
			addr = f.ln.Addr().String()
		}
	}
	m.srv.runMu.Unlock()
	hostKey := func() string {
		var got string
		cfg := &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.Password("x")},
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				got = ssh.FingerprintSHA256(k)
				return nil
			}, Timeout: 3 * time.Second}
		c, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			c.Close()
		}
		return got
	}
	before := hostKey()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	if _, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	after := hostKey()
	t.Logf("host key before %s after %s", before, after)
	if before == "" || after == "" {
		t.Fatal("no host key seen")
	}
	if before != after {
		t.Errorf("BUG: the SFTP host key changed on an admin change")
	}
}

// R7: the same image, spelled two ways (the configuration through a symlink,
// the API by its resolved path). It once got two independent writable
// drivers and lost files; one share per source is now the rule, so the second
// spelling is refused -- by its RESOLVED path, which is what the symlink was
// hiding -- and the first share is left as it was.
func TestFoundTwoDriversOneImage(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(dir, "roots")
	os.MkdirAll(roots, 0o755)
	img := image(t, roots, "disk.img", map[string]string{"/seed.txt": "seed"})
	link := filepath.Join(dir, "link.img")
	if err := os.Symlink(img, link); err != nil {
		t.Skip(err)
	}
	m := startManaged(t, dir, `share "a" {
  image  = "`+hclPath(link)+`"
  allow  = ["alice"]
  writers = ["alice"]
}`)
	ctx := context.Background()
	_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "b",
		Source: &adminv1.CreateShareRequest_Image{Image: img},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_WRITE)}})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "same source") {
		t.Errorf("refused for another reason: %v", err)
	}
	if m.srv.shareByName("b") != nil {
		t.Fatal("the refused share is served")
	}
	if c := m.put("alice", "hunter2", "/a/after.txt", "still writable"); c < 200 || c >= 300 {
		t.Errorf("the first share no longer takes a write: %d", c)
	}
}

// R9: everything at once, under -race, with a watchdog for deadlocks.
func TestFoundConcurrentStress(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	ctx := context.Background()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "x")
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ),
			grantOf(userSubject("bob"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	stop := time.Now().Add(4 * time.Second)
	var wg sync.WaitGroup
	loop := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; time.Now().Before(stop); i++ {
				f(i)
			}
		}()
	}
	loop(func(i int) {
		if i%2 == 0 {
			m.client.Grant(ctx, &adminv1.GrantRequest{Share: "t", Grant: grantOf(userSubject("carol"), adminv1.Access_ACCESS_READ)})
		} else {
			m.client.Revoke(ctx, &adminv1.RevokeRequest{Share: "t", Subject: userSubject("carol")})
		}
	})
	loop(func(i int) {
		if i%2 == 0 {
			m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "t"})
		} else {
			m.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "t"})
		}
	})
	loop(func(int) { m.client.ReloadDirectory(ctx, &adminv1.ReloadDirectoryRequest{}) })
	loop(func(int) { m.srv.reload() })
	loop(func(int) { m.client.ListShares(ctx, &adminv1.ListSharesRequest{}) })
	loop(func(int) { m.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "t"}) })
	loop(func(int) { m.client.GetServerInfo(ctx, &adminv1.GetServerInfoRequest{}) })
	loop(func(int) { m.client.ListUsers(ctx, &adminv1.ListUsersRequest{}) })
	loop(func(int) { m.scrape(t, "/metrics"); m.scrape(t, "/readyz") })
	loop(func(int) { m.get("alice", "hunter2", "/t/a.txt") })
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("DEADLOCK:\n%s", buf[:n])
	}
	st, err := readState(m.state)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := m.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "t"})
	t.Logf("final: disabled=%v served-enabled=%v gen=%d", st.Disabled, res.GetShare().GetEnabled(), m.srv.generationNumber())
	if st.isDisabled("t") == res.GetShare().GetEnabled() {
		t.Errorf("BUG: the state file and what is served disagree")
	}
}

// R2: a state file naming a share outside every source root -- the roots
// narrowed since, the file edited, or a component of the path swapped for a
// link out of the root (R8) -- stops the server at startup, naming the share.
func TestFoundStateFileShareOutsideTheRootsStopsTheStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the admin tests use unix socket paths")
	}
	for _, c := range []string{"edited", "swapped"} {
		t.Run(c, func(t *testing.T) {
			dir := t.TempDir()
			cfg, _, state, roots := managedConfig(t, dir, "")
			outside := filepath.Join(dir, "outside")
			os.MkdirAll(outside, 0o755)
			source := outside
			if c == "swapped" {
				// Created under the root, then a component replaced.
				os.MkdirAll(filepath.Join(roots, "up"), 0o755)
				source = filepath.Join(roots, "up", "t")
				if err := os.Symlink(outside, source); err != nil {
					t.Skip(err)
				}
			}
			b, _ := json.Marshal(stateFile{Version: 1, Shares: []managedShare{{Name: "x", Directory: source,
				Grants: []grant{{Subject: "alice"}}}}})
			os.WriteFile(state, b, 0o600)
			err := withState(cfg)
			if err == nil || !strings.Contains(err.Error(), `share "x"`) || !strings.Contains(err.Error(), "source roots") {
				t.Errorf("BUG: a state-file share outside source_roots (%s) was accepted at start: %v", source, err)
			}
		})
	}
	// Control: the same share under the root starts.
	dir := t.TempDir()
	cfg, _, state, roots := managedConfig(t, dir, "")
	inside := filepath.Join(roots, "t")
	os.MkdirAll(inside, 0o755)
	b, _ := json.Marshal(stateFile{Version: 1, Shares: []managedShare{{Name: "x", Directory: inside,
		Grants: []grant{{Subject: "alice"}}}}})
	os.WriteFile(state, b, 0o600)
	if err := withState(cfg); err != nil {
		t.Errorf("control: a state-file share under its root is refused: %v", err)
	}
}

// R8: a directory share the API created is opened from its root, one
// os.Root inside the other: a component swapped for a link out of the root
// after the check is refused at the open, not followed.
func TestFoundConfinedDirectoryRefusesALinkOut(t *testing.T) {
	dir := t.TempDir()
	roots := filepath.Join(dir, "roots")
	outside := filepath.Join(dir, "outside")
	tree := filepath.Join(roots, "up", "t")
	os.MkdirAll(tree, 0o755)
	os.MkdirAll(filepath.Join(outside, "t"), 0o755)
	write(t, tree, "a.txt", "inside")
	write(t, filepath.Join(outside, "t"), "a.txt", "outside the roots")
	real, _ := filepath.EvalSymlinks(tree)
	fsys, err := openConfinedDirectory([]string{roots}, real, nil)
	if err != nil {
		t.Fatalf("control: a share under its root does not open: %v", err)
	}
	if b, err := fsys.ReadFile("/a.txt"); err != nil || string(b) != "inside" {
		t.Errorf("control: %q %v", b, err)
	}
	fsys.Close()
	for _, swap := range []struct{ name, at, to string }{
		{"the share itself", tree, filepath.Join(outside, "t")},
		{"a component above it", filepath.Join(roots, "up"), outside},
	} {
		os.RemoveAll(filepath.Join(roots, "up"))
		os.MkdirAll(filepath.Join(roots, "up"), 0o755)
		if swap.at == tree {
			os.RemoveAll(tree)
		} else {
			os.RemoveAll(swap.at)
		}
		if err := os.Symlink(swap.to, swap.at); err != nil {
			t.Skip(err)
		}
		if fsys, err := openConfinedDirectory([]string{roots}, real, nil); err == nil {
			b, _ := fsys.ReadFile("/a.txt")
			fsys.Close()
			t.Errorf("BUG: %s swapped for a link out of the root, and the share opened (reads %q)", swap.name, b)
		}
	}
}

// R4: share names a protocol cannot serve -- a ServeMux wildcard, a path
// element, a line break forging an audit line -- are refused by the API,
// before anything is written.
func TestFoundUnservableShareNamesAreRefused(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	for _, name := range []string{"{x}", "{x...}", ".", "..", "a/b", "t\nadmin: forged", " lead", "trail ", "50%", "a:b"} {
		_, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: name,
			Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
			Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("BUG: CreateShare(%q) = %v, want InvalidArgument", name, err)
		}
	}
	if b, err := os.ReadFile(m.state); err == nil && strings.Contains(string(b), `"name"`) {
		t.Errorf("BUG: a refused name reached the state file: %s", b)
	}
	// Control: an ordinary name with a space in it is served.
	if _, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "my photos",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Errorf("control: %v", err)
	}
}

// R3: nothing a caller sends writes a line of the audit log of its own --
// not a subject with a carriage return or an escape sequence (refused), not
// an error quoting one (escaped) -- and refusals are audited too.
func TestFoundAuditLinesCannotBeForged(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	for _, v := range []string{"alice\radmin (uid=0): deleted share payroll", "bob\x1b[2K", "carol\u2028x"} {
		for _, s := range []*adminv1.Subject{userSubject(v), {Kind: &adminv1.Subject_Group{Group: v}},
			{Kind: &adminv1.Subject_OidcUser{OidcUser: v}}, {Kind: &adminv1.Subject_OidcGroup{OidcGroup: v}}} {
			_, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "t",
				Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
				Grants: []*adminv1.Grant{grantOf(s, adminv1.Access_ACCESS_READ)}})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("BUG: a subject %v was not refused: %v", s, err)
			}
		}
	}
	// A refusal reaches the log, on one line.
	_, err := m.client.DeleteShare(context.Background(), &adminv1.DeleteShareRequest{Name: "nothing\nhere"})
	if err == nil {
		t.Fatal("control: deleting a share that does not exist succeeded")
	}
	out := m.out.String()
	if !strings.Contains(out, "refused") {
		t.Errorf("BUG: a refused change left no audit line:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "here") || strings.HasPrefix(line, "admin (uid=0): deleted share payroll") {
			t.Errorf("BUG: a forged audit line: %q", line)
		}
	}
	if got := logSafe("a\u2028b"); got != `"a\u2028b"` {
		t.Errorf("logSafe(a U+2028 b) = %s", got)
	}
	if got := logSafe("a\nb"); got != `"a\nb"` {
		t.Errorf("logSafe(a\\nb) = %s", got)
	}
	if got := logSafe("my photos"); got != "my photos" {
		t.Errorf("control: logSafe quoted an ordinary string: %s", got)
	}
}

// R10: one share takes at most maxGrants grants, at creation and one by one.
func TestFoundGrantsAreBounded(t *testing.T) {
	dir := t.TempDir()
	pw := write(t, dir, "u.pw", "pw\n")
	var users strings.Builder
	var many []*adminv1.Grant
	for i := 0; i <= maxGrants; i++ {
		fmt.Fprintf(&users, "user \"u%d\" { password_file = %q }\n", i, hclPath(pw))
		many = append(many, grantOf(userSubject(fmt.Sprintf("u%d", i)), adminv1.Access_ACCESS_READ))
	}
	m := startManaged(t, dir, users.String())
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	_, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree}, Grants: many})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("BUG: %d grants accepted at creation: %v", len(many), err)
	}
	if _, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree}, Grants: many[:maxGrants]}); err != nil {
		t.Fatalf("control: %d grants refused: %v", maxGrants, err)
	}
	_, err = m.client.Grant(context.Background(), &adminv1.GrantRequest{Share: "t", Grant: many[maxGrants]})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("BUG: grant %d accepted: %v", maxGrants+1, err)
	}
}
