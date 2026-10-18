// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
	"github.com/go-filesystems/remote"
)

// What a share served as its people cannot mean is refused, with the reason.
func TestIdentityConfigurationsThatCannotWork(t *testing.T) {
	needSetuid(t)
	if protocolByName("sftp") == nil {
		t.Skip("this binary has no sftp")
	}
	dir := t.TempDir()
	users := `user "alice" { authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyDummyDummyDummyDummyDummyDummyDummyDu"] }` + "\n"
	ident := "identity { service_user = \"fileshare\" }\n"
	share := func(attrs string) string {
		return fmt.Sprintf("share \"home\" {\n directory = %q\n identity = \"system\"\n %s\n}\nserve \"sftp\" {}\n", hclPath(dir), attrs)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"another value", users + ident + strings.Replace(share(""), `"system"`, `"person"`, 1), `the one value is "system"`},
		{"an image", users + ident + "share \"home\" {\n image = \"/i\"\n identity = \"system\"\n}\nserve \"sftp\" {}\n", "for a directory share"},
		{"no identity block", users + share(""), "there is no identity block"},
		{"nobody to be", ident + share(""), "no user or users block"},
		{"a protocol that cannot", users + ident + share(`protocols = ["sftp", "smb"]`), "cannot serve it as its people yet"},
		{"no service user", users + "identity {\n service_user = \"\"\n}\n" + share(""), "needs service_user"},
		{"root as the front", users + "identity { service_user = \"root\" }\n" + share(""), "service_user is root"},
		{"min_uid 0", users + "identity {\n service_user = \"fs\"\n min_uid = 0\n}\n" + share(""), "min_uid is 0"},
		{"min_gid too big", users + "identity {\n service_user = \"fs\"\n min_gid = 4294967295\n}\n" + share(""), "min_gid is 4294967295"},
		{"a deny_uid that is no uid", users + "identity {\n service_user = \"fs\"\n deny_uids = [-1]\n}\n" + share(""), "which is no uid"},
		{"idle that is no duration", users + "identity {\n service_user = \"fs\"\n idle = \"soon\"\n}\n" + share(""), "a Go duration"},
		{"an identity block for nothing", users + ident + fmt.Sprintf("share \"home\" { directory = %q }\nserve \"sftp\" {}\n", hclPath(dir)), "no share says identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig([]string{write(t, t.TempDir(), "c.hcl", tc.body)})
			if err == nil {
				t.Fatalf("accepted:\n%s", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for another reason: %v (want %q)", err, tc.want)
			}
		})
	}
}

// needSetuid skips where shares served as their people are refused whole:
// Windows has no uid to start a worker as.
func needSetuid(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no setuid on windows")
	}
}

// On Windows the refusal says why, whatever else the share says.
func TestIdentityRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	err := (&config{Identity: &identityBlock{ServiceUser: "fs"}}).checkShareIdentity(shareBlock{Name: "h", Directory: "C:/h", Identity: identitySystem})
	if err == nil || !strings.Contains(err.Error(), "needs a Unix system") {
		t.Fatalf("%v", err)
	}
}

// The identity block's settings become the launcher's policy; what it does
// not say is the default.
func TestIdentityPolicy(t *testing.T) {
	two, three := int64(2000), int64(3000)
	p := (&identityBlock{MinUID: &two, MinGID: &three, DenyUIDs: []int64{65534}}).policy()
	if p.MinUID != 2000 || p.MinGID != 3000 || len(p.DenyUIDs) != 1 || p.DenyUIDs[0] != 65534 {
		t.Fatalf("policy %+v", p)
	}
	if p := (&identityBlock{}).policy(); p.MinUID != 1000 || p.MinGID != 1000 {
		t.Fatalf("default policy %+v", p)
	}
	if d, err := (&identityBlock{}).idle(); err != nil || d != defaultWorkerIdle {
		t.Fatalf("default idle %v %v", d, err)
	}
	if d, err := (&identityBlock{Idle: "5s"}).idle(); err != nil || d != 5*time.Second {
		t.Fatalf("idle %v %v", d, err)
	}
}

// A share served as its people goes over SFTP and WebDAV, and nowhere else:
// the others would have to serve it as this process.
func TestIdentityShareExports(t *testing.T) {
	sh := &share{name: "home", system: true}
	for _, p := range protocols {
		served, refused := p.exports(&config{}, []*share{sh})
		if identityProtocol(p.name) {
			if len(served) != 1 {
				t.Errorf("%s does not serve it", p.name)
			}
			continue
		}
		if len(refused) != 1 {
			t.Errorf("%s does not refuse it", p.name)
			continue
		}
		if why := p.refusal(sh); !strings.Contains(why, "served as its people") {
			t.Errorf("%s says %q", p.name, why)
		}
	}
}

// fakeLauncher hands out workers over the real remote protocol: each person
// gets their own directory under root, served by osfs on the far end of a
// pipe -- everything a launcher's worker is, but the uid.
type fakeLauncher struct {
	root    string
	refuse  map[string]bool
	fail    error
	started atomic.Int32
	mu      sync.Mutex
	open    []*remote.FS
}

func (l *fakeLauncher) get(person, share string) (filesystem.Filesystem, error) {
	if l.refuse[person] {
		return nil, &refusedWorker{person + ": no system account"}
	}
	if l.fail != nil {
		return nil, l.fail
	}
	dir := filepath.Join(l.root, share, person)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	fsys, err := osfs.Open(dir)
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	go func() { _ = remote.Serve(b, fsys); fsys.Close() }()
	r, err := remote.New(a)
	if err != nil {
		return nil, err
	}
	l.started.Add(1)
	l.mu.Lock()
	l.open = append(l.open, r)
	l.mu.Unlock()
	return r, nil
}

func TestWorkerPoolSharesAndReleases(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, 20*time.Millisecond)
	defer p.Close()

	w1, rel1, err := p.acquire("alice", "home")
	if err != nil {
		t.Fatal(err)
	}
	w2, rel2, err := p.acquire("alice", "home")
	if err != nil {
		t.Fatal(err)
	}
	if w1 != w2 || l.started.Load() != 1 {
		t.Fatalf("two acquires started %d workers", l.started.Load())
	}
	w3, rel3, err := p.acquire("bob", "home")
	if err != nil || w3 == w1 {
		t.Fatalf("bob shares alice's worker (%v)", err)
	}
	rel3()
	rel1()
	rel1() // a release counts once
	time.Sleep(60 * time.Millisecond)
	if p.size() != 1 {
		t.Fatalf("%d workers after bob left and alice holds one", p.size())
	}
	if _, err := w1.fsys.Stat("/"); err != nil {
		t.Fatalf("alice's worker was closed under her: %v", err)
	}
	rel2()
	deadline := time.Now().Add(2 * time.Second)
	for p.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("an unused worker was never closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := w1.fsys.Stat("/"); !isClosed(err) {
		t.Fatalf("a closed worker answers %v", err)
	}
}

// Acquiring again before the idle period ends keeps the worker.
func TestWorkerPoolReuseWithinIdle(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, time.Hour)
	defer p.Close()
	_, rel, _ := p.acquire("alice", "home")
	rel()
	_, rel, err := p.acquire("alice", "home")
	if err != nil {
		t.Fatal(err)
	}
	rel()
	if n := l.started.Load(); n != 1 {
		t.Fatalf("%d workers started", n)
	}
}

// Many first requests at once start ONE worker.
func TestWorkerPoolConcurrentFirstAcquire(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	slow := func(person, share string) (filesystem.Filesystem, error) {
		time.Sleep(20 * time.Millisecond)
		return l.get(person, share)
	}
	p := newWorkerPool(slow, time.Hour)
	defer p.Close()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, rel, err := p.acquire("alice", "home")
			if err != nil {
				t.Error(err)
				return
			}
			rel()
		}()
	}
	wg.Wait()
	if n := l.started.Load(); n != 1 {
		t.Fatalf("%d workers started", n)
	}
}

// A refusal is not kept: the next request asks again.
func TestWorkerPoolDoesNotKeepFailures(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir(), fail: errors.New("launcher gone")}
	p := newWorkerPool(l.get, time.Hour)
	defer p.Close()
	if _, _, err := p.acquire("alice", "home"); err == nil {
		t.Fatal("a failed start was served")
	}
	l.fail = nil
	_, rel, err := p.acquire("alice", "home")
	if err != nil {
		t.Fatalf("the failure was kept: %v", err)
	}
	rel()
}

// A worker that died is replaced, not served as errors until it goes idle.
func TestWorkerPoolReplacesADeadWorker(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, time.Hour)
	defer p.Close()
	w, rel, _ := p.acquire("alice", "home")
	rel()
	w.fsys.Close() // as a worker that exited looks from here
	w2, rel2, err := p.acquire("alice", "home")
	if err != nil {
		t.Fatal(err)
	}
	defer rel2()
	if w2 == w || l.started.Load() != 2 {
		t.Fatalf("the dead worker was served again")
	}
}

func TestWorkerPoolRefusals(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, time.Hour)
	if _, _, err := p.acquire("", "home"); err == nil {
		t.Fatal("a worker for nobody")
	}
	_, rel, _ := p.acquire("alice", "home")
	p.Close()
	rel() // after Close: nothing to do, and no panic
	if _, _, err := p.acquire("alice", "home"); !errors.Is(err, errPoolClosed) {
		t.Fatalf("a closed pool answers %v", err)
	}
	if l.started.Load() != 1 {
		t.Fatal("a closed pool started a worker")
	}
}

// reset closes every worker; a release that comes after finds nothing.
func TestWorkerPoolReset(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, time.Hour)
	defer p.Close()
	w, rel, _ := p.acquire("alice", "home")
	p.reset()
	if p.size() != 0 {
		t.Fatal("reset kept a worker")
	}
	if _, err := w.fsys.Stat("/"); !isClosed(err) {
		t.Fatalf("a reset worker answers %v", err)
	}
	rel()
	if p.size() != 0 {
		t.Fatal("a late release brought a worker back")
	}
}

// What a protocol builds over a worker is built once.
func TestWorkerAttach(t *testing.T) {
	l := &fakeLauncher{root: t.TempDir()}
	p := newWorkerPool(l.get, time.Hour)
	defer p.Close()
	w, rel, _ := p.acquire("alice", "home")
	defer rel()
	var built int
	for range 3 {
		v, err := w.attach("x", func(filesystem.Filesystem) (any, error) { built++; return built, nil })
		if err != nil || v != 1 {
			t.Fatalf("%v %v", v, err)
		}
	}
	if _, err := w.attach("y", func(filesystem.Filesystem) (any, error) { return nil, errors.New("no") }); err == nil {
		t.Fatal("a failed build was kept")
	}
}

// Without a launcher, a share served as its people is served to nobody --
// never as this process.
func TestWorkerOfWithoutLauncher(t *testing.T) {
	s := &server{}
	if _, _, err := s.workerOf(local("alice"), &share{name: "home", system: true}); !errors.Is(err, errNoLauncher) {
		t.Fatalf("%v", err)
	}
	s.workers = newWorkerPool((&fakeLauncher{root: t.TempDir()}).get, time.Hour)
	defer s.workers.Close()
	var refused *refusedWorker
	if _, _, err := s.workerOf(principal{name: "alice", federated: true}, &share{name: "home", system: true}); !errors.As(err, &refused) {
		t.Fatalf("a federated person with no local name got %v", err)
	}
}

// unionForWith puts each share served as its people in the tree through the
// worker, and leaves it out when there is none.
func TestUnionForWithWorkers(t *testing.T) {
	plain := &share{name: "plain"}
	home := &share{name: "home", system: true}
	other := &share{name: "other", system: true}
	if u := unionFor([]*share{plain, home}, local("alice")); len(u.entries) != 1 || u.entries[0].name != "plain" {
		t.Fatalf("without workers: %+v", u.entries)
	}
	dir := t.TempDir()
	fsys, err := osfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	u := unionForWith([]*share{plain, home, other}, local("alice"), func(sh *share) (filesystem.Filesystem, bool) {
		return fsys, sh.name == "home"
	})
	if len(u.entries) != 2 || u.entries[1].name != "home" || u.entries[1].fsys != fsys {
		t.Fatalf("with workers: %+v", u.entries)
	}
}

// identityConfig is a share served as its people, over the protocols named,
// to alice, bob and carol -- bob reading only.
func identityConfig(t *testing.T, serves string, users string) string {
	t.Helper()
	return fmt.Sprintf(`%s
identity { service_user = "fileshare" }
share "home" {
  directory = %q
  identity  = "system"
  writers   = ["alice", "carol"]
}
%s`, users, hclPath(t.TempDir()), serves)
}

func passwordUsers(t *testing.T) string {
	dir := t.TempDir()
	var b strings.Builder
	for _, u := range []string{"alice", "bob", "carol"} {
		fmt.Fprintf(&b, "user %q { password_file = %q }\n", u, hclPath(write(t, dir, u+".pw", u+"-pw\n")))
	}
	return b.String()
}
