// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package launch

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/go-filesystems/osfs"
	"github.com/go-filesystems/remote"

	"github.com/go-fileshare/fileshare/internal/account"
)

// unixPair is a connected pair of *net.UnixConn.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, b, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	conn := func(f *os.File) *net.UnixConn {
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conn(a), conn(b)
}

// inProcess is a Spawn that serves the share's directory from this process
// instead of a child: everything but the setuid, which needs root (see
// TestAsRoot).
func inProcess(t *testing.T, spawned *atomic.Int64) Spawn {
	return func(a account.Account, s Share) (*os.File, error) {
		spawned.Add(1)
		ours, theirs, err := socketpair()
		if err != nil {
			return nil, err
		}
		fsys, err := osfs.Open(s.Directory)
		if err != nil {
			return nil, err
		}
		c, err := net.FileConn(theirs)
		theirs.Close()
		if err != nil {
			return nil, err
		}
		go func() { _ = remote.Serve(c, fsys); _ = fsys.Close() }()
		return ours, nil
	}
}

type world struct {
	front   *Client
	spawned atomic.Int64
	dir     string
	done    chan error
	// logs is written by the launcher's goroutine. Its order with the
	// front's reads passes through a socket, which the race detector
	// cannot see, so it is locked.
	mu   sync.Mutex
	logs []string
}

func (w *world) log() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.logs)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{dir: t.TempDir(), done: make(chan error, 1)}
	_ = os.WriteFile(filepath.Join(w.dir, "hello.txt"), []byte("hello"), 0o644)
	l := &Launcher{
		Resolve: func(person string) (account.Account, error) {
			if person == "root" {
				return account.Account{}, fmt.Errorf("root: %w: uid 0 is root", account.ErrRefused)
			}
			return account.Account{Name: person, UID: 1001, GID: 1001, Groups: []uint32{1001}, From: "test"}, nil
		},
		Share: func(name string) (Share, bool) {
			if name != "photos" {
				return Share{}, false
			}
			return Share{Name: name, Directory: w.dir}, true
		},
		Spawn: inProcess(t, &w.spawned),
		Log: func(f string, a ...any) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.logs = append(w.logs, fmt.Sprintf(f, a...))
		},
	}
	front, launcher := unixPair(t)
	go func() { w.done <- l.Serve(launcher) }()
	w.front = NewClient(front)
	t.Cleanup(func() { _ = front.Close(); <-w.done })
	return w
}

// A front asks for a worker by person and share, and gets the share's files
// through it -- over a descriptor the launcher passed and did not keep.
func TestAWorkerServesTheShare(t *testing.T) {
	w := newWorld(t)
	fsys, err := w.front.Worker("alice", "photos")
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	b, err := fsys.ReadFile("hello.txt")
	if err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	if err := fsys.WriteFile("new.txt", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "new.txt")); err != nil {
		t.Fatal(err)
	}
	if logs := w.log(); len(logs) != 1 || !strings.Contains(logs[0], "uid 1001") {
		t.Fatalf("logs %q", logs)
	}
}

// What the launcher refuses, the front is told why, and no worker starts.
func TestRefusals(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct{ person, share, why string }{
		{"root", "photos", "uid 0 is root"},
		{"alice", "nope", `no share "nope"`},
	} {
		_, err := w.front.Worker(c.person, c.share)
		var r *Refused
		if !errors.As(err, &r) || !strings.Contains(r.Reason, c.why) {
			t.Errorf("%s/%s: %v", c.person, c.share, err)
		}
	}
	if w.spawned.Load() != 0 {
		t.Fatalf("%d workers started for refused requests", w.spawned.Load())
	}
	// The connection goes on after a refusal.
	if _, err := w.front.Worker("alice", "photos"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.front.Worker(strings.Repeat("x", maxName+1), "photos"); err == nil {
		t.Fatal("a name over the limit was sent")
	}
}

// A request the launcher cannot read ends the connection: only the front
// holds this socket, and a front that sends that is not the front.
func TestLauncherEndsOnBadRequests(t *testing.T) {
	big := make([]byte, 4)
	big[0] = 0xff
	for name, send := range map[string]func(c *net.UnixConn) error{
		"too long": func(c *net.UnixConn) error { _, err := c.Write(big); return err },
		"garbage":  func(c *net.UnixConn) error { return writeMsg(c, []byte{1, 2, 3}, nil) },
		"empty person": func(c *net.UnixConn) error {
			return writeMsg(c, appendStr(appendStr(nil, ""), "photos"), nil)
		},
		"with a descriptor": func(c *net.UnixConn) error {
			f, _ := os.Open(os.DevNull)
			defer f.Close()
			return writeMsg(c, appendStr(appendStr(nil, "alice"), "photos"), f)
		},
	} {
		t.Run(name, func(t *testing.T) {
			front, launcher := unixPair(t)
			defer front.Close()
			l := &Launcher{Spawn: func(account.Account, Share) (*os.File, error) {
				t.Error("a worker was started")
				return nil, errors.New("no")
			}}
			done := make(chan error, 1)
			go func() { done <- l.Serve(launcher) }()
			if err := send(front); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("the launcher took it")
			}
		})
	}
}

// Replies a front must not believe: no descriptor with a "started", two of
// them, a reply that does not decode, a launcher that hangs up.
func TestClientRefusesBadReplies(t *testing.T) {
	devnull := func() *os.File { f, _ := os.Open(os.DevNull); return f }
	for name, answer := range map[string]func(c *net.UnixConn){
		"started, no descriptor": func(c *net.UnixConn) { _ = writeMsg(c, reply(nil), nil) },
		"refused, with one": func(c *net.UnixConn) {
			f := devnull()
			defer f.Close()
			_ = writeMsg(c, reply(errors.New("no")), f)
		},
		"two descriptors": func(c *net.UnixConn) {
			f, g := devnull(), devnull()
			defer f.Close()
			defer g.Close()
			b := appendStr([]byte{0}, "")
			hdr := []byte{0, 0, 0, byte(len(b))}
			_, _, _ = c.WriteMsgUnix(append(hdr, b...), syscall.UnixRights(int(f.Fd()), int(g.Fd())), nil)
		},
		"status 7":  func(c *net.UnixConn) { _ = writeMsg(c, appendStr([]byte{7}, ""), nil) },
		"trailing":  func(c *net.UnixConn) { _ = writeMsg(c, append(reply(nil), 1), nil) },
		"too long":  func(c *net.UnixConn) { _, _ = c.Write([]byte{0xff, 0, 0, 0}) },
		"hangs up":  func(c *net.UnixConn) { _ = c.Close() },
		"cut short": func(c *net.UnixConn) { _, _ = c.Write([]byte{0, 0, 0, 9, 0}); _ = c.Close() },
		"not a socket": func(c *net.UnixConn) {
			f := devnull()
			defer f.Close()
			_ = writeMsg(c, reply(nil), f)
		},
	} {
		t.Run(name, func(t *testing.T) {
			front, launcher := unixPair(t)
			defer front.Close()
			defer launcher.Close()
			go func() {
				if _, _, err := readMsg(launcher, maxRequest); err == nil {
					answer(launcher)
				}
			}()
			if fsys, err := NewClient(front).Worker("alice", "photos"); err == nil {
				_ = fsys.Close()
				t.Fatal("the front believed it")
			}
		})
	}
}

// Verify, against ids that lie in every way it checks.
func TestVerify(t *testing.T) {
	good := ids{
		getuid: func() int { return 1001 }, geteuid: func() int { return 1001 },
		getgid: func() int { return 1001 }, getegid: func() int { return 1001 },
		getgroups: func() ([]int, error) { return []int{2000, 1001}, nil },
		setuid:    func(int) error { return syscall.EPERM },
		setgid:    func(int) error { return syscall.EPERM },
	}
	e := Expect{UID: 1001, GID: 1001, Groups: []uint32{1001, 2000}}
	if err := verify(good, e); err != nil {
		t.Fatal(err)
	}
	// getgroups may leave the primary out: still the same.
	g := good
	g.getgroups = func() ([]int, error) { return []int{2000}, nil }
	if err := verify(g, e); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ids){
		"real uid":         func(p *ids) { p.getuid = func() int { return 0 } },
		"effective uid":    func(p *ids) { p.geteuid = func() int { return 0 } },
		"real gid":         func(p *ids) { p.getgid = func() int { return 0 } },
		"effective gid":    func(p *ids) { p.getegid = func() int { return 0 } },
		"a group too many": func(p *ids) { p.getgroups = func() ([]int, error) { return []int{2000, 0}, nil } },
		"a group missing":  func(p *ids) { p.getgroups = func() ([]int, error) { return nil, nil } },
		"getgroups fails":  func(p *ids) { p.getgroups = func() ([]int, error) { return nil, syscall.EINVAL } },
		"root again":       func(p *ids) { p.setuid = func(int) error { return nil } },
		"root group again": func(p *ids) { p.setgid = func(int) error { return nil } },
	} {
		p := good
		mutate(&p)
		if err := verify(p, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := verify(good, Expect{UID: 0}); err == nil {
		t.Error("asked to run as root, and accepted")
	}
}

func TestParseExpect(t *testing.T) {
	e, err := ParseExpect(1001, 100, "100,2000")
	if err != nil || e.UID != 1001 || e.GID != 100 || fmt.Sprint(e.Groups) != "[100 2000]" {
		t.Fatalf("%+v %v", e, err)
	}
	if e, err := ParseExpect(1001, 100, ""); err != nil || e.Groups != nil {
		t.Fatalf("no groups: %+v %v", e, err)
	}
	for _, c := range []struct {
		uid, gid uint64
		groups   string
	}{{1 << 32, 1, ""}, {1<<32 - 1, 1, ""}, {1, 1<<32 - 1, ""}, {1, 1, "x"}, {1, 1, "4294967295"}, {1, 1, "1,,2"}} {
		if _, err := ParseExpect(c.uid, c.gid, c.groups); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if args := workerArgs(account.Account{UID: 5, GID: 6, Groups: []uint32{6, 7}}, Share{Directory: "/d", ReadOnly: true}); strings.Join(args, " ") !=
		"--directory /d --read-only=true --uid 5 --gid 6 --groups 6,7" {
		t.Fatalf("%q", args)
	}
}

// A worker started for real as root, then setuid to another account: it
// serves the share as that account, the kernel applies that account's
// permissions, and what it creates belongs to it. Skipped unless root.
// CI builds this test binary where another uid can execute it (go test's
// own build directory is 0700) and runs it with sudo.
func TestAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the worker is started with another uid")
	}
	const uid, gid = 64001, 64001
	// t.TempDir is made 0700 by root: the worker, another uid, could not
	// even reach it. Its parent is opened up; the share itself is the
	// worker's.
	dir := t.TempDir()
	_ = os.Chmod(filepath.Dir(dir), 0o755)
	_ = os.Chmod(dir, 0o755)
	_ = os.Chown(dir, uid, gid)
	_ = os.WriteFile(filepath.Join(dir, "mine.txt"), []byte("mine"), 0o600)
	_ = os.Chown(filepath.Join(dir, "mine.txt"), uid, gid)
	_ = os.WriteFile(filepath.Join(dir, "roots.txt"), []byte("root's"), 0o600) // root's, 0600
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l := &Launcher{
		Resolve: func(string) (account.Account, error) {
			return account.Account{Name: "worker-test", UID: uid, GID: gid, Groups: []uint32{gid}}, nil
		},
		Share: func(string) (Share, bool) { return Share{Name: "s", Directory: dir}, true },
		Spawn: Exec(exe, "-test.run=^TestWorkerMain$", "--"),
	}
	front, launcher := unixPair(t)
	done := make(chan error, 1)
	go func() { done <- l.Serve(launcher) }()
	defer func() { _ = front.Close(); <-done }()
	fsys, err := NewClient(front).Worker("worker-test", "s")
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	if b, err := fsys.ReadFile("mine.txt"); err != nil || string(b) != "mine" {
		t.Fatalf("its own file: %q %v", b, err)
	}
	if _, err := fsys.ReadFile("roots.txt"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("root's 0600 file, read as uid %d: %v", uid, err)
	}
	if err := fsys.WriteFile("made.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "made.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
		t.Fatalf("made.txt belongs to %d:%d, not %d:%d", st.Uid, st.Gid, uid, gid)
	}
}

// TestWorkerMain is the worker, when this test binary is started as one by
// TestAsRoot (Exec appends the worker's flags after "--").
func TestWorkerMain(t *testing.T) {
	args := os.Args
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i == len(args) {
		t.Skip("run as a worker by TestAsRoot only")
	}
	var dir, groups string
	var uid, gid uint64
	var ro bool
	rest := args[i+1:]
	for j := 0; j+1 < len(rest); j += 2 {
		switch rest[j] {
		case "--directory":
			dir = rest[j+1]
		case "--uid":
			fmt.Sscan(rest[j+1], &uid)
		case "--gid":
			fmt.Sscan(rest[j+1], &gid)
		case "--groups":
			groups = rest[j+1]
		}
		if strings.HasPrefix(rest[j], "--read-only=") {
			ro = rest[j] == "--read-only=true"
			j--
		}
	}
	e, err := ParseExpect(uid, gid, groups)
	if err != nil {
		t.Fatal(err)
	}
	if err := Worker(e, dir, ro); err != nil {
		t.Fatal(err)
	}
}

// What a worker inherits, checked without starting one: no environment but
// PATH, one descriptor, its own session, the person's ids with their groups
// set -- an empty list when they have none, never NoSetGroups, which would
// keep root's.
func TestCommand(t *testing.T) {
	t.Setenv("FILESHARE_SECRET_FOR_TEST", "s3cret")
	sock, _ := os.Open(os.DevNull)
	defer sock.Close()
	for _, groups := range [][]uint32{{1001, 2000}, nil} {
		a := account.Account{UID: 1001, GID: 1001, Groups: groups}
		cmd := command("/x/fileshare", []string{"worker"}, a, Share{Directory: "/d"}, sock)
		if strings.Join(cmd.Env, " ") != "PATH=/usr/bin:/bin FILESHARE_WORKER_FD=3" {
			t.Errorf("env %q", cmd.Env)
		}
		if cmd.Dir != "/" || len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != sock {
			t.Errorf("dir %q, extra files %v", cmd.Dir, cmd.ExtraFiles)
		}
		c := cmd.SysProcAttr.Credential
		if c == nil || c.Uid != 1001 || c.Gid != 1001 || c.NoSetGroups || c.Groups == nil || len(c.Groups) != len(groups) {
			t.Errorf("credential %+v", c)
		}
		if !cmd.SysProcAttr.Setsid {
			t.Error("not in a session of its own")
		}
		checkPlatformAttr(t, cmd.SysProcAttr)
		if cmd.Args[1] != "worker" || cmd.Args[2] != "--directory" {
			t.Errorf("args %q", cmd.Args)
		}
	}
}

// A descriptor is taken only when the launcher said it passed one, and only
// if it is a socket: taking fd 3 on faith closed the Go runtime's poller in a
// front run by hand, and the process died in netpoll.
func TestInheritedRefusesWhatWasNotPassed(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(r.Fd())
	t.Setenv("FILESHARE_TEST_FD", "")
	if _, err := Inherited(fd, "FILESHARE_TEST_FD"); err == nil || !strings.Contains(err.Error(), "not by hand") {
		t.Fatalf("no variable: %v", err)
	}
	t.Setenv("FILESHARE_TEST_FD", strconv.Itoa(fd))
	if _, err := Inherited(fd, "FILESHARE_TEST_FD"); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("a pipe: %v", err)
	}
	ours, theirs, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	sfd := int(theirs.Fd())
	t.Setenv("FILESHARE_TEST_FD", strconv.Itoa(sfd))
	f, err := Inherited(sfd, "FILESHARE_TEST_FD")
	if err != nil {
		t.Fatalf("a socket: %v", err)
	}
	f.Close()
	if _, err := Inherited(sfd, "FILESHARE_TEST_FD"); err == nil {
		t.Fatal("a closed descriptor was taken")
	}
	theirs.Close() // already closed through f; the error is expected
}
