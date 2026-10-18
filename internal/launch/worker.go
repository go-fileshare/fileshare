// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package launch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-filesystems/osfs"
	"github.com/go-filesystems/remote"

	"github.com/go-fileshare/fileshare/internal/account"
)

// workerFD is where a worker finds its end of the socket: the first of
// ExtraFiles.
const workerFD = 3

// Exec is the Spawn that starts exe -- this very binary -- with args (the
// subcommand that runs Worker) as a: setgroups, setgid, setuid in the child,
// each checked by the Go runtime before exec (SysProcAttr.Credential).
//
//   - The environment is EMPTY but for PATH: a worker running as a person
//     must not inherit the launcher's, whatever is in it.
//   - Its only descriptor besides 0-2 is its end of the socket; every other
//     one is close-on-exec, which Go guarantees for what it opens.
//   - It is in a session of its own, so a signal to the launcher's process
//     group is not one to it.
//   - Groups is set, never NoSetGroups: an empty list clears root's groups,
//     NoSetGroups would keep them.
func Exec(exe string, args ...string) Spawn {
	return func(a account.Account, s Share) (*os.File, error) {
		ours, theirs, err := socketpair()
		if err != nil {
			return nil, err
		}
		defer theirs.Close()
		cmd := command(exe, args, a, s, theirs)
		if err := cmd.Start(); err != nil {
			ours.Close()
			return nil, err
		}
		go func() { _ = cmd.Wait() }() // reaped; it ends when the front closes its end
		return ours, nil
	}
}

// command is the worker's command line and everything it inherits.
func command(exe string, args []string, a account.Account, s Share, socket *os.File) *exec.Cmd {
	cmd := exec.Command(exe, append(slices.Clone(args), workerArgs(a, s)...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout = nil, nil
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{socket}
	cmd.SysProcAttr = sysProcAttr(a)
	return cmd
}

func sysProcAttr(a account.Account) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: slices.Clone(a.Groups)},
		Setsid:     true,
	}
	if attr.Credential.Groups == nil {
		attr.Credential.Groups = []uint32{}
	}
	platformAttr(attr)
	return attr
}

// socketpair is a connected pair of unix stream sockets, close-on-exec, made
// under syscall.ForkLock so that no exec between socketpair and CloseOnExec
// inherits them.
func socketpair() (ours, theirs *os.File, err error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "launcher"), os.NewFile(uintptr(fds[1]), "worker"), nil
}

// workerArgs are what a worker is told: the tree, and the ids it must find
// itself running as -- from the launcher, root, which is trusted.
func workerArgs(a account.Account, s Share) []string {
	groups := make([]string, len(a.Groups))
	for i, g := range a.Groups {
		groups[i] = strconv.FormatUint(uint64(g), 10)
	}
	return []string{
		"--directory", s.Directory,
		"--read-only=" + strconv.FormatBool(s.ReadOnly),
		"--uid", strconv.FormatUint(uint64(a.UID), 10),
		"--gid", strconv.FormatUint(uint64(a.GID), 10),
		"--groups", strings.Join(groups, ","),
	}
}

// Expect is what a worker must find itself running as.
type Expect struct {
	UID, GID uint32
	Groups   []uint32
}

// ids is what the process is running as, and whether it can become root
// again: the real calls, replaced in tests.
type ids struct {
	getuid, geteuid, getgid, getegid func() int
	getgroups                        func() ([]int, error)
	setuid, setgid                   func(int) error
}

var processIDs = ids{
	getuid: os.Getuid, geteuid: os.Geteuid, getgid: os.Getgid, getegid: os.Getegid,
	getgroups: syscall.Getgroups, setuid: syscall.Setuid, setgid: syscall.Setgid,
}

// Verify is the worker's check, before it touches a file: it runs as exactly
// e -- real and effective, uid and gid, and exactly e.Groups -- it is not
// root, and it cannot become root again. Each of these has failed in some
// server before (CVE-2006-2607, CVE-2012-2653, CVE-2009-3589, CERT POS37-C).
func Verify(e Expect) error { return verify(processIDs, e) }

func verify(p ids, e Expect) error {
	if e.UID == 0 {
		return errors.New("a worker must never be asked to run as root")
	}
	uid, euid, gid, egid := p.getuid(), p.geteuid(), p.getgid(), p.getegid()
	if uid != int(e.UID) || euid != int(e.UID) {
		return fmt.Errorf("running as uid %d (effective %d), not %d", uid, euid, e.UID)
	}
	if gid != int(e.GID) || egid != int(e.GID) {
		return fmt.Errorf("running as gid %d (effective %d), not %d", gid, egid, e.GID)
	}
	got, err := p.getgroups()
	if err != nil {
		return fmt.Errorf("getgroups: %w", err)
	}
	have := make([]uint32, 0, len(got))
	for _, g := range got {
		have = append(have, uint32(g))
	}
	slices.Sort(have)
	have = slices.Compact(have)
	want := slices.Clone(e.Groups)
	slices.Sort(want)
	want = slices.Compact(want)
	// The primary gid may or may not be listed by getgroups; it is the one
	// difference allowed.
	have = slices.DeleteFunc(have, func(g uint32) bool { return g == e.GID })
	want = slices.DeleteFunc(want, func(g uint32) bool { return g == e.GID })
	if !slices.Equal(have, want) {
		return fmt.Errorf("supplementary groups %v, not %v", have, want)
	}
	if p.setuid(0) == nil {
		return errors.New("setuid(0) succeeded: this process can become root again")
	}
	if p.setgid(0) == nil {
		return errors.New("setgid(0) succeeded: this process can join root's group again")
	}
	return nil
}

// Worker is a worker's whole life, after Verify: open the tree, as the
// person, and serve it on the inherited socket until the front closes it.
func Worker(e Expect, dir string, readOnly bool) error {
	if err := Verify(e); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	if err := hardenWorker(); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	var opts []osfs.Option
	if readOnly {
		opts = append(opts, osfs.ReadOnly())
	}
	fsys, err := osfs.Open(dir, opts...)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	defer fsys.Close()
	f := os.NewFile(workerFD, "worker")
	if f == nil {
		return errors.New("worker: no socket on descriptor 3")
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("worker: the socket on descriptor 3: %w", err)
	}
	return remote.Serve(conn, fsys)
}

// ParseExpect reads the ids a worker was told, as workerArgs wrote them.
func ParseExpect(uid, gid uint64, groups string) (Expect, error) {
	if uid > 1<<32-2 || gid > 1<<32-2 {
		return Expect{}, errors.New("a uid or a gid out of range")
	}
	e := Expect{UID: uint32(uid), GID: uint32(gid)}
	if groups == "" {
		return e, nil
	}
	for _, s := range strings.Split(groups, ",") {
		g, err := strconv.ParseUint(s, 10, 32)
		if err != nil || g == 1<<32-1 {
			return Expect{}, fmt.Errorf("a group %q", s)
		}
		e.Groups = append(e.Groups, uint32(g))
	}
	return e, nil
}
