// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-authn/directory"
	filesystem "github.com/go-filesystems/interface"
	"github.com/spf13/cobra"

	"github.com/go-fileshare/fileshare/internal/account"
	"github.com/go-fileshare/fileshare/internal/launch"
)

// The two processes of a server whose shares are served as their people
// (docs/identity.md, "The launcher").
//
//	fileshare serve        as root: the LAUNCHER. It binds the listeners,
//	                       starts the front as service_user and answers its
//	                       requests for workers. It speaks no protocol.
//	fileshare serve-front  as service_user: the FRONT. Everything `serve`
//	                       does without identity shares, over the listeners
//	                       it was handed, asking the launcher for workers.
//
// Descriptor 3 of the front is its end of the socket to the launcher; 4 and
// up are the listeners, one per serve block, in the configuration's order.
const (
	frontLauncherFD = 3
	frontFirstLnFD  = 4
)

// serveWithLauncher is `serve` for a configuration with identity shares.
func serveWithLauncher(cfg *config, files []string, out io.Writer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("shares served as their people (identity = %q) need `fileshare serve` started as root: "+
			"it stays root only to start each person's worker, and serves the protocols as %s",
			identitySystem, cfg.Identity.ServiceUser)
	}
	front, err := serviceAccount(cfg.Identity.ServiceUser)
	if err != nil {
		return err
	}
	resolver, closeDir, err := launcherResolver(cfg)
	if err != nil {
		return err
	}
	defer closeDir()
	shares := map[string]launch.Share{}
	for _, b := range cfg.Shares {
		if b.Identity == identitySystem {
			dir, err := filepath.Abs(b.Directory)
			if err != nil {
				return fmt.Errorf("share %q: %w", b.Name, err)
			}
			shares[b.Name] = launch.Share{Name: b.Name, Directory: dir, ReadOnly: b.ReadOnly}
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding this program, to start the front and the workers: %w", err)
	}

	// Bind first, as `serve` always has: a privileged port is bound here, so
	// the front needs no privilege to have it.
	var lns []*os.File
	defer func() {
		for _, f := range lns {
			f.Close()
		}
	}()
	var protos []string
	for _, b := range cfg.Serves {
		ln, err := net.Listen("tcp", b.Addr)
		if err != nil {
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		f, err := ln.(*net.TCPListener).File()
		ln.Close() // f is a copy
		if err != nil {
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		lns = append(lns, f)
		protos = append(protos, b.Protocol)
	}

	conn, theirs, err := launch.Pair()
	if err != nil {
		return err
	}
	defer conn.Close()
	cmd := frontCommand(exe, files, protos, front, theirs, lns)
	if err := cmd.Start(); err != nil {
		theirs.Close()
		return fmt.Errorf("starting the front as %s: %w", front.name, err)
	}
	theirs.Close()
	for _, f := range lns {
		f.Close() // the front holds them now; the launcher listens on nothing
	}
	lns = nil
	fmt.Fprintf(out, "launcher: the front runs as %s (uid %d), pid %d\n", front.name, front.uid, cmd.Process.Pid)

	// Signals reach the front: a stop, or SIGHUP's reload, is its to act on.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	l := &launch.Launcher{
		Resolve: resolver.Resolve,
		Share: func(name string) (launch.Share, bool) {
			s, ok := shares[name]
			return s, ok
		},
		Spawn: launch.Exec(exe, "worker"),
		Log: func(format string, args ...any) {
			fmt.Fprintf(out, "launcher: "+format+"\n", args...)
		},
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(conn) }()
	waitErr := cmd.Wait()
	conn.Close()
	if err := <-served; err != nil && !errors.Is(err, net.ErrClosed) {
		// The front sent what a front does not: it is gone now either way.
		fmt.Fprintf(out, "launcher: the front's requests ended: %v\n", err)
	}
	if waitErr != nil {
		return fmt.Errorf("the front: %w", waitErr)
	}
	return nil
}

// frontAccount is the account the front runs as.
type frontAccount struct {
	name     string
	uid, gid uint32
	groups   []uint32
	home     string
}

func serviceAccount(name string) (frontAccount, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return frontAccount{}, fmt.Errorf("the identity block's service_user: %w", err)
	}
	a := frontAccount{name: name, home: u.HomeDir}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return frontAccount{}, fmt.Errorf("service_user %s: uid %q", name, u.Uid)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return frontAccount{}, fmt.Errorf("service_user %s: gid %q", name, u.Gid)
	}
	if uid == 0 || gid == 0 {
		return frontAccount{}, fmt.Errorf("service_user %s is uid %d, gid %d: the front must not be root, nor in root's group", name, uid, gid)
	}
	a.uid, a.gid = uint32(uid), uint32(gid)
	ids, err := u.GroupIds()
	if err != nil {
		return frontAccount{}, fmt.Errorf("the groups of service_user %s: %w", name, err)
	}
	for _, s := range ids {
		g, err := strconv.ParseUint(s, 10, 32)
		if err != nil || g == 0 {
			continue // root's group is never given to the front
		}
		a.groups = append(a.groups, uint32(g))
	}
	slices.Sort(a.groups)
	a.groups = slices.Compact(a.groups)
	return a, nil
}

// frontCommand is the front's command line and everything it inherits: the
// launcher's environment with HOME and USER made the service account's, the
// socket on descriptor 3, the listeners from 4.
func frontCommand(exe string, files, protos []string, a frontAccount, sock *os.File, lns []*os.File) *exec.Cmd {
	args := []string{"serve-front", "--listeners", strings.Join(protos, ",")}
	for _, f := range files {
		if abs, err := filepath.Abs(f); err == nil {
			f = abs
		}
		args = append(args, "--config", f)
	}
	cmd := exec.Command(exe, args...)
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "USER=") || strings.HasPrefix(kv, "LOGNAME=")
	})
	env = slices.DeleteFunc(env, func(kv string) bool {
		return strings.HasPrefix(kv, launch.FrontEnv+"=") || strings.HasPrefix(kv, launch.WorkerEnv+"=")
	})
	cmd.Env = append(env, "HOME="+a.home, "USER="+a.name, "LOGNAME="+a.name,
		launch.FrontEnv+"="+strconv.Itoa(frontLauncherFD))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = append([]*os.File{sock}, lns...)
	groups := slices.Clone(a.groups)
	if groups == nil {
		groups = []uint32{}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: a.uid, Gid: a.gid, Groups: groups},
	}
	return cmd
}

// launcherResolver resolves people as the launcher does: the directory this
// configuration names, asked by the launcher itself, then /etc/passwd.
func launcherResolver(cfg *config) (*account.Resolver, func(), error) {
	dirs, err := sources(cfg)
	if err != nil {
		return nil, nil, err
	}
	r := &account.Resolver{
		Find:     func(name string) (*directory.Identity, error) { return findIdentity(dirs, name) },
		GroupGID: func(group string) (uint32, bool, error) { return groupGID(dirs, group) },
		MemberOf: func(name string) ([]string, error) { return memberOf(dirs, name) },
		Passwd:   account.SystemPasswd,
		Policy:   cfg.Identity.policy(),
	}
	return r, func() { dirs.Close() }, nil
}

// findIdentity is name's identity in the directory, or nil. The directory is
// asked again at every worker's start, so a uidNumber changed there is used
// by the next worker without a restart.
func findIdentity(dirs *directory.Set, name string) (*directory.Identity, error) {
	ids, err := dirs.Identities()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if id.Name() == name {
			return id, nil
		}
	}
	return nil, nil
}

// memberOf is the groups that list name among their members. A source that
// cannot list its groups is not asked (directory.Set.GroupNames): its people
// get the groups their identity names, and no more.
func memberOf(dirs *directory.Set, name string) ([]string, error) {
	groups, err := dirs.GroupNames()
	if err != nil {
		return nil, err
	}
	var in []string
	for _, g := range groups {
		members, err := dirs.Members(g)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", g, err)
		}
		if slices.Contains(members, name) {
			in = append(in, g)
		}
	}
	return in, nil
}

// groupGID is a directory group's gidNumber; a group with none is no system
// group, and gives the worker nothing.
func groupGID(dirs *directory.Set, group string) (uint32, bool, error) {
	attrs, err := dirs.GroupAttributes(group)
	if err != nil {
		return 0, false, err
	}
	vals := attrs.Get("gidNumber")
	switch len(vals) {
	case 0:
		return 0, false, nil
	case 1:
		g, err := strconv.ParseUint(vals[0], 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("gidNumber %q is not a number", vals[0])
		}
		return uint32(g), true, nil
	}
	return 0, false, fmt.Errorf("gidNumber has %d values, not one", len(vals))
}

// newFrontCmd is the front's role. Hidden: the launcher starts it, and run
// by hand it finds no launcher on descriptor 3 and refuses.
func newFrontCmd(o *options) *cobra.Command {
	var listeners string
	cmd := &cobra.Command{
		Use:           "serve-front",
		Short:         "Serve the protocols for a launcher, as the service account (internal)",
		Hidden:        true,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serveFront(cmd, o, listeners)
		},
	}
	o.bind(cmd.Flags())
	cmd.Flags().StringVar(&listeners, "listeners", "", "the protocols of the inherited listeners, in order")
	return cmd
}

func serveFront(cmd *cobra.Command, o *options, listeners string) error {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("the front never runs as root: `fileshare serve` starts it as the identity block's service_user")
	}
	cfg, err := configOf(o, nil)
	if err != nil {
		return err
	}
	if cfg.Identity == nil {
		return errors.New("the front was started for a configuration with no identity block")
	}
	protos := strings.Split(listeners, ",")
	if len(protos) != len(cfg.Serves) {
		return fmt.Errorf("the launcher passed %d listeners and the configuration has %d serve blocks", len(protos), len(cfg.Serves))
	}
	// The launcher's socket first: run by hand, this is what is missing,
	// and saying so beats a listener's "bad file descriptor".
	conn, err := launch.FrontConn(frontLauncherFD)
	if err != nil {
		return err
	}
	var lns []net.Listener
	for i, p := range protos {
		if cfg.Serves[i].Protocol != p {
			return fmt.Errorf("listener %d is for %s and serve block %d is %s: the configuration changed under the launcher",
				i+1, p, i+1, cfg.Serves[i].Protocol)
		}
		f, err := frontListenerFile(frontFirstLnFD + i)
		if err != nil {
			return fmt.Errorf("the %s listener: %w", p, err)
		}
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("the %s listener: %w", p, err)
		}
		lns = append(lns, ln)
	}
	idle, err := cfg.Identity.idle()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := open(cfg, cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer srv.Close()
	client := launch.NewClient(conn)
	srv.workers = newWorkerPool(func(person, share string) (filesystem.Filesystem, error) {
		fsys, err := client.Worker(person, share)
		if err != nil {
			var refused *launch.Refused
			if errors.As(err, &refused) {
				return nil, &refusedWorker{refused.Reason}
			}
			return nil, err
		}
		return fsys, nil
	}, idle)
	srv.closers = append(srv.closers, srv.workers, conn)
	srv.inherited = lns
	return srv.run(ctx, cfg)
}

// frontListenerFile is listener fd, checked to be a socket: FrontConn has
// already found the launcher's variable, so these were passed too.
func frontListenerFile(fd int) (*os.File, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("descriptor %d: %w", fd, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return nil, fmt.Errorf("descriptor %d is not a socket", fd)
	}
	return os.NewFile(uintptr(fd), "listener"), nil
}
