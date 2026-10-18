// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/go-fileshare/fileshare/internal/account"
)

// Serving a directory AS each person (docs/identity.md).
//
// A share with identity = "system" is not opened by this process. Each
// person who reaches it gets a worker: a process running with their uid, gid
// and groups, started by the launcher -- `fileshare serve` itself, as root --
// which serves the tree to this process over a socket. The kernel then
// decides what they may read and write, and a file they create is theirs.
//
//	identity {
//	  service_user = "fileshare"   # what the front runs as
//	  min_uid      = 1000          # the default; uid 0 is refused whatever it says
//	  min_gid      = 1000
//	  deny_uids    = [65534]
//	  idle         = "2m"          # how long an unused worker is kept
//	}
//	share "home" {
//	  directory = "/srv/home"
//	  identity  = "system"
//	}

// identityBlock is the top-level identity block.
type identityBlock struct {
	// ServiceUser is the account the front -- the process that speaks the
	// protocols -- runs as. It must not be root: a front that is root is a
	// front that need not ask the launcher for anything.
	ServiceUser string  `hcl:"service_user"`
	MinUID      *int64  `hcl:"min_uid,optional"`
	MinGID      *int64  `hcl:"min_gid,optional"`
	DenyUIDs    []int64 `hcl:"deny_uids,optional"`
	// Idle is how long a worker nobody uses is kept, as a Go duration.
	Idle string `hcl:"idle,optional"`
}

// identitySystem is the one value identity takes on a share.
const identitySystem = "system"

// defaultWorkerIdle is how long an unused worker is kept when idle is not
// said: long enough that a WebDAV client's requests, which come one at a time
// with gaps, do not each start a process; short enough that a person who left
// is not a process for long.
const defaultWorkerIdle = 2 * time.Minute

// identityProtocols are the protocols that can serve a share as its people
// today: those where the person is known where the filesystem is chosen.
// SMB and NFS need a filesystem per session in their libraries, S3 the
// launcher to read LDAP (docs/identity.md, "Phases").
var identityProtocols = []string{"sftp", "webdav"}

func identityProtocol(name string) bool { return slices.Contains(identityProtocols, name) }

// checkShareIdentity is the share's identity setting, checked with the rest of
// the share.
func (c *config) checkShareIdentity(s shareBlock) error {
	switch s.Identity {
	case "":
		return nil
	case identitySystem:
	default:
		return fmt.Errorf("share %q says identity = %q: the one value is %q", s.Name, s.Identity, identitySystem)
	}
	switch {
	case runtime.GOOS == "windows":
		return fmt.Errorf("share %q says identity = %q, which needs a Unix system: a worker is started with a uid and a gid", s.Name, identitySystem)
	case s.Directory == "":
		// An image is one file, opened once; there is no uid to open it as
		// that would make its files someone's.
		return fmt.Errorf("share %q says identity = %q, which is for a directory share, and it is an image", s.Name, identitySystem)
	case c.Identity == nil:
		return fmt.Errorf("share %q says identity = %q and there is no identity block: it says which account the front runs as", s.Name, identitySystem)
	case len(c.Users) == 0 && len(c.Directories) == 0:
		// Nobody to be: a worker runs as a person, and an anonymous client is
		// nobody.
		return fmt.Errorf("share %q says identity = %q and no user or users block says who people are", s.Name, identitySystem)
	}
	for _, p := range s.Protocols {
		if !identityProtocol(p) {
			return fmt.Errorf("share %q says identity = %q and names %s, which cannot serve it as its people yet: %s can",
				s.Name, identitySystem, p, list(identityProtocols))
		}
	}
	return nil
}

// check is the identity block on its own.
func (b *identityBlock) check(c *config) error {
	if b == nil {
		return nil
	}
	if b.ServiceUser == "" {
		return errors.New("the identity block needs service_user: the account the front runs as")
	}
	if b.ServiceUser == "root" {
		return errors.New("the identity block's service_user is root: the front would need no launcher to be anybody")
	}
	for name, v := range map[string]*int64{"min_uid": b.MinUID, "min_gid": b.MinGID} {
		if v != nil && (*v < 1 || *v > 1<<32-2) {
			return fmt.Errorf("the identity block's %s is %d: it is from 1 to 4294967294, and 0 is root's whatever it says", name, *v)
		}
	}
	for _, u := range b.DenyUIDs {
		if u < 0 || u > 1<<32-1 {
			return fmt.Errorf("the identity block's deny_uids holds %d, which is no uid", u)
		}
	}
	if _, err := b.idle(); err != nil {
		return err
	}
	if !slices.ContainsFunc(c.Shares, func(s shareBlock) bool { return s.Identity == identitySystem }) {
		return errors.New("there is an identity block and no share says identity = \"system\": it would change nothing")
	}
	return nil
}

// policy is the accounts no worker may run as.
func (b *identityBlock) policy() account.Policy {
	p := account.DefaultPolicy
	if b.MinUID != nil {
		p.MinUID = uint32(*b.MinUID)
	}
	if b.MinGID != nil {
		p.MinGID = uint32(*b.MinGID)
	}
	for _, u := range b.DenyUIDs {
		p.DenyUIDs = append(p.DenyUIDs, uint32(u))
	}
	return p
}

func (b *identityBlock) idle() (time.Duration, error) {
	if b.Idle == "" {
		return defaultWorkerIdle, nil
	}
	d, err := time.ParseDuration(b.Idle)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("the identity block's idle is %q: a Go duration above zero, such as \"2m\"", b.Idle)
	}
	return d, nil
}

// systemShares reports whether any share is served as its people.
func (c *config) systemShares() bool {
	return slices.ContainsFunc(c.Shares, func(s shareBlock) bool { return s.Identity == identitySystem })
}

// errNoLauncher is a share served as its people, on a server no launcher
// started: there is nobody to start a worker, and serving the tree as this
// process instead is the one thing not to do.
var errNoLauncher = errors.New("it is served as its people, and this server was not started as root to start their workers")

// workerOf is p's worker on sh, and the release that ends this use of it.
func (s *server) workerOf(p principal, sh *share) (*worker, func(), error) {
	if s.workers == nil {
		return nil, nil, errNoLauncher
	}
	if !p.byName() {
		// A person the provider vouches for, whose name this server does
		// not take as one of its own (local_names): they have no account
		// here to be.
		return nil, nil, &refusedWorker{fmt.Sprintf("%s is vouched for by the identity provider, and has no account here", p.name)}
	}
	return s.workers.acquire(p.name, sh.name)
}

// refusedWorker is a worker refused for this person -- by the launcher, which
// found no account or one the policy forbids, or here -- as opposed to one
// that could not be started.
type refusedWorker struct{ why string }

func (r *refusedWorker) Error() string { return r.why }
