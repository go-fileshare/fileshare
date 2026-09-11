// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/go-authn/directory"
	"github.com/go-authn/oidc"
	"golang.org/x/crypto/ssh"

	"github.com/go-filesystems/detect"
	filesystem "github.com/go-filesystems/interface"

	filesystem_exfat "github.com/go-filesystems/exfat"
	filesystem_ext4 "github.com/go-filesystems/ext4"
	filesystem_fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/hfsplus"
	filesystem_iso9660 "github.com/go-filesystems/iso9660"
	filesystem_ntfs "github.com/go-filesystems/ntfs"
	filesystem_squashfs "github.com/go-filesystems/squashfs"
	filesystem_ufs "github.com/go-filesystems/ufs"
)

// A server is everything the configuration asked for, opened and ready.
type server struct {
	name   string
	shares []*share
	// who everybody is and what their source could give to prove them. The
	// model is go-authn/directory's: no single credential answers all three
	// protocols that authenticate.
	who map[string]*directory.Identity
	// dir is where they came from, for `check` to say.
	dir *directory.Set
	out io.Writer

	// cfg is the configuration this server was opened from, for the parts
	// that are read at request time rather than copied at startup.
	cfg *config
	// oidc verifies bearer tokens, when the configuration named a provider.
	// Only WebDAV can carry one -- see oidcauth.go.
	oidc *oidc.Verifier

	// hostKeyFile is the SFTP identity, when the configuration named one, and
	// trustedCAFile the authorities whose certificates are accepted.
	hostKeyFile   string
	trustedCAFile string
	// stopping is closed when the server is going away, for protocols whose
	// own Close is what stops them rather than the listener closing.
	stopping chan struct{}

	closers []io.Closer
}

// syncWriter is one writer several goroutines may use.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// registerDrivers tells detect what this command can open. It is a list
// because every driver answers to the same name: each has an OpenReader of
// exactly detect.Opener's shape.
func registerDrivers() {
	detect.Register(detect.FAT32, filesystem_fat32.OpenReader)
	detect.Register(detect.ExFAT, filesystem_exfat.OpenReader)
	detect.Register(detect.Ext4, filesystem_ext4.OpenReader)
	detect.Register(detect.NTFS, filesystem_ntfs.OpenReader)
	detect.Register(detect.ISO9660, filesystem_iso9660.OpenReader)
	detect.Register(detect.SquashFS, filesystem_squashfs.OpenReader)
	detect.Register(detect.HFSPlus, hfsplus.OpenReader)
	detect.Register(detect.UFS, filesystem_ufs.OpenReader)
}

// ⛔ What is NOT here, and why, so the next reader does not have to find out:
//
// go-filesystems also ships apfs, btrfs, xfs and zfs. They are not missing by
// oversight -- they have a DIFFERENT shape. Each opens a disk image and picks
// a PARTITION (`Open(path string, partIndex int)`, -1 meaning "find the first
// data partition"), over a read-write block backend that must also answer
// Size, Sync, Truncate and Close. detect.Register takes an io.ReaderAt and a
// size, which is a filesystem at offset zero and nothing else.
//
// Serving them means deciding what a share's `image` is: today it is a
// FILESYSTEM image, and for those four it would be a DISK image with a
// partition table -- a different question, and one worth asking out loud
// rather than answering in a registration list. ffs is not here either, for
// the opposite reason: it is a thin alias over ufs, which IS here.

// open builds a server from a configuration: every password read, every image
// opened, every driver wrapped in the one lock they will all share.
//
// Everything is opened BEFORE anything listens, so a bad path is a refusal at
// the start rather than an error the first client sees.
func open(cfg *config, out io.Writer) (*server, error) {
	registerDrivers()
	s := &server{name: cfg.Name, cfg: cfg, who: map[string]*directory.Identity{},
		// Locked, because the protocols write here from their OWN goroutines
		// -- sftp says whether it generated a host key while the others are
		// announcing themselves -- and two goroutines writing one io.Writer
		// is a data race whatever the writer is.
		out: &syncWriter{w: out}, hostKeyFile: cfg.HostKeyFile, trustedCAFile: cfg.TrustedUserCAFile,
		stopping: make(chan struct{})}
	if s.name == "" {
		s.name = "FILESHARE"
	}
	dirs, err := sources(cfg)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.dir = dirs
	s.closers = append(s.closers, dirs)
	ids, err := s.dir.Identities()
	if err != nil {
		s.Close()
		return nil, err
	}
	for _, id := range ids {
		s.who[id.Name()] = id
	}
	// Now that the directories have answered, the names in the file can be
	// checked against the people who exist rather than against the file
	// itself -- see config.resolve.
	if err := cfg.resolve(s.dir, s.who); err != nil {
		s.Close()
		return nil, err
	}

	if v, err := openOIDC(cfg.OIDC); err != nil {
		s.Close()
		return nil, fmt.Errorf("the identity provider: %w", err)
	} else if v != nil {
		s.oidc = v
	}

	for _, b := range cfg.Shares {
		// The lists are expanded HERE: by the time a protocol sees a share,
		// "@staff" is the people in it. A group whose membership changes in
		// the directory is picked up by a restart -- said plainly, because
		// asking on every connection is a different design and this is not it.
		allow, err := directory.Expand(b.Allow, s.dir)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		writers, err := directory.Expand(b.Writers, s.dir)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		sh := &share{
			name:      b.Name,
			image:     b.Image,
			readOnly:  b.ReadOnly,
			allow:     allow,
			writers:   writers,
			protocols: b.Protocols,
		}
		f, ro, err := openImageFile(b.Image, b.ReadOnly)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("opening %s: %w", b.Image, err)
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			s.Close()
			return nil, err
		}
		fsys, kind, err := openShareImage(b, f, info.Size(), ro)
		if err != nil {
			f.Close()
			s.Close()
			return nil, fmt.Errorf("%s: %w", b.Image, err)
		}
		if ro && !sh.readOnly {
			// Not what was asked for, so it is said out loud: the share works,
			// and it will not take a write.
			fmt.Fprintf(out, "%s could not be opened for writing: %s is read-only\n", b.Image, b.Name)
			sh.readOnly = true
			sh.writers = nil
		}
		// The DRIVER is wrapped, not a wrapper around it. A struct that
		// embeds filesystem.Filesystem has exactly that method set, so
		// wrapping one for the sake of closing a file would erase Opener and
		// WritableFile -- and with them the positional read and write paths,
		// measured at ~70x the whole-file fallback. The file is closed
		// alongside instead.
		sh.fsys = lockFS(fsys)
		sh.kind = kind
		// Remembered so `check` can say it: a driver that was NAMED was not
		// checked against the image's magic the way a found one was, and a
		// reader deciding whether to trust the row should know which it is.
		sh.named = b.Filesystem != ""
		sh.size = uint64(info.Size())
		s.closers = append(s.closers, sh.fsys, f)
		s.shares = append(s.shares, sh)
	}
	return s, nil
}

// openShareImage opens the filesystem in an image, either by finding out what
// it is or by being told.
//
// Being told is not only for the four that cannot be sniffed. A share may name
// any of them, and then the image is opened as THAT or refused -- which is
// what somebody wants when an image carries something that looks like two
// things, or when a misdetection would be worse than a refusal.
func openShareImage(b shareBlock, f *os.File, size int64, readOnly bool) (filesystem.Filesystem, detect.Type, error) {
	if b.Filesystem == "" {
		return detect.Open(f, size)
	}
	if partitionAware(b.Filesystem) {
		partition := -1
		if b.Partition != nil {
			partition = *b.Partition
		}
		fsys, err := openNamed(b.Filesystem, f, size, readOnly, partition)
		if err != nil {
			return nil, detect.Unknown, fmt.Errorf("as %s: %w", b.Filesystem, err)
		}
		return fsys, detect.Type(b.Filesystem), nil
	}
	// One of the sniffable ones, named on purpose. detect owns the openers, so
	// it opens it -- and then says whether the image really was that, which is
	// the difference between "open it as ext4" and "hope it is ext4".
	fsys, kind, err := detect.Open(f, size)
	if err != nil {
		return nil, detect.Unknown, err
	}
	if string(kind) != b.Filesystem {
		fsys.Close()
		return nil, detect.Unknown, fmt.Errorf("the share says %s and the image holds %s",
			b.Filesystem, kind)
	}
	return fsys, kind, nil
}

// detectOpen is detect.Open, named here so a test can reach it.
var detectOpen = detect.Open

// Close closes every driver, and so every image.
func (s *server) Close() error {
	s.stop()
	var err error
	for _, c := range s.closers {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// password answers what a protocol asks when somebody authenticates.
// sortedIdentities is everybody, in a stable order: a listing that reshuffles
// itself between two runs is one nobody can trust.
func (s *server) sortedIdentities() []*directory.Identity {
	out := make([]*directory.Identity, 0, len(s.who))
	for _, id := range s.who {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b *directory.Identity) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// stop tells the protocols that stop by their own Close, once.
func (s *server) stop() {
	select {
	case <-s.stopping:
	default:
		close(s.stopping)
	}
}

// ntKey is what NTLMv2 needs: MD4(UTF16LE(password)), from the password when
// the source gave one and from the hash when it gave that instead. A person
// whose directory holds only a bcrypt cannot use SMB, and that is a fact about
// NTLMv2 rather than a decision made here.
func (s *server) ntKey(user string) ([]byte, bool) {
	id, ok := s.who[user]
	if !ok {
		return nil, false
	}
	key, err := id.NTKey()
	return key, err == nil
}

// matches answers the question HTTP Basic asks, which anything holding a hash
// -- or a directory that will bind -- can answer.
func (s *server) matches(user, password string) bool {
	id, ok := s.who[user]
	return ok && id.Verify(password) == nil
}

// keysFor is what SFTP asks. The lines a directory holds are parsed here,
// where a bad one can be dropped rather than refused: a key added to LDAP by
// somebody else must not stop this server from starting.
func (s *server) keysFor(user string) []ssh.PublicKey {
	id, ok := s.who[user]
	if !ok {
		return nil
	}
	var keys []ssh.PublicKey
	for _, line := range id.Keys() {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// sharesFor is what this user may see, in the order the configuration gave.
func (s *server) sharesFor(user string) []*share {
	var out []*share
	for _, sh := range s.shares {
		if sh.mayUse(user) {
			out = append(out, sh)
		}
	}
	return out
}

func (s *server) shareByName(name string) *share {
	for _, sh := range s.shares {
		if sh.name == name {
			return sh
		}
	}
	return nil
}

// run listens for every protocol the configuration named, and serves until the
// context is cancelled or one of them fails.
//
// One failure stops the lot. A file server that is reachable over two of the
// three protocols it was told to serve is a server nobody can reason about --
// and the one that is missing is exactly the one somebody is waiting on.
func (s *server) run(ctx context.Context, cfg *config) error {
	type running struct {
		p  *protocol
		ln net.Listener
	}
	var started []running
	closeAll := func() {
		for _, r := range started {
			r.ln.Close()
		}
	}
	// Bind FIRST, announce second: a program that prints its address before
	// it has one is a harness that lies about what failed.
	for i := range cfg.Serves {
		b := cfg.Serves[i]
		p := protocolByName(b.Protocol)
		ln, err := net.Listen("tcp", b.Addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		started = append(started, running{p, ln})
	}
	for _, r := range started {
		s.announce(r.p, r.ln.Addr().String())
	}

	errs := make(chan error, len(started))
	var wg sync.WaitGroup
	for _, r := range started {
		wg.Add(1)
		go func(r running) {
			defer wg.Done()
			err := r.p.serve(s, r.p, r.ln)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				errs <- fmt.Errorf("%s: %w", r.p.name, err)
				return
			}
			errs <- nil
		}(r)
	}
	select {
	case <-ctx.Done():
		s.stop()
		closeAll()
		wg.Wait()
		return nil
	case err := <-errs:
		s.stop()
		closeAll()
		wg.Wait()
		return err
	}
}

// announce says what is being served where, and -- as loudly -- what is NOT.
func (s *server) announce(p *protocol, addr string) {
	served, refused := p.exports(s.shares)
	names := make([]string, 0, len(served))
	for _, sh := range served {
		names = append(names, sh.name)
	}
	if len(names) == 0 {
		fmt.Fprintf(s.out, "%-6s on %s — NOTHING: every share names who may use it\n", p.name, addr)
	} else {
		fmt.Fprintf(s.out, "%-6s on %s — %s\n", p.name, addr, list(names))
	}
	for _, sh := range refused {
		fmt.Fprintf(s.out, "       %s\n", p.refusal(sh))
	}
}

// openImageFile opens the image for what it will be used for, and says which
// it got.
//
// os.Open is read-only, and *os.File has a WriteAt method whichever way it was
// opened -- so a share served from one would be announced READ-WRITE and refuse
// every write from deep inside a driver. A file that cannot be opened for
// writing is served read-only rather than not at all, and the caller says so.
func openImageFile(path string, readOnly bool) (*os.File, bool, error) {
	if !readOnly {
		if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
			return f, false, nil
		}
	}
	f, err := os.Open(path)
	return f, true, err
}
