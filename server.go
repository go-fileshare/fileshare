// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/oidc"
	"github.com/go-authn/servercert"
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
	name string
	// shares is replaced whole when the admin API changes them, and read
	// through currentShares; a *share is never modified once it is here.
	sharesMu sync.RWMutex
	shares   []*share
	// who everybody is and what their source could give to prove them. The
	// model is go-authn/directory's: no single credential answers all three
	// protocols that authenticate.
	who map[string]*directory.Identity
	// whoMu guards who, which a directory reload replaces while the
	// protocols read it; see reload.go. Read it through person, anybody and
	// people, never directly.
	whoMu sync.RWMutex
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

	// What run keeps so the shares can be swapped under it; see
	// generation.go.
	runMu    sync.Mutex
	feeds    []*feed
	gen      *generation
	genN     uint64
	failures chan error
	// ready is true while a generation is serving every feed.
	ready atomic.Bool
	stats serverStats
	// mgr is the admin API's, when it runs.
	mgr atomic.Pointer[manager]

	// changeMu makes an admin change and a directory reload one at a time:
	// both build a list of shares from the one being served and swap it in.
	changeMu sync.Mutex
	// smbAddUser adds somebody to the running SMB server, when there is
	// one: the one change a reload makes without a new generation.
	smbAddUser atomic.Pointer[func(name string, ntKey []byte)]

	// certs is where the TLS certificate comes from, and tlsConfigs what
	// each protocol served over TLS is served with; see tls.go.
	certs      *servercert.Source
	tlsConfigs map[string]*tls.Config

	// sshKRL is the provider's list of revoked SSH certificates, when the
	// oidc block names one. It outlives generations, and is fetched by run.
	sshKRL *revocationList
	// nfsCRL is the client CA's CRL, when NFS takes identities from
	// certificates; see nfs_identity.go.
	nfsCRL *revocationList
	// ssf is the shared signals receiver, and revocations what it has
	// received; see caep.go.
	ssf         *ssfReceiver
	revocations *revocationStore
}

// federatedRevoked says whether a credential the provider's word stands
// behind, issued at issued, was revoked since -- nil when no ssf block asks.
func (s *server) federatedRevoked(name, iss, sub string, issued time.Time) error {
	if s.revocations == nil {
		return nil
	}
	return s.revocations.check(name, iss, sub, issued)
}

// currentShares is the list being served now.
func (s *server) currentShares() []*share {
	s.sharesMu.RLock()
	defer s.sharesMu.RUnlock()
	return s.shares
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
		stopping: make(chan struct{}), stats: serverStats{started: time.Now()}}
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
	if err := cfg.resolve(s.dir, s.people()); err != nil {
		s.Close()
		return nil, err
	}

	// The certificate is opened with everything else, so a missing file or
	// an ACME cache nobody may write is a refusal at the start rather than
	// a handshake failure at the first client.
	if cfg.TLS != nil {
		certs, err := servercert.New(cfg.TLS.servercert())
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		s.certs = certs
		s.closers = append(s.closers, certs)
		s.tlsConfigs = map[string]*tls.Config{}
		for _, b := range cfg.Serves {
			c, err := s.tlsFor(b.Protocol)
			if err != nil {
				s.Close()
				return nil, err
			}
			if c != nil {
				s.tlsConfigs[b.Protocol] = c
			}
		}
	}

	if l, err := openSSHKRL(cfg.OIDC, s.out); err != nil {
		s.Close()
		return nil, err
	} else {
		s.sshKRL = l
	}
	if cfg.SSF != nil {
		r, err := newSSFReceiver(cfg.SSF, s.out)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.ssf, s.revocations = r, r.store
	}
	if l, err := openNFSCRL(cfg.serveBlockFor("nfs"), s.out); err != nil {
		s.Close()
		return nil, err
	} else {
		s.nfsCRL = l
	}

	if v, err := openOIDC(cfg.OIDC); err != nil {
		s.Close()
		return nil, fmt.Errorf("the identity provider: %w", err)
	} else if v != nil {
		s.oidc = v
	}

	shares, err := s.openShares(cfg.Shares, nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.shares = shares
	return s, nil
}

// openShares opens every share a list of blocks describes.
//
// previous is the shares being served now, when there are some: a share whose
// IMAGE is unchanged -- same file, same filesystem, same partition -- takes
// the driver that is already open instead of opening the image a second time.
// That is not an economy. Two drivers over one image each believe they own
// it, and the one that is about to be closed may still be writing; the new
// share must see the same driver, not a second opinion of the same bytes.
// Only who may use it, and whether it is read-only, are taken from the block.
//
// What was opened here and not taken by the result is closed before returning
// an error, so a refused change leaves nothing open behind it.
func (s *server) openShares(blocks []shareBlock, previous []*share) ([]*share, error) {
	return s.openSharesExpanding(blocks, previous, func(names []string) ([]string, error) {
		return directory.Expand(names, s.dir)
	})
}

// openSharesExpanding is openShares with the lists expanded by expand: a
// reload expands them more forgivingly than a start does -- see reload.go.
func (s *server) openSharesExpanding(blocks []shareBlock, previous []*share,
	expand func([]string) ([]string, error)) (_ []*share, err error) {
	var opened []*share
	defer func() {
		if err != nil {
			for _, sh := range opened {
				sh.close()
			}
		}
	}()
	var out []*share
	for _, b := range blocks {
		// The lists are expanded HERE: by the time a protocol sees a share,
		// "@staff" is the people in it. A group whose membership changes in
		// the directory is picked up by a restart -- said plainly, because
		// asking on every connection is a different design and this is not it.
		allowNames, allowClaims, err := splitRules(b.Allow)
		if err != nil {
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		writerNames, writerClaims, err := splitRules(b.Writers)
		if err != nil {
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		allow, err := expand(allowNames)
		if err != nil {
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		writers, err := expand(writerNames)
		if err != nil {
			return nil, fmt.Errorf("share %q: %w", b.Name, err)
		}
		sh := &share{
			name:         b.Name,
			image:        b.source(),
			readOnly:     b.ReadOnly || b.noWriters,
			allow:        allow,
			writers:      writers,
			allowClaims:  allowClaims,
			writerClaims: writerClaims,
			protocols:    b.Protocols,
			opened:       imageKeyOf(b),
			block:        b,
			allowNamed:   len(allowNames) > 0,
			writersNamed: len(writerNames) > 0,
		}
		if prev := sameImage(previous, sh.opened); prev != nil {
			if prev.openedReadOnly && !b.ReadOnly {
				// The file itself was opened read-only, and a driver cannot be
				// made writable after the fact. Reopening it here would put a
				// second driver on an image the first is still serving.
				return nil, fmt.Errorf("share %q: %s was opened read-only, so it cannot become writable "+
					"while it is served; delete the share and create it again", b.Name, b.source())
			}
			sh.adopt(prev)
			out = append(out, sh)
			continue
		}
		open := s.openImage
		if b.Directory != "" {
			open = s.openDirectory
		}
		if err := open(sh, b); err != nil {
			return nil, err
		}
		opened = append(opened, sh)
		out = append(out, sh)
	}
	return out, nil
}

// openImage opens a share's image and its filesystem, and says -- once, when
// it happens -- every way the share ended up less writable than it asked.
func (s *server) openImage(sh *share, b shareBlock) error {
	out := s.out
	f, ro, err := openImageFile(b.Image, b.ReadOnly)
	if err != nil {
		if hint := deviceOpenHint(b.Image, err); hint != "" {
			return fmt.Errorf("opening %s: %w\n       %s", b.Image, err, hint)
		}
		return fmt.Errorf("opening %s: %w", b.Image, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	// A device has no length in its inode, so it is asked. Doing this
	// through Stat alone handed every driver a zero-length image.
	size, err := imageLength(f, info)
	if err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", b.Image, err)
	}
	// What the drivers read through. A raw device refuses an unaligned
	// read -- and reading a two-byte field at offset 11 is what parsing a
	// FAT BPB is -- so a device gets a reader that rounds out to whole
	// blocks. Without it /dev/rdisk4 reported `unknown filesystem`, the
	// EINVAL swallowed by a detector that found no magic number.
	var r io.ReaderAt = f
	if isDevice(info) {
		r = alignedReaderAt{r: f, size: size}
		if !sh.readOnly {
			// The same reasoning as a share that picked a partition: it
			// will be served, and it will not take a write. Writing to a
			// live disk is not a decision to make silently.
			fmt.Fprintf(out, "%s is a device, so %s is read-only\n", b.Image, b.Name)
			sh.readOnly = true
		}
		sh.forcedReadOnly = true
	}
	fsys, kind, took, err := openShareImage(b, f, r, size, ro)
	if err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", b.Image, err)
	}
	sh.openedReadOnly = ro
	if ro && !sh.readOnly {
		// Not what was asked for, so it is said out loud: the share works,
		// and it will not take a write.
		fmt.Fprintf(out, "%s could not be opened for writing: %s is read-only\n", b.Image, b.Name)
		sh.readOnly = true
		sh.writers = nil
	}
	if took != "" {
		if !sh.readOnly {
			// ⛔ A share that chose a partition is READ-ONLY, and saying so
			// here is the whole point: the driver would be given the
			// partition's offsets over a file that is the whole disk, so a
			// write lands at the same offset from the start of the IMAGE --
			// on the partition table, as often as not. It refuses, and
			// without this line the share would read as writable in `check`
			// and refuse every write at the client instead.
			fmt.Fprintf(out, "%s serves %s, so it is read-only: writing into a partition "+
				"is not supported yet\n", b.Name, took)
			sh.readOnly = true
			sh.writers = nil
		}
		sh.forcedReadOnly = true
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
	sh.partition = took
	// size, not info.Size(): the latter is 0 for a device, and this is
	// what `check` prints.
	sh.size = uint64(size)
	sh.closers = []io.Closer{sh.fsys, f}
	return nil
}

// sameImage is the share among previous that has this image open, if any.
func sameImage(previous []*share, k imageKey) *share {
	for _, sh := range previous {
		if sh.opened == k && sh.fsys != nil {
			return sh
		}
	}
	return nil
}

// openShareImage opens the filesystem in an image, either by finding out what
// it is or by being told.
//
// Being told is not only for the four that cannot be sniffed. A share may name
// any of them, and then the image is opened as THAT or refused -- which is
// what somebody wants when an image carries something that looks like two
// things, or when a misdetection would be worse than a refusal.
// r is what everything READS through, and it is not always f: a raw device
// refuses an unaligned read, so a device is handed an alignedReaderAt. f stays
// the *os.File because the writable path needs WriteAt, which a device never
// takes -- see device.go.
func openShareImage(b shareBlock, f *os.File, r io.ReaderAt, size int64, readOnly bool) (filesystem.Filesystem, detect.Type, string, error) {
	// The partition first, and for EVERY filesystem: a disk image holding
	// FAT32 has a table in front of it as often as one holding XFS does, and
	// detection reads offset zero, where a partitioned image has the table.
	choice := partitionChoice{label: b.PartitionLabel, uuid: b.PartitionUUID}
	if b.Partition != nil {
		choice.index = *b.Partition
	}
	view, viewSize, took, err := selectPartition(r, size, choice)
	if err != nil {
		return nil, detect.Unknown, "", err
	}

	if b.Filesystem == "" {
		fsys, kind, err := detect.Open(view, viewSize)
		return fsys, kind, took, err
	}
	if partitionAware(b.Filesystem) {
		// Those four find a partition themselves. When this configuration
		// already chose one, they are handed that view and told the image IS
		// the filesystem -- so the two mechanisms never both run, and what
		// `check` prints is what was opened.
		fsys, err := openNamed(b.Filesystem, f, view, viewSize, readOnly, choice)
		if err != nil {
			return nil, detect.Unknown, "", fmt.Errorf("as %s: %w", b.Filesystem, err)
		}
		return fsys, detect.Type(b.Filesystem), took, nil
	}
	// One of the sniffable ones, named on purpose. detect owns the openers, so
	// it opens it -- and then says whether the image really was that, which is
	// the difference between "open it as ext4" and "hope it is ext4".
	fsys, kind, err := detect.Open(view, viewSize)
	if err != nil {
		return nil, detect.Unknown, "", err
	}
	if string(kind) != b.Filesystem {
		fsys.Close()
		return nil, detect.Unknown, "", fmt.Errorf("the share says %s and the image holds %s",
			b.Filesystem, kind)
	}
	return fsys, kind, took, nil
}

// detectOpen is detect.Open, named here so a test can reach it.
var detectOpen = detect.Open

// Close closes every driver, and so every image.
func (s *server) Close() error {
	s.stop()
	var err error
	for _, sh := range s.currentShares() {
		if cerr := sh.close(); err == nil {
			err = cerr
		}
	}
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
	who := s.people()
	out := make([]*directory.Identity, 0, len(who))
	for _, id := range who {
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
	id, ok := s.person(user)
	if !ok {
		return nil, false
	}
	key, err := id.NTKey()
	return key, err == nil
}

// matches answers the question HTTP Basic asks, which anything holding a hash
// -- or a directory that will bind -- can answer.
func (s *server) matches(user, password string) bool {
	id, ok := s.person(user)
	return ok && id.Verify(password) == nil
}

// keysFor is what SFTP asks. The lines a directory holds are parsed here,
// where a bad one can be dropped rather than refused: a key added to LDAP by
// somebody else must not stop this server from starting.
func (s *server) keysFor(user string) []ssh.PublicKey {
	id, ok := s.person(user)
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

// sharesFor is what this person may see, in the order the configuration gave.
func (s *server) sharesFor(p principal) []*share {
	var out []*share
	for _, sh := range s.currentShares() {
		if sh.mayUse(p) {
			out = append(out, sh)
		}
	}
	return out
}

func (s *server) shareByName(name string) *share {
	for _, sh := range s.currentShares() {
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
//
// The sockets are bound once and outlive every change to the shares: see
// generation.go for what a change does to the servers behind them.
func (s *server) run(ctx context.Context, cfg *config) error {
	var feeds []*feed
	closeAll := func() {
		for _, f := range feeds {
			f.Close()
		}
	}
	// Bind FIRST, announce second: a program that prints its address before
	// it has one is a harness that lies about what failed.
	for i := range cfg.Serves {
		b := cfg.Serves[i]
		ln, err := net.Listen("tcp", b.Addr)
		if err != nil {
			closeAll()
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		feeds = append(feeds, newFeed(b.Protocol, ln))
	}
	for _, f := range feeds {
		s.announce(protocolByName(f.proto), f.ln.Addr().String())
	}

	s.runMu.Lock()
	s.feeds = feeds
	s.failures = make(chan error, 1)
	s.genN = 1
	s.gen = s.startGeneration(s.genN, feeds, s.failures)
	s.runMu.Unlock()
	s.ready.Store(true)

	// The control listeners come after the data ones, so a readiness probe
	// never answers for a server that has not bound its ports.
	ctl, err := s.startControl(ctx, cfg)
	if err != nil {
		s.shutdown(closeAll)
		return err
	}
	defer ctl()

	// The directory is read again on SIGHUP, and every `reload` when the
	// configuration says so; see reload.go.
	every, _ := cfg.reloadEvery()
	stopReload := make(chan struct{})
	defer close(stopReload)
	go s.reloadLoop(every, hangups(stopReload), stopReload)
	for _, l := range s.revocationLists() {
		go l.run(stopReload)
	}
	if s.ssf != nil {
		ssfCtx, cancelSSF := context.WithCancel(ctx)
		defer cancelSSF()
		go s.ssf.run(ssfCtx)
	}

	select {
	case <-ctx.Done():
		s.shutdown(closeAll)
		return nil
	case err := <-s.failures:
		s.shutdown(closeAll)
		return err
	}
}

// shutdown stops the current generation and closes the sockets.
func (s *server) shutdown(closeFeeds func()) {
	s.ready.Store(false)
	s.stop()
	s.runMu.Lock()
	defer s.runMu.Unlock()
	closeFeeds()
	if s.gen != nil {
		s.gen.stop()
		s.gen = nil
	}
}

// swap serves a new list of shares: the running protocol servers are
// stopped -- their connections with them -- and new ones start over the same
// sockets. The shares no longer served are closed once nothing serves them.
//
// It is refused before run has bound anything, and after it has stopped.
func (s *server) swap(next []*share) (closed uint64, err error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.gen == nil {
		return 0, errors.New("the server is not serving")
	}
	s.ready.Store(false)
	closed = s.gen.stop()
	s.sharesMu.Lock()
	prev := s.shares
	s.shares = next
	s.sharesMu.Unlock()
	s.genN++
	s.gen = s.startGeneration(s.genN, s.feeds, s.failures)
	s.ready.Store(true)
	// Closes only what nobody serves any more: a share carried over shares
	// its driver with its successor.
	release(prev, next)
	for _, f := range s.feeds {
		s.announce(protocolByName(f.proto), f.ln.Addr().String())
	}
	return closed, nil
}

// generationNumber is how many share lists this server has served.
func (s *server) generationNumber() uint64 {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.genN
}

// announce says what is being served where, and -- as loudly -- what is NOT.
func (s *server) announce(p *protocol, addr string) {
	served, refused := p.exports(s.cfg, s.currentShares())
	names := make([]string, 0, len(served))
	for _, sh := range served {
		names = append(names, sh.name)
	}
	over := ""
	if s.tlsConfigs[p.name] != nil {
		over = " (TLS)"
	}
	if len(names) == 0 {
		fmt.Fprintf(s.out, "%-6s on %s%s — NOTHING: every share names who may use it\n", p.name, addr, over)
	} else {
		fmt.Fprintf(s.out, "%-6s on %s%s — %s\n", p.name, addr, over, list(names))
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
	// ⛔ A DEVICE TAKES A DIFFERENT OPEN, and it is checked before the
	// read-write attempt rather than after: asking for O_RDWR on a disk is the
	// request that must not be made casually. openDevice asks the kernel for
	// exclusive access, which is what keeps a mounted filesystem from being
	// read in a state that never existed on disk. See device.go.
	if fi, err := os.Stat(path); err == nil && isDevice(fi) {
		f, err := openDevice(path)
		return f, true, err
	}
	if !readOnly {
		if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
			return f, false, nil
		}
	}
	f, err := os.Open(path)
	return f, true, err
}

// person is somebody the directories know, as of the last read.
func (s *server) person(name string) (*directory.Identity, bool) {
	s.whoMu.RLock()
	defer s.whoMu.RUnlock()
	id, ok := s.who[name]
	return id, ok
}

// anybody reports whether the directories know anybody at all.
func (s *server) anybody() bool {
	s.whoMu.RLock()
	defer s.whoMu.RUnlock()
	return len(s.who) > 0
}

// people is everybody, as of the last read. The map is never modified once
// it is here -- a reload replaces it -- so the caller may range over it.
func (s *server) people() map[string]*directory.Identity {
	s.whoMu.RLock()
	defer s.whoMu.RUnlock()
	return s.who
}

// revocationLists are the lists this server keeps copies of.
func (s *server) revocationLists() []*revocationList {
	var out []*revocationList
	if s.sshKRL != nil {
		out = append(out, s.sshKRL)
	}
	if s.nfsCRL != nil {
		out = append(out, s.nfsCRL)
	}
	return out
}
