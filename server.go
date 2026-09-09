// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/go-filesystems/detect"

	filesystem_exfat "github.com/go-filesystems/exfat"
	filesystem_ext4 "github.com/go-filesystems/ext4"
	filesystem_fat32 "github.com/go-filesystems/fat32"
	"github.com/go-filesystems/hfsplus"
	filesystem_iso9660 "github.com/go-filesystems/iso9660"
	filesystem_ntfs "github.com/go-filesystems/ntfs"
	filesystem_squashfs "github.com/go-filesystems/squashfs"
)

// A server is everything the configuration asked for, opened and ready.
type server struct {
	name   string
	shares []*share
	users  map[string]string // user -> password
	out    io.Writer

	closers []io.Closer
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
}

// open builds a server from a configuration: every password read, every image
// opened, every driver wrapped in the one lock they will all share.
//
// Everything is opened BEFORE anything listens, so a bad path is a refusal at
// the start rather than an error the first client sees.
func open(cfg *config, out io.Writer) (*server, error) {
	registerDrivers()
	s := &server{name: cfg.Name, users: map[string]string{}, out: out}
	if s.name == "" {
		s.name = "FILESHARE"
	}
	for _, u := range cfg.Users {
		pw, err := u.password()
		if err != nil {
			s.Close()
			return nil, err
		}
		s.users[u.Name] = pw
	}
	for _, b := range cfg.Shares {
		sh := &share{
			name:     b.Name,
			image:    b.Image,
			readOnly: b.ReadOnly,
			allow:    b.Allow,
			writers:  b.Writers,
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
		fsys, kind, err := detect.Open(f, info.Size())
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
		sh.size = uint64(info.Size())
		s.closers = append(s.closers, sh.fsys, f)
		s.shares = append(s.shares, sh)
	}
	return s, nil
}

// detectOpen is detect.Open, named here so a test can reach it.
var detectOpen = detect.Open

// Close closes every driver, and so every image.
func (s *server) Close() error {
	var err error
	for _, c := range s.closers {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// password answers what a protocol asks when somebody authenticates.
func (s *server) password(user string) (string, bool) {
	pw, ok := s.users[user]
	return pw, ok
}

// authenticate is the check every authenticating protocol makes.
func (s *server) authenticate(user, password string) bool {
	want, ok := s.users[user]
	return ok && want == password
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
		closeAll()
		wg.Wait()
		return nil
	case err := <-errs:
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
