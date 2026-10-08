// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"os"
	"slices"

	"github.com/go-filesystems/detect"
	filesystem "github.com/go-filesystems/interface"
)

// A share is one image, exported under a name, to some people.
//
// The three rules compose, and every protocol answers them the same way:
//
//	allow    empty  -> anyone who authenticated may use it
//	allow    listed -> only those named
//	writers  empty  -> whoever may use it may write, unless ReadOnly
//	writers  listed -> only those named write; the rest get it read-only
//	read_only       -> nobody writes, whatever writers says
type share struct {
	name     string
	image    string
	readOnly bool
	allow    []string
	writers  []string
	// allowClaims and writerClaims are the `oidc:` entries of the two lists:
	// people the identity provider names, who need not exist anywhere here.
	allowClaims  []claimRule
	writerClaims []claimRule
	// protocols is which of them may carry this share; empty means all of
	// them. See protocol.exports.
	protocols []string

	// Filled in when the image is opened.
	fsys filesystem.Filesystem
	kind detect.Type
	size uint64
	// capacity, when set, is the total and available bytes as they are
	// NOW, asked at every query; size is then only what the admin API
	// shows. A directory share has one, an image none. See capacity.go.
	capacity func() (total, avail uint64)
	// named is true when the configuration said which filesystem this is,
	// rather than the magic saying so.
	named bool
	// partition describes the one that was taken, when the share chose one,
	// in the words the configuration could have used to ask for it.
	partition string

	// opened is what was opened, so a later list of shares can tell whether
	// it names the same image; see server.openShares.
	opened imageKey
	// openedReadOnly is true when the FILE was opened read-only, whatever
	// the share asked. forcedReadOnly is true when the share cannot take a
	// write whatever the block says -- a device, or a chosen partition.
	openedReadOnly bool
	forcedReadOnly bool
	// askedWrite is whether the block the driver was opened for asked to
	// write. A driver that fell back to read-only on its own -- a device, a
	// file this process may not write -- was asked; only a block that was
	// read_only and now is not is asking for something the open never tried.
	askedWrite bool
	// closers are the driver and the file under it, owned by whichever
	// share holds them last.
	closers []io.Closer
	// block is what the share was opened from, for a reload to expand its
	// lists again.
	block shareBlock
	// allowNamed and writersNamed say the configuration WROTE names in the
	// two lists, whatever they expand to now.
	//
	// ⛔ An empty allow means "anyone who authenticates", and a list whose
	// only group has emptied expands to exactly that -- so a share written
	// for @engineers would open to everybody the moment the last engineer
	// left. What decides whether a share is open is what was written; what
	// it expands to decides only who is in it.
	allowNamed, writersNamed bool
}

// allowsAnyone reports whether this share is for anyone who authenticates:
// nothing was written in allow, rather than what was written expanding to
// nobody.
func (s *share) allowsAnyone() bool {
	return !s.allowNamed && len(s.allow) == 0 && len(s.allowClaims) == 0
}

// anyAllowedWrites reports whether everybody allowed may write, because
// nothing was written in writers.
func (s *share) anyAllowedWrites() bool {
	return !s.writersNamed && len(s.writers) == 0 && len(s.writerClaims) == 0
}

// An imageKey is what makes two shares the same opened image.
//
// ⛔ The FILE is compared, not its path: two spellings of one image -- a
// symbolic link, the resolved path the admin API keeps -- are one image, and
// two drivers over it each believe they own it. Measured by the security
// review: 40 concurrent writes through two drivers left 26 to 32 of 41
// files. info is the file as stat saw it, compared with os.SameFile.
type imageKey struct {
	directory               bool
	filesystem, label, uuid string
	partition               int
	info                    os.FileInfo
}

func (k imageKey) same(o imageKey) bool {
	return k.directory == o.directory && k.filesystem == o.filesystem && k.label == o.label &&
		k.uuid == o.uuid && k.partition == o.partition &&
		k.info != nil && o.info != nil && os.SameFile(k.info, o.info)
}

func imageKeyOf(b shareBlock) imageKey {
	k := imageKey{directory: b.Directory != "", filesystem: b.Filesystem,
		label: b.PartitionLabel, uuid: b.PartitionUUID}
	if fi, err := os.Stat(b.source()); err == nil {
		k.info = fi
	}
	if b.Partition != nil {
		k.partition = *b.Partition
	}
	return k
}

// adopt serves the driver prev opened. Both hold it until one of the two
// lists is let go of -- see release -- so a change that fails after this
// leaves prev exactly as it was.
func (s *share) adopt(prev *share) {
	s.fsys, s.kind, s.size, s.named, s.partition = prev.fsys, prev.kind, prev.size, prev.named, prev.partition
	s.capacity = prev.capacity
	s.openedReadOnly, s.forcedReadOnly, s.askedWrite = prev.openedReadOnly, prev.forcedReadOnly, prev.askedWrite
	s.closers = prev.closers
	if s.openedReadOnly || s.forcedReadOnly {
		s.readOnly = true
		s.writers = nil
	}
}

// release closes the drivers of shares that no share in keep still serves:
// after a change, the old list is released against the new one, and a
// change that failed releases the new list against the old.
func release(shares, keep []*share) {
	for _, sh := range shares {
		if !slices.ContainsFunc(keep, func(k *share) bool { return k.fsys == sh.fsys }) {
			sh.close()
		}
	}
}

// close closes what this share owns.
func (s *share) close() error {
	var err error
	for _, c := range s.closers {
		if cerr := c.Close(); err == nil {
			err = cerr
		}
	}
	s.closers = nil
	return err
}

// restricted reports whether this share names anybody. A restricted share
// cannot be served by a protocol that does not know who is asking.
func (s *share) restricted() bool {
	return !s.allowsAnyone() || !s.anyAllowedWrites()
}

// mayUse reports whether somebody may reach this share at all.
func (s *share) mayUse(p principal) bool {
	if s.allowsAnyone() {
		return true
	}
	return (p.byName() && slices.Contains(s.allow, p.name)) || p.matches(s.allowClaims)
}

// readOnlyFor reports whether this person's view of the share is read-only.
func (s *share) readOnlyFor(p principal) bool {
	if s.readOnly {
		return true
	}
	if s.anyAllowedWrites() {
		return false
	}
	return !(p.byName() && slices.Contains(s.writers, p.name)) && !p.matches(s.writerClaims)
}

// anyoneWrites reports whether the share is writable with no question asked --
// the only kind a protocol without authentication may serve read-write.
func (s *share) anyoneWrites() bool { return !s.readOnly && !s.restricted() }

// users is who this share is for, as a person reads it.
func (s *share) who() string {
	if s.allowsAnyone() {
		return "anyone who authenticates"
	}
	if len(s.allow) == 0 && len(s.allowClaims) == 0 {
		return "nobody: every name it was written for is gone from the directory"
	}
	return list(withRules(s.allow, s.allowClaims))
}

// withRules is the names, then the provider's rules, as the configuration
// spells them.
func withRules(names []string, rules []claimRule) []string {
	out := slices.Clone(names)
	for _, r := range rules {
		out = append(out, r.String())
	}
	return out
}

// writeAccess says who may write, in the same voice.
func (s *share) writeAccess() string {
	switch {
	case s.readOnly:
		return "nobody (read_only)"
	case !s.anyAllowedWrites():
		if len(s.writers) == 0 && len(s.writerClaims) == 0 {
			return "nobody: every name it was written for is gone from the directory"
		}
		return list(withRules(s.writers, s.writerClaims))
	case !s.allowsAnyone():
		return s.who()
	}
	return "anyone who authenticates"
}

// list is a list a person reads, not a slice a program prints.
func list(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	out := names[0]
	for _, n := range names[1 : len(names)-1] {
		out += ", " + n
	}
	return out + " and " + names[len(names)-1]
}
