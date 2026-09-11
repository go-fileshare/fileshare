// SPDX-License-Identifier: BSD-3-Clause

package main

import (
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
	// protocols is which of them may carry this share; empty means all of
	// them. See protocol.exports.
	protocols []string

	// Filled in when the image is opened.
	fsys filesystem.Filesystem
	kind detect.Type
	size uint64
	// named is true when the configuration said which filesystem this is,
	// rather than the magic saying so.
	named bool
}

// restricted reports whether this share names anybody. A restricted share
// cannot be served by a protocol that does not know who is asking.
func (s *share) restricted() bool { return len(s.allow) > 0 || len(s.writers) > 0 }

// mayUse reports whether a user may reach this share at all.
func (s *share) mayUse(user string) bool {
	return len(s.allow) == 0 || slices.Contains(s.allow, user)
}

// readOnlyFor reports whether this user's view of the share is read-only.
func (s *share) readOnlyFor(user string) bool {
	if s.readOnly {
		return true
	}
	return len(s.writers) > 0 && !slices.Contains(s.writers, user)
}

// anyoneWrites reports whether the share is writable with no question asked --
// the only kind a protocol without authentication may serve read-write.
func (s *share) anyoneWrites() bool { return !s.readOnly && !s.restricted() }

// users is who this share is for, as a person reads it.
func (s *share) who() string {
	if len(s.allow) == 0 {
		return "anyone who authenticates"
	}
	return list(s.allow)
}

// writeAccess says who may write, in the same voice.
func (s *share) writeAccess() string {
	switch {
	case s.readOnly:
		return "nobody (read_only)"
	case len(s.writers) > 0:
		return list(s.writers)
	case len(s.allow) > 0:
		return list(s.allow)
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
