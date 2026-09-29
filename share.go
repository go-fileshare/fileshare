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
	// named is true when the configuration said which filesystem this is,
	// rather than the magic saying so.
	named bool
	// partition describes the one that was taken, when the share chose one,
	// in the words the configuration could have used to ask for it.
	partition string
}

// restricted reports whether this share names anybody. A restricted share
// cannot be served by a protocol that does not know who is asking.
func (s *share) restricted() bool {
	return len(s.allow) > 0 || len(s.writers) > 0 || len(s.allowClaims) > 0 || len(s.writerClaims) > 0
}

// mayUse reports whether somebody may reach this share at all.
func (s *share) mayUse(p principal) bool {
	if len(s.allow) == 0 && len(s.allowClaims) == 0 {
		return true
	}
	return slices.Contains(s.allow, p.name) || p.matches(s.allowClaims)
}

// readOnlyFor reports whether this person's view of the share is read-only.
func (s *share) readOnlyFor(p principal) bool {
	if s.readOnly {
		return true
	}
	if len(s.writers) == 0 && len(s.writerClaims) == 0 {
		return false
	}
	return !slices.Contains(s.writers, p.name) && !p.matches(s.writerClaims)
}

// anyoneWrites reports whether the share is writable with no question asked --
// the only kind a protocol without authentication may serve read-write.
func (s *share) anyoneWrites() bool { return !s.readOnly && !s.restricted() }

// users is who this share is for, as a person reads it.
func (s *share) who() string {
	if len(s.allow) == 0 && len(s.allowClaims) == 0 {
		return "anyone who authenticates"
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
	case len(s.writers) > 0 || len(s.writerClaims) > 0:
		return list(withRules(s.writers, s.writerClaims))
	case len(s.allow) > 0 || len(s.allowClaims) > 0:
		return list(withRules(s.allow, s.allowClaims))
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
