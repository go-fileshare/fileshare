// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-authn/directory"
)

// Reading the directory again, while serving.
//
//	reload = "5m"      # and on SIGHUP, and on the admin API's ReloadDirectory
//
// The people a server serves come from a directory -- a file, SQL, LDAP --
// that other things change: go-authn/bridge writes an application password
// into a table and deletes it when the person is disabled. Without a reload
// the server serves whoever was there when it started.
//
// What a reload does depends on what changed, and the line is drawn at
// REVOCATION:
//
//	only additions        somebody new, whose arrival changes no share's
//	                      expanded lists: added in place -- SMB's running
//	                      server included -- and no connection is touched. A
//	                      bridge creating application passwords all day
//	                      disturbs nobody. Somebody who joins a group a share
//	                      names changes that share, and is a new generation.
//	anything taken away   somebody gone, a credential changed, a share's
//	                      expanded lists different: a new generation, and the
//	                      old one's connections closed, exactly as an admin
//	                      change is -- see generation.go. A session that
//	                      outlived its person's removal is the thing a reload
//	                      exists to end.
//	a broken directory    the database unreachable, a query failing: NOTHING
//	                      changes. An outage must not empty a file server,
//	                      and "nobody" is what a failed read looks like.
//
// A share naming somebody who is gone, or a group that no longer exists, is
// served without them -- that is the safe direction -- and said, rather than
// refused the way a startup refuses it: refusing would keep the old lists,
// and the old lists are the access that was just taken away.

// reloadResult is what one reload found and did.
type reloadResult struct {
	added, removed, changed []string
	// swapped is true when a new generation was started, and closed how
	// many connections it closed.
	swapped bool
	closed  uint64
	notes   []string
}

// errUnchanged is what reloadLoop does not bother to say.
var errUnchanged = errors.New("unchanged")

// reload reads the directory again and serves what it says.
func (s *server) reload() (reloadResult, error) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	var r reloadResult

	ids, err := s.dir.Identities()
	if err != nil {
		s.stats.reloads.failed.Add(1)
		return r, fmt.Errorf("the directory could not be read, so nothing changed: %w", err)
	}
	next := make(map[string]*directory.Identity, len(ids))
	for _, id := range ids {
		next[id.Name()] = id
	}
	prev := s.people()
	for name, id := range next {
		old, ok := prev[name]
		switch {
		case !ok:
			r.added = append(r.added, name)
		case fingerprint(old) != fingerprint(id):
			r.changed = append(r.changed, name)
		}
	}
	for name := range prev {
		if _, ok := next[name]; !ok {
			r.removed = append(r.removed, name)
		}
	}
	slices.Sort(r.added)
	slices.Sort(r.removed)
	slices.Sort(r.changed)

	// The shares' lists, expanded against the directory as it is now.
	current := s.currentShares()
	blocks := make([]shareBlock, 0, len(current))
	for _, sh := range current {
		blocks = append(blocks, sh.block)
	}
	expand := tolerantExpand(s.dir, next, &r.notes)
	listsChanged := false
	for _, sh := range current {
		allow, writers, err := expandLists(sh.block, expand)
		if err != nil {
			s.stats.reloads.failed.Add(1)
			return reloadResult{}, fmt.Errorf("share %q: %w; nothing changed", sh.name, err)
		}
		if !sameSet(allow, sh.allow) || (!sh.readOnly && !sameSet(writers, sh.writers)) {
			listsChanged = true
		}
	}

	if len(r.removed) == 0 && len(r.changed) == 0 && !listsChanged {
		if len(r.added) == 0 {
			s.stats.reloads.unchanged.Add(1)
			return r, errUnchanged
		}
		// Additions only: nobody loses anything, so nobody is disconnected.
		s.setPeople(next)
		if add := s.smbAddUser.Load(); add != nil {
			for _, name := range r.added {
				if key, err := next[name].NTKey(); err == nil {
					(*add)(name, key)
				}
			}
		}
		s.stats.reloads.added.Add(1)
		return r, nil
	}

	shares, err := s.openSharesExpanding(blocks, current, expand)
	if err != nil {
		s.stats.reloads.failed.Add(1)
		return reloadResult{}, fmt.Errorf("%w; nothing changed", err)
	}
	s.setPeople(next)
	closed, err := s.swap(shares)
	if err != nil {
		release(shares, current)
		s.stats.reloads.failed.Add(1)
		return reloadResult{}, err
	}
	r.swapped, r.closed = true, closed
	s.stats.reloads.swapped.Add(1)
	return r, nil
}

// fingerprint is what about somebody, if it changed, must end their
// sessions: where they come from, the key NTLMv2 works from, their SSH keys,
// and what kinds of proof their source holds. A password is not compared --
// nothing here holds one to compare -- but it changes the NT key, and a
// directory that only checks passwords checks them live at every request.
func fingerprint(id *directory.Identity) string {
	var b strings.Builder
	b.WriteString(id.Where())
	b.WriteByte('|')
	if key, err := id.NTKey(); err == nil {
		b.WriteString(hex.EncodeToString(key))
	}
	b.WriteByte('|')
	keys := id.Keys()
	slices.Sort(keys)
	b.WriteString(strings.Join(keys, "\n"))
	for _, c := range []directory.Credential{directory.Password, directory.Verifier, directory.NTHash, directory.PublicKeys} {
		if id.Can(c) {
			b.WriteString("|y")
		} else {
			b.WriteString("|n")
		}
	}
	return b.String()
}

// tolerantExpand expands a list as a reload must: a group that no longer
// exists grants nothing, and a person no longer in the directory is left in
// the list, where nobody can authenticate as them -- both said in notes. A
// directory that cannot answer is still an error: that is an outage, not a
// removal.
func tolerantExpand(dir *directory.Set, people map[string]*directory.Identity, notes *[]string) func([]string) ([]string, error) {
	return func(names []string) ([]string, error) {
		var out []string
		for _, n := range names {
			if !directory.IsGroup(n) {
				if _, ok := people[n]; !ok {
					note(notes, fmt.Sprintf("%s is no longer in %s: nobody can use their access", n, dir.Describe()))
				}
				out = append(out, n)
				continue
			}
			members, err := directory.Expand([]string{n}, dir)
			if errors.Is(err, directory.ErrNoSuchGroup) {
				note(notes, fmt.Sprintf("group %s no longer exists: it grants nothing", n))
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, members...)
		}
		return out, nil
	}
}

func note(notes *[]string, s string) {
	if !slices.Contains(*notes, s) {
		*notes = append(*notes, s)
	}
}

// expandLists expands a share block's allow and writers, leaving out the
// identity provider's rules, which a token answers and no directory does.
func expandLists(b shareBlock, expand func([]string) ([]string, error)) (allow, writers []string, err error) {
	allowNames, _, err := splitRules(b.Allow)
	if err != nil {
		return nil, nil, err
	}
	writerNames, _, err := splitRules(b.Writers)
	if err != nil {
		return nil, nil, err
	}
	if allow, err = expand(allowNames); err != nil {
		return nil, nil, err
	}
	if writers, err = expand(writerNames); err != nil {
		return nil, nil, err
	}
	return allow, writers, nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// setPeople replaces who everybody is.
func (s *server) setPeople(who map[string]*directory.Identity) {
	s.whoMu.Lock()
	s.who = who
	s.whoMu.Unlock()
}

// reloadStats counts reloads by what they did.
type reloadStats struct {
	unchanged, added, swapped, failed atomic.Uint64
}

// reloadLoop reloads every interval, and whenever asked -- SIGHUP -- until
// the server stops, and says what each reload changed.
func (s *server) reloadLoop(every time.Duration, asked <-chan struct{}, stop <-chan struct{}) {
	var tick <-chan time.Time
	if every > 0 {
		t := time.NewTicker(every)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-stop:
			return
		case <-tick:
		case <-asked:
		}
		s.sayReload(s.reload())
	}
}

// sayReload prints what a reload did, in the voice of the rest of the
// server's output. An unchanged directory says nothing.
func (s *server) sayReload(r reloadResult, err error) {
	switch {
	case errors.Is(err, errUnchanged):
		return
	case err != nil:
		fmt.Fprintf(s.out, "directory: %v\n", err)
		return
	}
	var said []string
	if len(r.added) > 0 {
		said = append(said, "added "+list(r.added))
	}
	if len(r.removed) > 0 {
		said = append(said, "removed "+list(r.removed))
	}
	if len(r.changed) > 0 {
		said = append(said, "changed "+list(r.changed))
	}
	if len(said) == 0 {
		said = append(said, "the shares' lists changed")
	}
	what := "in place, no connection touched"
	if r.swapped {
		what = fmt.Sprintf("a new generation, %d connection(s) closed", r.closed)
	}
	fmt.Fprintf(s.out, "directory: %s -- %s\n", strings.Join(said, "; "), what)
	for _, n := range r.notes {
		fmt.Fprintf(s.out, "       %s\n", n)
	}
}
