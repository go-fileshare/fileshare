// SPDX-License-Identifier: BSD-3-Clause

// Package account resolves a person to the system account a worker runs as:
// a uid, a primary gid and supplementary gids (docs/identity.md). It is the
// launcher's: the front never names a uid, it names a person, and this decides
// what that person is on this system -- or refuses.
//
// The order: the directory first, through the attributes it already carries
// (uidNumber and gidNumber, RFC 2307, from the configuration file, LDAP or
// SQL alike; supplementary groups from the person's groups' gidNumber); then
// /etc/passwd and /etc/group by name. Nothing else: an identity provider's
// token carries no uid (OIDC Core §5.1 has no such claim), and none is
// guessed from a name.
package account

import (
	"errors"
	"fmt"
	"math"
	"os/user"
	"slices"
	"strconv"

	"github.com/go-authn/directory"
)

// Account is what a worker runs as.
type Account struct {
	Name   string
	UID    uint32
	GID    uint32   // primary
	Groups []uint32 // supplementary, the primary included, sorted, no duplicates
	From   string   // where it was found: "the directory" or "/etc/passwd"
	// Dropped are supplementary gids below the policy's MinGID, left out.
	Dropped []uint32
}

// Policy says which accounts a worker may never run as.
type Policy struct {
	// MinUID and MinGID: a uid or a primary gid below these is refused; a
	// supplementary gid below MinGID is dropped (Account.Dropped).
	MinUID, MinGID uint32
	// DenyUIDs are refused whatever their value.
	DenyUIDs []uint32
}

// DefaultPolicy is min_uid = min_gid = 1000, nothing else denied.
var DefaultPolicy = Policy{MinUID: 1000, MinGID: 1000}

// noChange is (uid_t)-1: to setresuid and setresgid it means "leave this one
// as it is", so a worker given it would keep the launcher's root.
const noChange = math.MaxUint32

var (
	// ErrNoAccount: the person has no system account here -- neither the
	// directory nor /etc/passwd knows one. They are refused (docs/identity.md).
	ErrNoAccount = errors.New("no system account")
	// ErrRefused: the account exists, and the policy forbids running as it.
	ErrRefused = errors.New("refused by the identity policy")
)

// Passwd looks a name up in /etc/passwd and /etc/group: os/user, which with
// CGO_ENABLED=0 reads those two files on Linux and the BSDs, and asks the
// system on macOS -- never NSS, sssd or winbind.
type Passwd func(name string) (uid, gid uint32, groups []uint32, err error)

// Resolver resolves names against a directory, then a Passwd.
type Resolver struct {
	// Find is the directory's identity of name, or nil if it has none.
	Find func(name string) (*directory.Identity, error)
	// GroupGID is the gidNumber of one of the person's directory groups;
	// ok is false for a group that has none (it is no system group).
	GroupGID func(group string) (gid uint32, ok bool, err error)
	// MemberOf is the directory's groups that list name as a member (a
	// configuration's group block, RFC 2307 memberUid). They are added to
	// the groups the identity itself names (memberOf): a source says one or
	// the other, and either makes a supplementary group. Nil asks nothing.
	MemberOf func(name string) ([]string, error)
	Passwd   Passwd
	Policy   Policy
}

// Resolve is name's account, or ErrNoAccount, or ErrRefused -- each wrapped
// with the reason.
func (r *Resolver) Resolve(name string) (Account, error) {
	a, err := r.find(name)
	if err != nil {
		return Account{}, err
	}
	return r.Policy.apply(a)
}

func (r *Resolver) find(name string) (Account, error) {
	if r.Find != nil {
		id, err := r.Find(name)
		if err != nil {
			return Account{}, fmt.Errorf("%s: %w", name, err)
		}
		if id != nil {
			a, found, err := r.fromDirectory(id)
			if err != nil || found {
				return a, err
			}
		}
	}
	if r.Passwd != nil {
		uid, gid, groups, err := r.Passwd(name)
		if err == nil {
			return Account{Name: name, UID: uid, GID: gid, Groups: groups, From: "/etc/passwd"}, nil
		}
		if !errors.Is(err, ErrNoAccount) {
			return Account{}, fmt.Errorf("%s: /etc/passwd: %w", name, err)
		}
	}
	return Account{}, fmt.Errorf("%s: %w", name, ErrNoAccount)
}

// fromDirectory reads uidNumber and gidNumber. A person with neither is not
// found here (found false); one with only one of them, or with two values
// for one, is an error -- a half-configured account is not guessed at.
func (r *Resolver) fromDirectory(id *directory.Identity) (Account, bool, error) {
	attrs := id.Attributes()
	us, gs := attrs.Get("uidNumber"), attrs.Get("gidNumber")
	if len(us) == 0 && len(gs) == 0 {
		return Account{}, false, nil
	}
	uid, err := one("uidNumber", us)
	if err == nil {
		var gid uint32
		gid, err = one("gidNumber", gs)
		if err == nil {
			a := Account{Name: id.Name(), UID: uid, GID: gid, From: "the directory"}
			groups, err := r.groupsOf(id)
			if err != nil {
				return Account{}, true, err
			}
			for _, g := range groups {
				if r.GroupGID == nil {
					break
				}
				n, ok, gerr := r.GroupGID(g)
				if gerr != nil {
					return Account{}, true, fmt.Errorf("%s: group %s: %w", id.Name(), g, gerr)
				}
				if ok {
					a.Groups = append(a.Groups, n)
				}
			}
			return a, true, nil
		}
	}
	return Account{}, true, fmt.Errorf("%s: %w", id.Name(), err)
}

// groupsOf is the groups the identity names, and those that name it.
func (r *Resolver) groupsOf(id *directory.Identity) ([]string, error) {
	groups := id.Groups()
	if r.MemberOf == nil {
		return groups, nil
	}
	more, err := r.MemberOf(id.Name())
	if err != nil {
		return nil, fmt.Errorf("%s: the groups listing them: %w", id.Name(), err)
	}
	for _, g := range more {
		if !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

// one is the single decimal value of a numeric attribute.
func one(attr string, vals []string) (uint32, error) {
	if len(vals) != 1 {
		return 0, fmt.Errorf("%s has %d values, not one", attr, len(vals))
	}
	return parseID(attr, vals[0])
}

func parseID(what, s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a number from 0 to %d", what, s, uint64(math.MaxUint32))
	}
	return uint32(n), nil
}

// apply refuses what the policy forbids, and drops supplementary groups
// below MinGID. uid 0 and (uid_t)-1 are refused whatever the policy says.
func (p Policy) apply(a Account) (Account, error) {
	refuse := func(why string) (Account, error) {
		return Account{}, fmt.Errorf("%s: %w: %s", a.Name, ErrRefused, why)
	}
	switch {
	case a.UID == 0:
		return refuse("uid 0 is root")
	case a.UID == noChange || a.GID == noChange:
		return refuse("4294967295 is (uid_t)-1, which setresuid reads as \"leave it as it is\"")
	case a.GID == 0:
		return refuse("gid 0 is root's group")
	case a.UID < p.MinUID:
		return refuse(fmt.Sprintf("uid %d is below min_uid %d", a.UID, p.MinUID))
	case a.GID < p.MinGID:
		return refuse(fmt.Sprintf("gid %d is below min_gid %d", a.GID, p.MinGID))
	case slices.Contains(p.DenyUIDs, a.UID):
		return refuse(fmt.Sprintf("uid %d is in deny_uids", a.UID))
	}
	groups := []uint32{a.GID}
	var dropped []uint32
	for _, g := range a.Groups {
		if g == 0 || g == noChange || g < p.MinGID {
			dropped = append(dropped, g)
			continue
		}
		groups = append(groups, g)
	}
	slices.Sort(groups)
	a.Groups = slices.Compact(groups)
	slices.Sort(dropped)
	a.Dropped = slices.Compact(dropped)
	return a, nil
}

// SystemPasswd is Passwd over os/user.
func SystemPasswd(name string) (uid, gid uint32, groups []uint32, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return 0, 0, nil, ErrNoAccount
		}
		return 0, 0, nil, err
	}
	if uid, err = parseID("uid", u.Uid); err != nil {
		return 0, 0, nil, err
	}
	if gid, err = parseID("gid", u.Gid); err != nil {
		return 0, 0, nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("the groups of %s: %w", name, err)
	}
	for _, s := range ids {
		g, err := parseID("gid", s)
		if err != nil {
			return 0, 0, nil, err
		}
		groups = append(groups, g)
	}
	return uid, gid, groups, nil
}
