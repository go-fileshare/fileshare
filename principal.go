// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"slices"
	"strings"
)

// A principal is somebody who authenticated: their name, and -- when an
// identity provider vouched for them -- what it said about them.
//
// The distinction matters because a share can now name people this server
// has never heard of. A university's federation knows who is in the
// photography project; this server should not have to copy the list, and
// should not have to be restarted when it changes. So a share says
// `oidc:groups:urn:mace:univ-example.fr:photos`, and it is the TOKEN that
// says whether somebody is in it.
type principal struct {
	name string
	// federated is true when the name comes from the identity provider,
	// and groups are then its groups claim. For anybody else they mean
	// nothing: a password proves a name, not a membership the provider
	// asserted.
	federated bool
	groups    []string
}

// local is somebody authenticated by this server's own directory.
func local(name string) principal { return principal{name: name} }

// A claimRule is one `oidc:` entry of a share's allow or writers list.
//
//	oidc:groups:<value>  -- the token's groups claim contains <value>
//	oidc:user:<name>     -- the token names <name> (its username claim)
//
// The spelling follows opkssh's auth_id, where `oidc:groups:X` means the
// same thing, so that one vocabulary describes who may reach a file server
// and who may reach a shell.
type claimRule struct {
	kind  string // "groups" or "user"
	value string
}

func (r claimRule) String() string { return "oidc:" + r.kind + ":" + r.value }

// splitRules separates a list into the names the directory answers for and
// the rules the identity provider answers for.
func splitRules(list []string) (names []string, rules []claimRule, err error) {
	for _, e := range list {
		rest, ok := strings.CutPrefix(e, "oidc:")
		if !ok {
			names = append(names, e)
			continue
		}
		kind, value, ok := strings.Cut(rest, ":")
		if !ok || value == "" || (kind != "groups" && kind != "user") {
			return nil, nil, fmt.Errorf("%q: an identity provider rule is oidc:groups:<value> or oidc:user:<name>", e)
		}
		rules = append(rules, claimRule{kind, value})
	}
	return names, rules, nil
}

// matches reports whether any rule holds for this principal. Only a
// federated principal can match: `oidc:user:alice` names the provider's
// alice, and a local account that happens to be called alice is somebody
// else.
func (p principal) matches(rules []claimRule) bool {
	if !p.federated {
		return false
	}
	for _, r := range rules {
		switch r.kind {
		case "user":
			if r.value == p.name {
				return true
			}
		case "groups":
			if slices.Contains(p.groups, r.value) {
				return true
			}
		}
	}
	return false
}
