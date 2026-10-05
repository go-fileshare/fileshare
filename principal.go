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
	// localName is set on a federated principal when the oidc block says
	// local_names: its name is then the local account of that name.
	localName bool
}

// byName reports whether the plain names of a share's allow and writers
// lists may match this principal: always for somebody this server
// authenticated, and for the provider's people only when local_names says
// their names are local names.
func (p principal) byName() bool { return !p.federated || p.localName }

// local is somebody authenticated by this server's own directory.
func local(name string) principal { return principal{name: name} }

// A claimRule is one `oidc:` entry of a share's allow or writers list.
//
//	oidc:groups:<value>  -- the token's groups claim contains <value>
//	oidc:user:<name>     -- the token names <name> (its username claim)
//	oidc:domain:<domain> -- the name is <something>@<domain>: an eppn or a
//	                        subject-id's scope, which the SAML side has
//	                        already checked belongs to the institution
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
		if !ok || value == "" || (kind != "groups" && kind != "user" && kind != "domain") {
			return nil, nil, fmt.Errorf("%q: an identity provider rule is oidc:groups:<value>, oidc:user:<name> or oidc:domain:<domain>", e)
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
		case "domain":
			if d := p.domain(); d != "" && d == strings.ToLower(r.value) {
				return true
			}
		}
	}
	return false
}

// domain is the part of the name after its last "@", lower-cased: the
// scope of an eppn or a subject-id. "" when the name has none.
//
// It can be trusted as far as the provider can: go-authn/bridge drops an
// identifier whose scope the IdP's federation metadata does not grant it, so
// alice@univ-a.fr is somebody univ-a.fr's own IdP vouched for.
func (p principal) domain() string {
	at := strings.LastIndexByte(p.name, '@')
	if at < 0 || at == len(p.name)-1 {
		return ""
	}
	return strings.ToLower(p.name[at+1:])
}

// domainAllowed says whether the oidc block's domains admit p. No list
// admits everybody the provider vouches for.
func (o *oidcBlock) domainAllowed(p principal) bool {
	if o == nil || len(o.Domains) == 0 {
		return true
	}
	return slices.Contains(o.lowerDomains(), p.domain())
}

func (o *oidcBlock) lowerDomains() []string {
	out := make([]string, len(o.Domains))
	for i, d := range o.Domains {
		out[i] = strings.ToLower(strings.TrimSpace(d))
	}
	return out
}
