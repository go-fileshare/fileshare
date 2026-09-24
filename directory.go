// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
)

// Where the people come from.
//
// The model is go-authn/directory's, not this program's: who somebody is, and
// what their source could give to prove them. It lives there because it is not
// a file server's question -- anything that authenticates asks it -- and
// because the answer is the same awkward one everywhere:
//
//	SMB needs the password or its MD4; an LDAP bind cannot answer it.
//	WebDAV needs anything that can check a password, including a bind.
//	SFTP needs a key, and asks nothing about passwords at all.
//
// So `check` prints, per person, which protocols their credentials can
// actually answer -- see report.

// sources builds the directory this configuration describes: the `user` and
// `group` blocks first, then each `users` block in the order they were
// written. The first source that knows a name owns it, so a service account
// written down here is not overridden by one that appears in LDAP later.
func sources(cfg *config) (*directory.Set, error) {
	set := directory.NewSet(hclSource(cfg))
	// hcldir opens them, and closes what it opened if a later one fails: a
	// half-open set is a server holding a database it will never use.
	srcs, err := hcldir.OpenAll(cfg.Directories)
	if err != nil {
		set.Close()
		return nil, err
	}
	for _, src := range srcs {
		set.Add(src)
	}
	return set, nil
}

// hclSource turns the configuration file's own blocks into a source.
//
// The building is hcldir's now. It was written here and again in
// go-authn/authnd, and the two copies had already drifted apart; see the note
// on userBlock in config.go.
func hclSource(cfg *config) directory.Source {
	// The errors here were caught when the configuration was checked; a
	// second report of the same thing would be noise.
	src, err := hcldir.File(cfg.Users, cfg.Groups)
	if err != nil {
		return &directory.Static{Name: "the configuration file", Groups: map[string][]string{}}
	}
	return src
}
