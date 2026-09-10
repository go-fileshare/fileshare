// SPDX-License-Identifier: BSD-3-Clause

//go:build !noldap

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
)

// openLDAP connects once, to find out whether the directory is there at all.
func openLDAP(b usersBlock) (directory.Source, error) {
	cfg := ldapdir.Config{
		URL: b.URL, BaseDN: b.BaseDN, BindDN: b.BindDN,
		UserFilter: b.UserFilter, UserAttribute: b.UserAttribute,
		GroupBaseDN: b.GroupBaseDN, GroupFilter: b.GroupFilter,
		GroupAttribute: b.GroupAttribute, MemberAttribute: b.MemberAttribute,
		StartTLS: b.StartTLS,
	}
	if b.BindPasswordFile != "" {
		raw, err := os.ReadFile(b.BindPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("the bind password: %w", err)
		}
		cfg.BindPassword = strings.TrimSpace(string(raw))
	}
	return ldapdir.New(cfg)
}
