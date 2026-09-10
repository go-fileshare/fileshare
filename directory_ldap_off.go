// SPDX-License-Identifier: BSD-3-Clause

//go:build noldap

package main

import (
	"fmt"

	"github.com/go-authn/directory"
)

// Built without LDAP: no LDAP client is linked into this binary.
func openLDAP(usersBlock) (directory.Source, error) {
	return nil, fmt.Errorf("this binary was built without LDAP support (-tags noldap)")
}
