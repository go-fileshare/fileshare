// SPDX-License-Identifier: BSD-3-Clause

//go:build nosql

package main

import (
	"fmt"

	"github.com/go-authn/directory"
)

// Built without SQL: no database driver is linked into this binary, and
// neither is the code that would read one.
//
// A configuration naming a database is told THAT, which is a different thing
// from being told the driver does not exist -- the first is a binary chosen
// too small, the second a typo, and they are fixed differently.
func openSQL(usersBlock) (directory.Source, error) {
	return nil, fmt.Errorf("this binary was built without SQL support (-tags nosql)")
}
