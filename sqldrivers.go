// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql

package main

// The database drivers this binary can use.
//
// They are imported HERE, by the program, and not by
// go-authn/directory/hcldir: a driver is a choice a deployment makes and a
// library has no business making it. PostgreSQL alone has three, and a site
// that wants SQLite should not carry the other two -- which is what `-tags
// nosql` leaves out, along with the `users "sql"` block itself.
import (
	_ "github.com/go-sql-driver/mysql" // mysql
	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	_ "modernc.org/sqlite"             // sqlite, in pure Go: no cgo
)
