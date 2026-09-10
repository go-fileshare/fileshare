// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql

package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"

	_ "github.com/go-sql-driver/mysql" // mysql
	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	_ "modernc.org/sqlite"             // sqlite, in pure Go: no cgo
)

// openSQL opens the database and hands sqldir the caller's own queries.
//
// The DRIVER is imported here rather than by the library, which is why this
// program can be built without PostgreSQL in it (see the build tags in the
// README) and why the library has no opinion about which of the three
// PostgreSQL drivers anybody uses.
func openSQL(b usersBlock) (directory.Source, error) {
	if b.DSNFile == "" {
		return nil, fmt.Errorf("a dsn_file is needed: a DSN holds a password, so it lives in a file and not on a command line")
	}
	raw, err := os.ReadFile(b.DSNFile)
	if err != nil {
		return nil, fmt.Errorf("the DSN file: %w", err)
	}
	driver, err := sqlDriver(b.Driver)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("opening the database: %w", err)
	}
	// Reached at startup rather than at the first login: a directory that is
	// not answering is a server that cannot authenticate anybody, and it
	// should say so before it listens.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("the database is not answering: %w", err)
	}
	return sqldir.New(db, sqldir.Queries{People: b.UsersQuery, Groups: b.GroupsQuery},
		sqldir.Named("a "+b.Driver+" database"))
}

// sqlDriver maps the name a person writes -- the database's, not the Go
// package's -- to a registered driver.
//
// The drivers are imported HERE rather than by go-authn/directory/sqldir,
// because a driver is a choice a deployment makes and a library has no
// business making it: PostgreSQL alone has three, and a program that wants
// SQLite should not carry the other two.
func sqlDriver(name string) (string, error) {
	switch name {
	case "postgres", "postgresql", "pgx":
		return "pgx", nil
	case "sqlite", "sqlite3":
		return "sqlite", nil
	case "mysql", "mariadb":
		return "mysql", nil
	case "":
		return "", fmt.Errorf("a driver is needed: sqlite, postgres or mysql")
	}
	return "", fmt.Errorf("there is no %q driver here: sqlite, postgres or mysql", name)
}
