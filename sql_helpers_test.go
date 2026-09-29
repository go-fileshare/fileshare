// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// sqliteWith writes a database, runs the schema into it, and returns the path
// of a file holding its DSN -- which is how the configuration names it.
func sqliteWith(t *testing.T, dir, schema string) string {
	t.Helper()
	path := filepath.Join(dir, "people.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return write(t, dir, "dsn", path+"\n")
}
