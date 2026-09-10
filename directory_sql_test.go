//go:build !nosql && !nosmb

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// People and groups out of a real database, into a real mount.
//
// The database is SQLite because a test should not need a server, but nothing
// here is SQLite-shaped: the queries are the configuration's, the columns are
// the site's, and the same block with a postgres driver and a different select
// reads a site's existing table. What is being measured is the WIRING -- an
// HCL block, to a query, to an identity, to somebody NTLMv2 lets in -- and
// that wiring is the same for every driver.
func TestUsersAndGroupsFromASQLDatabase(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	dsn := sqliteWith(t, dir, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
`)
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
  groups   = "select team, member from teams"
}

share "photos" {
  image = %q
  allow = ["@engineers"]
}

share "open" { image = %q }
`, hclPath(dsn), hclPath(img), hclPath(open)) + serveBlocks()

	// The report first: who came out of the database, and what they can use.
	out, err := execute(t, "check", write(t, dir, "c.hcl", body))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	for _, want := range []string{"dora", "eli", "a sqlite database", "a password"} {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password out of the database")
	}

	// Then the mount. dora is in the database and in @engineers there; the
	// share names neither her nor the group's members, only the group.
	r := start(t, body)
	fs := mountSMB(t, r, "dora", "hunter2", "photos")
	if got, err := fs.ReadFile("greeting.txt"); err != nil || string(got) != "hello" {
		t.Errorf("dora read %q, %v", got, err)
	}
	// eli is in the same database and not in the group: known, and refused.
	if es := tryMountSMB(t, r, "eli", "swordfish", "photos"); es != nil {
		if _, err := es.ReadFile("greeting.txt"); err == nil {
			t.Error("eli is in no group the share names and read it anyway")
		}
	}
}

// A database that is not answering is refused at startup, not at the first
// login: a server that cannot authenticate anybody should say so before it
// listens, rather than accepting connections and refusing everybody.
func TestADatabaseThatIsNotThereIsRefusedAtStartup(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	// A path SQLite is told not to create.
	dsn := write(t, dir, "dsn", "file:"+filepath.ToSlash(filepath.Join(dir, "absent.db"))+"?mode=rw\n")
	body := fmt.Sprintf(`
users "sql" {
  driver   = "sqlite"
  dsn_file = %q
  users    = "select login, secret from staff"
}

share "open" { image = %q }
`, hclPath(dsn), hclPath(img)) + serveBlocks()
	if out, err := execute(t, "check", write(t, dir, "c.hcl", body)); err == nil {
		t.Fatalf("check accepted a database that is not there:\n%s", out)
	} else if !strings.Contains(err.Error(), "not answering") {
		t.Errorf("the refusal reads %q", err)
	}
}

// A DSN holds a password, so it is read from a file and never written in the
// configuration -- and the refusal says why, because somebody who tried to put
// it inline is about to look for the flag instead.
func TestASQLBlockWithoutADSNFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := fmt.Sprintf(`
users "sql" {
  driver = "sqlite"
  users  = "select login, secret from staff"
}

share "open" { image = %q }
`, hclPath(img)) + serveBlocks()
	if _, err := execute(t, "check", write(t, dir, "c.hcl", body)); err == nil {
		t.Fatal("check accepted a sql block with no dsn_file")
	} else if !strings.Contains(err.Error(), "dsn_file") {
		t.Errorf("the refusal reads %q", err)
	}
}

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
