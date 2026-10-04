// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A share must not contain what decides who may do what: its writers would
// rewrite it. Every protected file, inside a directory share, is refused;
// the control is the same file outside it. The trust anchors and lists
// (ssh_ca_file, the KRL and CRL files and their state) were not protected
// until v0.16.0, and the rule had no test.
func TestAShareHoldingWhatDecidesAccessIsRefused(t *testing.T) {
	share := t.TempDir()
	outside := t.TempDir()
	for name, set := range map[string]func(c *config, p string){
		"ssh_ca_file":        func(c *config, p string) { c.OIDC = &oidcBlock{SSHCAFile: p} },
		"ssh_krl_file":       func(c *config, p string) { c.OIDC = &oidcBlock{SSHKRLFile: p} },
		"ssh_krl_ca_file":    func(c *config, p string) { c.OIDC = &oidcBlock{SSHKRLCAFile: p} },
		"ssh_krl_state_file": func(c *config, p string) { c.OIDC = &oidcBlock{SSHKRLStateFile: p} },
		"client_ca_file":     func(c *config, p string) { c.Serves = []serveBlock{{ClientCAFile: p}} },
		"crl_file":           func(c *config, p string) { c.Serves = []serveBlock{{CRLFile: p}} },
		"crl_ca_file":        func(c *config, p string) { c.Serves = []serveBlock{{CRLCAFile: p}} },
		"crl_state_file":     func(c *config, p string) { c.Serves = []serveBlock{{CRLStateFile: p}} },
		"trusted_user_ca":    func(c *config, p string) { c.TrustedUserCAFile = p },
		"admin state_file":   func(c *config, p string) { c.Admin = &adminBlock{StateFile: p} },
		// Where the people come from, and what proves who they are: none of
		// these was protected until an audit of v0.16.7 found a writer of a
		// /home share adding his key to alice's authorized_keys_file.
		"authorized_keys_file": func(c *config, p string) { c.Users = []userBlock{{Name: "alice", AuthorizedKeysFile: p}} },
		"password_file":        func(c *config, p string) { c.Users = []userBlock{{Name: "alice", PasswordFile: p}} },
		"users sql dsn_file":   func(c *config, p string) { c.Directories = []usersBlock{{Kind: "sql", DSNFile: p}} },
		"users ldap bind_password_file": func(c *config, p string) {
			c.Directories = []usersBlock{{Kind: "ldap", BindPasswordFile: p}}
		},
		"ssf ca_file": func(c *config, p string) { c.SSF = &ssfBlock{CAFile: p} },
	} {
		for _, where := range []string{share, outside} {
			p := filepath.Join(where, "f")
			os.WriteFile(p, []byte("x"), 0o600)
			c := &config{}
			set(c, p)
			err := c.checkNoShareHoldsSecrets([]shareBlock{{Name: "d", Directory: share}})
			if (err == nil) == (where == share) {
				t.Errorf("%s in the share = %v: err = %v", name, where == share, err)
			}
			os.Remove(p)
		}
	}
}

// A sqlite DSN names a FILE, and that file is the directory: whoever may write
// into a share holding it rewrites everybody's password. The DSN file lives
// outside the share here, so only the database it names can be the reason;
// both spellings sqlite accepts are read, and the control is the same database
// outside the share.
func TestAShareHoldingTheSqliteDatabaseIsRefused(t *testing.T) {
	share := t.TempDir()
	outside := t.TempDir()
	for _, where := range []string{share, outside} {
		db := filepath.Join(where, "people.db")
		for _, spelling := range []string{db, "file:" + filepath.ToSlash(db) + "?mode=ro"} {
			dsn := write(t, t.TempDir(), "dsn", spelling+"\n")
			c := &config{Directories: []usersBlock{{Kind: "sql", Driver: "sqlite", DSNFile: dsn}}}
			err := c.checkNoShareHoldsSecrets([]shareBlock{{Name: "d", Directory: share}})
			if (err == nil) == (where == share) {
				t.Errorf("database %q in the share = %v: err = %v", spelling, where == share, err)
			}
		}
	}
	// A DSN naming no file protects nothing, and is not an error.
	for _, spelling := range []string{":memory:", "file::memory:?cache=shared", ""} {
		if got := sqliteFiles(write(t, t.TempDir(), "dsn", spelling)); got != nil {
			t.Errorf("%q names %v", spelling, got)
		}
	}
	if got := sqliteFiles(filepath.Join(outside, "no-such-dsn")); got != nil {
		t.Errorf("an unreadable DSN file names %v", got)
	}
}
