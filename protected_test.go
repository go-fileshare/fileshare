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
