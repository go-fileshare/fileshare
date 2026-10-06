// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !nogrpc && !noprovisioner

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheProvisionersArguments(t *testing.T) {
	if _, err := execute(t, "provisioner"); err == nil || !strings.Contains(err.Error(), "-c <file>") {
		t.Errorf("no configuration: %v", err)
	}
	cfg := filepath.Join(t.TempDir(), "p.hcl")
	if _, err := execute(t, "provisioner", "-c", cfg, "--image", "x.img"); err == nil || !strings.Contains(err.Error(), "serves none") {
		t.Errorf("--image: %v", err)
	}
	if _, err := execute(t, "provisioner", "-c", cfg); err == nil {
		t.Error("a missing file was accepted")
	}
	// A configuration that parses, and a machine where its parents are not:
	// the start refuses, naming what it looked for.
	d := t.TempDir()
	os.WriteFile(cfg, []byte(`
provisioner {
  listen     = "unix://`+d+`/p.sock"
  client_uid = 990
  group      = "990"
  max_volume = "1G"
  state_file = "`+d+`/v.json"
  parent "fast" { btrfs = "`+d+`/nope" }
}
`), 0o600)
	if _, err := execute(t, "provisioner", "-c", cfg); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("a parent that is not there: %v", err)
	}
}
