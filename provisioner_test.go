// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
)

func TestTheProvisionerSaysWhatItIs(t *testing.T) {
	out, err := execute(t, "provisioner", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CAP_SYS_ADMIN", "-c", "unix socket", "Linux only"} {
		if !strings.Contains(out, want) {
			t.Errorf("the provisioner's help does not mention %q", want)
		}
	}
	if _, err := execute(t, "provisioner", "extra/arg"); err == nil {
		t.Error("an argument was accepted")
	}
}
