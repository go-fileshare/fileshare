// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || nogrpc || noprovisioner

package main

import (
	"strings"
	"testing"
)

func TestABinaryWithoutTheProvisionerSaysWhy(t *testing.T) {
	_, err := execute(t, "provisioner", "-c", "p.hcl")
	if err == nil || !strings.Contains(err.Error(), "has no provisioner") {
		t.Errorf("provisioner in a build without it: %v", err)
	}
}
