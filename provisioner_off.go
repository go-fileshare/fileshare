// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || nogrpc || noprovisioner

package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// runProvisioner says why there is none, rather than "unknown command": the
// difference between a typo and a build.
func runProvisioner(*cobra.Command, *options) error {
	return fmt.Errorf("this binary has no provisioner: it is built only for Linux, "+
		"and left out by -tags nogrpc or noprovisioner (this one is %s/%s)", runtime.GOOS, runtime.GOARCH)
}
