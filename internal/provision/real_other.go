// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package provision

import "errors"

// newSystem refuses: the provisioner's storage is Linux's. The package builds
// here only so its tests run, against fakes.
func newSystem() (*system, error) {
	return nil, errors.New("the provisioner runs on Linux only")
}
