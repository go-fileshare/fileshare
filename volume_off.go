// SPDX-License-Identifier: BSD-3-Clause

//go:build nogrpc

package main

import "strings"

// Built with -tags nogrpc: no admin API, so no provisioner to ask, and no
// share is ever made from a volume. A state file that holds some -- written
// by a fuller build -- leaves them defined and unserved.

type volumeService interface{}

func resolveVolumes(_ *adminBlock, shares []managedShare) map[string]*volumeResolution {
	out := map[string]*volumeResolution{}
	for _, m := range shares {
		if m.Volume != nil {
			out[strings.ToUpper(m.Name)] = &volumeResolution{
				why: "this binary was built with -tags nogrpc, which leaves volumes out"}
		}
	}
	return out
}
